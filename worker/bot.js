/* SubZer0 Sentinel: interactive Telegram bot on Cloudflare Workers.
 *
 * Telegram -> POST /tg (webhook, checked with the secret token header) -> reply.
 * Handles messages, button taps (callback_query) and inline mode (@SubZer0Robot CVE-… in any chat).
 * Data comes from the published site only (api/latest.json, api/cve/<id>.json, api/hubs.json), so the bot
 * never disagrees with the website. Watchlists live in KV under "w:<chat id>"; the 6-hourly snapshot job
 * (scripts/notify_telegram.py) reads them and DMs matches. Groups: admins manage a group watchlist (same "w:<chat>"),
 * and "g:<chat>" marks a group that wants the morning brief (scripts/digest.py forwards the daily channel post there).
 *
 * Bindings: KV (namespace), BOT_TOKEN (secret), WEBHOOK_SECRET (secret), SITE (plain text), ADMIN_ID (optional).
 */
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/i;
const MAX_WATCH = 10;
const PAGE = 5;
const RATE = 20; // messages + taps per chat per minute
const CHANNEL = 'https://t.me/RootAccessClub';
const BOT = 'SubZer0Robot';
const SEV_DOT = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
const NUM = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣'];

const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s; };
/* "arista velocloud orchestrator arista velocloud orchestrator" -> "arista velocloud orchestrator" */
const dedupe = s => { const seen = new Set(); return String(s || '').split(/\s+/).filter(w => { const k = w.toLowerCase(); if (!k || seen.has(k)) return false; seen.add(k); return true; }).join(' '); };
const pct = e => (e * 100 >= 10 ? (e * 100).toFixed(0) : (e * 100).toFixed(1)) + '%';
const norm = s => String(s || '').toLowerCase().replace(/[^a-z0-9.+_\- ]/g, ' ').replace(/\s+/g, ' ').trim();
const n = x => Number(x || 0).toLocaleString('en-US');

/* ---------- buttons (style: "danger" red, "success" green, "primary" blue; older apps ignore it) ---------- */
const b = (text, o, style) => (style ? { text, ...o, style } : { text, ...o });
const cb = (text, data, style) => b(text, { callback_data: data }, style);
const link = (text, url, style) => b(text, { url }, style);
/* opens the Mini App in private chats, the site elsewhere (web_app buttons only work in private chats) */
const app = (env, text, path, priv, style) => b(text, priv ? { web_app: { url: env.SITE + path } } : { url: env.SITE + path }, style);
const share = (url, text) => `https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`;
const kb = rows => ({ inline_keyboard: rows.filter(r => r && r.length) });

/* vcheck:start — shared by site/app.js and worker/bot.js (tests/test_versions.py keeps the copies identical). */
const VPRE={dev:0,snapshot:0,alpha:1,a:1,beta:2,b:2,preview:3,pre:3,rc:4,cr:4};
const vtok=v=>(String(v).trim().toLowerCase().replace(/^v(?=\d)/,'').match(/\d+|[a-z]+/g)||[]).map(t=>/^\d+$/.test(t)?+t:t);
function vcmp(a,b){const x=vtok(a),y=vtok(b);let i=0;
  for(;i<x.length&&i<y.length;i++){const p=x[i],q=y[i];if(p===q)continue;const np=typeof p==='number',nq=typeof q==='number';
    if(np&&nq)return p<q?-1:1;if(np)return q in VPRE?1:-1;if(nq)return p in VPRE?-1:1;
    const rp=p in VPRE?VPRE[p]:9,rq=q in VPRE?VPRE[q]:9;if(rp!==rq)return rp<rq?-1:1;return p<q?-1:1}
  const longer=x.length>y.length,rest=(longer?x:y).slice(i),sg=longer?1:-1;if(!rest.length)return 0;
  if(typeof rest[0]==='string')return rest[0] in VPRE?-sg:sg;return rest.some(t=>t!==0)?sg:0}
const vfix=e=>e[5]||(e[3]&&e[4]===0?e[3]:'');
function vhit(v,e){const lo=e[1],li=e[2],hi=e[3],hx=e[4];if(hx===-1)return false;
  if(lo){const c=vcmp(v,lo);if(c<0||(c===0&&!li))return false}if(hi){const c=vcmp(v,hi);if(c>0||(c===0&&!hx))return false}return true}
const VER_RE=/^v?[0-9][0-9a-z.\-_+~]*$/i;
const vnorm=s=>String(s||'').toLowerCase().replace(/_/g,' ').replace(/[^a-z0-9.+ ]/g,' ').replace(/\s+/g,' ').trim();
/* "nginx 1.24.0" -> {words:['nginx'],version:'1.24.0',shards:['n']} */
function vparse(q){let t=vnorm(String(q||'').replace(/@/g,' ')).split(' ').filter(Boolean).filter(w=>w!=='version'&&w!=='ver');
  let version='';if(t.length>1&&VER_RE.test(t[t.length-1])&&(/[.\-]/.test(t[t.length-1])||/^\d+$/.test(t[t.length-1])))version=t.pop().replace(/^v/,'');
  const shards=[...new Set(t.map(w=>/^[a-z]/.test(w)?w[0]:'0'))].slice(0,4);return{words:t,version,shards}}
/* shards: {shardName: shardJSON}. Returns ranked products with affected CVEs for the version (or every range when no version). */
function vcheck(q,shards,max){const P=vparse(q);max=max||6;if(!P.words.length)return{...P,products:[]};const cands=[];
  for(const s of P.shards){const S=shards[s];if(!S)continue;for(const key in S.p){const [ven,pro]=key.split('|'),words=(ven+' '+pro).split(' ');
    if(!P.words.every(w=>words.some(x=>x.startsWith(w))))continue;const j=P.words.join(' ');
    const score=(pro===j||(ven+' '+pro)===j?4:pro.startsWith(j)?3:words.includes(P.words[0])?2:1)*1000-words.length*10+Math.min(9,S.p[key].length/20);
    cands.push({key,ven,pro,score,S})}}
  const seen=new Set();cands.sort((a,b)=>b.score-a.score);
  const products=cands.filter(c=>!seen.has(c.key)&&seen.add(c.key)).slice(0,max).map(({key,ven,pro,S})=>{const by=new Map();let unknown=0,ranged=0;
    for(const e of S.p[key]){const m=S.c[e[0]];if(e[4]===-1){unknown++;continue}ranged++;
      if(P.version&&!vhit(P.version,e))continue;const o=by.get(m[0]);if(!o)by.set(m[0],{id:m[0],sev:m[1],p:m[2],kev:!!m[3],cvss:m[4],title:m[5],ranges:[e],fix:vfix(e)});else{o.ranges.push(e);const f=vfix(e);if(f&&(!o.fix||vcmp(f,o.fix)>0))o.fix=f}}
    const list=[...by.values()].sort((a,b)=>a.p-b.p||b.kev-a.kev||b.cvss-a.cvss);let fix='';for(const c of list)if(c.fix&&(!fix||vcmp(c.fix,fix)>0))fix=c.fix;
    return{key,vendor:ven,product:pro,affected:list,unknown,ranged,fix}});
  return{...P,products}}
const vrange=e=>e[4]===-1?'version not given':e[1]&&e[3]&&e[1]===e[3]&&e[2]&&e[4]?'= '+e[1]:[e[1]?(e[2]?'≥ ':'> ')+e[1]:'',e[3]?(e[4]?'≤ ':'< ')+e[3]:''].filter(Boolean).join(', ');
/* vcheck:end */

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') return new Response('SubZer0 Sentinel is running. Talk to @SubZer0Robot on Telegram.\n');
    if (req.method !== 'POST' || url.pathname !== '/tg') return new Response('not found', { status: 404 });
    if (!env.WEBHOOK_SECRET || req.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.WEBHOOK_SECRET)
      return new Response('forbidden', { status: 403 });
    let update;
    try { update = await req.json(); } catch { return new Response('bad request', { status: 400 }); }
    ctx.waitUntil(handle(update, env).catch(e => oops(env, e)));
    return new Response('ok');
  },
};

/* ---------- safety: per-chat rate limit, error log, admin alert ---------- */
const hits = new Map();
function limited(chat, now = Date.now()) {
  const h = hits.get(chat);
  if (!h || now - h.t > 60000) { hits.set(chat, { t: now, c: 1, warned: false }); if (hits.size > 5000) hits.clear(); return 0; }
  h.c++;
  if (h.c <= RATE) return 0;
  if (!h.warned) { h.warned = true; return 1; } // warn once, then stay quiet
  return 2;
}

async function oops(env, e) {
  const msg = clip((e && e.message) || String(e), 200);
  console.log('handle failed', msg);
  try {
    const day = 'e:' + new Date().toISOString().slice(0, 10);
    const c = Number(await env.KV.get(day)) || 0;
    await env.KV.put(day, String(c + 1), { expirationTtl: 86400 * 8 });
    if (env.ADMIN_ID && !(await env.KV.get('alert'))) { // at most one admin DM per hour
      await env.KV.put('alert', '1', { expirationTtl: 3600 });
      await tg(env, 'sendMessage', { chat_id: env.ADMIN_ID, text: `⚠️ <b>SubZer0 bot error</b>\n<code>${esc(msg)}</code>\n\n/stats for details`, parse_mode: 'HTML' });
    }
  } catch { /* logging must never throw */ }
}

const seenUsers = new Set();
async function remember(env, chat) {
  if (seenUsers.has(chat)) return;
  seenUsers.add(chat);
  try { if (!(await env.KV.get('u:' + chat))) await env.KV.put('u:' + chat, String(Date.now())); } catch { /* not critical */ }
}

/* ---------- routing ---------- */
async function handle(update, env) {
  if (update.callback_query) return onTap(update.callback_query, env);
  if (update.inline_query) return onInline(update.inline_query, env);
  if (update.my_chat_member) return onMember(update.my_chat_member, env);
  const msg = update.message;
  if (!msg || !msg.chat || typeof msg.text !== 'string') return;
  const chat = msg.chat.id, priv = msg.chat.type === 'private';
  const text = msg.text.trim().slice(0, 300);
  const m = text.match(/^\/([a-z_]+)(?:@\w+)?\s*(.*)$/i);
  const cmd = m ? m[1].toLowerCase() : '', arg = m ? m[2].trim() : text;
  if (!m && !priv) return; // in groups only answer explicit commands
  const lim = limited(chat);
  if (lim === 1) return send(env, chat, { text: 'Slow down a little — try again in a minute.' });
  if (lim) return;
  if (priv) await remember(env, chat);

  if (cmd === 'start') {
    const a = arg.replace(/_/g, '-');
    if (CVE_RE.test(a)) return reply(env, chat, await cveView(env, a.match(CVE_RE)[0].toUpperCase(), priv));
    if (/^watch-.+/i.test(a)) return watch(env, chat, arg.slice(6).replace(/_/g, ' '), priv);
    if (a === 'watch') return send(env, chat, await listView(env, chat, priv));
    if (a === 'top') return send(env, chat, await topView(env, 0, priv));
    if (a === 'week') return send(env, chat, await weekView(env, priv));
    if (a === 'brief' && !priv) return; // "Add to a group" link: the welcome message already covers it
  }
  if (cmd === 'start' || cmd === 'menu') return send(env, chat, await menuView(env, priv));
  if (cmd === 'help') return send(env, chat, helpView(env, priv));
  if (cmd === 'top') return send(env, chat, await topView(env, 0, priv));
  if (cmd === 'week' || cmd === 'weekly') return send(env, chat, await weekView(env, priv));
  if (cmd === 'daily' || cmd === 'morning' || cmd === 'brief') return daily(env, msg, arg);
  if ((cmd === 'watch' || cmd === 'unwatch') && !priv && norm(arg) && !(await isAdmin(env, msg.chat.id, msg.from, msg.sender_chat)))
    return send(env, chat, { text: 'Only group admins can change the group watchlist. Anyone can see it: /list' });
  if (cmd === 'watch') return watch(env, chat, arg, priv);
  if (cmd === 'unwatch') return unwatch(env, chat, arg, priv);
  if (cmd === 'list' || cmd === 'watchlist' || cmd === 'settings') return send(env, chat, await listView(env, chat, priv));
  if (cmd === 'search' || cmd === 'find') return send(env, chat, await searchView(env, arg, priv));
  if (cmd === 'check' || cmd === 'affected') return send(env, chat, await checkView(env, arg, priv));
  if (cmd === 'myid') return send(env, chat, { text: `Your chat id: <code>${esc(chat)}</code>` });
  if (cmd === 'stats') return send(env, chat, await statsView(env, chat));
  if (cmd === 'cve' || (!m && CVE_RE.test(text))) {
    const id = (arg.match(CVE_RE) || text.match(CVE_RE) || [])[0];
    if (!id) return send(env, chat, { text: 'Send a CVE id, e.g. <code>/cve CVE-2026-110447</code>' });
    return reply(env, chat, await cveView(env, id.toUpperCase(), priv));
  }
  if (!m && /\./.test(vparse(text).version)) return send(env, chat, await checkView(env, text, priv)); // "nginx 1.24.0" = version check
  if (!m) return send(env, chat, await searchView(env, text, priv)); // plain words in a DM = search
}

/* button taps: t:<page> top list · c:<id> CVE card · wk week · l list · m menu · a:/A:<kw> watch · r:<kw> unwatch · s search tip
 * g group brief view · G:on/G:off morning brief (groups) · in groups every change (a A r S M G) is for admins only */
async function onTap(q, env) {
  const data = String(q.data || ''), msg = q.message, chat = msg && msg.chat && msg.chat.id;
  const answer = (text, alert) => tg(env, 'answerCallbackQuery', { callback_query_id: q.id, ...(text ? { text, show_alert: !!alert } : {}) });
  if (!chat) return answer();
  if (limited(chat)) return answer('Slow down a little — try again in a minute.');
  const priv = msg.chat.type === 'private';
  const [op, rest = ''] = [data.slice(0, data.indexOf(':') < 0 ? data.length : data.indexOf(':')), data.includes(':') ? data.slice(data.indexOf(':') + 1) : ''];
  if (op === 'noop') return answer();
  if (!priv && 'aArSMG'.includes(op) && op && !(await isAdmin(env, chat, q.from))) return answer('Only group admins can change this.', true);
  if (op === 'G' && !priv && (rest === 'on' || rest === 'off')) {
    await setBrief(env, chat, rest === 'on', msg.chat.title);
    await answer(rest === 'on' ? '☀️ Morning brief on' : 'Morning brief off');
    return edit(env, msg, await briefView(env, chat));
  }
  if (op === 'c' && CVE_RE.test(rest)) { await answer(); return reply(env, chat, await cveView(env, rest.toUpperCase(), priv)); }
  if (op === 'a' || op === 'A') {
    const r = await addWatch(env, chat, rest);
    await answer(r.toast, !r.ok);
    if (op === 'A' && r.ok) return edit(env, msg, await listView(env, chat, priv));
    return;
  }
  if (op === 'r') {
    const doc = await getDoc(env, chat);
    doc.k = doc.k.filter(x => x !== rest);
    await saveDoc(env, chat, doc);
    await answer(`Removed ${rest}`);
    return edit(env, msg, await listView(env, chat, priv));
  }
  if ((op === 'S' && (rest === 'p1' || rest === 'crit')) || (op === 'M' && (rest === 'now' || rest === 'daily'))) {
    const doc = await getDoc(env, chat);
    if (!doc.k.length) { await answer('Add a name first: /watch nginx', true); return edit(env, msg, await listView(env, chat, priv)); }
    if (op === 'S') doc.s = rest; else doc.m = rest;
    await saveDoc(env, chat, doc);
    await answer(op === 'S' ? (rest === 'crit' ? '🔴 Patch-now + new critical CVEs' : '🎯 Patch-now CVEs only') : (rest === 'daily' ? '🗓 One summary a day' : '⚡ Right away'));
    return edit(env, msg, await listView(env, chat, priv));
  }
  if (op === 'q') { await answer(); return send(env, chat, await searchView(env, rest, priv)); }
  if (op === 's') return answer('Just send a name like nginx, wordpress or xss — or a CVE id.', true);
  await answer();
  const view = op === 't' ? await topView(env, Number(rest) || 0, priv) : op === 'wk' ? await weekView(env, priv)
    : op === 'l' ? await listView(env, chat, priv) : op === 'g' && !priv ? await briefView(env, chat) : await menuView(env, priv);
  return msg.photo ? send(env, chat, view) : edit(env, msg, view);
}

/* ---------- data ---------- */
async function site(env, path) {
  const r = await fetch(env.SITE + path, { cf: { cacheTtl: 300, cacheEverything: true }, headers: { 'User-Agent': 'SubZer0-bot' } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('site ' + r.status + ' ' + path);
  return r.json();
}
async function safe(env, path) { try { return await site(env, path); } catch (e) { await oops(env, e); return undefined; } }
const DOWN = { text: 'The site did not answer. Try again in a minute.' };
async function hubs(env) { const h = await safe(env, 'api/hubs.json'); return h && Array.isArray(h.topics) ? h : null; }

/* the vendor/product page for a keyword or a CVE's product line */
function topicIn(h, textLow) {
  if (!h) return null;
  return h.topics.filter(t => t.term && t.term.length >= 3 && new RegExp(`(^|[^a-z0-9])${t.term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`).test(textLow))
    .sort((x, y) => y.term.length - x.term.length)[0] || null;
}

/* ---------- views: { text, markup } ---------- */
function helpView(env, priv) {
  return {
    text: ['<b>SubZer0 Sentinel</b> · CVE briefing in your chat', '',
      '/top — what to patch right now', '/week — this week\'s recap', '/cve <code>CVE-2026-110447</code> — one CVE (or just send the id)',
      '/search <code>nginx</code> — vendor, product or weakness (or just send a word)',
      '/check <code>chrome 150.0.7</code> — is the version you run affected? (or just send name + version)',
      '/watch <code>nginx</code> — DM me when it gets a patch-now CVE', '/settings — your watchlist: critical too? instant or daily?', '',
      ...(priv ? [] : ['', '<b>In this group</b>', '/daily — ☀️ morning brief on/off (admins)', '/watch <code>nginx</code> — group watchlist (admins), /list to see it']),
      `In any chat: type <code>@${BOT} CVE-2026-…</code> to share a CVE card.`, `Add me to a group for a ☀️ morning brief: /daily`, `Live alerts: @RootAccessClub · Site: ${env.SITE}`].join('\n'),
    markup: kb([[cb('≡ Menu', 'm', 'primary')]]),
  };
}

async function menuView(env, priv) {
  const d = await safe(env, 'api/latest.json'), t = (d && d.totals) || {};
  const p1 = d && Array.isArray(d.patch_now) ? d.patch_now.length : null;
  const text = ['🧊 <b>SubZer0 Sentinel</b>', '<i>What to patch first, ranked by real exploitation (CISA KEV, EPSS, public exploits).</i>', '',
    d ? `🎯 <b>${p1}</b> to patch now · 🏛 <b>${n(t.known_exploited)}</b> on CISA KEV · ${n(t.cves)} CVEs in 30 days` : '',
    d && d.generated_at ? `<i>Updated ${esc(String(d.generated_at).slice(0, 16).replace('T', ' '))} UTC · refreshed every 6 hours</i>` : '',
    '', 'Send a CVE id, or a name like <code>nginx</code> or <code>xss</code>.'].filter((x, i, a) => x || a[i - 1]).join('\n');
  return {
    text,
    markup: kb([[cb('🎯 Patch now', 't:0', 'danger'), cb('📅 This week', 'wk', 'primary')],
      priv ? [cb('👁 My watchlist', 'l', 'success'), cb('🔎 Search', 's')] : [cb('☀️ Morning brief', 'g', 'success'), cb('👁 Group watchlist', 'l')],
      [link('📣 Channel', CHANNEL), app(env, '🌐 Open SubZer0', '', priv)]]),
  };
}

function cveText(d) {
  const sev = String(d.severity || 'unknown');
  const lines = [`${SEV_DOT[sev] || '⚪️'} <b>${esc(d.id)}</b> · ${esc(sev.toUpperCase())}${d.cvss ? ' ' + Number(d.cvss).toFixed(1) : ''}`];
  if (d.products) lines.push(`<i>${esc(clip(dedupe(d.products), 80))}</i>`);
  lines.push('', esc(clip(d.desc || d.title, 420)), '');
  const prio = d.priority === 1 ? `🎯 <b>Patch now</b> — ${esc(d.why)}` : d.priority === 2 ? '🗓 Patch this week' : d.priority === 3 ? '📋 Planned patching' : d.priority ? '👀 Track' : '';
  if (prio) lines.push(prio);
  const sig = [];
  if (d.kev) sig.push('🏛 CISA KEV');
  if (d.weaponized) sig.push('⚔️ weaponized');
  else if (d.public_exploit) sig.push('🧨 public exploit');
  if (typeof d.epss === 'number') sig.push('📈 EPSS ' + pct(d.epss));
  if (sig.length) lines.push(sig.join(' · '));
  if (d.published) lines.push(`Published ${esc(d.published)}${d.archived ? ` · archived ${esc(d.archived)}` : ''}`);
  return lines.join('\n');
}

async function cveView(env, id, priv) {
  let d;
  try { d = await site(env, `api/cve/${id}.json`); } catch (e) { await oops(env, e); return DOWN; }
  if (!d) return { text: `<b>${esc(id)}</b> is not in the SubZer0 snapshot (last 30 days + archive).`, markup: kb([[link('Open on NVD', `https://nvd.nist.gov/vuln/detail/${id}`)]]) };
  const h = await hubs(env);
  const topic = topicIn(h, `${d.products || ''} ${d.title || ''}`.toLowerCase());
  const weak = h && Array.isArray(h.weaknesses) && Array.isArray(d.cwe) ? h.weaknesses.find(w => d.cwe.includes(w.id)) : null;
  const text = cveText(d);
  let photo = null;
  if (text.length < 1000) {
    try { const r = await fetch(`${env.SITE}og/${d.id}.jpg`, { method: 'HEAD', cf: { cacheTtl: 3600 } }); if (r.ok) photo = `${env.SITE}og/${d.id}.jpg`; } catch { /* no card */ }
  }
  return {
    text, photo,
    markup: kb([[app(env, '📂 Open dossier', `cve/${d.id}`, priv, d.priority === 1 ? 'danger' : 'primary')],
      [priv && topic ? cb(`👁 Watch ${clip(topic.name, 22)}`, `a:${topic.term}`, 'success') : null, weak ? link(`📖 ${clip(weak.name.replace(/\s*\(.*\)$/, ''), 22)}`, env.SITE + weak.path) : null].filter(Boolean),
      [b('📋 Copy ID', { copy_text: { text: d.id } }), link('↗ Share', share(d.url || env.SITE + 'cve/' + d.id, `${d.id}: ${clip(d.title, 90)}`))]]),
  };
}

async function topView(env, page, priv) {
  const d = await safe(env, 'api/latest.json');
  if (!d || !Array.isArray(d.patch_now)) return DOWN;
  const all = d.patch_now, pages = Math.max(1, Math.ceil(all.length / PAGE)), p = Math.min(Math.max(0, page), pages - 1);
  const items = all.slice(p * PAGE, p * PAGE + PAGE);
  const t = d.totals || {};
  const text = [`🎯 <b>Patch now</b> · ${all.length} CVEs`, `<i>${n(t.cves)} CVEs in 30 days · ${n(t.known_exploited)} on CISA KEV</i>`, '',
    ...items.map((i, k) => `${NUM[k]} ${SEV_DOT[i.severity] || '⚪️'} <a href="${esc(i.url)}">${esc(i.id)}</a>${i.cvss ? ' · ' + Number(i.cvss).toFixed(1) : ''}${i.kev ? ' · KEV' : ''}\n   ${esc(clip(dedupe(i.products) || i.title, 60))} — <i>${esc(i.why)}</i>`),
    '', '<i>Tap a number for the full card.</i>'].join('\n');
  return {
    text,
    markup: kb([items.map((i, k) => cb(NUM[k], 'c:' + i.id)),
      pages > 1 ? [cb('‹ Prev', 't:' + Math.max(0, p - 1)), cb(`${p + 1} / ${pages}`, 'noop'), cb('Next ›', 't:' + Math.min(pages - 1, p + 1))] : null,
      [app(env, 'See all in SubZer0', 'research?view=p1', priv, 'danger'), cb('≡ Menu', 'm')]]),
  };
}

async function weekView(env, priv) {
  const h = await hubs(env), w = h && h.week;
  if (!w) return { text: 'The weekly recap is not available right now. Try /top.', markup: kb([[cb('🎯 Patch now', 't:0', 'danger')]]) };
  const top = w.top || [];
  const text = [`📅 <b>${esc(w.label)}</b> · ${esc(w.span)}`,
    `<i>${n(w.n)} CVEs · ${w.p1} patch now · ${w.kev} on CISA KEV · ${n(w.crit)} critical</i>`, '', '🎯 <b>Top this week</b>',
    ...top.map((i, k) => `${NUM[k] || '•'} ${SEV_DOT[i.sev] || '⚪️'} <a href="${esc(env.SITE + 'cve/' + i.id)}">${esc(i.id)}</a>${i.cvss ? ' · ' + Number(i.cvss).toFixed(1) : ''}${i.kev ? ' · KEV' : ''}\n   ${esc(clip(i.title, 70))}`)].join('\n');
  return {
    text,
    markup: kb([top.slice(0, 5).map((i, k) => cb(NUM[k], 'c:' + i.id)), [app(env, '📖 Read the full recap', w.path, priv, 'primary'), cb('≡ Menu', 'm')]]),
  };
}

async function searchView(env, q, priv) {
  const kw = norm(q);
  if (kw.length < 2) return { text: 'Send a vendor, product or weakness, e.g. <code>/search nginx</code> or <code>/search xss</code>.' };
  const h = await hubs(env);
  if (!h) return DOWN;
  const has = s => String(s || '').toLowerCase().includes(kw);
  const topics = h.topics.filter(t => has(t.name) || (t.term && (t.term === kw || has(t.term) || (kw.length > 3 && kw.includes(t.term))))).slice(0, 4);
  const weak = (h.weaknesses || []).filter(w => has(w.name) || w.id.toLowerCase() === kw || w.id.toLowerCase() === 'cwe-' + kw).slice(0, 3);
  const canWatch = priv && kw.length >= 3 && kw.length <= 40;
  if (!topics.length && !weak.length) {
    return { text: `🔎 No page for <b>${esc(kw)}</b> yet.${canWatch ? '\nYou can still watch it: you get a DM when a matching CVE becomes patch now.' : ''}`,
      markup: kb([canWatch ? [cb(`👁 Watch ${clip(kw, 24)}`, 'a:' + kw, 'success')] : null, [cb('≡ Menu', 'm')]]) };
  }
  const lines = [`🔎 <b>${esc(kw)}</b>`, ''];
  for (const t of topics) lines.push(`📂 <b>${esc(t.name)}</b> · ${n(t.n)} CVEs${t.p1 ? ` · 🎯 ${t.p1} patch now` : ''}`);
  for (const w of weak) lines.push(`📖 <b>${esc(w.name)}</b> (${esc(w.id)}) · ${n(w.n)} CVEs`);
  const best = topics[0];
  return {
    text: lines.join('\n'),
    markup: kb([...topics.map(t => [app(env, `📂 ${clip(t.name, 28)}`, t.path, priv, 'primary')]), ...weak.map(w => [link(`📖 ${clip(w.name, 30)}`, env.SITE + w.path)]),
      canWatch ? [cb(`👁 Watch ${clip(best ? best.name : kw, 22)}`, 'a:' + (best && best.term ? best.term : kw), 'success')] : null, [cb('≡ Menu', 'm')]]),
  };
}

/* ---------- "is my version affected?" ---------- */
const VCACHE = new Map(); // shard -> { t, doc }: parsed once per isolate for 10 minutes
async function vshard(env, name) {
  const hit = VCACHE.get(name);
  if (hit && Date.now() - hit.t < 600000) return hit.doc;
  const doc = await safe(env, `api/versions/${name}.json`);
  if (doc && doc.p) { VCACHE.set(name, { t: Date.now(), doc }); if (VCACHE.size > 40) VCACHE.delete(VCACHE.keys().next().value); }
  return doc && doc.p ? doc : null;
}
async function checkView(env, q, priv) {
  q = String(q || '').trim().slice(0, 80);
  const P = vparse(q);
  if (!P.words.length) return { text: '🧪 Send a product and the version you run, e.g. <code>/check chrome 150.0.7</code>.' };
  const shards = {};
  for (const s of P.shards) { const d = await vshard(env, s); if (d) shards[s] = d; }
  const R = vcheck(q, shards, 2), name = p => (p.product.startsWith(p.vendor) || !p.vendor ? '' : p.vendor + ' ') + p.product;
  const full = link('🌐 Full result', `${env.SITE}?check=${encodeURIComponent(q)}`);
  if (!R.products.length) {
    return { text: `🧪 No version data for <b>${esc(P.words.join(' '))}</b> in the last 30 days.\nThat is not the same as safe. Try /search ${esc(P.words[0])}.`,
      markup: kb([[cb(`🔎 Search ${clip(P.words.join(' '), 24)}`, 'q:' + P.words.join(' ').slice(0, 40), 'primary')], [cb('≡ Menu', 'm')]]) };
  }
  const lines = [], pick = [];
  for (const p of R.products) {
    const a = p.affected, p1 = a.filter(c => c.p === 1).length, kev = a.filter(c => c.kev).length;
    lines.push(`🧪 <b>${esc(name(p))}</b>${R.version ? ` <code>${esc(R.version)}</code>` : ''}`);
    if (!R.version) lines.push(`📋 ${n(a.length)} CVEs with version ranges. Add your version: <code>/check ${esc(p.product)} 1.2.3</code>`);
    else if (a.length) {
      lines.push(`🔴 <b>Affected by ${n(a.length)} CVE${a.length === 1 ? '' : 's'}</b>${p1 ? ` · 🎯 ${p1} patch now` : ''}${kev ? ` · ⚠️ ${kev} exploited (KEV)` : ''}`);
      if (p.fix) lines.push(`⬆️ Upgrade to <code>${esc(p.fix)}</code> or later`);
    } else lines.push(`✅ No known CVEs for this version · ${n(p.ranged)} ranges checked`);
    for (const c of a.slice(0, pick.length ? 2 : 4)) {
      if (pick.length >= 5) break;
      pick.push(c.id);
      lines.push(`${NUM[pick.length - 1]} <code>${esc(c.id)}</code> ${SEV_DOT[c.sev] || '⚪'} P${c.p}${c.kev ? ' · KEV' : ''} · ${esc(vrange(c.ranges[0]))}`);
    }
    if (p.unknown) lines.push(`<i>+${p.unknown} more name it without a version, check those by hand.</i>`);
    lines.push('');
  }
  lines.push('<i>NVD + GitHub advisory version ranges, last 30 days. No match is not a guarantee.</i>');
  return { text: lines.join('\n'), markup: kb([pick.map((id, i) => cb(NUM[i], 'c:' + id)), [full], [cb('≡ Menu', 'm')]]) };
}

const SENS = { p1: 'a patch-now CVE', crit: 'a patch-now or a new critical CVE' };
async function listView(env, chat, priv = true) {
  const doc = await getDoc(env, chat), k = doc.k;
  if (k.length) {
    const on = (label, val, cur) => (val === cur ? '✓ ' : '') + label;
    const who = priv ? 'You get' : 'This group gets', how = priv ? 'a DM right away' : 'a message right away';
    return { text: [`👁 <b>${priv ? 'Your' : 'Group'} watchlist</b> · ${k.length}/${MAX_WATCH}`, ...k.map(x => '• ' + esc(x)), '',
      `🔔 ${who} ${doc.m === 'daily' ? '<b>one summary a day</b> (around 09:45 Tehran / 06:15 UTC)' : `<b>${how}</b>`} when one of these gets <b>${SENS[doc.s]}</b>.`,
      `Change it below${priv ? '' : ' (admins)'}. Tap ✕ to remove a name, or send <code>/watch name</code> to add.`].join('\n'),
      markup: kb([...k.map(x => [cb(`✕ ${clip(x, 30)}`, 'r:' + x, 'danger')]),
        [cb(on('🎯 Patch now only', 'p1', doc.s), 'S:p1', doc.s === 'p1' ? 'success' : undefined), cb(on('🔴 + Critical', 'crit', doc.s), 'S:crit', doc.s === 'crit' ? 'success' : undefined)],
        [cb(on('⚡ Instant', 'now', doc.m), 'M:now', doc.m === 'now' ? 'success' : undefined), cb(on('🗓 Daily summary', 'daily', doc.m), 'M:daily', doc.m === 'daily' ? 'success' : undefined)],
        [cb('≡ Menu', 'm')]]) };
  }
  const h = await hubs(env);
  const pop = h ? h.topics.filter(t => t.term && t.term.length >= 3 && t.term.length <= 40).sort((x, y) => y.n - x.n).slice(0, 6) : [];
  return { text: priv ? '👁 <b>Your watchlist is empty</b>\nPick what you run, or send <code>/watch nginx</code>. You get a DM only when it gets a patch-now CVE.'
    : '👁 <b>The group watchlist is empty</b>\nAdmins: pick what your team runs, or send <code>/watch nginx</code>. The group gets a message only when it gets a patch-now CVE.',
    markup: kb([...[0, 2, 4].map(i => pop.slice(i, i + 2).map(t => cb(`＋ ${clip(t.name, 20)}`, 'A:' + t.term, 'success'))), [cb('≡ Menu', 'm')]]) };
}

async function statsView(env, chat) {
  if (!env.ADMIN_ID || String(chat) !== String(env.ADMIN_ID)) return { text: 'This command is for the bot owner.' };
  const count = async prefix => { let c = 0, cursor; for (let i = 0; i < 20; i++) { const r = await env.KV.list({ prefix, cursor }); c += r.keys.length; if (r.list_complete) break; cursor = r.cursor; } return c; };
  const day = new Date().toISOString().slice(0, 10);
  const d = await safe(env, 'api/latest.json');
  const age = d && d.generated_at ? ((Date.now() - Date.parse(d.generated_at)) / 3600000).toFixed(1) : '?';
  return { text: ['📊 <b>SubZer0 bot</b>', `Users: <b>${n(await count('u:'))}</b>`, `Watchlists: <b>${n(await count('w:'))}</b> (groups: ${n(await count('w:-'))})`,
    `Groups with the morning brief: <b>${n(await count('g:'))}</b>`,
    `Errors today: <b>${Number(await env.KV.get('e:' + day)) || 0}</b>`, `Data age: <b>${age} h</b>${Number(age) > 8 ? ' ⚠️ refresh may be stuck' : ''}`].join('\n') };
}

/* ---------- watchlist ---------- */
/* w:<chat> = { k: keywords, s: "p1" | "crit" (sensitivity), m: "now" | "daily" (delivery), t: updated } */
async function getDoc(env, chat) {
  let v = null;
  try { v = await env.KV.get('w:' + chat, 'json'); } catch { /* treat as empty */ }
  return { k: Array.isArray(v && v.k) ? v.k : [], s: v && v.s === 'crit' ? 'crit' : 'p1', m: v && v.m === 'daily' ? 'daily' : 'now' };
}
async function getWatch(env, chat) { return (await getDoc(env, chat)).k; }
async function saveDoc(env, chat, doc) {
  if (doc.k.length) await env.KV.put('w:' + chat, JSON.stringify({ k: doc.k, s: doc.s, m: doc.m, t: Date.now() }));
  else { await env.KV.delete('w:' + chat); await env.KV.delete('q:' + chat); }
}
async function saveWatch(env, chat, k) { const doc = await getDoc(env, chat); doc.k = k; return saveDoc(env, chat, doc); }
async function addWatch(env, chat, arg) {
  const kw = norm(arg);
  if (kw.length < 3 || kw.length > 40) return { ok: false, toast: 'Use 3–40 characters: a vendor or product name.' };
  const k = await getWatch(env, chat);
  if (k.includes(kw)) return { ok: true, kw, k, toast: `Already watching ${kw}` };
  if (k.length >= MAX_WATCH) return { ok: false, toast: `You can watch up to ${MAX_WATCH} names. Remove one first (/list).` };
  k.push(kw);
  await saveWatch(env, chat, k);
  return { ok: true, kw, k, added: true, toast: `👁 Watching ${kw}` };
}

async function watch(env, chat, arg, priv) {
  if (!norm(arg)) return send(env, chat, await listView(env, chat, priv));
  const r = await addWatch(env, chat, arg);
  if (!r.ok) return send(env, chat, { text: esc(r.toast) });
  const t = topicIn(await hubs(env), r.kw);
  const page = t ? `\n\n📂 ${esc(t.name)} has its own page: ${n(t.n)} CVEs ranked by what to patch first.` : '';
  return send(env, chat, {
    text: `👁 ${r.added ? 'Watching' : 'Already watching'} <b>${esc(r.kw)}</b>. ${priv ? 'You get a DM here' : 'This group gets a message'} when it gets ${SENS[(await getDoc(env, chat)).s]} (change it in /settings).\nNow watching: ${r.k.map(esc).join(', ')}${page}`,
    markup: kb([t ? [app(env, `📂 Open the ${clip(t.name, 26)} page`, t.path, priv, 'primary')] : null, [cb(priv ? '👁 My watchlist' : '👁 Group watchlist', 'l', 'success'), cb('≡ Menu', 'm')]]),
  });
}

async function unwatch(env, chat, arg, priv = true) {
  const kw = norm(arg), k = await getWatch(env, chat);
  if (!kw) return send(env, chat, await listView(env, chat, priv));
  const next = kw === 'all' ? [] : k.filter(x => x !== kw);
  if (next.length === k.length && kw !== 'all') return send(env, chat, { text: `<b>${esc(kw)}</b> is not on your list.`, markup: kb([[cb('👁 My watchlist', 'l', 'success')]]) });
  await saveWatch(env, chat, next);
  return send(env, chat, { text: next.length ? `Removed. Still watching: ${next.map(esc).join(', ')}` : 'Watchlist cleared.', markup: kb([[cb('👁 My watchlist', 'l', 'success')]]) });
}

/* ---------- groups: welcome on add, admin check, ☀️ morning brief (g:<chat>) ---------- */
const admins = new Map();
async function isAdmin(env, chat, from, senderChat) {
  if (senderChat && senderChat.id === chat) return true; // anonymous group admin
  if (!from || !from.id) return false;
  const key = chat + ':' + from.id, hit = admins.get(key);
  if (hit && Date.now() - hit.t < 60000) return hit.ok;
  const r = await tg(env, 'getChatMember', { chat_id: chat, user_id: from.id });
  const ok = !!(r.ok && r.result && (r.result.status === 'creator' || r.result.status === 'administrator'));
  if (admins.size > 2000) admins.clear();
  admins.set(key, { t: Date.now(), ok });
  return ok;
}
async function setBrief(env, chat, on, title) {
  if (on) await env.KV.put('g:' + chat, JSON.stringify({ t: Date.now(), title: clip(title, 60) }));
  else await env.KV.delete('g:' + chat);
}
async function briefView(env, chat) {
  const on = !!(await env.KV.get('g:' + chat));
  return { text: [`☀️ <b>Morning brief</b> · ${on ? 'on ✓' : 'off'}`, '',
    'One short post here around <b>10:00 Tehran (06:30 UTC)</b>: what got actively exploited and what to patch now.',
    'Quiet days are skipped, so it never spams the group.', '', on ? 'Admins can turn it off below or with <code>/daily off</code>.' : 'Admins: turn it on below or send <code>/daily on</code>.'].join('\n'),
    markup: kb([[on ? cb('🔕 Turn off', 'G:off') : cb('☀️ Turn on the morning brief', 'G:on', 'success')], [cb('👁 Group watchlist', 'l'), cb('🎯 Patch now', 't:0', 'danger')]]) };
}
async function daily(env, msg, arg) {
  const chat = msg.chat.id;
  if (msg.chat.type === 'private') return send(env, chat, { text: '☀️ The morning brief is for groups: add me to your team\'s group and send /daily there.\nFor yourself: /watch a product and pick 🗓 Daily summary in /settings.',
    markup: kb([[link('➕ Add to a group', `https://t.me/${BOT}?startgroup=brief`, 'success')], [cb('👁 My watchlist', 'l')]]) });
  const a = norm(arg);
  if (a === 'on' || a === 'off') {
    if (!(await isAdmin(env, chat, msg.from, msg.sender_chat))) return send(env, chat, { text: 'Only group admins can turn the morning brief on or off.' });
    await setBrief(env, chat, a === 'on', msg.chat.title);
  }
  return send(env, chat, await briefView(env, chat));
}
async function onMember(u, env) {
  const chat = u.chat && u.chat.id, type = u.chat && u.chat.type;
  if (!chat || (type !== 'group' && type !== 'supergroup')) return;
  const was = (u.old_chat_member || {}).status, now = (u.new_chat_member || {}).status;
  if (now === 'left' || now === 'kicked') { // removed: forget the group
    for (const k of ['g:', 'w:', 'q:']) { try { await env.KV.delete(k + chat); } catch { /* best effort */ } }
    return;
  }
  if ((now === 'member' || now === 'administrator') && (was === 'left' || was === 'kicked' || !was)) {
    return send(env, chat, { text: ['👋 <b>SubZer0 Sentinel is here</b>', '<i>What to patch first, ranked by real exploitation.</i>', '',
      '☀️ <b>Morning brief</b>: one short post a day with what to patch (admins: tap below or /daily on).',
      '👁 <b>Group watchlist</b>: admins send <code>/watch nginx</code>, the group hears about patch-now CVEs.',
      '🔎 Anyone: /top · /check <code>openssl 3.0.1</code> · /cve <code>CVE-…</code>', '', 'Live alerts: @RootAccessClub'].join('\n'),
      markup: kb([[cb('☀️ Turn on the morning brief', 'G:on', 'success')], [cb('🎯 Patch now', 't:0', 'danger'), link('📣 Channel', CHANNEL)]]) });
  }
}

/* ---------- inline mode: @SubZer0Robot CVE-2026-… in any chat ---------- */
async function onInline(q, env) {
  const text = String(q.query || '').trim().slice(0, 64);
  const results = [];
  const card = d => ({
    type: 'article', id: d.id, title: `${d.id} · ${String(d.severity || '').toUpperCase()}${d.cvss ? ' ' + Number(d.cvss).toFixed(1) : ''}${d.kev ? ' · KEV' : ''}`,
    description: clip(dedupe(d.products) || d.title, 120), thumbnail_url: `${env.SITE}og.png`,
    input_message_content: { message_text: cveText(d), parse_mode: 'HTML', link_preview_options: { is_disabled: true } },
    reply_markup: kb([[link('📂 Open dossier', d.url || env.SITE + 'cve/' + d.id, d.priority === 1 ? 'danger' : 'primary')], [link('🔔 Get alerts', `https://t.me/${BOT}?start=watch`, 'success')]]),
  });
  const id = (text.match(CVE_RE) || [])[0];
  if (id) {
    const d = await safe(env, `api/cve/${id.toUpperCase()}.json`);
    if (d) results.push(card(d));
  } else {
    const d = await safe(env, 'api/latest.json');
    const kw = norm(text);
    const list = d && Array.isArray(d.patch_now) ? d.patch_now.filter(i => !kw || `${i.id} ${i.products} ${i.title}`.toLowerCase().includes(kw)).slice(0, 10) : [];
    for (const i of list) results.push(card({ ...i, desc: i.title, priority: 1 }));
  }
  return tg(env, 'answerInlineQuery', { inline_query_id: q.id, results, cache_time: 300, is_personal: false,
    button: { text: '🔔 Get patch-now alerts in DM', start_parameter: 'watch' } });
}

/* ---------- Telegram ---------- */
async function tg(env, method, body, retry = true) {
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (r.ok) { if (method !== 'getChatMember') return { ok: true }; try { return { ok: true, result: (await r.json()).result }; } catch { return { ok: false }; } }
  let j = {};
  try { j = await r.json(); } catch { /* not json */ }
  const wait = j.parameters && j.parameters.retry_after;
  if (r.status === 429 && retry && wait && wait <= 5) { await new Promise(res => setTimeout(res, wait * 1000)); return tg(env, method, body, false); }
  if (!/not modified/.test(j.description || '')) console.log('telegram', method, r.status, clip(j.description, 160));
  return { ok: false, status: r.status, desc: j.description || '' };
}

async function send(env, chat, view) {
  const body = { chat_id: chat, text: view.text, parse_mode: 'HTML', link_preview_options: { is_disabled: true } };
  if (view.markup) body.reply_markup = view.markup;
  const r = await tg(env, 'sendMessage', body);
  if (!r.ok && r.status === 403) { try { await env.KV.delete('w:' + chat); if (chat < 0) await env.KV.delete('g:' + chat); } catch { /* best effort */ } } // blocked / removed
  return r;
}

/* a CVE card goes out as a photo with the share card when the site has one */
async function reply(env, chat, view) {
  if (view.photo) {
    const r = await tg(env, 'sendPhoto', { chat_id: chat, photo: view.photo, caption: view.text, parse_mode: 'HTML', ...(view.markup ? { reply_markup: view.markup } : {}) });
    if (r.ok) return r;
  }
  return send(env, chat, view);
}

async function edit(env, msg, view) {
  const body = { chat_id: msg.chat.id, message_id: msg.message_id, text: view.text, parse_mode: 'HTML', link_preview_options: { is_disabled: true } };
  if (view.markup) body.reply_markup = view.markup;
  const r = await tg(env, 'editMessageText', body);
  if (!r.ok && !/not modified/.test(r.desc)) return send(env, msg.chat.id, view);
  return r;
}

export const _test = { handle, norm, helpView, limited, topicIn, hits, admins };
