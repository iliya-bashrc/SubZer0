/* SubZer0 Sentinel: interactive Telegram bot on Cloudflare Workers.
 *
 * Telegram -> POST /tg (webhook, checked with the secret token header) -> reply.
 * Data comes from the published site only (api/latest.json, api/cve/<id>.json), so the bot never
 * disagrees with the website. Watchlists live in KV under "w:<chat id>"; the 6-hourly snapshot job
 * (scripts/notify_telegram.py) reads them and DMs matches.
 *
 * Bindings: KV (namespace), BOT_TOKEN (secret), WEBHOOK_SECRET (secret), SITE (plain text).
 */
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/i;
const MAX_WATCH = 10;
const SEV_DOT = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s; };
/* "arista velocloud orchestrator arista velocloud orchestrator" -> "arista velocloud orchestrator" */
const dedupe = s => { const seen = new Set(); return String(s || '').split(/\s+/).filter(w => { const k = w.toLowerCase(); if (!k || seen.has(k)) return false; seen.add(k); return true; }).join(' '); };
const pct = e => (e * 100 >= 10 ? (e * 100).toFixed(0) : (e * 100).toFixed(1)) + '%';

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') return new Response('SubZer0 Sentinel is running. Talk to @SubZer0Robot on Telegram.\n');
    if (req.method !== 'POST' || url.pathname !== '/tg') return new Response('not found', { status: 404 });
    if (!env.WEBHOOK_SECRET || req.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.WEBHOOK_SECRET)
      return new Response('forbidden', { status: 403 });
    let update;
    try { update = await req.json(); } catch { return new Response('bad request', { status: 400 }); }
    ctx.waitUntil(handle(update, env).catch(e => console.log('handle failed', e && e.message)));
    return new Response('ok');
  },
};

async function handle(update, env) {
  const msg = update.message;
  if (!msg || !msg.chat || typeof msg.text !== 'string') return;
  const chat = msg.chat.id, priv = msg.chat.type === 'private';
  const text = msg.text.trim().slice(0, 300);
  const m = text.match(/^\/([a-z_]+)(?:@\w+)?\s*(.*)$/i);
  const cmd = m ? m[1].toLowerCase() : '', arg = m ? m[2].trim() : text;
  if (!m && !priv) return; // in groups only answer explicit commands

  if (cmd === 'start' && CVE_RE.test(arg.replace(/_/g, '-'))) return cve(env, chat, arg.replace(/_/g, '-').match(CVE_RE)[0].toUpperCase(), priv);
  if (cmd === 'start' || cmd === 'help') return send(env, chat, help(env), priv ? appButton(env, 'Open SubZer0', '') : null);
  if (cmd === 'top') return top(env, chat, priv);
  if (cmd === 'watch') return watch(env, chat, arg, priv);
  if (cmd === 'unwatch') return unwatch(env, chat, arg);
  if (cmd === 'list' || cmd === 'watchlist') return list(env, chat);
  if (cmd === 'cve' || (!m && CVE_RE.test(text))) {
    const id = (arg.match(CVE_RE) || text.match(CVE_RE) || [])[0];
    if (!id) return send(env, chat, 'Send a CVE id, e.g. <code>/cve CVE-2026-110447</code>');
    return cve(env, chat, id.toUpperCase(), priv);
  }
  if (!m) return send(env, chat, 'Send me a CVE id (like <code>CVE-2026-110447</code>) or try /top. /help lists everything.');
}

function help(env) {
  return [
    '<b>SubZer0 Sentinel</b> · CVE briefing in your chat',
    '',
    '/cve <code>CVE-2026-110447</code> — summary of one CVE (or just send the id)',
    '/top — what to patch right now',
    '/watch <code>nginx</code> — DM me when a product you use gets a patch-now CVE',
    '/unwatch <code>nginx</code> · /list — manage your watchlist',
    '',
    `Live alerts: @RootAccessClub · Full site: ${env.SITE}`,
  ].join('\n');
}

async function site(env, path) {
  const r = await fetch(env.SITE + path, { cf: { cacheTtl: 300, cacheEverything: true }, headers: { 'User-Agent': 'SubZer0-bot' } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('site ' + r.status);
  return r.json();
}

async function cve(env, chat, id, priv) {
  let d;
  try { d = await site(env, `api/cve/${id}.json`); } catch { return send(env, chat, 'The site did not answer. Try again in a minute.'); }
  if (!d) return send(env, chat, `<b>${esc(id)}</b> is not in the SubZer0 snapshot (last 30 days + archive).\nNVD: https://nvd.nist.gov/vuln/detail/${esc(id)}`);
  const sev = String(d.severity || 'unknown');
  const head = `${SEV_DOT[sev] || '⚪️'} <b>${esc(d.id)}</b> · ${esc(sev.toUpperCase())}${d.cvss ? ' ' + Number(d.cvss).toFixed(1) : ''}`;
  const sig = [];
  if (d.kev) sig.push('🏛 CISA KEV');
  if (d.weaponized) sig.push('⚔️ weaponized');
  else if (d.public_exploit) sig.push('🧨 public exploit');
  if (typeof d.epss === 'number') sig.push('📈 EPSS ' + pct(d.epss));
  const prio = d.priority === 1 ? `🎯 <b>Patch now</b> — ${esc(d.why)}` : d.priority === 2 ? '🗓 Patch this week' : d.priority === 3 ? '📋 Planned patching' : d.priority ? '👀 Track' : '';
  const lines = [head];
  if (d.products) lines.push(`<i>${esc(clip(dedupe(d.products), 80))}</i>`);
  lines.push('', esc(clip(d.desc || d.title, 420)), '');
  if (prio) lines.push(prio);
  if (sig.length) lines.push(sig.join(' · '));
  if (d.published) lines.push(`Published ${esc(d.published)}${d.archived ? ` · archived ${esc(d.archived)}` : ''}`);
  return send(env, chat, lines.join('\n'), appButton(env, 'Open dossier', `cve/${d.id}`, priv));
}

async function top(env, chat, priv) {
  let d;
  try { d = await site(env, 'api/latest.json'); } catch { d = null; }
  if (!d || !Array.isArray(d.patch_now)) return send(env, chat, 'The site did not answer. Try again in a minute.');
  const items = d.patch_now.slice(0, 7).map(i =>
    `${SEV_DOT[i.severity] || '⚪️'} <a href="${esc(i.url)}">${esc(i.id)}</a>${i.cvss ? ' · ' + Number(i.cvss).toFixed(1) : ''}\n   ${esc(clip(dedupe(i.products) || i.title, 60))} — <i>${esc(i.why)}</i>`);
  const t = d.totals || {};
  const text = [`🎯 <b>Patch now</b> · ${d.patch_now.length} CVEs`, `<i>${(t.cves || 0).toLocaleString('en-US')} CVEs in 30 days · ${t.known_exploited || 0} on CISA KEV</i>`, '', ...items].join('\n');
  return send(env, chat, text, appButton(env, 'See all in SubZer0', 'research?view=p1', priv));
}

const norm = s => String(s || '').toLowerCase().replace(/[^a-z0-9.+_\- ]/g, ' ').replace(/\s+/g, ' ').trim();

async function getWatch(env, chat) {
  try { const v = await env.KV.get('w:' + chat, 'json'); return Array.isArray(v && v.k) ? v.k : []; } catch { return []; }
}

async function watch(env, chat, arg, priv) {
  if (!priv) return send(env, chat, 'Watchlists work in a private chat: open @SubZer0Robot and send /watch there.');
  const kw = norm(arg);
  if (kw.length < 3 || kw.length > 40) return send(env, chat, 'Usage: <code>/watch nginx</code> (3–40 characters: a vendor or product name).');
  const k = await getWatch(env, chat);
  if (k.includes(kw)) return send(env, chat, `Already watching <b>${esc(kw)}</b>. /list shows everything.`);
  if (k.length >= MAX_WATCH) return send(env, chat, `You can watch up to ${MAX_WATCH} names. Remove one with /unwatch first.`);
  k.push(kw);
  await env.KV.put('w:' + chat, JSON.stringify({ k, t: Date.now() }));
  return send(env, chat, `👁 Watching <b>${esc(kw)}</b>. When a CVE for it becomes <b>patch now</b>, you get a DM here.\nNow watching: ${k.map(esc).join(', ')}`);
}

async function unwatch(env, chat, arg) {
  const kw = norm(arg), k = await getWatch(env, chat);
  if (!kw) return send(env, chat, 'Usage: <code>/unwatch nginx</code> — or <code>/unwatch all</code>.');
  const next = kw === 'all' ? [] : k.filter(x => x !== kw);
  if (next.length === k.length && kw !== 'all') return send(env, chat, `<b>${esc(kw)}</b> is not on your list. /list shows it.`);
  if (next.length) await env.KV.put('w:' + chat, JSON.stringify({ k: next, t: Date.now() }));
  else await env.KV.delete('w:' + chat);
  return send(env, chat, next.length ? `Removed. Still watching: ${next.map(esc).join(', ')}` : 'Watchlist cleared.');
}

async function list(env, chat) {
  const k = await getWatch(env, chat);
  return send(env, chat, k.length ? `👁 <b>Your watchlist</b>\n${k.map(x => '• ' + esc(x)).join('\n')}\n\nRemove with <code>/unwatch name</code>.`
    : 'Your watchlist is empty. Add one with <code>/watch nginx</code>.');
}

/* An inline button that opens the Mini App (private chats) or the site (groups). */
function appButton(env, label, path, priv = true) {
  const url = env.SITE + path;
  return { inline_keyboard: [[priv ? { text: label, web_app: { url } } : { text: label, url }]] };
}

async function send(env, chat, text, markup) {
  const body = { chat_id: chat, text, parse_mode: 'HTML', link_preview_options: { is_disabled: true } };
  if (markup) body.reply_markup = markup;
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!r.ok) console.log('telegram', r.status, (await r.text()).slice(0, 200));
}

export const _test = { handle, norm, help };
