// Drives worker/bot.js with a fake Telegram, site and KV. Run by tests/test_bot.py (needs node).
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dir = mkdtempSync(join(tmpdir(), 'szbot-'));
writeFileSync(join(dir, 'bot.mjs'), readFileSync(join(root, 'worker/bot.js')));
const { default: worker, _test } = await import(pathToFileURL(join(dir, 'bot.mjs')).href);

const SITE = 'https://example.test/SubZer0/';
const latest = { generated_at: new Date().toISOString(), totals: { cves: 18000, known_exploited: 30 },
  patch_now: Array.from({ length: 12 }, (_, i) => ({ id: `CVE-2026-${1000 + i}`, title: `Bug ${i} in WordPress plugin`, severity: 'critical', cvss: 9.8, kev: i === 0,
    why: 'on CISA KEV', products: i < 3 ? 'WordPress' : 'Acme Widget', url: `${SITE}cve/CVE-2026-${1000 + i}` })) };
const hubs = { week: { key: '2026-w43', path: 'week/2026-w43', label: 'Week 43, 2026', span: 'Oct 19 – Oct 25', n: 3000, p1: 10, kev: 3, crit: 400,
  top: [{ id: 'CVE-2026-1000', title: 'Top bug', sev: 'critical', cvss: 9.8, kev: true }] },
  topics: [{ path: 'product/wordpress', name: 'WordPress', term: 'wordpress', n: 1000, p1: 7 }, { path: 'product/nginx', name: 'nginx', term: 'nginx', n: 20, p1: 0 }],
  weaknesses: [{ path: 'weakness/cwe-79', id: 'CWE-79', name: 'Cross-site scripting (XSS)', n: 1200 }] };
const cve = { id: 'CVE-2026-1000', title: 'WordPress bug', desc: 'A bug.', severity: 'critical', cvss: 9.8, epss: 0.5, kev: true, public_exploit: true,
  weaponized: false, priority: 1, why: 'on CISA KEV', published: '2026-10-20', products: 'WordPress Core', cwe: ['CWE-79'], url: `${SITE}cve/CVE-2026-1000` };

const vshardN = { v: 1, c: [['CVE-2026-2001', 'critical', 1, 1, 9.8, 'nginx heap overflow'], ['CVE-2026-2002', 'high', 3, 0, 7.5, 'nginx leak']],
  p: { 'f5|nginx': [[0, '', 1, '1.25.3', 0, ''], [1, '1.20.0', 1, '1.22.1', 1, ''], [1, '', 1, '', -1, '']] } };
let calls = [], siteDown = false, tgStatus = 200;
globalThis.fetch = async (url, opt = {}) => {
  url = String(url);
  if (url.startsWith('https://api.telegram.org/')) {
    const method = url.split('/').pop(), body = JSON.parse(opt.body);
    calls.push({ method, body });
    if (method === 'getChatMember') return new Response(JSON.stringify({ ok: true, result: { status: body.user_id === 1 ? 'administrator' : 'member' } }), { status: 200 });
    return new Response(JSON.stringify(tgStatus === 200 ? { ok: true } : { ok: false, description: 'Forbidden: bot was blocked by the user' }), { status: tgStatus });
  }
  if (siteDown) return new Response('', { status: 503 });
  const path = url.slice(SITE.length);
  if (opt.method === 'HEAD') return new Response('', { status: path === 'og/CVE-2026-1000.jpg' ? 200 : 404 });
  const doc = { 'api/latest.json': latest, 'api/hubs.json': hubs, 'api/cve/CVE-2026-1000.json': cve, 'api/versions/n.json': vshardN }[path];
  return doc ? new Response(JSON.stringify(doc), { status: 200 }) : new Response('', { status: 404 });
};
const store = new Map();
const KV = { async get(k, t) { const v = store.get(k); return v == null ? null : t === 'json' ? JSON.parse(v) : v; }, async put(k, v) { store.set(k, v); },
  async delete(k) { store.delete(k); }, async list({ prefix }) { return { keys: [...store.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })), list_complete: true }; } };
const env = { SITE, KV, BOT_TOKEN: '1:x', WEBHOOK_SECRET: 's', ADMIN_ID: '42' };
const dm = (text, id = 7) => ({ message: { chat: { id, type: 'private' }, text } });
const tap = (data, id = 7, extra = {}) => ({ callback_query: { id: 'q', data, message: { message_id: 5, chat: { id, type: 'private' }, text: 'x', ...extra } } });
const run = async u => { calls = []; await _test.handle(u, env); return calls; };
const buttons = c => (c.body.reply_markup ? c.body.reply_markup.inline_keyboard.flat() : []);

// webhook secret is enforced
const ctx = { waitUntil() {} };
assert.equal((await worker.fetch(new Request('https://w/tg', { method: 'POST', body: '{}' }), env, ctx)).status, 403);
assert.equal((await worker.fetch(new Request('https://w/tg', { method: 'POST', body: '{}', headers: { 'X-Telegram-Bot-Api-Secret-Token': 's' } }), env, ctx)).status, 200);

// /start: menu with colored buttons, user remembered
let c = await run(dm('/start'));
assert.equal(c[0].method, 'sendMessage');
assert.match(c[0].body.text, /12<\/b> to patch now/);
assert.deepEqual(buttons(c[0]).slice(0, 2).map(x => [x.callback_data, x.style]), [['t:0', 'danger'], ['wk', 'primary']]);
assert.ok(store.has('u:7'));

// top list paginates by editing the same message
c = await run(tap('t:1'));
assert.deepEqual(c.map(x => x.method), ['answerCallbackQuery', 'editMessageText']);
assert.match(c[1].body.text, /CVE-2026-1005/);
assert.ok(buttons(c[1]).some(x => x.text === '2 / 3'));

// CVE card: photo share card, dossier + watch + weakness + copy + share
c = await run(dm('CVE-2026-1000'));
assert.equal(c[0].method, 'sendPhoto');
const bt = buttons(c[0]);
assert.ok(bt.some(x => x.callback_data === 'a:wordpress' && x.style === 'success'));
assert.ok(bt.some(x => x.url === SITE + 'weakness/cwe-79'));
assert.ok(bt.some(x => x.copy_text && x.copy_text.text === 'CVE-2026-1000'));
assert.ok(bt.some(x => x.web_app && x.style === 'danger'));

// watch via button, list shows ✕, remove via button
c = await run(tap('a:wordpress'));
assert.match(c[0].body.text, /Watching wordpress/);
assert.deepEqual(JSON.parse(store.get('w:7')).k, ['wordpress']);
c = await run(dm('/list'));
assert.ok(buttons(c[0]).some(x => x.callback_data === 'r:wordpress' && x.style === 'danger'));
c = await run(tap('r:wordpress'));
assert.ok(!store.has('w:7'));
// empty list offers one-tap suggestions
assert.ok(buttons(c[1]).some(x => x.callback_data === 'A:wordpress'));
// deep link from the channel
c = await run(dm('/start watch_nginx'));
assert.deepEqual(JSON.parse(store.get('w:7')).k, ['nginx']);

// settings: sensitivity + delivery survive adding and removing names
c = await run(tap('S:crit'));
assert.match(c[0].body.text, /critical/);
c = await run(tap('M:daily'));
let doc = JSON.parse(store.get('w:7'));
assert.deepEqual([doc.s, doc.m], ['crit', 'daily']);
c = await run(dm('/watch fortinet'));
assert.match(c[0].body.text, /new critical CVE/);
doc = JSON.parse(store.get('w:7'));
assert.deepEqual([doc.k, doc.s, doc.m], [['nginx', 'fortinet'], 'crit', 'daily']);
c = await run(dm('/settings'));
assert.ok(buttons(c[0]).some(x => x.callback_data === 'M:daily' && x.style === 'success' && x.text.startsWith('✓')));
assert.match(c[0].body.text, /one summary a day/);
await run(tap('r:fortinet'));
doc = JSON.parse(store.get('w:7'));
assert.deepEqual([doc.k, doc.s, doc.m], [['nginx'], 'crit', 'daily']);
store.set('q:7', '[]');
await run(dm('/unwatch all'));
assert.ok(!store.has('w:7') && !store.has('q:7'));
await run(dm('/start watch_nginx'));

// free text search finds vendor pages and weaknesses
c = await run(dm('xss'));
assert.ok(buttons(c[0]).some(x => x.url === SITE + 'weakness/cwe-79'));
c = await run(dm('wordpress'));
assert.match(c[0].body.text, /WordPress/);

// groups: commands only, no web_app buttons
c = await run({ message: { chat: { id: -100, type: 'supergroup' }, text: 'hello' } });
assert.equal(c.length, 0);
c = await run({ message: { chat: { id: -100, type: 'supergroup' }, text: '/top' } });
assert.ok(buttons(c[0]).every(x => !x.web_app));
const gm = (text, from = 2) => ({ message: { chat: { id: -100, type: 'supergroup', title: 'Sec team' }, from: { id: from }, text } });
const gtap = (data, from = 2) => ({ callback_query: { id: 'q', data, from: { id: from }, message: { message_id: 5, chat: { id: -100, type: 'supergroup' }, text: 'x' } } });
c = await run(gm('/watch nginx'));
assert.match(c.at(-1).body.text, /Only group admins/);
assert.ok(!store.has('w:-100'));
c = await run(gm('/watch@SubZer0Robot nginx', 1)); // admin: group watchlist
assert.match(c.at(-1).body.text, /This group gets a message/);
assert.deepEqual(JSON.parse(store.get('w:-100')).k, ['nginx']);
assert.ok(c.every(x => !buttons(x).some(y => y.web_app)));
c = await run(gm('/list'));
assert.match(c[0].body.text, /Group watchlist/);
c = await run(gtap('r:nginx'));
assert.equal(c[c.length - 1].method, 'answerCallbackQuery');
assert.match(c.at(-1).body.text, /Only group admins/);
assert.ok(store.has('w:-100'));
// morning brief: members can look, only admins switch it
c = await run(gm('/daily on'));
assert.match(c.at(-1).body.text, /Only group admins/);
assert.ok(!store.has('g:-100'));
_test.admins.clear();
c = await run(gm('/daily on', 1));
assert.match(c.at(-1).body.text, /Morning brief<\/b> · on/);
assert.equal(JSON.parse(store.get('g:-100')).title, 'Sec team');
c = await run(gtap('G:off', 1));
assert.ok(!store.has('g:-100'));
assert.equal(c.at(-1).method, 'editMessageText');
c = await run(gtap('G:on', 1));
assert.ok(store.has('g:-100'));
c = await run({ message: { chat: { id: -100, type: 'supergroup' }, sender_chat: { id: -100 }, text: '/daily off' } }); // anonymous admin
assert.ok(!store.has('g:-100'));
c = await run(dm('/daily'));
assert.ok(buttons(c[0]).some(x => x.url && x.url.includes('startgroup=')));
// added to a group: welcome with a brief button; removed: group forgotten
const member = (was, now) => ({ my_chat_member: { chat: { id: -100, type: 'supergroup' }, old_chat_member: { status: was }, new_chat_member: { status: now } } });
c = await run(member('left', 'member'));
assert.match(c[0].body.text, /SubZer0 Sentinel is here/);
assert.ok(buttons(c[0]).some(x => x.callback_data === 'G:on'));
store.set('g:-100', '{}');
c = await run(member('member', 'kicked'));
assert.equal(c.length, 0);
assert.ok(!store.has('g:-100') && !store.has('w:-100'));
c = await run({ my_chat_member: { chat: { id: 7, type: 'private' }, old_chat_member: { status: 'member' }, new_chat_member: { status: 'kicked' } } });
assert.equal(c.length, 0);
c = await run(gm('/help'));
assert.match(c[0].body.text, /In this group/);

// inline mode
c = await run({ inline_query: { id: 'i', query: 'CVE-2026-1000' } });
assert.equal(c[0].method, 'answerInlineQuery');
assert.equal(c[0].body.results[0].id, 'CVE-2026-1000');
c = await run({ inline_query: { id: 'i', query: '' } });
assert.equal(c[0].body.results.length, 10);

// admin only stats; others are refused
c = await run(dm('/stats', 7));
assert.match(c[0].body.text, /bot owner/);
c = await run(dm('/stats', 42));
assert.match(c[0].body.text, /Users: <b>\d+/);

// site down: friendly message, error counted, admin alerted once
siteDown = true;
c = await run(dm('/top', 8));
assert.ok(c.some(x => x.body.chat_id === '42' && /bot error/.test(x.body.text)));
assert.ok(c.some(x => x.body.chat_id === 8 && /did not answer/.test(x.body.text)));
c = await run(dm('/top', 8));
assert.ok(!c.some(x => x.body.chat_id === '42'));
siteDown = false;

// blocked user: watchlist dropped
store.set('w:9', JSON.stringify({ k: ['nginx'] }));
tgStatus = 403; await run(dm('/help', 9)); tgStatus = 200;
assert.ok(!store.has('w:9'));

// rate limit: warn once, then quiet
_test.hits.clear();
let warned = 0, total = 0;
for (let i = 0; i < 30; i++) { c = await run(dm('/help', 11)); total += c.length; warned += c.filter(x => /Slow down/.test(x.body.text)).length; }
assert.equal(warned, 1);
assert.equal(total, 21);

// every callback_data fits Telegram's 64-byte limit
c = await run(dm('/watch ' + 'a'.repeat(40)));
for (const x of [...buttons(c[0])]) if (x.callback_data) assert.ok(Buffer.byteLength(x.callback_data) <= 64);
// version check: /check and plain "name x.y.z" messages
c = await run(dm('/check nginx 1.21.0'));
assert.match(c[0].body.text, /Affected by 2 CVEs/);
assert.match(c[0].body.text, /Upgrade to <code>1\.25\.3<\/code>/);
assert.match(c[0].body.text, /1 more name it without a version/);
assert.ok(buttons(c[0]).some(x => x.callback_data === 'c:CVE-2026-2001'));
assert.ok(buttons(c[0]).some(x => x.url && x.url.endsWith('?check=nginx%201.21.0')));
c = await run(dm('nginx 1.24.0'));
assert.match(c[0].body.text, /Affected by 1 CVE\b/);
c = await run(dm('nginx 1.26.0'));
assert.match(c[0].body.text, /No known CVEs for this version/);
c = await run(dm('/check nosuchthing 1.0'));
assert.match(c[0].body.text, /No version data/);
for (const x of [...buttons(c[0])]) if (x.callback_data) assert.ok(Buffer.byteLength(x.callback_data) <= 64);
c = await run(dm('nginx'));
assert.ok(!/Affected/.test(c[0].body.text)); // plain word without version is still a search
// owner drafts: only the owner can post; Post copies to CHANNEL_ID without the Post/Skip row
const draftMsg = { message_id: 50, chat: { id: 42, type: 'private' }, caption: 'CVE-2026-1 alert', caption_entities: [{ type: 'bold', offset: 0, length: 10 }], photo: [{}],
  reply_markup: { inline_keyboard: [[{ text: 'open', url: 'https://x' }], [{ text: '📤 Post to channel', callback_data: 'P' }, { text: '✕ Skip', callback_data: 'X' }]] } };
const otap = (data, from) => ({ callback_query: { id: 'q', data, from: { id: from }, message: draftMsg } });
c = await run(otap('P', 7));
assert.match(c[0].body.text, /Only the channel owner/);
assert.ok(!c.some(x => x.method === 'copyMessage'));
c = await run(otap('P', 42));
assert.match(c.at(-1).body.text, /CHANNEL_ID is not set/); // not configured: nothing posted
env.CHANNEL_ID = '@RootAccessClub';
c = await run(otap('P', 42));
const cp = c.find(x => x.method === 'copyMessage');
assert.equal(cp.body.chat_id, '@RootAccessClub');
assert.deepEqual(cp.body.reply_markup.inline_keyboard, [[{ text: 'open', url: 'https://x' }]]);
assert.ok(c.some(x => x.method === 'editMessageReplyMarkup'));
c = await run(otap('X', 42));
assert.ok(!c.some(x => x.method === 'copyMessage'));
assert.equal(c.at(-1).body.reply_markup.inline_keyboard[0][0].text, '✕ Skipped');
// reply to a draft with a note: note on top, entities shifted
c = await run({ message: { chat: { id: 42, type: 'private' }, from: { id: 42 }, text: 'My take', reply_to_message: draftMsg } });
const cn = c.find(x => x.method === 'copyMessage');
assert.equal(cn.body.caption, 'My take\n\nCVE-2026-1 alert');
assert.equal(cn.body.caption_entities[0].offset, 9);
assert.match(c.at(-1).body.text, /with your note/);
// someone else replying to a draft is just a normal message
c = await run({ message: { chat: { id: 7, type: 'private' }, from: { id: 7 }, text: 'hi there', reply_to_message: draftMsg } });
assert.ok(!c.some(x => x.method === 'copyMessage'));
const textDraft = { ...draftMsg, photo: undefined, caption: undefined, text: 'Early warning', entities: [{ type: 'bold', offset: 0, length: 5 }] };
c = await run({ message: { chat: { id: 42, type: 'private' }, from: { id: 42 }, text: 'Heads up', reply_to_message: textDraft } });
const sm = c.find(x => x.method === 'sendMessage' && x.body.chat_id === '@RootAccessClub');
assert.equal(sm.body.text, 'Heads up\n\nEarly warning');
assert.equal(sm.body.entities[0].offset, 10);
delete env.CHANNEL_ID;
console.log('bot harness ok');
