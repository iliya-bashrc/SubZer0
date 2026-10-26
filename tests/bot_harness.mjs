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

let calls = [], siteDown = false, tgStatus = 200;
globalThis.fetch = async (url, opt = {}) => {
  url = String(url);
  if (url.startsWith('https://api.telegram.org/')) {
    calls.push({ method: url.split('/').pop(), body: JSON.parse(opt.body) });
    return new Response(JSON.stringify(tgStatus === 200 ? { ok: true } : { ok: false, description: 'Forbidden: bot was blocked by the user' }), { status: tgStatus });
  }
  if (siteDown) return new Response('', { status: 503 });
  const path = url.slice(SITE.length);
  if (opt.method === 'HEAD') return new Response('', { status: path === 'og/CVE-2026-1000.jpg' ? 200 : 404 });
  const doc = { 'api/latest.json': latest, 'api/hubs.json': hubs, 'api/cve/CVE-2026-1000.json': cve }[path];
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
c = await run({ message: { chat: { id: -100, type: 'supergroup' }, text: '/watch nginx' } });
assert.match(c[0].body.text, /private chat/);

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
console.log('bot harness ok');
