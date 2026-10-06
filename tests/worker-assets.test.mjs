import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import test from 'node:test';
import { buildWorkerAssets, REQUIRED_BUNDLE_FILES, STATIC_DIRECTORIES, STATIC_FILES } from '../scripts/build_worker_assets.mjs';

async function createSources(root, omit = null) {
  for (const name of STATIC_FILES) {
    if (name !== omit) await writeFile(join(root, name), `public:${name}`);
  }
  for (const name of STATIC_DIRECTORIES) await mkdir(join(root, name), { recursive: true });
  await writeFile(join(root, 'assets', 'telegram-mark.svg'), '<svg />');
  for (const name of REQUIRED_BUNDLE_FILES) {
    if (name === omit || !name.includes('/')) continue;
    const path = join(root, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, 'verified fixture');
  }
  await writeFile(join(root, 'snapshot', 'data', 'sample.json'), '{}');
}

async function listFiles(root, current = root) {
  const result = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) result.push(...await listFiles(root, path));
    else if (entry.isFile()) result.push(relative(root, path).replaceAll('\\', '/'));
  }
  return result;
}

test('builds only allowlisted app and snapshot files and removes stale output', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'subzero-worker-assets-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await createSources(root);
  await writeFile(join(root, 'README.md'), 'not public');
  await mkdir(join(root, 'scripts'));
  await writeFile(join(root, 'scripts', 'update_data.py'), 'not public');
  await mkdir(join(root, 'tests'));
  await writeFile(join(root, 'tests', 'worker.test.mjs'), 'not public');
  await mkdir(join(root, 'dist'));
  await writeFile(join(root, 'dist', 'stale.txt'), 'stale');

  const output = await buildWorkerAssets(root);
  const files = new Set(await listFiles(output));

  for (const name of REQUIRED_BUNDLE_FILES) assert.ok(files.has(name), `missing ${name}`);
  assert.ok(files.has('assets/telegram-mark.svg'));
  assert.ok(files.has('snapshot/data/sample.json'));
  assert.ok(!files.has('README.md'));
  assert.ok(!files.has('scripts/update_data.py'));
  assert.ok(!files.has('tests/worker.test.mjs'));
  assert.ok(!files.has('stale.txt'));
});

test('does not replace a previous bundle when a required source is missing', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'subzero-worker-assets-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await createSources(root, 'index.html');
  await mkdir(join(root, 'dist'));
  const sentinel = join(root, 'dist', 'known-good.txt');
  await writeFile(sentinel, 'keep');

  await assert.rejects(buildWorkerAssets(root), /Required Worker asset source is missing/);
  assert.equal(await readFile(sentinel, 'utf8'), 'keep');
});
