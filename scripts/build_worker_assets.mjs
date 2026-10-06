import { cp, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const STATIC_FILES = Object.freeze([
  'index.html',
  'app.js',
  'community.js',
  'styles.css',
  'feed.css',
  'community.css',
  'severity-effects.css',
  'sw.js',
]);
export const STATIC_DIRECTORIES = Object.freeze(['assets', 'snapshot']);
export const REQUIRED_BUNDLE_FILES = Object.freeze([
  ...STATIC_FILES,
  'snapshot/manifest.json',
  'snapshot/data/overview.json',
  'snapshot/data/history.json',
  'snapshot/data/epss.json',
  'snapshot/data/search-index.json.gz',
]);

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

async function rejectSymlinks(path) {
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new Error(`Refusing to publish symlink: ${path}`);
  if (!info.isDirectory()) return;
  for (const entry of await readdir(path, { withFileTypes: true })) {
    await rejectSymlinks(join(path, entry.name));
  }
}

async function syncPath(path) {
  if (process.platform === 'win32') return;
  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncTree(root) {
  if (process.platform === 'win32') return;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const child = join(root, entry.name);
    if (entry.isDirectory()) await syncTree(child);
    else if (entry.isFile()) await syncPath(child);
  }
  await syncPath(root);
}

export async function buildWorkerAssets(repoRoot = PROJECT_ROOT) {
  const root = resolve(repoRoot);
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory()) throw new Error(`Worker asset source is not a directory: ${root}`);

  for (const name of STATIC_FILES) {
    const path = join(root, name);
    const info = await lstat(path).catch((error) => {
      if (error.code === 'ENOENT') throw new Error(`Required Worker asset source is missing: ${path}`);
      throw error;
    });
    if (!info.isFile()) throw new Error(`Expected a regular Worker asset file: ${path}`);
    await rejectSymlinks(path);
  }
  for (const name of STATIC_DIRECTORIES) {
    const path = join(root, name);
    const info = await lstat(path).catch((error) => {
      if (error.code === 'ENOENT') throw new Error(`Required Worker asset source is missing: ${path}`);
      throw error;
    });
    if (!info.isDirectory()) throw new Error(`Expected a Worker asset directory: ${path}`);
    await rejectSymlinks(path);
  }

  const output = join(root, 'dist');
  if (await exists(output)) {
    const info = await lstat(output);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error(`Refusing to replace non-directory Worker output: ${output}`);
    }
  }

  const temporaryRoot = await mkdtemp(join(root, '.subzero-worker-assets-'));
  const staged = join(temporaryRoot, 'dist');
  const backup = join(temporaryRoot, 'previous-dist');
  let movedPrevious = false;
  try {
    await mkdir(staged);
    for (const name of STATIC_FILES) {
      await cp(join(root, name), join(staged, name));
    }
    for (const name of STATIC_DIRECTORIES) {
      await cp(join(root, name), join(staged, name), { recursive: true, dereference: false, preserveTimestamps: true });
    }

    for (const name of REQUIRED_BUNDLE_FILES) {
      const path = join(staged, name);
      const info = await lstat(path).catch(() => null);
      if (!info?.isFile()) throw new Error(`Worker asset bundle is incomplete: ${name}`);
    }
    await syncTree(staged);

    if (await exists(output)) {
      await rename(output, backup);
      movedPrevious = true;
      await syncPath(root);
    }
    try {
      await rename(staged, output);
      await syncPath(root);
    } catch (error) {
      if (movedPrevious && !(await exists(output))) {
        await rename(backup, output);
        await syncPath(root);
        movedPrevious = false;
      }
      throw error;
    }
    return output;
  } finally {
    if (movedPrevious && !(await exists(output)) && (await exists(backup))) {
      await rename(backup, output);
    }
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const output = await buildWorkerAssets();
  let count = 0;
  async function countFiles(path) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await countFiles(child);
      else if (entry.isFile()) count += 1;
    }
  }
  await countFiles(output);
  console.log(`Staged ${count} allowlisted Worker assets in ${output}`);
}
