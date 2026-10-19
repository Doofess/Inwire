/**
 * Which folder a picked folder means for a monitoring dataset (ADR 0061): `resolveDatasetFolder`, main's
 * Electron-free half of "Choose folder".
 *
 *   npx tsx scripts/monitoring/location-choose.ts
 *
 * Plain tsx. Injected fakes cover the rules and both case variants; one real temp directory proves the
 * same decision against a real file system.
 */
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveDatasetFolder, type ResolveDeps } from '../../electron/monitoring/location';
import { DATASET_SUBFOLDER } from '../../src/services/monitoring/datasetPlan';

let failures = 0;
let passes = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`.slice(0, 900));
  }
}

const DEFAULT_ROOT = '/data/Inwire/monitoring';
const CAPTURES = '/data/Inwire/captures';
const SEGMENT = 'journal-000000000001.iwmj';

/** A fake file system: `folders` maps a path to the names inside it; every path is its own real path. */
function fakeDeps(folders: Record<string, string[]>, over: Partial<ResolveDeps> = {}): ResolveDeps {
  const known = new Set(Object.keys(folders));
  return {
    defaultRoot: DEFAULT_ROOT,
    capturesRoot: CAPTURES,
    caseInsensitive: false,
    realpath: (p) => { if (!known.has(p) && p !== CAPTURES && p !== path.dirname(CAPTURES)) throw new Error(`ENOENT: ${p}`); return p; },
    exists: (p) => known.has(p),
    list: (p) => { const names = folders[p]; if (names === undefined) throw new Error(`ENOENT: ${p}`); return names; },
    ...over,
  };
}

const j = (...parts: string[]): string => path.join(...parts);

test('a plain folder gets the Inwire Monitoring subfolder', () => {
  const r = resolveDatasetFolder('/mnt/disk', fakeDeps({ '/mnt/disk': ['photos', 'notes.txt'] }));
  assert.deepEqual(r, { ok: true, root: j('/mnt/disk', DATASET_SUBFOLDER), isDefaultLocation: false });
});

test('a folder that holds a segment, or the legacy journal, is the dataset itself', () => {
  for (const name of [SEGMENT, 'journal.iwmj']) {
    const r = resolveDatasetFolder('/mnt/old', fakeDeps({ '/mnt/old': [name, 'rollups.iwmr'] }));
    assert.deepEqual(r, { ok: true, root: '/mnt/old', isDefaultLocation: false }, name);
  }
});

test('the default root answers as the default location, whatever its spelling', () => {
  const r = resolveDatasetFolder(DEFAULT_ROOT, fakeDeps({ [DEFAULT_ROOT]: ['settings.json'] }));
  assert.deepEqual(r, { ok: true, root: DEFAULT_ROOT, isDefaultLocation: true });
  const upper = resolveDatasetFolder(DEFAULT_ROOT.toUpperCase(), fakeDeps(
    { [DEFAULT_ROOT]: [], [DEFAULT_ROOT.toUpperCase()]: [] }, { caseInsensitive: true },
  ));
  assert.deepEqual(upper, { ok: true, root: DEFAULT_ROOT, isDefaultLocation: true });
  // Case-sensitive: a different spelling is a different folder.
  const other = resolveDatasetFolder(DEFAULT_ROOT.toUpperCase(), fakeDeps({ [DEFAULT_ROOT]: [], [DEFAULT_ROOT.toUpperCase()]: [] }));
  assert.equal(other.ok && other.isDefaultLocation, false);
});

test('an existing subfolder (a junction) is followed to its real path', () => {
  const sub = j('/mnt/disk', DATASET_SUBFOLDER);
  const r = resolveDatasetFolder('/mnt/disk', fakeDeps({ '/mnt/disk': [DATASET_SUBFOLDER], [sub]: [] }, {
    realpath: (p) => (p === sub ? '/elsewhere/real' : p),
  }));
  assert.deepEqual(r, { ok: true, root: '/elsewhere/real', isDefaultLocation: false });
});

test('the captures folder and a folder inside it are refused; a parent is refused only when it is the dataset', () => {
  for (const picked of [CAPTURES, `${CAPTURES}/ring`, '/data/Inwire', '/data']) {
    const r = resolveDatasetFolder(picked, fakeDeps({ [picked]: ['x'], [CAPTURES]: [] }));
    // `/data` and `/data/Inwire` resolve to a subfolder of themselves: that subfolder is a sibling
    // of the captures folder, which is allowed, unless the folder holds a journal and is the dataset.
    if (picked === '/data/Inwire' || picked === '/data') {
      assert.equal(r.ok, true, picked);
    } else {
      assert.equal(r.ok, false, picked);
      assert.match((r as { message: string }).message, /captures/i);
    }
  }
  // A parent holding a journal is itself the dataset, so it contains the captures folder: refused.
  for (const parent of ['/data/Inwire', '/data']) {
    const r = resolveDatasetFolder(parent, fakeDeps({ [parent]: [SEGMENT], [CAPTURES]: [] }));
    assert.equal(r.ok, false, parent);
    assert.match((r as { message: string }).message, /captures/i);
  }
});

test('case-insensitive: the captures folder in any case is refused; case-sensitive keeps them apart', () => {
  const folders = { '/DATA/INWIRE/CAPTURES': [SEGMENT], '/DATA/INWIRE': [SEGMENT], [CAPTURES]: [] };
  for (const picked of ['/DATA/INWIRE/CAPTURES', '/DATA/INWIRE']) {
    const ci = resolveDatasetFolder(picked, fakeDeps(folders, { caseInsensitive: true }));
    assert.equal(ci.ok, false, picked);
    const cs = resolveDatasetFolder(picked, fakeDeps(folders, { caseInsensitive: false }));
    assert.equal(cs.ok, true, `${picked} (case-sensitive)`);
  }
});

test('a captures folder that does not exist yet still compares', () => {
  const picked = `${CAPTURES}/ring`;
  const folders = { [picked]: [SEGMENT], '/data/Inwire': [SEGMENT] };
  const missing = { exists: (p: string) => p in folders };
  const r = resolveDatasetFolder(picked, fakeDeps(folders, missing));
  assert.equal(r.ok, false);
  assert.match((r as { message: string }).message, /captures/i);
  const parent = resolveDatasetFolder('/data/Inwire', fakeDeps(folders, missing));
  assert.equal(parent.ok, false);
});

test('a folder that cannot be resolved or listed is a stated refusal, not a throw', () => {
  const missing = resolveDatasetFolder('/nope', fakeDeps({}));
  assert.equal(missing.ok, false);
  assert.match((missing as { message: string }).message, /ENOENT/);
  const unreadable = resolveDatasetFolder('/mnt/disk', fakeDeps({ '/mnt/disk': [] }, { list: () => { throw new Error('EACCES: denied'); } }));
  assert.equal(unreadable.ok, false);
  assert.match((unreadable as { message: string }).message, /EACCES/);
});

// --- a real directory --------------------------------------------------------------------------------------------

const realDeps = (defaultRoot: string, capturesRoot: string): ResolveDeps => ({
  defaultRoot, capturesRoot, caseInsensitive: process.platform === 'win32' || process.platform === 'darwin',
  realpath: (p) => realpathSync(p), exists: (p) => existsSync(p), list: (p) => readdirSync(p),
});

test('a real folder: plain, holding a segment, the default root and the captures folder', () => {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'inwire-location-')));
  try {
    const defaultRoot = path.join(base, 'monitoring');
    const captures = path.join(base, 'captures');
    const plain = path.join(base, 'plain');
    const adopted = path.join(base, 'adopted');
    for (const d of [defaultRoot, plain, adopted, path.join(captures, 'ring')]) mkdirSync(d, { recursive: true });
    writeFileSync(path.join(adopted, SEGMENT), '');
    const deps = realDeps(defaultRoot, captures);
    assert.deepEqual(resolveDatasetFolder(plain, deps), { ok: true, root: path.join(plain, DATASET_SUBFOLDER), isDefaultLocation: false });
    assert.deepEqual(resolveDatasetFolder(adopted, deps), { ok: true, root: adopted, isDefaultLocation: false });
    assert.deepEqual(resolveDatasetFolder(defaultRoot, deps), { ok: true, root: defaultRoot, isDefaultLocation: true });
    assert.equal(resolveDatasetFolder(captures, deps).ok, false);
    assert.equal(resolveDatasetFolder(path.join(captures, 'ring'), deps).ok, false);
    // The captures folder missing: the parent of it is still a refusal once it holds a journal.
    rmSync(captures, { recursive: true, force: true });
    writeFileSync(path.join(base, SEGMENT), '');
    assert.equal(resolveDatasetFolder(base, deps).ok, false);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

console.log(`\n${passes} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
