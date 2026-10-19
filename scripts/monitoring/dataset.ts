/**
 * Where a monitoring dataset lives, what it may hold, and what a discard may
 * touch (ADR 0061): the pure decisions in `datasetPlan.ts` and the settings
 * file's version 2.
 *
 *   npx tsx scripts/monitoring/dataset.ts
 *
 * Plain tsx. Every case hands the decision a list of names or a hand-built
 * `RecoveryResult`; the files-on-disk half (a real folder with a foreign file in
 * it, a discard while collecting) is `location.ts`.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  classifyAdoption, classifyMonitoringName, DATASET_SUBFOLDER, encodeDatasetFile, newDatasetFile,
  planMonitoringDiscard, readDatasetFile, refuseLocation,
} from '../../src/services/monitoring/datasetPlan';
import type { RecoveryResult } from '../../src/services/monitoring/journal';
import { readMonitoringSettings, saveMonitoringSettings, SETTINGS_FILE } from '../../electron/monitoring/settings';

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

const GEN = 'a'.repeat(32);
const OTHER_GEN = 'b'.repeat(32);
const SEG1 = 'journal-000000000001.iwmj';
const SEG2 = 'journal-000000000101.iwmj';

function recovery(over: Partial<RecoveryResult> = {}): RecoveryResult {
  return {
    generation: GEN, completeEntries: 10, lastEntryId: 10, validBytes: 1000, tornTail: null, status: 'ok',
    segments: [], policies: [1], pendingUnlink: [], tornRoll: null, ...over,
  };
}

// --- the location -------------------------------------------------------------------------------------------

test('refuse-captures-overlap: the chosen folder equals, is inside, or contains the captures root', () => {
  const captures = 'C:\\Users\\me\\AppData\\Roaming\\Inwire\\captures';
  const win = { caseInsensitive: true };
  assert.match(refuseLocation(captures, captures, win) ?? '', /captures/i);
  assert.match(refuseLocation(`${captures}\\x`, captures, win) ?? '', /captures/i);
  assert.match(refuseLocation('C:\\Users\\me\\AppData\\Roaming\\Inwire', captures, win) ?? '', /captures/i);
  assert.match(refuseLocation('c:\\users\\ME\\appdata\\roaming\\inwire\\CAPTURES\\', captures, win) ?? '', /captures/i);
  // A sibling that only shares a prefix is not an overlap, and neither is another disk.
  assert.equal(refuseLocation('C:\\Users\\me\\AppData\\Roaming\\Inwire\\captures-old', captures, win), null);
  assert.equal(refuseLocation('D:\\Inwire Monitoring', captures, win), null);
  // Case matters where the file system says it does.
  assert.equal(refuseLocation('/home/me/Captures', '/home/me/captures', { caseInsensitive: false }), null);
  assert.notEqual(refuseLocation('/home/me/captures/a', '/home/me/captures', { caseInsensitive: false }), null);
});

test('the dataset subfolder is named Inwire Monitoring', () => {
  assert.equal(DATASET_SUBFOLDER, 'Inwire Monitoring');
});

// --- the names ----------------------------------------------------------------------------------------------

test('classify: every dataset name, the app name and foreign names', () => {
  const at = (name: string, isDefaultLocation = false) => classifyMonitoringName(name, { isDefaultLocation });
  for (const n of ['journal.iwmj', SEG1, 'journal-123456789012345678.iwmj', 'rollups.iwmr', 'archive.iwma', 'dataset.json']) {
    assert.equal(at(n), 'dataset', n);
    assert.equal(at(n, true), 'dataset', n);
  }
  assert.equal(at('settings.json', true), 'app');
  assert.equal(at('settings.json', false), 'foreign');
  assert.equal(at('journal.iwmj.0123456789ab.partial'), 'dataset');
  assert.equal(at('dataset.json.0123456789AB.partial'), 'foreign', 'the partial suffix is lower-case hex');
  assert.equal(at('journal.iwmj.0123456789a.partial'), 'foreign', 'twelve digits, no fewer');
  assert.equal(at('settings.json.0123456789ab.partial', true), 'app');
  for (const n of ['notes.txt', 'journal.iwmj.bak', 'journal-1.iwmj', 'journal-00000000000.iwmj', 'Journal.iwmj', '', '.', '..',
    'journal.iwmj\\x', 'a/journal.iwmj', 'archive.iwma.old', 'captures']) assert.equal(at(n), 'foreign', JSON.stringify(n));
});

// --- discard ------------------------------------------------------------------------------------------------

test('empty-plan-deletes-nothing', () => {
  for (const isDefaultLocation of [true, false]) {
    assert.deepEqual(planMonitoringDiscard([], { isDefaultLocation }), { remove: [], keep: [], foreign: [] });
  }
});

test('discard-foreign-files-survive', () => {
  const plan = planMonitoringDiscard(['journal-000000000001.iwmj', 'rollups.iwmr', 'notes.txt', 'journal.iwmj.bak'], { isDefaultLocation: false });
  assert.deepEqual([...plan.remove].sort(), ['journal-000000000001.iwmj', 'rollups.iwmr']);
  assert.deepEqual([...plan.foreign].sort(), ['journal.iwmj.bak', 'notes.txt']);
  assert.deepEqual(plan.keep, []);
});

test('discard: settings.json is kept in the default location and is foreign elsewhere; never removed', () => {
  const names = [SEG2, SEG1, 'archive.iwma', 'rollups.iwmr', 'dataset.json', 'settings.json', 'journal.iwmj'];
  const home = planMonitoringDiscard(names, { isDefaultLocation: true });
  assert.deepEqual(home.keep, ['settings.json']);
  assert.deepEqual(home.foreign, []);
  assert.ok(!home.remove.includes('settings.json'));
  const away = planMonitoringDiscard(names, { isDefaultLocation: false });
  assert.deepEqual(away.foreign, ['settings.json']);
  assert.ok(!away.remove.includes('settings.json'));
});

test('discard: segments go newest first, then the archive and cache, and dataset.json last', () => {
  const plan = planMonitoringDiscard(['dataset.json', 'rollups.iwmr', SEG1, 'archive.iwma', SEG2, 'journal.iwmj'], { isDefaultLocation: false });
  assert.deepEqual(plan.remove, [SEG2, SEG1, 'journal.iwmj', 'archive.iwma', 'rollups.iwmr', 'dataset.json']);
});

test('discard: an interrupted atomic write is the dataset\'s and goes with it', () => {
  const plan = planMonitoringDiscard(['dataset.json.0123456789ab.partial', 'x.partial'], { isDefaultLocation: false });
  assert.deepEqual(plan.remove, ['dataset.json.0123456789ab.partial']);
  assert.deepEqual(plan.foreign, ['x.partial']);
});

// --- dataset.json -------------------------------------------------------------------------------------------

test('dataset.json: round trip, and every malformed form is a stated failure', () => {
  const f = newDatasetFile(GEN, 1_800_000_000_000);
  assert.deepEqual(f, { version: 1, generation: GEN, createdMs: 1_800_000_000_000, replaced: null, discarding: null });
  const back = readDatasetFile(encodeDatasetFile(f));
  assert.ok(back.ok);
  assert.deepEqual(back.ok && back.file, f);
  const replaced = { ...f, replaced: { discardedAtMs: 5, previousGeneration: OTHER_GEN, previousFromMs: 1, previousThroughMs: 4 }, discarding: { generation: OTHER_GEN, fromMs: 1, throughMs: 4 } };
  const r = readDatasetFile(encodeDatasetFile(replaced));
  assert.ok(r.ok && r.file.discarding?.generation === OTHER_GEN && r.file.discarding.throughMs === 4 && r.file.replaced?.previousThroughMs === 4);
  for (const bad of ['', 'x', '[]', '{}', JSON.stringify({ ...f, version: 2 }), JSON.stringify({ ...f, generation: 'zz' }),
    JSON.stringify({ ...f, createdMs: -1 }), JSON.stringify({ ...f, discarding: { generation: 1 } }),
    JSON.stringify({ ...f, discarding: { generation: OTHER_GEN } }), JSON.stringify({ ...f, replaced: {} })]) {
    const x = readDatasetFile(bad);
    assert.equal(x.ok, false, bad);
    assert.ok(!x.ok && x.message.length > 10);
  }
});

// --- adoption -----------------------------------------------------------------------------------------------

const here = { isDefaultLocation: false };
const archiveOk = { status: 'ok' as const, generation: GEN };

test('adopt: an empty or missing folder is a new dataset', () => {
  assert.deepEqual(classifyAdoption([], null, null, here), { kind: 'new' });
  assert.deepEqual(classifyAdoption(['settings.json'], null, null, { isDefaultLocation: true }), { kind: 'new' });
});

test('adopt: a clean dataset is adopted as it is', () => {
  assert.deepEqual(classifyAdoption([SEG1, 'rollups.iwmr', 'archive.iwma', 'dataset.json'], recovery(), archiveOk, { ...here, datasetGeneration: GEN }),
    { kind: 'adopt', truncatedTailBytes: null });
});

test('adopt: a torn tail is adopted and says how many bytes go', () => {
  const r = classifyAdoption([SEG1], recovery({ tornTail: { fromOffset: 900, bytes: 37 } }), null, here);
  assert.deepEqual(r, { kind: 'adopt', truncatedTailBytes: 37 });
});

test('adopt: interior corruption is adopted read-only, with the scan\'s words', () => {
  const r = classifyAdoption([SEG1], recovery({ status: 'corrupt', problem: 'an entry is damaged at 512' }), null, here);
  assert.equal(r.kind, 'adopt-read-only');
  assert.ok(r.kind === 'adopt-read-only' && r.problem.includes('an entry is damaged at 512'));
});

test('adopt: a generation that differs from dataset.json, or an archive of another dataset, is read-only', () => {
  const a = classifyAdoption([SEG1, 'dataset.json'], recovery(), null, { ...here, datasetGeneration: OTHER_GEN });
  assert.equal(a.kind, 'adopt-read-only');
  const b = classifyAdoption([SEG1, 'archive.iwma'], recovery(), { status: 'ok', generation: OTHER_GEN }, here);
  assert.equal(b.kind, 'adopt-read-only');
  assert.ok(b.kind === 'adopt-read-only' && /archive/i.test(b.problem));
  const c = classifyAdoption([SEG1, 'archive.iwma'], recovery(), { status: 'corrupt', generation: null }, here);
  assert.equal(c.kind, 'adopt-read-only');
});

test('adopt: a decoder policy this build does not read is refused, untouched, naming what was found', () => {
  const r = classifyAdoption([SEG1], recovery({ status: 'unknown-version', policies: [3], problem: 'decoder policy 3' }), null, here);
  assert.equal(r.kind, 'refuse');
  assert.ok(r.kind === 'refuse' && r.reason === 'refused-version' && r.message.includes('decoder policy 3'));
});

test('adopt: any foreign name refuses, names at most five, and beats a clean journal', () => {
  const names = [SEG1, 'a.txt', 'b.txt', 'c.txt', 'd.txt', 'e.txt', 'f.txt', 'g.txt'];
  const r = classifyAdoption(names, recovery(), null, here);
  assert.equal(r.kind, 'refuse');
  assert.ok(r.kind === 'refuse' && r.reason === 'foreign-files');
  assert.ok(r.kind === 'refuse' && r.names?.length === 5 && r.names.every((n) => n.endsWith('.txt')));
  const only = classifyAdoption(['notes.txt'], null, null, here);
  assert.ok(only.kind === 'refuse' && only.reason === 'foreign-files');
});

// --- settings v2 --------------------------------------------------------------------------------------------

const tmp = (): string => mkdtempSync(path.join(os.tmpdir(), 'inwire-dataset-settings-'));
const SOURCE = { exporterIPv4: '192.0.2.1', bindIPv4: '192.0.2.9', port: 2055, storageLimitBytes: 64 * 1024 * 1024 };

test('settings v1 migrates to location null and the default retention, and is rewritten as v2 on save', () => {
  const dir = tmp();
  try {
    writeFileSync(path.join(dir, SETTINGS_FILE), JSON.stringify({ version: 1, source: SOURCE }));
    const read = readMonitoringSettings(dir);
    assert.ok(read.ok);
    assert.ok(read.ok && read.location === null);
    assert.deepEqual(read.ok && read.retention, { keepRawDays: null, atLimit: 'stop' });
    assert.deepEqual(read.ok && read.config, SOURCE);
    const saved = saveMonitoringSettings(dir, SOURCE);
    assert.ok(saved.ok);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, SETTINGS_FILE), 'utf8')),
      { version: 2, source: SOURCE, location: null, retention: { keepRawDays: null, atLimit: 'stop' } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings v2: location and retention round-trip, a save of one keeps the other, and bad values are refused', () => {
  const dir = tmp();
  try {
    assert.ok(saveMonitoringSettings(dir, SOURCE).ok);
    assert.ok(saveMonitoringSettings(dir, undefined, { location: 'D:\\Inwire Monitoring' }).ok);
    assert.ok(saveMonitoringSettings(dir, undefined, { retention: { keepRawDays: 30, atLimit: 'expire-oldest' } }).ok);
    const read = readMonitoringSettings(dir);
    assert.ok(read.ok && read.location === 'D:\\Inwire Monitoring');
    assert.deepEqual(read.ok && read.retention, { keepRawDays: 30, atLimit: 'expire-oldest' });
    assert.deepEqual(read.ok && read.config, SOURCE);
    assert.equal(saveMonitoringSettings(dir, undefined, { retention: { keepRawDays: 0, atLimit: 'stop' } }).ok, false);
    assert.equal(saveMonitoringSettings(dir, undefined, { location: '' }).ok, false);
    assert.ok(saveMonitoringSettings(dir, undefined, { location: null }).ok);
    const after = readMonitoringSettings(dir);
    assert.ok(after.ok && after.location === null && after.retention.keepRawDays === 30);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: version 3 is refused with the version named, as a version-1 build refuses 2', () => {
  const dir = tmp();
  try {
    writeFileSync(path.join(dir, SETTINGS_FILE), JSON.stringify({ version: 3, source: SOURCE, location: null }));
    const read = readMonitoringSettings(dir);
    assert.ok(!read.ok && /version 3/.test(read.message));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a location that is not a string, and a retention that is not a policy, are stated failures', () => {
  const dir = tmp();
  try {
    writeFileSync(path.join(dir, SETTINGS_FILE), JSON.stringify({ version: 2, source: SOURCE, location: 7, retention: { keepRawDays: null, atLimit: 'stop' } }));
    assert.equal(readMonitoringSettings(dir).ok, false);
    writeFileSync(path.join(dir, SETTINGS_FILE), JSON.stringify({ version: 2, source: SOURCE, location: null, retention: { keepRawDays: 0, atLimit: 'stop' } }));
    assert.equal(readMonitoringSettings(dir).ok, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

if (failures > 0) {
  console.log(`\n${failures} of ${failures + passes} FAILED`);
  process.exit(1);
}
console.log(`\nall passed (${passes})`);
