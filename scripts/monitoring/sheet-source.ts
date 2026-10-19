/**
 * Three facts about the Monitoring sheet that no script can drive without a
 * window, held by reading the components' source (as `scripts/session/view.ts`
 * does for the shell): the final review's CR8, CR4 and M8.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MONITORING_FOLDER, readDraft } from '../../src/components/monitoring/monitoringCopy';
import { test, runAll } from './queryRig';

const read = (name: string): string => readFileSync(new URL(`../../src/components/monitoring/${name}`, import.meta.url), 'utf8');

test('CR8: Start records the source as started only after client.start succeeded', () => {
  const src = read('SourceForm.tsx');
  const startAt = src.indexOf('await client.start(');
  assert.ok(startAt > 0, 'the form starts the listener');
  assert.equal(src.indexOf('startedThisSession.push'), src.lastIndexOf('startedThisSession.push'), 'one place records');
  const calls = [...src.matchAll(/\bremember\(config\)/g)].map((m) => m.index!);
  assert.ok(calls.length >= 1);
  for (const at of calls) assert.ok(at > startAt, 'remember(config) comes after the start call, never before it');
  assert.match(src, /if \(result\.ok\) remember\(config\)/);
});

test('CR4: Focus is a snapshot with a visible time and a Refresh, and does not poll', () => {
  const src = read('Focus.tsx');
  assert.match(src, /as of \{localTime\(asOfMs\)\}/);
  assert.match(src, /Refresh/);
  assert.doesNotMatch(src, /setInterval/, 'Focus does not re-query on a timer');
});

test('M8: a damaged history says how to start a new one, with the real folder', () => {
  const src = read('SourceStatus.tsx');
  const at = src.indexOf("intake.storage === 'refused-corrupt'");
  assert.ok(at > 0);
  const block = src.slice(at, at + 500);
  assert.match(block, /MONITORING_FOLDER/);
  assert.match(block, /Inwire does not delete it/);
  assert.equal(MONITORING_FOLDER, '%LOCALAPPDATA%\\Inwire\\monitoring');
});

test('limit: a storage limit too large is told apart from one too small', () => {
  const base = { exporterIPv4: '192.0.2.1', bindIPv4: '192.0.2.20', port: '2055', unit: 'GiB' as const };
  const err = (limit: string, unit: 'MiB' | 'GiB' = 'GiB') => readDraft({ ...base, limit, unit }).errors.limit;
  assert.equal(err('8'), undefined, 'a sensible limit has no error');
  assert.equal(err('65536'), undefined, '64 TiB itself is accepted');
  assert.match(err('65537') ?? '', /at most 64 TiB/, 'one GiB past the cap says too large');
  assert.match(err('1e12') ?? '', /at most 64 TiB/);
  assert.match(err('1', 'MiB') ?? '', /at least 16 MiB/, 'too small keeps its own words');
  assert.match(err('0') ?? '', /at least 16 MiB/);
  assert.match(err('-5') ?? '', /at least 16 MiB/);
  assert.match(err('') ?? '', /at least 16 MiB/);
  assert.match(err('abc') ?? '', /at least 16 MiB/);
});

const COPY_CONSTANTS = [
  'Evidence expired',
  'Not available: this minute exceeded the key budget, and its evidence has expired.',
  'Nothing expires unless you turn this on',
  'Totals come from retained minute rollups.',
  'under the retention policy',
  'was discarded before',
];

test('Task 6: the storage block carries its fields and adds no confirm of its own', () => {
  const src = read('StorageBlock.tsx');
  for (const label of ['Kept in', 'Change…', 'Keep up to', 'Keep raw evidence for', 'At the storage limit', 'Discard…']) {
    assert.ok(src.includes(label), `StorageBlock says "${label}"`);
  }
  const form = read('SourceForm.tsx');
  assert.ok(!form.includes('Keep up to'), 'the limit field moved out of SourceForm');
  // Discard acts at once: it renders after Start and Save, not among the drafts they save.
  assert.ok(form.indexOf('<DiscardControl') > form.indexOf("'Start'"), 'Discard renders below Start');
  assert.match(form, /firstStart && busy !== 'load' && !readOnly/, 'no firewall note while Start is off for a read-only folder');
  assert.doesNotMatch(src, /uppercase/, 'section titles are sentence case');
  assert.doesNotMatch(src, /confirm\(/);
  assert.doesNotMatch(src, /role="dialog"/);
  assert.doesNotMatch(src, /alertdialog/);
});

test('Task 6: the expiry copy is held verbatim in monitoringCopy', () => {
  const src = read('monitoringCopy.ts');
  for (const text of COPY_CONSTANTS) assert.ok(src.includes(text), `monitoringCopy holds "${text}"`);
});

test('Task 6: Export evidence bundle sits in the same button row as Export CSV', () => {
  const src = read('History.tsx');
  const csv = src.indexOf('Export CSV');
  const bundle = src.indexOf('Export evidence bundle');
  assert.ok(csv > 0 && bundle > 0);
  assert.ok(Math.abs(bundle - csv) < 900, 'the two buttons are neighbours');
  assert.ok(!src.slice(Math.min(csv, bundle), Math.max(csv, bundle)).includes('</div>'), 'no row closes between them');
});

test('Task 6: the chart marks aggregate-only apart from observed-records and has the legend entry', () => {
  const src = read('HistoryChart.tsx');
  assert.match(src, /EVIDENCE_EXPIRED_LEGEND/);
  assert.match(src, /b\.coverage === 'aggregate-only'/);
});

test('Task 6: Focus words an expired range from the copy function, not the reply message', () => {
  const src = read('Focus.tsx');
  assert.match(src, /'evidence-expired'/);
  assert.match(src, /evidenceExpiredText\(/);
});

test('Final: an expired or failed Focus drops the old list and can still be refreshed; a stale journal is asked again a bounded number of times', () => {
  const src = read('Focus.tsx');
  const failures = src.slice(src.indexOf("reply.code === 'cancelled'"), src.indexOf('setError(reply.message)'));
  assert.match(failures, /'evidence-expired'/);
  assert.match(failures, /setResult\(null\)[\s\S]*'evidence-expired'/, 'the expired note and the error do not sit under an older list');
  const staleBranch = src.slice(src.indexOf("reply.code === 'stale-generation'"));
  assert.match(staleBranch.slice(0, 300), /MAX_STALE/, 'a journal that keeps reopening ends in a message, not an endless re-ask');
  const resultBlock = src.indexOf('{result && (');
  assert.ok(resultBlock > 0);
  const refreshUses = [...src.matchAll(/onClick=\{onRefresh\}/g)].map((m) => m.index ?? 0);
  assert.ok(refreshUses.length === 1 && refreshUses[0] < resultBlock, 'Refresh is defined once, outside the result block, so the expired and error states reach it');
});

process.exit((await runAll()) === 0 ? 0 : 1);
