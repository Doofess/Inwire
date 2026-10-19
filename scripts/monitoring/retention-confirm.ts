/**
 * The words of the retention confirmation: saving a policy that expires raw evidence now says what goes,
 * what stays and the cut, in main's dialog, before the settings are written. The copy is a pure function
 * of the utility's preview and the candidate policy, so it is asserted here without Electron.
 *
 *   npx tsx scripts/monitoring/retention-confirm.ts
 */
import assert from 'node:assert/strict';
import { retentionConfirmation } from '../../electron/monitoring/retentionConfirm';
import { readRetentionPreviewResult, readRetentionSaveReply, type RetentionPreviewResult } from '../../src/services/monitoring/control';
import type { RetentionPolicy } from '../../src/services/monitoring/retention';

type Preview = Extract<RetentionPreviewResult, { ok: true }>;

let failures = 0;
let passes = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}\n        ${String((e as Error).stack ?? e).split('\n').slice(0, 5).join('\n        ')}`);
  }
}

const fmt = (ms: number): string => `<${ms}>`;
const age: Preview = { ok: true, segments: 3, fromMs: 1000, cutMs: 5000, cause: 'age' };
const copy = (p: Preview, policy: RetentionPolicy) => retentionConfirmation(p, policy, { formatTime: fmt });
const text = (c: ReturnType<typeof copy>): string => `${c.title}\n${c.message}\n${c.detail}`;
const days14: RetentionPolicy = { keepRawDays: 14, atLimit: 'stop' };

test('Cancel is first, the default and the cancel; the dialog is a warning without link buttons', () => {
  const c = copy(age, days14);
  assert.equal(c.buttons[0], 'Cancel');
  assert.notEqual(c.buttons[1], 'Cancel');
  assert.equal(c.defaultId, 0);
  assert.equal(c.cancelId, 0);
  assert.equal(c.type, 'warning');
  assert.equal(c.noLink, true);
});

test('an age expiry names the days, the segment count, the range, the cut plus one, what stays and that it is final', () => {
  const t = text(copy(age, days14));
  assert.match(t, /keeping raw evidence for 14 days/i);
  assert.match(t, /3 segments/);
  assert.match(t, /<1000>/);
  assert.match(t, /before <5001>/, 'the cut is the last received time of the last segment, so "before" is that plus one');
  assert.match(t, /minute totals/);
  assert.match(t, /archive/);
  assert.match(t, /cannot be undone/);
  assert.doesNotMatch(t, /storage limit/, 'the limit is not mentioned when the plan is by age');
  assert.doesNotMatch(t, /!|undefined|null|NaN/);
});

test('one day and one segment are singular', () => {
  const t = text(copy({ ...age, segments: 1 }, { keepRawDays: 1, atLimit: 'stop' }));
  assert.match(t, /1 day\b/);
  assert.match(t, /1 segment\b/);
  assert.doesNotMatch(t, /1 days|1 segments/);
});

test('a limit expiry says the oldest evidence goes at the storage limit, with and without an age', () => {
  const only = text(copy({ ...age, cause: 'limit' }, { keepRawDays: null, atLimit: 'expire-oldest' }));
  assert.match(only, /oldest/);
  assert.match(only, /storage limit/);
  assert.doesNotMatch(only, /\bdays?\b/);
  const both = text(copy({ ...age, cause: 'limit' }, { keepRawDays: 7, atLimit: 'expire-oldest' }));
  assert.match(both, /7 days/);
  assert.match(both, /storage limit/);
});

test('a preview with no cut or range still reads as a sentence', () => {
  const t = text(copy({ ...age, fromMs: null, cutMs: null }, days14));
  assert.doesNotMatch(t, /null|NaN|undefined|<>/);
  assert.match(t, /3 segments/);
});

test('the preview reader takes a preview and refuses anything else as failed', () => {
  assert.deepEqual(readRetentionPreviewResult(age), age);
  const none = { ...age, segments: 0, fromMs: null, cutMs: null, cause: null };
  assert.deepEqual(readRetentionPreviewResult(none), none);
  assert.deepEqual(readRetentionPreviewResult({ ok: false, reason: 'busy', message: 'm' }), { ok: false, reason: 'busy', message: 'm' });
  for (const bad of [null, 7, { ok: true }, { ...age, segments: -1 }, { ...age, cutMs: 'x' }, { ...age, cause: 'user-before' }, { ok: false, reason: 'cancelled', message: 'm' }]) {
    const r = readRetentionPreviewResult(bad);
    assert.equal(r.ok, false);
    assert.equal(!r.ok && r.reason, 'failed');
  }
});

test('a save reply may be cancelled, and still carries its own message', () => {
  assert.deepEqual(readRetentionSaveReply({ ok: false, reason: 'cancelled', message: '' }), { ok: false, reason: 'cancelled', message: '' });
});

console.log(`\n${passes} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
