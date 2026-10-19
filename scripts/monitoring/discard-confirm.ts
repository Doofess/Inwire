/**
 * The words of the discard confirmation (ADR 0061): what goes, what stays and the actual cut, as main's
 * dialog states them. The copy is a pure function of the utility's preview, so it is asserted here
 * without Electron.
 *
 *   npx tsx scripts/monitoring/discard-confirm.ts
 */
import assert from 'node:assert/strict';
import { discardConfirmation } from '../../electron/monitoring/discardConfirm';
import { readDiscardPreviewResult, type DiscardPreviewResult } from '../../src/services/monitoring/control';

type Preview = Extract<DiscardPreviewResult, { ok: true }>;

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
const FOLDER = 'D:\\Inwire Monitoring';
const whole: Preview = { ok: true, scope: 'all', segments: 4, fromMs: 1000, throughMs: 9000, cutMs: null };
const before: Preview = { ok: true, scope: 'before', segments: 2, fromMs: 1000, throughMs: null, cutMs: 5000 };
const copy = (p: Preview, o: { isDefaultLocation?: boolean; requestedBeforeMs?: number | null } = {}) =>
  discardConfirmation(p, { folder: FOLDER, isDefaultLocation: o.isDefaultLocation ?? false, requestedBeforeMs: o.requestedBeforeMs ?? null, formatTime: fmt });
const text = (c: ReturnType<typeof copy>): string => `${c.title}\n${c.message}\n${c.detail}`;

test('the safe button is first, the default and the cancel; the dialog is a warning without link buttons', () => {
  for (const c of [copy(whole), copy(before, { requestedBeforeMs: 6000 })]) {
    assert.deepEqual(c.buttons, ['Cancel', 'Discard']);
    assert.equal(c.defaultId, 0);
    assert.equal(c.cancelId, 0);
    assert.equal(c.type, 'warning');
    assert.equal(c.noLink, true);
  }
});

test('a whole discard names what goes, what stays and the folder', () => {
  const t = text(copy(whole));
  assert.match(t, /every journal segment \(4\)/i);
  assert.match(t, /minute archive/);
  assert.match(t, /rollup cache/);
  assert.match(t, /<1000>/);
  assert.match(t, /<9000>/);
  assert.match(t, /stays/i);
  assert.ok(t.includes(FOLDER), 'the folder is named');
  assert.match(t, /did not write/);
  assert.doesNotMatch(t, /settings/i, 'settings are not mentioned for a folder the user picked');
  assert.doesNotMatch(t, /!/);
});

test('a whole discard in the default location says the settings stay', () => {
  assert.match(text(copy(whole, { isDefaultLocation: true })), /settings/i);
});

test('a whole discard of nothing countable still reads as a sentence', () => {
  const t = text(copy({ ...whole, segments: 0, fromMs: null, throughMs: null }));
  assert.doesNotMatch(t, /\(0\)|null|NaN|undefined/);
  assert.match(t, /journal/);
});

test('a discard before a date names the segments, the cut, the requested date and what stays', () => {
  const t = text(copy(before, { requestedBeforeMs: 6000 }));
  assert.match(t, /2 segments of raw datagrams/);
  assert.match(t, /<1000>/);
  assert.match(t, /<5000>/);
  assert.match(t, /<6000>/, 'the requested date is shown when it differs from the cut');
  assert.match(t, /whole segments/);
  assert.match(t, /at or before/);
  assert.match(t, /minute totals/);
  assert.match(t, /Evidence expired/);
  assert.match(t, /after/);
  assert.doesNotMatch(t, /!/);
});

test('one segment is singular, and no requested date is not invented', () => {
  const t = text(copy({ ...before, segments: 1 }));
  assert.match(t, /1 segment of raw datagrams/);
  assert.doesNotMatch(t, /1 segments/);
  assert.doesNotMatch(t, /<6000>|null|NaN|undefined/);
});

test('a requested date equal to the cut is not stated twice', () => {
  const t = text(copy(before, { requestedBeforeMs: 5000 }));
  assert.match(t, /<5000>/);
  assert.doesNotMatch(t, /at or before/, 'nothing to explain when the cut is the date asked for');
});

test('the preview reader takes a preview, and refuses anything else as failed', () => {
  assert.deepEqual(readDiscardPreviewResult(before), before);
  assert.deepEqual(readDiscardPreviewResult(whole), whole);
  assert.deepEqual(readDiscardPreviewResult({ ok: false, reason: 'busy', message: 'm' }), { ok: false, reason: 'busy', message: 'm' });
  for (const bad of [null, 7, { ok: true }, { ...before, segments: -1 }, { ...before, cutMs: 'x' }, { ...before, scope: 'some' }, { ok: false, reason: 'cancelled', message: 'm' }]) {
    const r = readDiscardPreviewResult(bad);
    assert.equal(r.ok, false);
    assert.equal(!r.ok && r.reason, 'failed');
  }
});

console.log(`\n${passes} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
