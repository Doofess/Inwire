/**
 * The words of the start confirmation: Start against a dataset recorded from a different exporter asks
 * first, in main's dialog, and says both addresses. The copy is a pure function, so it is asserted here
 * without Electron.
 *
 *   npx tsx scripts/monitoring/start-confirm.ts
 */
import assert from 'node:assert/strict';
import { startConfirmation } from '../../electron/monitoring/startConfirm';
import { readStartResult } from '../../src/services/monitoring/control';

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

const c = startConfirmation('10.0.0.1', '10.0.0.2');
const text = `${c.title}\n${c.message}\n${c.detail}`;

test('Cancel is first, the default and the cancel; the dialog is a warning without link buttons', () => {
  assert.equal(c.buttons[0], 'Cancel');
  assert.equal(c.buttons[1], 'Start recording');
  assert.equal(c.defaultId, 0);
  assert.equal(c.cancelId, 0);
  assert.equal(c.type, 'warning');
  assert.equal(c.noLink, true);
});

test('it states the recorded exporter, the configured one and that they would share one history', () => {
  assert.match(c.detail, /recorded from 10\.0\.0\.1/);
  assert.match(c.detail, /record 10\.0\.0\.2 into the same history/);
  assert.ok(text.includes('10.0.0.1') && text.includes('10.0.0.2'));
});

test('sentence case, no exclamation marks, nothing undefined', () => {
  assert.doesNotMatch(text, /!|undefined|null|NaN/);
  for (const line of [c.title, c.message, ...c.buttons]) assert.match(line, /^[A-Z0-9]/);
});

test('the start reader keeps a source-differs refusal with its recorded exporter, and drops an unknown reason', () => {
  assert.deepEqual(
    readStartResult({ ok: false, message: 'm', reason: 'source-differs', recordedExporter: '10.0.0.1' }),
    { ok: false, message: 'm', reason: 'source-differs', recordedExporter: '10.0.0.1' },
  );
  assert.deepEqual(readStartResult({ ok: false, message: 'm', reason: 'cancelled' }), { ok: false, message: 'm', reason: 'cancelled' });
  // A source-differs that does not say what was recorded cannot be asked about: a plain failure.
  assert.deepEqual(readStartResult({ ok: false, message: 'm', reason: 'source-differs' }), { ok: false, message: 'm' });
  assert.deepEqual(readStartResult({ ok: false, message: 'm', reason: 'whatever' }), { ok: false, message: 'm' });
  assert.deepEqual(readStartResult({ ok: false, message: 'm' }), { ok: false, message: 'm' });
});

console.log(`\n${passes} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
