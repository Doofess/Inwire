/**
 * Assertion tests for the Time column's five formats.
 *
 *   npx tsx scripts/packet-list/time-format.ts
 *
 * The clock formats are asserted by SHAPE, never against a literal string. This
 * repo's "CI" is whoever runs the script, on whatever machine they are sitting
 * at, and a literal expectation would pass in one timezone and fail in the next
 * - which teaches people to ignore the suite rather than to fix the code.
 *
 * UTC is the exception: it is the same everywhere by definition, so it can be
 * checked exactly, and that exact check is what proves the local formats are
 * reading a real clock rather than echoing the same numbers back.
 */
import { formatTimeColumn, TIME_FORMAT_LABELS, type TimeFormat } from '../../src/lib/formatTimeColumn';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function matches(name: string, value: string, re: RegExp) {
  const pass = re.test(value);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        ${JSON.stringify(value)} does not match ${re}`);
}

/** A packet is only ever read for three fields here. */
function pkt(timestampMs: number, relativeTime: number): Packet {
  return { tsUs: Math.round(timestampMs * 1000), relativeTime } as Packet;
}

// 2026-08-31T13:37:21.694700Z, chosen so every field is distinguishable.
const T = Date.UTC(2026, 7, 31, 13, 37, 21, 694) + 0.7;
const first = pkt(T, 5.8814);
const second = pkt(T + 112.867871, 5.994268);

// --- Relative ---------------------------------------------------------------

check('relative reads the packet\'s own relativeTime, not a recomputation',
  formatTimeColumn('relative', first, null), '5.881400');

// --- Delta ------------------------------------------------------------------

{
  // The first row has nothing to be relative to. Zero would be a claim that no
  // time passed, which is a different and false statement.
  check('the first row reports no previous packet', formatTimeColumn('delta', first, null), '-');
  matches('a delta is a fixed-precision number',
    formatTimeColumn('delta', second, first), /^\d+\.\d{6}$/);
  check('...measured against the row above it',
    formatTimeColumn('delta', second, first).startsWith('0.112'), true);
  // Out-of-order timestamps happen on multi-interface captures. A negative gap
  // in this column reads as a broken clock rather than as what it is.
  check('an out-of-order packet clamps to zero rather than showing negative',
    formatTimeColumn('delta', first, second), '0.000000');
}

// --- UTC: exact, because it is the same everywhere --------------------------

check('utc is exact and independent of the machine running this',
  formatTimeColumn('utc', first, null), '2026-08-31 13:37:21');

// --- Local clock: shape only ------------------------------------------------

matches('clock is hh:mm:ss, whole seconds',
  formatTimeColumn('clock', first, null), /^\d{2}:\d{2}:\d{2}$/);

matches('date is a full local date and time',
  formatTimeColumn('date', first, null), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);

{
  // The local formats must agree with each other, whatever the timezone.
  const clock = formatTimeColumn('clock', first, null);
  const date = formatTimeColumn('date', first, null);
  check('date ends with exactly what clock shows', date.endsWith(clock), true);
}

{
  /**
   * No sub-second part on any wall-clock format.
   *
   * These three used to append six digits, which made a reading of the clock
   * twice as long as the column holding it for precision nobody takes off a
   * clock face - a capture is correlated against a log or an incident timeline
   * by the second.
   *
   * Checked rather than assumed, because putting it back is a one-token edit
   * and the formats that DO need the precision are right beside them in the
   * same switch.
   */
  const absolute = (['clock', 'date', 'utc'] as const)
    .map((format) => formatTimeColumn(format, first, null));
  check('no wall-clock format carries a fraction of a second',
    absolute.filter((v) => v.includes('.')), []);

  // ...and the two that are about elapsed time still carry all six places,
  // which is where the precision went rather than being lost.
  check('the elapsed formats keep full precision',
    [
      /^\d+\.\d{6}$/.test(formatTimeColumn('relative', first, null)),
      /^\d+\.\d{6}$/.test(formatTimeColumn('delta', second, first)),
    ],
    [true, true]);
}
// --- Every format is labelled and none throws -------------------------------

{
  const formats = Object.keys(TIME_FORMAT_LABELS) as TimeFormat[];
  check('five formats are offered', formats.length, 5);
  const unlabelled = formats.filter((f) => !TIME_FORMAT_LABELS[f]?.trim());
  check('every format has a label for the menu', unlabelled.length, 0);

  let threw = false;
  for (const format of formats) {
    try {
      formatTimeColumn(format, first, null);
      formatTimeColumn(format, second, first);
    } catch {
      threw = true;
    }
  }
  check('no format throws, with or without a previous packet', threw, false);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
