/**
 * Assertion tests for the byte formatter.
 *
 *   npx tsx scripts/analytics/format-bytes.ts
 *
 * There were four of these and they disagreed. Three were merely inconsistent -
 * `1.5M` against `1.5 MB`, one decimal for MB against none for KB - but the
 * fourth was **wrong**: `NetworkMatrix` formatted inline with a KB tier and no
 * MB tier, so a 40 MB conversation in the Top Talkers card rendered as
 * `40960.0K`. The tiering lives in one place now, and this pins the boundary
 * that was missing along with the ones that were not.
 */
import { formatBytes } from '../../src/lib/formatBytes';

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

const compact = (n: number) => formatBytes(n, { compact: true });

// --- the tier that was missing --------------------------------------------
check('a 40 MB conversation is megabytes, not 40960 kilobytes', compact(40 * 1024 * 1024), '40.0M');
check('...and gigabytes exist too', compact(3 * 1024 ** 3), '3.0G');
check('...and it stops at the largest unit rather than inventing one',
  compact(5 * 1024 ** 5), '5120.0T');

// --- the boundaries -------------------------------------------------------
check('a byte count below a kilobyte is bytes', compact(842), '842B');
check('1023 is still bytes', compact(1023), '1023B');
// `>=` and not `>`: 1024 bytes reads as 1 KB, never as "1024 B".
check('1024 is one kilobyte, not 1024 bytes', compact(1024), '1.0K');
check('zero is zero bytes', compact(0), '0B');

// --- whole bytes stay whole -----------------------------------------------
//
// The unit-0 branch rounds instead of taking a decimal, because "842.0 B" reads
// as a measurement whose precision it does not have - a byte count is exact.
check('bytes carry no decimal', compact(842.4), '842B');
check('...but everything above them carries one', compact(1536), '1.5K');

// --- the two presentations ------------------------------------------------
//
// Both are deliberate. Compact is for the dashboard cards, where a row is 352px
// and already holds two addresses and a protocol; spaced is for the export
// panel and the settings readouts, which have room.
check('spaced is the default', formatBytes(1536), '1.5 KB');
check('...with two-letter units and a space', formatBytes(40 * 1024 * 1024), '40.0 MB');
check('...and single bytes read the same either way', formatBytes(7), '7 B');

// --- nothing is not zero --------------------------------------------------
//
// An em dash, following the rule the Network panel already states: a null is
// always an em dash and never a guess. `NaN B` and `-1 B` are both worse than
// saying nothing.
check('a value that is not a number says nothing', formatBytes(NaN), '—');
check('...as does a negative one', formatBytes(-1), '—');
check('...and an infinite one', formatBytes(Infinity), '—');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All byte-format checks passed.');
process.exit(0);
