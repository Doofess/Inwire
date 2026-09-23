/**
 * The byte-range hex four dissectors used to write four ways.
 *
 *   npx tsx scripts/dissect/hex-bytes.ts
 *
 * `dissect/hexBytes.ts` replaced a loop that `quic.ts`, `icmp.ts`,
 * `mediaType.ts` and `ber.ts` each carried a copy of. Two things need holding
 * and neither is a speed:
 *
 * **The string is byte-identical**, because it is compared against the
 * reference analyzer's `show` for every `FT_BYTES` field in
 * `tree-coverage.ts`. That gate covers it on the fixtures; this covers the
 * shape on inputs the fixtures do not contain - a single byte, an empty range,
 * a range that ends before it starts.
 *
 * **The clamp is now on both ends for every caller**, which it was not before:
 * `hexOfRange` clamped both, `hexColons` clamped only the top, and `berHex`
 * clamped neither. An unclamped low end reads `bytes[-1]`, which is
 * `undefined`, and `undefined.toString(16)` is a thrown `TypeError` out of the
 * middle of dissection - on offsets derived from length fields an adversary
 * writes. The assertions below are the ones that would have thrown.
 *
 * The 4.7x it also happens to be is a measurement, printed by
 * `scripts/perf/profile.ts` and asserted nowhere (ADR 0041).
 */
import { hexColons, hexRun } from '../../src/services/dissect/hexBytes';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const bytes = new Uint8Array([0x00, 0x0f, 0x10, 0xa5, 0xff]);

console.log('\n--- the string itself ---\n');

check('a whole range is colon-separated lowercase hex',
  hexColons(bytes, 0, bytes.length), '00:0f:10:a5:ff');
// The leading zero is the half that `toString(16)` alone gets wrong, and it is
// invisible in a hand-read of the output: `0f` against `f` reads as a typo.
check('every byte is two digits', hexColons(bytes, 0, 2), '00:0f');
check('a single byte carries no separator', hexColons(bytes, 3, 4), 'a5');
check('an interior range starts where it is told', hexColons(bytes, 2, 4), '10:a5');
check('the run form has no separators', hexRun(bytes, 0, bytes.length), '000f10a5ff');

console.log('\n--- the empty answers, which must be a string and not a throw ---\n');

check('an empty range is empty', hexColons(bytes, 2, 2), '');
check('a reversed range is empty', hexColons(bytes, 4, 1), '');
check('an empty array is empty', hexColons(new Uint8Array(0), 0, 10), '');
check('...and the run form agrees', hexRun(bytes, 4, 1), '');

console.log('\n--- the clamp: every one of these used to be a read past an end ---\n');

// `bytes[-1]` is `undefined`. Under the old per-byte `toString(16)` that threw
// a `TypeError` out of the middle of dissection; under the lookup table it is
// quieter and worse - `HEX[undefined]` is `undefined` and `out +=` renders it
// as the literal text "undefined" in the middle of a hex dump. Verified by
// removing the clamp: these two lines fail, and nothing else in the suite does.
check('a negative start is clamped to 0', hexColons(bytes, -4, 2), '00:0f');
check('an end past the array stops at the array',
  hexColons(bytes, 3, 9_999), 'a5:ff');
check('both ends at once', hexColons(bytes, -100, 100), '00:0f:10:a5:ff');
check('a start past the end is empty, not a wrap',
  hexColons(bytes, 99, 120), '');
check('the run form clamps identically', hexRun(bytes, -1, 9_999), '000f10a5ff');

console.log('\n--- every byte value, because the table is 256 entries ---\n');

// A table indexed by byte is one typo away from being right for 255 of them.
// Built the slow way on purpose: this is the definition the table encodes.
const all = new Uint8Array(256);
for (let i = 0; i < 256; i++) all[i] = i;
const longhand: string[] = [];
for (let i = 0; i < 256; i++) longhand.push(i.toString(16).padStart(2, '0'));
check('every byte 0x00..0xff renders as the longhand does',
  hexColons(all, 0, 256), longhand.join(':'));
check('...and the run form too', hexRun(all, 0, 256), longhand.join(''));

console.log(failures === 0
  ? '\nAll hex byte-range checks passed.'
  : `\n${failures} hex byte-range check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
