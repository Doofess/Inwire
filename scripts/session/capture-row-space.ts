/**
 * What row *i* of the packet list actually is.
 *
 *   npx tsx scripts/session/capture-row-space.ts
 *
 * ## Why this is worth its own script
 *
 * The list scrolls rows, and a row is one of three things: a frame in the RAM
 * window, a position in the capture on disk, or nothing. Which one comes out of
 * four numbers and a bitmap, and **getting it wrong does not fail**. It shows
 * the wrong frame, confidently, at the right row height, and the only way to
 * notice is to already know which frame should have been there.
 *
 * `rowSource.ts` covers the seam; this covers the arithmetic behind the seam
 * once the capture is bigger than memory and a filter has been run over the
 * whole of it.
 *
 * ## The property that matters most
 *
 * A filtered list reads from two places - the scan's bitmap for the rows below
 * the window, the in-memory filter for the window itself - and the frames in
 * the window are on disk **as well**, because the writer wrote them. So the
 * boundary between the two halves decides whether every frame in the window is
 * listed once or twice.
 *
 * The check for that is not "does the split look right". It is: **the list has
 * exactly as many rows as the filter has matches over the whole capture**.
 * That is one number, it is computed two completely different ways, and it
 * catches both the double count and the gap.
 */
import {
  MAX_ADDRESSABLE_ROWS, addressRow, matchesBeforeWindow, rowOfOrdinal, rowSpace,
  type RowAddress, type RowSpace,
} from '../../src/lib/captureRowSpace';
import { MatchSet } from '../../src/services/capture/matchSet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 240));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 240));
  }
}
/** A bitmap over `[0, frames)` holding every ordinal `matches` accepts. */
function bitmap(frames: number, matches: (ordinal: number) => boolean): MatchSet {
  const set = new MatchSet(frames);
  for (let i = 0; i < frames; i++) if (matches(i)) set.set(i);
  return set.seal();
}

/** Every row's address, in order. */
function addresses(space: RowSpace, set: MatchSet | null): RowAddress[] {
  const out: RowAddress[] = [];
  for (let i = 0; i < space.count; i++) out.push(addressRow(space, set, i));
  return out;
}

console.log('--- the capture in order, no filter ---\n');

{
  // The window is the whole capture. Every capture that fits in memory.
  const space = rowSpace(0, 500, null);
  check('nothing below the window: the rows are the window',
    [space.count, space.fromDisk, space.skipped], [500, 0, 0]);
  check('...and row 0 is the window\'s first frame',
    addressRow(space, null, 0), { where: 'window', at: 0 });
  check('...and one past the end is nowhere',
    addressRow(space, null, 500), { where: 'none' });
}

{
  // 10,000 on disk under a 500-frame window.
  const space = rowSpace(10_000, 500, null);
  check('the list addresses the capture', space.count, 10_500);
  check('row 0 is the oldest frame on disk',
    addressRow(space, null, 0), { where: 'disk', ordinal: 0 });
  check('the last disk row is the one before the window',
    addressRow(space, null, 9_999), { where: 'disk', ordinal: 9_999 });
  check('the window starts exactly where the disk stops',
    addressRow(space, null, 10_000), { where: 'window', at: 0 });
  check('the last row is the window\'s last frame',
    addressRow(space, null, 10_499), { where: 'window', at: 499 });

  // The inverse, which is what keeps the selection in view.
  check('an ordinal maps back to its row', rowOfOrdinal(space, null, 4_321), 4_321);
  check('...and an ordinal inside the window does not',
    rowOfOrdinal(space, null, 10_200), -1);
}

console.log('\n--- filtered over the whole capture ---\n');

{
  // 20,000 frames captured; the window holds the last 500. One in three
  // matches, so both halves have some.
  const CAPTURED = 20_000;
  const BELOW = 19_500;
  const matches = (ordinal: number) => ordinal % 3 === 0;
  const set = bitmap(CAPTURED, matches);

  // What the in-memory filter would produce over the window: the matching
  // frames of `[BELOW, CAPTURED)`.
  let windowRows = 0;
  for (let i = BELOW; i < CAPTURED; i++) if (matches(i)) windowRows++;

  const space = rowSpace(BELOW, windowRows, set);

  // THE assertion. Counted two ways: by the bitmap over the whole capture, and
  // by the split this module computes. A boundary at the scan's end instead of
  // at the window would list every matching frame in the window twice.
  let allMatches = 0;
  for (let i = 0; i < CAPTURED; i++) if (matches(i)) allMatches++;
  check('the list has exactly as many rows as the capture has matches',
    space.count, allMatches);

  check('the disk half is the matches before the window',
    space.fromDisk, allMatches - windowRows);

  // Every row, checked against the oracle: the k-th row is the k-th matching
  // frame of the capture.
  const wanted: number[] = [];
  for (let i = 0; i < CAPTURED; i++) if (matches(i)) wanted.push(i);
  const seen = addresses(space, set).map((at, row) =>
    at.where === 'disk' ? at.ordinal
      : at.where === 'window' ? BELOW + windowOrdinal(matches, BELOW, CAPTURED, at.at)
        : -1 - row);
  check('every row is the matching frame at that position', seen, wanted);

  // No frame is addressed twice, which is the same property from the other
  // side and would catch an off-by-one the count assertion cannot.
  check('...and no frame twice', new Set(seen).size, seen.length);

  check('an ordinal below the window maps back to its row',
    rowOfOrdinal(space, set, 300), 100);
  check('...and a non-matching ordinal maps to where its rank puts it',
    // 301 does not match; `rank` counts the 101 matches before it, which is
    // the row its neighbour occupies. Documented rather than defended: the
    // caller only ever asks about ordinals it read out of the bitmap.
    rowOfOrdinal(space, set, 301), 101);
}

{
  // A filter that matches nothing, and one that matches everything - the two
  // ends where the tail-clearing and the empty-prefix arithmetic would show.
  const none = bitmap(8_000, () => false);
  const empty = rowSpace(7_800, 0, none);
  check('a filter matching nothing has no rows', empty.count, 0);
  check('...and row 0 is nowhere', addressRow(empty, none, 0), { where: 'none' });

  const all = bitmap(8_000, () => true);
  const full = rowSpace(7_800, 200, all);
  check('a filter matching everything has every row', full.count, 8_000);
  check('...with the boundary still at the window', full.fromDisk, 7_800);
}

console.log('\n--- a capture that grew after the scan started ---\n');

{
  // The scan covered 10,000 ordinals; the window has since moved to 12,000, so
  // 2,000 frames sit below the window that the bitmap knows nothing about.
  const SCANNED = 10_000;
  const BELOW = 12_000;
  const matches = (ordinal: number) => ordinal % 4 === 0;
  const set = bitmap(SCANNED, matches);
  const space = rowSpace(BELOW, 50, set);

  let scannedMatches = 0;
  for (let i = 0; i < SCANNED; i++) if (matches(i)) scannedMatches++;

  check('the disk half is what the scan reached, not what the window sits on',
    space.fromDisk, scannedMatches);
  check('...which is what `matchesBeforeWindow` clamps to',
    matchesBeforeWindow(set, BELOW), scannedMatches);

  // The rows between the scan's end and the window are simply not listed. That
  // is a gap the caller reports (`uncoveredRows`), and what must NOT happen is
  // a row pointing into it - an ordinal the bitmap cannot place would read a
  // frame nobody filtered.
  const beyond = addresses(space, set)
    .filter((at): at is { where: 'disk'; ordinal: number } => at.where === 'disk')
    .filter((at) => at.ordinal >= SCANNED);
  check('no row addresses a frame the scan never saw', beyond, []);
}

console.log('\n--- past what the scroll canvas can express ---\n');

{
  const OVER = MAX_ADDRESSABLE_ROWS + 25_000;
  const space = rowSpace(OVER, 0, null);
  check('the count stops at the canvas limit', space.count, MAX_ADDRESSABLE_ROWS);
  check('...and the trim comes off the front', space.skipped, 25_000);
  // The newest rows are the ones on screen and the ones a live capture is
  // adding to. Trimming the tail would show the wrong million and a half.
  check('row 0 is the oldest row still addressable, not the oldest frame',
    addressRow(space, null, 0), { where: 'disk', ordinal: 25_000 });
  check('the last row is the last frame',
    addressRow(space, null, MAX_ADDRESSABLE_ROWS - 1),
    { where: 'disk', ordinal: OVER - 1 });
  check('an ordinal below the trim has no row', rowOfOrdinal(space, null, 100), -1);
  check('...and one above it does',
    rowOfOrdinal(space, null, 25_100), 100);
}

console.log('\n--- addressRow and rowOfOrdinal are inverses ---\n');

{
  // Round-tripped over a filtered space, which is where the two are computed
  // by different means - `ordinalAt` walks the bitmap, `rank` counts it.
  const set = bitmap(30_000, (o) => o % 7 === 0 || o % 11 === 0);
  const space = rowSpace(29_000, 40, set);
  let mismatched = 0;
  for (let row = 0; row < space.fromDisk; row++) {
    const at = addressRow(space, set, row);
    if (at.where !== 'disk') { mismatched++; continue; }
    if (rowOfOrdinal(space, set, at.ordinal) !== row) mismatched++;
  }
  check('every disk row round-trips through its ordinal', mismatched, 0);
}

console.log('\n--- above a floor: a ring took the front (ADR 0052) ---\n');

{
  // 4,000 frames gone, 6,000 on disk below a 50-frame window.
  const space = rowSpace(10_000, 50, null, 4_000);
  check('the list holds what is left, and no more', [space.count, space.fromDisk], [6_050, 6_000]);
  check('row 0 is the first frame still held',
    [addressRow(space, null, 0), addressRow(space, null, 5_999), addressRow(space, null, 6_000)],
    [{ where: 'disk', ordinal: 4_000 }, { where: 'disk', ordinal: 9_999 }, { where: 'window', at: 0 }]);
  check('a frame the ring took has no row, and the floor has row 0',
    [rowOfOrdinal(space, null, 3_999), rowOfOrdinal(space, null, 4_000)], [-1, 0]);
}

{
  // Filtered, the same property as above: the list has exactly as many rows
  // as the filter has matches over what is left of the capture.
  const matches = (o: number) => o % 3 === 0 || o % 17 === 0;
  const captured = 12_000;
  const set = bitmap(captured, matches);
  const floor = 4_000;
  const below = 10_000;
  let windowMatches = 0;
  for (let o = below; o < captured; o++) if (matches(o)) windowMatches++;
  let left = 0;
  for (let o = floor; o < captured; o++) if (matches(o)) left++;
  const space = rowSpace(below, windowMatches, set, floor);
  check('filtered, the rows are the matches of what is left', space.count, left);
  const first = addressRow(space, set, 0);
  let firstLeft = floor;
  while (!matches(firstLeft)) firstLeft++;
  check('...row 0 is the first match at or above the floor', first, { where: 'disk', ordinal: firstLeft });
  let mismatched = 0;
  for (let row = 0; row < space.fromDisk; row++) {
    const at = addressRow(space, set, row);
    if (at.where !== 'disk' || at.ordinal < floor || !matches(at.ordinal)) { mismatched++; continue; }
    if (rowOfOrdinal(space, set, at.ordinal) !== row) mismatched++;
  }
  check('...and every disk row is a match above the floor that round-trips', mismatched, 0);
}

{
  const unfloored = rowSpace(10_000, 50, null);
  check('with no floor nothing moves', [unfloored.floor, unfloored.base, unfloored.fromDisk], [0, 0, 10_000]);
}

/** Which capture ordinal the window's n-th matching frame is. The oracle. */
function windowOrdinal(
  matches: (ordinal: number) => boolean, below: number, captured: number, n: number,
): number {
  let seen = 0;
  for (let i = below; i < captured; i++) {
    if (!matches(i)) continue;
    if (seen === n) return i - below;
    seen++;
  }
  return -1;
}

console.log(failures === 0
  ? '\nAll capture row space checks passed.'
  : `\n${failures} capture row space check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
