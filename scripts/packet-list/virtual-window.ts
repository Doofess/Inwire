/**
 * Assertion tests for the packet list's virtualisation window.
 *
 *   npx tsx scripts/packet-list/virtual-window.ts
 *
 * This exists because of one bug, and the bug is worth stating because its
 * shape is the reason the arithmetic was pulled out of the component at all.
 *
 * `scrollTop` is React state fed by the scroll event, so when the row count
 * shrinks underneath it - a filter applied while the list is scrolled deep -
 * it holds an offset that is no longer reachable. Unclamped, that gives a
 * `startIndex` past `endIndex`, an empty slice, and a single top spacer the
 * height of the OLD list. Measured on a real capture: **157,117 pixels of
 * nothing** where 1,362 rows should have been.
 *
 * And the spacer is what made it stick, rather than flicker and recover. It
 * kept `scrollHeight` large enough that the browser never clamped `scrollTop`,
 * which kept `startIndex` past the end, which kept the spacer. Scrolling did
 * not help, because there was nothing to scroll to.
 *
 * So the property held here is not "the window is right" but the stronger
 * **"the window is never empty when there are rows to show"** - which is the
 * only statement that would have caught it.
 */
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { virtualWindow } from '../../src/lib/virtualWindow';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const ROW = 20;
const VIEW = 900;
const OVERSCAN = 15;

// --- At the top of a long list ------------------------------------------------
{
  const w = virtualWindow(8000, 0, VIEW, ROW, OVERSCAN);
  check('the first row is rendered', w.startIndex, 0);
  check('...with nothing above it', w.topSpacerHeight, 0);
  checkTrue('...and enough rows to fill the viewport',
    w.endIndex * ROW >= VIEW);
  check('the spacers and rows add up to the full height',
    w.topSpacerHeight + (w.endIndex - w.startIndex) * ROW + w.bottomSpacerHeight,
    8000 * ROW);
}

// --- The bug: the list shrinks while scrolled deep --------------------------------
//
// 8,000 rows, scrolled to the bottom, then a filter cuts it to 1,362. The
// offset of 156,232 is no longer reachable - the whole list is now 27,240px.
{
  const w = virtualWindow(1362, 156_232, VIEW, ROW, OVERSCAN);
  checkTrue('a stale offset still renders rows', w.endIndex > w.startIndex);
  checkTrue('...starting inside the list', w.startIndex < 1362);
  check('...and ending at the last row', w.endIndex, 1362);
  // The 157,117px spacer is the signature of the bug. The whole content is
  // 27,240px now, so nothing in it may be taller than that.
  checkTrue('the top spacer cannot exceed the content',
    w.topSpacerHeight <= 1362 * ROW);
  check('the spacers and rows still add up',
    w.topSpacerHeight + (w.endIndex - w.startIndex) * ROW + w.bottomSpacerHeight,
    1362 * ROW);
}

// --- The property, over the whole space ---------------------------------------------
//
// Not one case but every combination of a plausible offset against a plausible
// row count: whenever there are rows, at least one must be rendered. That is
// the statement a blank list violates, and the reason it is phrased this way
// rather than as an expected index.
{
  let blank = 0;
  let mismatched = 0;
  for (const totalRows of [1, 2, 47, 1362, 8000, 700_000]) {
    for (const scrollTop of [0, 1, 900, 27_240, 156_232, 1e7, -50]) {
      const w = virtualWindow(totalRows, scrollTop, VIEW, ROW, OVERSCAN);
      if (w.endIndex <= w.startIndex) blank++;
      const total = w.topSpacerHeight + (w.endIndex - w.startIndex) * ROW + w.bottomSpacerHeight;
      if (Math.abs(total - totalRows * ROW) > 0.001) mismatched++;
    }
  }
  check('no offset ever renders an empty window over a non-empty list', blank, 0);
  check('the spacers always account for exactly the rows not drawn', mismatched, 0);
}

// --- Overscan -------------------------------------------------------------------------
{
  const w = virtualWindow(8000, 4000, VIEW, ROW, OVERSCAN);
  // 4000/20 = row 200 at the top of the viewport; overscan draws 15 before it.
  check('rows are drawn above the viewport', w.startIndex, 185);
  checkTrue('...and below it', w.endIndex >= Math.ceil((4000 + VIEW) / ROW));
  check('the top spacer matches the first drawn row', w.topSpacerHeight, 185 * ROW);
}

// --- Degenerate inputs -------------------------------------------------------------------
{
  check('an empty list renders nothing', virtualWindow(0, 0, VIEW, ROW, OVERSCAN),
    { startIndex: 0, endIndex: 0, topSpacerHeight: 0, bottomSpacerHeight: 0 });
  // Before the first row has been measured there is no row height, and
  // dividing by it would produce Infinity as an index.
  check('a zero row height renders nothing rather than NaN',
    virtualWindow(100, 500, VIEW, 0, OVERSCAN),
    { startIndex: 0, endIndex: 0, topSpacerHeight: 0, bottomSpacerHeight: 0 });
  const negative = virtualWindow(100, -500, VIEW, ROW, OVERSCAN);
  check('a negative offset starts at the top', negative.startIndex, 0);
  // A list shorter than the viewport is entirely visible whatever the offset.
  const short = virtualWindow(3, 99_999, VIEW, ROW, OVERSCAN);
  check('a list shorter than the viewport draws all of it',
    [short.startIndex, short.endIndex], [0, 3]);
  check('...with no spacers at all',
    [short.topSpacerHeight, short.bottomSpacerHeight], [0, 0]);
}

/**
 * ...and every surface that virtualises rows uses THIS window.
 *
 * The clamp above is only worth having where it is reached, and it was not.
 * `HexDumpView.tsx` carried its own four-line copy of this arithmetic - the
 * version from before the clamp existed - so the one component whose scroll
 * offset is supplied by an *outer* document, and is therefore not bounded by a
 * scroller at all, was the one running the unguarded code.
 *
 * It was found by reading rather than by failing, which is exactly why it gets
 * a check: a second implementation of one window is how the first came to be
 * missing a line the second has, and nothing here could see it. Source text
 * rather than behaviour, because a React component is not reachable from plain
 * `tsx` - the same reason `scripts/session/side-bar.ts` reads its files.
 */
{
  console.log();
  const virtualised = [
    'src/components/packet-list/PacketList.tsx',
    'src/components/stream-follower/StreamFollowerPane.tsx',
    'src/components/packet-details/HexDumpView.tsx',
  ];
  for (const file of virtualised) {
    const source = readFileSync(file, 'utf8');
    checkTrue(`${basename(file)} takes its window from virtualWindow.ts`,
      /import \{[^}]*\bvirtualWindow\b[^}]*\} from/.test(source));
    // The shape of the copy that was here: an index derived straight from an
    // unclamped offset. `virtualWindow` is the only place that division belongs.
    checkTrue(`...rather than deriving a row index from a raw offset`,
      !/Math\.floor\(\s*scrollTop\s*\//.test(source));
  }
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All virtual-window checks passed.');
process.exit(0);
