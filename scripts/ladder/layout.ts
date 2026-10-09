/**
 * Assertion tests for the ladder view's layout.
 *
 *   npx tsx scripts/ladder/layout.ts
 *
 * A ladder is read for two things: which way each frame went, and in what
 * order. Both are arithmetic, and both fail invisibly - an arrow pointing the
 * wrong way looks exactly like a conversation that really did that, and a
 * frame dropped at a window edge looks like a gap in the traffic.
 *
 * So what is held here is the geometry rather than the drawing:
 *
 *   - **Nothing inside the window is lost, and nothing outside it is drawn.**
 *     The counts of what is above and below must add up with what is placed.
 *   - **Order survives crowding.** A TCP window's worth of segments arrives
 *     inside a millisecond; placing them purely by time collapses them onto
 *     one pixel. They are nudged apart, and the nudge must never let a later
 *     frame end up above an earlier one - which is the one thing a ladder
 *     cannot be wrong about.
 *   - **Zoom keeps its anchor.** Whatever is under the pointer stays under the
 *     pointer, or every zoom step loses the thing being looked at.
 *   - **Degenerate inputs do not produce NaN.** A one-frame stream has no time
 *     span, and a view that has not been sized yet has no height.
 */
import {
  initialWindow, ladderExtent, layoutLadder, panWindow, windowAround, zoomWindow,
  type LadderWindow,
} from '../../src/components/ladder/ladderLayout';
import { itemPacket, type LadderItem } from '../../src/components/ladder/ladderRuns';
import { isFromClient } from '../../src/services/followStream';
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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const CLIENT = { address: '10.0.0.4', port: 54321 };
const SERVER = { address: '93.184.216.34', port: 443 };

function frame(id: number, time: number, fromClient: boolean,
  fields: Record<string, string | number> = {}): Packet {
  const src = fromClient ? CLIENT : SERVER;
  const dst = fromClient ? SERVER : CLIENT;
  return {
    id, relativeTime: time, length: 100 + id,
    source: src.address, sourcePort: src.port,
    destination: dst.address, destPort: dst.port,
    info: `frame ${id}`, fields,
  } as unknown as Packet;
}

const WHOLE: LadderWindow = { from: 0, to: 10 };

/**
 * Every frame as its own item, which is what the geometry is held on: the
 * folding is `scripts/session/ladder-runs.ts`'s question, and this file's is
 * where an item lands once it exists.
 */
function items(frames: readonly Packet[]): LadderItem[] {
  return frames.map((packet) => ({
    kind: 'frame', packet, from: isFromClient(packet, CLIENT) ? 'client' : 'server',
  }));
}

/** A band over `frames`, as `foldRuns` would build it. */
function band(frames: readonly Packet[]): LadderItem {
  let bytes = 0;
  for (const f of frames) bytes += f.length;
  return {
    kind: 'band', from: isFromClient(frames[0], CLIENT) ? 'client' : 'server',
    first: frames[0], last: frames[frames.length - 1], count: frames.length, bytes,
    time: frames[0].relativeTime, endTime: frames[frames.length - 1].relativeTime, ruleKey: '',
  };
}

// --- Which way each arrow points ------------------------------------------------
{
  const frames = [frame(1, 0, true), frame(2, 1, false), frame(3, 2, true)];
  const { arrows } = layoutLadder(items(frames), WHOLE, 600);
  check('every frame in the window is placed', arrows.length, 3);
  check('arrows leave the lane that sent them',
    arrows.map((a) => a.from), ['client', 'server', 'client']);
  check('...and carry the frame itself, not a copy',
    itemPacket(arrows[0].item) === frames[0], true);
  check('the frame numbers survive in order', arrows.map((a) => itemPacket(a.item).id), [1, 2, 3]);
}

// --- The window is a window --------------------------------------------------------
{
  const frames = Array.from({ length: 11 }, (_, i) => frame(i + 1, i, i % 2 === 0));
  const layout = layoutLadder(items(frames), { from: 3, to: 6 }, 600);
  check('only frames inside the window are placed',
    layout.arrows.map((a) => itemPacket(a.item).id), [4, 5, 6, 7]);
  // The counts are what the scroll hints read. If they did not add up, the
  // view would tell the user there is nothing above when there is.
  check('frames above the window are counted', layout.before, 3);
  check('frames below it are counted', layout.after, 4);
  check('every frame is accounted for exactly once',
    layout.before + layout.arrows.length + layout.after, frames.length);

  // Both edges inclusive: a frame exactly on the boundary belongs to the view
  // rather than falling between two windows and never being drawn at all.
  const edge = layoutLadder(items([frame(1, 3, true), frame(2, 6, true)]),
    { from: 3, to: 6 }, 600);
  check('a frame on either boundary is inside the window', edge.arrows.length, 2);
}

// --- Time maps to position ----------------------------------------------------------
{
  const frames = [frame(1, 0, true), frame(2, 5, true), frame(3, 10, true)];
  const { arrows } = layoutLadder(items(frames), WHOLE, 600);
  check('the first frame is at the top', arrows[0].y, 0);
  check('the middle frame is halfway down', arrows[1].y, 300);
  check('the last frame is at the bottom', arrows[2].y, 600);
  checkTrue('...and none of them is marked crowded', arrows.every((a) => !a.crowded));
}

// --- Crowding: order is what must survive ---------------------------------------------
//
// A TCP window's worth of segments arrives inside a millisecond. Positioned
// purely by time they land on one pixel, the labels overprint, and the burst
// reads as a single frame.
{
  const burst = Array.from({ length: 20 }, (_, i) => frame(i + 1, 5 + i * 0.00001, true));
  const { arrows } = layoutLadder(items(burst), WHOLE, 600);
  check('every frame in a burst is still placed', arrows.length, 20);

  // The property that matters. A ladder may compress time; it may never show
  // two frames in the wrong order.
  let ordered = true;
  for (let i = 1; i < arrows.length; i++) {
    if (arrows[i].y < arrows[i - 1].y) ordered = false;
  }
  checkTrue('a burst never puts a later frame above an earlier one', ordered);

  let separated = true;
  for (let i = 1; i < arrows.length; i++) {
    if (arrows[i].y - arrows[i - 1].y < 17.9) separated = false;
  }
  checkTrue('...and every arrow is far enough apart to read', separated);

  // Marked, because the spacing there means order rather than duration, and a
  // view that did not say so would be showing a time axis that lies.
  checkTrue('the nudged arrows say they were nudged', arrows.slice(1).every((a) => a.crowded));
  checkTrue('the first of a burst is not marked', !arrows[0].crowded);
}

// --- Degenerate inputs -------------------------------------------------------------------
{
  check('an empty stream lays out to nothing',
    layoutLadder(items([]), WHOLE, 600).arrows.length, 0);
  check('...and has a usable extent rather than an infinite one',
    ladderExtent(items([])), { from: 0, to: 1 });

  // One frame has no span. A zero-width extent would divide by zero in every
  // scale built from it, so it is widened around the frame.
  const single = ladderExtent(items([frame(1, 4, true)]));
  check('a one-frame stream is given a span', [single.from, single.to], [3.5, 4.5]);
  checkTrue('...and its arrow has a real position',
    Number.isFinite(layoutLadder(items([frame(1, 4, true)]), single, 600).arrows[0].y));

  // A view that has not been measured yet asks for zero height, and a window
  // with no width is what an unsized caller passes.
  const unsized = layoutLadder(items([frame(1, 1, true)]), { from: 1, to: 1 }, 0);
  checkTrue('a zero-width window produces a number, not NaN',
    Number.isFinite(unsized.arrows[0].y));
}

// --- Zoom keeps its anchor -----------------------------------------------------------------
{
  const extent: LadderWindow = { from: 0, to: 100 };
  const window: LadderWindow = { from: 20, to: 60 };

  // Zooming about the middle keeps the middle where it was.
  const mid = zoomWindow(window, extent, 0.5, 0.5);
  check('zooming about the centre keeps the centre',
    (mid.from + mid.to) / 2, (window.from + window.to) / 2);
  check('...and halves the span', mid.to - mid.from, 20);

  // Zooming about the top keeps the top, which is what makes wheel-zoom feel
  // attached to the pointer rather than recentring under it.
  const top = zoomWindow(window, extent, 0.5, 0);
  check('zooming about the top edge keeps the top edge', top.from, 20);

  check('zooming out is clamped to the whole stream',
    zoomWindow(window, extent, 100, 0.5), extent);
  // Clamping must not leave the window hanging off the end.
  const far = zoomWindow({ from: 90, to: 100 }, extent, 4, 0.5);
  checkTrue('a window clamped at the end stays inside the stream',
    far.from >= extent.from && far.to <= extent.to);
}

// --- Panning ------------------------------------------------------------------------------
{
  const extent: LadderWindow = { from: 0, to: 100 };
  const window: LadderWindow = { from: 20, to: 40 };
  check('panning down moves by a fraction of the span',
    panWindow(window, extent, 0.5), { from: 30, to: 50 });
  check('panning past the start stops at the start',
    panWindow(window, extent, -10), { from: 0, to: 20 });
  check('panning past the end stops at the end',
    panWindow(window, extent, 10), { from: 80, to: 100 });
  check('the span never changes while panning',
    panWindow(window, extent, 10).to - panWindow(window, extent, 10).from, 20);
}

// --- Jumping to a selected frame -------------------------------------------------------------
{
  const extent: LadderWindow = { from: 0, to: 100 };
  const window: LadderWindow = { from: 20, to: 30 };
  const jumped = windowAround(70, window, extent);
  check('the frame ends up centred', (jumped.from + jumped.to) / 2, 70);
  // Somebody who zoomed in on a handshake and then clicked a frame in the
  // packet list wants to arrive at the detail they were already using.
  check('...at the zoom level already in use', jumped.to - jumped.from, 10);
  const early = windowAround(1, window, extent);
  checkTrue('a frame near the start stays inside the stream', early.from >= extent.from);
}

// --- Opening on a window that fits ---------------------------------------------------------
//
// A busy conversation is a thousand frames over two minutes. Drawn into a
// viewport with room for a dozen, all thousand land on top of each other -
// which is not a dense view of the conversation, it is an unreadable one.
{
  const many = Array.from({ length: 1362 }, (_, i) => frame(i + 1, i * 0.076, i % 3 === 0));
  const opening = initialWindow(items(many), 300);
  const laid = layoutLadder(items(many), opening, 300);
  checkTrue('a busy conversation does not open on all of it',
    laid.arrows.length < many.length);
  checkTrue('...but on enough to fill the view', laid.arrows.length >= 10);
  check('...and says how many are still below', laid.after, many.length - laid.arrows.length);
  check('...starting at the beginning, which is the part that explains the rest',
    laid.before, 0);

  // A short conversation is shown whole rather than artificially windowed.
  const few = [frame(1, 0, true), frame(2, 0.5, false)];
  check('a short conversation opens on all of it',
    layoutLadder(items(few), initialWindow(items(few), 300), 300).arrows.length, 2);

  // A burst can put a viewport's worth of frames inside a microsecond, and a
  // window that narrow has no readable time axis.
  const burst = Array.from({ length: 200 }, (_, i) => frame(i + 1, i * 1e-7, true));
  const tight = initialWindow(items(burst), 300);
  checkTrue('a window is never narrower than a millisecond',
    tight.to - tight.from >= 0.001 - 1e-9);
}

// --- Content taller than the viewport is reported, not clipped -------------------------------
//
// Nudging apart a burst can push the last arrow below the bottom. Clipping it
// would be a conversation that appears to stop - a thing conversations really
// do, so it must never be faked.
{
  const burst = Array.from({ length: 60 }, (_, i) => frame(i + 1, 5 + i * 1e-6, true));
  const laid = layoutLadder(items(burst), WHOLE, 200);
  check('every frame is still laid out', laid.arrows.length, 60);
  checkTrue('the content is taller than the viewport', laid.contentHeight > 200);
  checkTrue('...tall enough for the last arrow',
    laid.contentHeight >= laid.arrows[laid.arrows.length - 1].y);
  // And an uncrowded layout needs no extra room at all.
  const sparse = layoutLadder(items([frame(1, 0, true), frame(2, 10, true)]), WHOLE, 600);
  check('an uncrowded layout asks for no more than the viewport',
    sparse.contentHeight, 600);
}

// --- The cap, which is what actually bounds the drawing ---------------------------------
//
// A time window cannot bound it, and this is the case that proved it. Frames
// are not spread evenly through time: a connection whose first seventeen
// frames span ninety idle seconds gives a window ninety seconds wide, and the
// same span later in the conversation - where the traffic is - holds over a
// thousand. Measured on a real TLS session, a window sized to seventeen frames
// drew 1,347 the moment it was panned.
{
  const quietThenBusy = [
    // Seventeen frames spread over ninety seconds...
    ...Array.from({ length: 17 }, (_, i) => frame(i + 1, i * 5.3, i % 2 === 0)),
    // ...then a thousand inside the next ninety.
    ...Array.from({ length: 1000 }, (_, i) => frame(100 + i, 95 + i * 0.09, i % 2 === 0)),
  ];
  const extent = ladderExtent(items(quietThenBusy));
  const opening = initialWindow(items(quietThenBusy), 300);
  check('the opening window really does hold what fits',
    layoutLadder(items(quietThenBusy), opening, 300).arrows.length,
    layoutLadder(items(quietThenBusy), opening, 300, 11).arrows.length);

  // The same span, moved to where the traffic is.
  const moved = windowAround(140, opening, extent);
  const uncapped = layoutLadder(items(quietThenBusy), moved, 300);
  checkTrue('...but the same span elsewhere would draw far too many',
    uncapped.arrows.length > 500);

  const capped = layoutLadder(items(quietThenBusy), moved, 300, 11);
  check('the cap holds it to what the viewport can show', capped.arrows.length, 11);
  // Not silently dropped: the view offers to pan to them.
  check('...and the rest are reported as later frames',
    capped.before + capped.arrows.length + capped.after, quietThenBusy.length);
  checkTrue('...counted as later rather than earlier',
    capped.after > uncapped.after);
}

// --- A band is one row ---------------------------------------------------------------------
//
// A quiet run of a thousand frames is one item (ADR 0055), placed where it
// starts and labelled with what it holds. The layout reads nothing else from
// it - the folding is `scripts/session/ladder-runs.ts`'s question.
{
  const quiet = Array.from({ length: 1000 }, (_, i) => frame(10 + i, 2 + i * 0.004, true));
  const stream: LadderItem[] = [
    ...items([frame(1, 0, true), frame(2, 1, false)]),
    band(quiet),
    ...items([frame(2000, 9, true)]),
  ];
  const laid = layoutLadder(stream, WHOLE, 600);
  check('a band is one arrow, not a thousand', laid.arrows.length, 4);
  const row = laid.arrows[2];
  check('...placed where it starts', row.time, 2);
  check('...from the lane its frames left', row.from, 'client');
  check('...with no flags', row.flags, '');
  check('...and no category', row.category, null);
  // 1,000 frames of `100 + id` with ids 10..1009: 609,500 B.
  check('...labelled with what it holds', row.info, '1,000 frames · 595.2 KB · 3.996 s');
  check('...as thick as its mean frame', row.length, quiet.reduce((n, f) => n + f.length, 0) / 1000);
  checkTrue('...and carrying the band itself', row.item === stream[2]);

  // The extent runs to the band's END. A stream closing on a long quiet run
  // would otherwise have an extent its last band runs past, and the minimap
  // would show the band ending where it began.
  const closing: LadderItem[] = [...items([frame(1, 0, true)]), band(quiet)];
  check('the extent runs to a band\'s end', ladderExtent(closing), { from: 0, to: 2 + 999 * 0.004 });

  // The window test reads where an item starts, so a band is counted on the
  // side its first frame falls, like any other item.
  const later = layoutLadder(stream, { from: 5, to: 10 }, 600);
  check('a band starting before the window is counted above it', [later.before, later.arrows.length, later.after], [3, 1, 0]);

  // The opening window is sized by items, so a band that would have been a
  // thousand rows counts as one.
  const opening = initialWindow(stream, 300);
  check('the opening window holds the band as one row', layoutLadder(stream, opening, 300).arrows.length, 4);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ladder layout checks passed.');
process.exit(0);
