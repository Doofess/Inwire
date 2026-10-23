/**
 * Placing one conversation's items on a ladder: two lanes, time running down.
 *
 * Pure, and separate from the component that draws it, for the reason every
 * other layout in this app is: the arithmetic is where the bugs live and the
 * SVG is where they are invisible. An arrow pointing the wrong way, or a frame
 * silently dropped at a window edge, looks exactly like a conversation that
 * really did that.
 *
 * ## Items, not frames
 *
 * What is laid out is `foldRuns`'s output (`ladderRuns.ts`, ADR 0055): a frame
 * that says something is an item of its own, and a quiet run is one band. The
 * layout places either by the time it starts and reads nothing else from it,
 * so a band costs one row where its frames would have cost thousands.
 *
 * ## Only the visible window is materialised
 *
 * A stream can be a hundred thousand frames. Turning all of them into
 * positioned arrows would build a hundred thousand objects to draw a few
 * hundred, on every zoom and every scroll. `layoutLadder` takes a time window
 * and returns only what falls inside it.
 *
 * The items themselves are **not** copied - a frame item holds a reference
 * into the buffer or the store's answer, and the arrows carry the same
 * references. The only thing this allocates is the positions.
 *
 * ## A note on where the frames come from
 *
 * The specification for this view said to request a time-windowed slice from
 * the Worker. The Worker has no buffer to slice: it drains `pendingPackets` on
 * every flush and keeps only a tree cache (`docs/decisions/0007`). The frames
 * come from the store and the main thread's buffer (`streamFrames.ts`), which
 * is where the packet list, the filter and the statistics all read them from.
 * The concern behind that instruction is real, and this is what answers it -
 * the window, not the boundary.
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../../services/dissect/fieldAccess';
import { categoryOfPacket } from '../../services/expertInfo';
import { formatBytes } from '../../lib/formatBytes';
import type { ExpertCategory } from '../../types/packet';
import { itemTime, type LadderItem } from './ladderRuns';

/** Which lane a frame leaves from. */
export type Lane = 'client' | 'server';

export interface LadderArrow {
  /** The frame or the band, by reference. Never a copy. */
  item: LadderItem;
  /** Where it starts, so an arrow knows which way to point. */
  from: Lane;
  /** Vertical position in the laid-out area, in pixels from the top. */
  y: number;
  /**
   * Seconds since the capture started: where the item starts, even when that
   * is above the window. A band straddling the window's top edge is placed at
   * the edge - `y` says where - and keeps its own start here.
   */
  time: number;
  /** The frame's own length, for the thickness; a band's mean frame length. */
  length: number;
  /** TCP flags as they read in the list - "SYN, ACK" - or empty. Empty for a band. */
  flags: string;
  /** The Info line, which is what a ladder is actually read for. A band's says what it holds. */
  info: string;
  /** The expert category this frame reads as, or null. Null for a band, whose frames have none. */
  category: ExpertCategory | null;
  /** True when two or more items share this row because they are too close. */
  crowded: boolean;
}

export interface LadderWindow {
  /** Seconds, inclusive. */
  from: number;
  to: number;
}

export interface LadderLayout {
  arrows: LadderArrow[];
  /** The height the arrows were laid out into. */
  height: number;
  /**
   * How tall the drawing actually needs to be.
   *
   * Larger than `height` when nudging has pushed the last arrow past the
   * bottom, which happens whenever the window holds more frames than the
   * viewport has rows for. The view scrolls to it rather than clipping:
   * dropping arrows off the bottom would be a conversation that appears to
   * stop, which is a thing conversations really do and so must never be faked.
   */
  contentHeight: number;
  /** Items on the stream before and after the window, for the scroll hints. */
  before: number;
  after: number;
  /** The whole stream's extent, which is what the minimap draws. */
  extent: LadderWindow;
}

/**
 * How close two arrows may be before the later one is nudged down.
 *
 * A ladder positioned purely by time collapses under a burst: a TCP window's
 * worth of segments arrive inside a millisecond and land on the same pixel,
 * so the labels overprint and the conversation reads as one frame. Nudging
 * keeps them separable and keeps their **order**, which is the thing a ladder
 * exists to show - at the cost of the vertical position no longer being exactly
 * proportional to time in a burst. `crowded` marks the ones this happened to,
 * so the view can say the spacing there is order rather than duration.
 *
 * A row reaches 16px above its line (the chip) and 13 below it (the number),
 * `ROW_ABOVE` and `ROW_BELOW` in `ladderMarks.ts`, so 29 is where one row's
 * number meets the next row's chip; the extra pixel is air. It was 26, which
 * overprinted the number's descenders on the chip below in every burst.
 */
export const MIN_ROW_GAP = 30;

/** TCP flag fields, in the order the reference analyzer prints them. */
const FLAG_FIELDS: [string, string][] = [
  ['tcp.flags.syn', 'SYN'],
  ['tcp.flags.fin', 'FIN'],
  ['tcp.flags.reset', 'RST'],
  ['tcp.flags.push', 'PSH'],
  ['tcp.flags.ack', 'ACK'],
  ['tcp.flags.urg', 'URG'],
];

function flagsOf(packet: Packet): string {
  const set: string[] = [];
  for (const [abbrev, label] of FLAG_FIELDS) {
    if (fieldValue(packet, abbrev) === 1) set.push(label);
  }
  return set.join(', ');
}

/** What a band's label says: how many frames, how many bytes, how long. */
function bandInfo(count: number, bytes: number, time: number, endTime: number): string {
  return `${count.toLocaleString()} frames · ${formatBytes(bytes)} · ${(endTime - time).toFixed(3)} s`;
}

/**
 * The time span of a stream, which is what the minimap and the initial view
 * are both scaled to. A band counts to its end, or a stream closing on a long
 * quiet run would have an extent its last band runs past.
 *
 * A stream of one frame has no span. Returning a zero-width window would make
 * every scale divide by zero, so it is widened to a second around the frame -
 * arbitrary, but it puts the single arrow in the middle of a readable axis
 * instead of at a coordinate that is NaN.
 */
export function ladderExtent(items: readonly LadderItem[]): LadderWindow {
  if (items.length === 0) return { from: 0, to: 1 };
  let from = Infinity;
  let to = -Infinity;
  for (const item of items) {
    const start = itemTime(item);
    const end = item.kind === 'band' ? item.endTime : start;
    if (start < from) from = start;
    if (end > to) to = end;
  }
  if (!(to > from)) return { from: from - 0.5, to: from + 0.5 };
  return { from, to };
}

/**
 * Lays out the items that fall inside a time window.
 *
 * `items` must be in capture order, which is what `foldRuns` returns from
 * frames in capture order. A frame is inside the window by its time; a band
 * is an interval, and is inside when any of it is - zooming into the middle
 * of a long band must show the band, not an empty ladder saying there is one
 * row above. A band that starts above the window is placed at the window's
 * top edge. Items wholly outside the window are counted rather than
 * positioned, so the view can say what is above and below without walking
 * the stream again.
 */
export function layoutLadder(
  items: readonly LadderItem[],
  window: LadderWindow,
  height: number,
  /**
   * The most arrows to draw, whatever the window holds.
   *
   * A time window cannot bound this on its own, and the reason is worth
   * stating because it is not obvious: frames are not spread evenly through
   * time. A connection whose first seventeen frames span ninety idle seconds
   * gives a window ninety seconds wide - and the same ninety seconds later in
   * the conversation, where the traffic actually is, holds over a thousand.
   * Measured on a real TLS session: a window sized to seventeen frames drew
   * 1,347 the moment it was panned.
   *
   * So the count is capped here, and the remainder is reported as `after` -
   * which the view already knows how to say. Drawing is bounded by the
   * viewport rather than by an assumption about how traffic is distributed.
   */
  maxArrows = Number.MAX_SAFE_INTEGER,
): LadderLayout {
  const extent = ladderExtent(items);
  const span = window.to - window.from;
  // A window with no width would put every arrow at the same coordinate and
  // divide by zero on the way. Treated as the whole extent instead, which is
  // what a caller that has not sized itself yet actually means.
  const scale = span > 0 ? height / span : 0;

  const arrows: LadderArrow[] = [];
  let before = 0;
  let after = 0;
  let lastY = -Infinity;

  for (const item of items) {
    const time = itemTime(item);
    const end = item.kind === 'band' ? item.endTime : time;
    if (end < window.from) { before++; continue; }
    if (time > window.to) { after++; continue; }
    // Past the cap everything else is "later", which is exactly what it is:
    // the view offers to pan to it rather than pretending it is not there.
    if (arrows.length >= maxArrows) { after++; continue; }

    // Clamped: a band that began above the window is drawn at its top edge.
    const placed = Math.max(time, window.from);
    const exact = scale > 0 ? (placed - window.from) * scale : height / 2;
    // Order is preserved by construction: items arrive in capture order and
    // `y` never decreases, so an arrow nudged down pushes the next one down
    // too rather than being overtaken by it.
    const y = Math.max(exact, lastY + MIN_ROW_GAP);
    const crowded = y > exact + 0.5;
    lastY = y;

    if (item.kind === 'frame') {
      const { packet } = item;
      arrows.push({
        item, from: item.from, y, time,
        length: packet.length,
        flags: flagsOf(packet),
        info: packet.info,
        category: categoryOfPacket(packet) ?? null,
        crowded,
      });
    } else {
      // A band's frames carry no flag and no finding, or they would not be in
      // one, so its row has neither. Its thickness is its mean frame length,
      // which is what makes a band of ACKs and a band of data differ.
      arrows.push({
        item, from: item.from, y, time,
        length: item.bytes / item.count,
        flags: '',
        info: bandInfo(item.count, item.bytes, item.time, item.endTime),
        category: null,
        crowded,
      });
    }
  }

  return {
    arrows, height, before, after, extent,
    // The last arrow's position and no more: the view already pads below the
    // plot, which is what leaves room for that arrow's lower label. Adding a
    // whole row here as well put an uncrowded layout 26px over its viewport
    // and gave every ladder a scrollbar with nothing under it.
    contentHeight: Math.max(height, lastY),
  };
}

/**
 * How many arrows a given height can show without overlapping.
 *
 * Two text lines ride on each arrow - the Info line above it and the frame
 * number below - so the spacing is set by the labels rather than by the lines.
 */
export function arrowsThatFit(height: number): number {
  return Math.max(1, Math.floor(height / MIN_ROW_GAP));
}

/**
 * The window a conversation should open on.
 *
 * **Not the whole stream.** A busy conversation is a thousand frames over two
 * minutes, and showing all of them in a viewport with room for a dozen draws a
 * thousand arrows on top of each other - which is not a dense view of the
 * conversation, it is an unreadable one. Opening on a window that fits means
 * the first thing seen is legible, and the minimap says where in the whole it
 * sits.
 *
 * It opens at the **start**, because the beginning of a conversation is the
 * part that explains the rest: the handshake, the request, who spoke first.
 */
export function initialWindow(
  items: readonly LadderItem[], height: number,
): LadderWindow {
  const extent = ladderExtent(items);
  const fits = arrowsThatFit(height);
  if (items.length <= fits) return extent;
  // The time at which the last item that fits starts, so the opening view is
  // full rather than merely bounded - a window sized by time would be empty on
  // a conversation that starts with a long pause.
  const last = itemTime(items[fits - 1]);
  // A burst can put `fits` frames inside a microsecond, which would open on a
  // window too narrow to read a time from. Never less than a millisecond.
  return { from: extent.from, to: Math.max(last, extent.from + 0.001) };
}

/**
 * A window zoomed about a point, clamped to the stream.
 *
 * `anchor` is 0..1 down the view, so zooming keeps whatever is under the
 * pointer under the pointer - the same property the geo map's zoom needed, and
 * for the same reason: a zoom that recentres instead loses the thing being
 * looked at on every step.
 */
export function zoomWindow(
  window: LadderWindow, extent: LadderWindow, factor: number, anchor: number,
): LadderWindow {
  const span = window.to - window.from;
  const focus = window.from + span * anchor;
  const nextSpan = span * factor;

  const fullSpan = extent.to - extent.from;
  // Never wider than the stream, and never so narrow that the axis is showing
  // less than a microsecond - past that the numbers stop being readable and
  // the arrows are already one per row.
  const clamped = Math.min(Math.max(nextSpan, 1e-6), fullSpan);
  let from = focus - clamped * anchor;
  let to = from + clamped;

  if (from < extent.from) { from = extent.from; to = from + clamped; }
  if (to > extent.to) { to = extent.to; from = to - clamped; }
  return { from: Math.max(from, extent.from), to: Math.min(to, extent.to) };
}

/** A window moved by a fraction of its own span, clamped to the stream. */
export function panWindow(
  window: LadderWindow, extent: LadderWindow, fraction: number,
): LadderWindow {
  const span = window.to - window.from;
  let from = window.from + span * fraction;
  if (from < extent.from) from = extent.from;
  if (from + span > extent.to) from = extent.to - span;
  return { from, to: from + span };
}

/**
 * The scroll that shows a row from `top` to `bottom`, moving as little as it
 * can - or not at all when the row is already in view.
 *
 * The window is time, but the drawing can be taller than the viewport: nudging
 * a burst apart pushes rows below it, so a frame inside the window can still be
 * off screen. A row taller than the viewport shows its top, where its chip is.
 */
export function revealScroll(scrollTop: number, viewport: number, top: number, bottom: number): number {
  if (top < scrollTop || bottom - top > viewport) return top;
  if (bottom > scrollTop + viewport) return bottom - viewport;
  return scrollTop;
}

/**
 * The line under an arrow: its frame number and size, and on a crowded row a
 * note that its place is not to scale. The note goes first when the line would
 * overrun the lanes, because the number is what the row is found by.
 * `charWidth` is the chips' 10px advance; the line is set at 9px.
 */
export function rowMeta(number: string, bytes: number, crowded: boolean, span: number, charWidth: number): string {
  const base = `${number} · ${Math.round(bytes)} B`;
  if (!crowded) return base;
  const full = `${base} · ordered, not to scale`;
  return full.length * charWidth * 0.9 <= span ? full : base;
}

/**
 * A window containing one frame, for jumping to a selection.
 *
 * Keeps the current zoom rather than resetting it: somebody who has zoomed in
 * on a handshake and then clicks a frame in the packet list wants to be taken
 * to it at the detail they were already looking at.
 */
export function windowAround(
  time: number, window: LadderWindow, extent: LadderWindow,
): LadderWindow {
  const span = window.to - window.from;
  return panWindow(
    { from: time - span / 2, to: time + span / 2 }, extent, 0,
  );
}
