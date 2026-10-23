/**
 * What the ladder writes beside its arrows (ADR 0055 §4): each side's state
 * as it changes, and where the capture is blind.
 *
 * Pure, and separate from the component that draws it, for the reason the
 * layout is: a pill on the wrong lane, a "packets missing" row printed over a
 * frame, or an end marker on a stream that closed cleanly each look like a
 * conversation that really did that. Both functions take the layout's arrows,
 * so everything here is bounded by the window rather than by the stream.
 *
 * ## A marker takes a row where the time axis gives it none
 *
 * A marker is a full-width row of text, and the one for a lost segment belongs
 * between two arrows. Where the gap in time already leaves room, nothing
 * moves; where it does not, that arrow and every arrow below it move down by
 * exactly what is missing. Order is kept and proportion is not, which is the
 * trade `layoutLadder` already makes when it nudges a burst apart. A marker at
 * the stream's start goes above the plot instead - `topRoom` says by how much
 * the plot moves down - so the first arrow stays on its tick.
 */
import type { Packet } from '../../types/packet';
import type { StreamStep, StreamSummary } from '../../services/conversation/streamDigest';
import type { Evidence, Side, TcpOutcome, TcpState } from '../../services/conversation/tcpStates';
import type { LadderArrow, LadderLayout } from './ladderLayout';

/** How far a row reaches above its `y` - the chip over the line - and below it - the number under it. */
export const ROW_ABOVE = 16;
export const ROW_BELOW = 13;
/** A marker row: one line of 9px text with air on either side. */
export const MARK_ROW = 24;

export type MarkKind = 'ring-floor' | 'joined' | 'lost' | 'open-end';

export interface LadderMark {
  kind: MarkKind;
  /** The marker's centre line, in the plot's coordinates. Negative for one above the plot. */
  y: number;
  text: string;
}

export interface MarkedLadder {
  /** The layout's arrows, each moved down by the marker rows opened above it. */
  arrows: LadderArrow[];
  marks: LadderMark[];
  /** Room above the plot's top for the markers at the stream's start. */
  topRoom: number;
  /** `LadderLayout.contentHeight`, grown by the rows the markers took. */
  contentHeight: number;
}

/** Outcomes under which the capture ended before the connection did. */
const OPEN_ENDED = new Set<TcpOutcome>(['open', 'closing', 'half-closed by client', 'half-closed by server']);

const LOST = 'Packets missing here';

/**
 * Places the gap markers around a laid-out window.
 *
 * `complete` says every frame of the stream is in hand; while it is false the
 * end marker is withheld, because "after the capture ended" placed under the
 * last frame read so far would be placed under a frame that is not the last.
 *
 * The ring-floor marker wins over the joined marker: a ring that deleted a
 * handshake did not make it unseen, and the frame it names is the one the
 * store still holds.
 */
export function markLadder(
  layout: LadderLayout, frames: readonly Packet[], summary: StreamSummary | null, complete: boolean,
): MarkedLadder {
  const marks: LadderMark[] = [];
  if (summary === null || layout.arrows.length === 0 || frames.length === 0) {
    return { arrows: [...layout.arrows], marks, topRoom: 0, contentHeight: layout.contentHeight };
  }

  // Above the plot: the stream's start, when the window holds it, and a lost
  // segment on the first row drawn, which has no row above it to sit between.
  const top: { kind: MarkKind; text: string }[] = [];
  if (layout.before === 0) {
    if (frames[0].id > summary.firstId || (summary.startExpired === true && summary.joinedMidStream)) {
      top.push({ kind: 'ring-floor', text: `Frames before #${frames[0].id} were removed by the ring` });
    } else if (summary.joinedMidStream) {
      top.push({ kind: 'joined', text: 'Joined mid-stream: the handshake was not captured' });
    }
  }
  if (lostBefore(layout.arrows[0])) top.push({ kind: 'lost', text: LOST });
  const topRoom = top.length * MARK_ROW;
  top.forEach((mark, i) => marks.push({ ...mark, y: -(top.length - i) * MARK_ROW + MARK_ROW / 2 }));

  const arrows: LadderArrow[] = [];
  let shift = 0;
  let lastY = -Infinity;
  layout.arrows.forEach((arrow, i) => {
    let y = arrow.y + shift;
    if (i > 0 && lostBefore(arrow)) {
      // The least `y` at which this row's chip clears a marker row under the
      // previous row's number. Where time already gives it, the marker sits
      // in the gap; where it does not, this row and the rest move down.
      const least = lastY + ROW_BELOW + MARK_ROW + ROW_ABOVE;
      if (y < least) { shift += least - y; y = least; }
      marks.push({ kind: 'lost', y: y - ROW_ABOVE - MARK_ROW / 2, text: LOST });
    }
    arrows.push(y === arrow.y ? arrow : { ...arrow, y });
    lastY = y;
  });

  let contentHeight = Math.max(layout.height, lastY);
  if (complete && layout.after === 0 && OPEN_ENDED.has(summary.outcome)) {
    const y = lastY + ROW_BELOW + MARK_ROW / 2;
    marks.push({ kind: 'open-end', y, text: 'State unknown after the capture ended' });
    contentHeight = Math.max(contentHeight, y + MARK_ROW / 2);
  }
  return { arrows, marks, topRoom, contentHeight };
}

/** A frame the analysis says follows a hole. A band holds no such frame, or it would not be one. */
function lostBefore(arrow: LadderArrow): boolean {
  return arrow.item.kind === 'frame' && (arrow.item.packet.analysisFlags?.includes('lost_segment') ?? false);
}

export interface LanePill {
  side: Side;
  /** The row of the frame that moved this side, as the layout placed it. */
  y: number;
  frameId: number;
  to: TcpState;
  evidence: Evidence;
  /** What the pill says: the state, and "(expected)" on TIME_WAIT, which no segment shows. */
  text: string;
  /** How the state was reached when it was not seen sent, for the pill's title; null when it was. */
  note: string | null;
  /** 0 for the side's last step on this row, counting away from the lane for the steps before it. */
  slot: number;
}

const NOTE: Record<Evidence, string | null> = {
  sent: null,
  received: 'assumed: the segment was seen, its arrival was not',
  inferred: 'inferred: not visible on the wire',
};

/**
 * The state each side entered, placed on the row of the frame that did it.
 *
 * A step's frame is a row of its own when it carries the flag that moved the
 * machine, and inside a band when it did not - the third segment of a
 * handshake is a plain ACK, and so is the one that acknowledges a FIN. Either
 * way the pill goes on that row. A step whose frame is outside the window has
 * no row, and no pill.
 *
 * One segment can move a side twice - a SYN+ACK takes an unseen listener
 * through LISTEN to SYN_RCVD - so a row can hold two pills for one lane.
 * `slot` orders them: the state the side is in after the frame sits nearest
 * its lane, and the one it passed through sits beyond it.
 */
export function lanePills(arrows: readonly LadderArrow[], steps: readonly StreamStep[]): LanePill[] {
  if (steps.length === 0 || arrows.length === 0) return [];
  const rowOfFrame = new Map<number, number>();
  const bands: { first: number; last: number; y: number }[] = [];
  for (const arrow of arrows) {
    if (arrow.item.kind === 'frame') rowOfFrame.set(arrow.item.packet.id, arrow.y);
    else bands.push({ first: arrow.item.first.id, last: arrow.item.last.id, y: arrow.y });
  }
  const rowOf = (id: number): number | undefined => {
    const y = rowOfFrame.get(id);
    if (y !== undefined) return y;
    for (const band of bands) if (id >= band.first && id <= band.last) return band.y;
    return undefined;
  };

  const pills: LanePill[] = [];
  for (const step of steps) {
    const y = rowOf(step.frameId);
    if (y === undefined) continue;
    pills.push({
      side: step.side, y, frameId: step.frameId, to: step.to, evidence: step.evidence,
      text: step.to === 'TIME_WAIT' ? 'TIME_WAIT (expected)' : step.to,
      note: NOTE[step.evidence],
      slot: 0,
    });
  }
  for (let i = pills.length - 1; i >= 0; i--) {
    let slot = 0;
    for (let j = i + 1; j < pills.length; j++) {
      if (pills[j].side === pills[i].side && pills[j].y === pills[i].y) slot++;
    }
    pills[i].slot = slot;
  }
  return pills;
}
