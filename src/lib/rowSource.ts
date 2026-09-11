/**
 * What the packet list reads rows from.
 *
 * ## Why the list stops indexing an array
 *
 * `packets.length` used to **be** the capture. It is now the RAM window over
 * one, and the frames below that window are on disk, indexed, and readable -
 * they are simply not reachable by scrolling, because the list can only render
 * what it can subscript. This interface is the seam that fixes that: the list
 * asks for row *i* and is answered with a packet, or with "not yet", or with
 * "never".
 *
 * Three states, and they are the same three `PacketDetailState` already uses,
 * deliberately. A reader who has seen the detail pane spin while a frame's
 * bytes come back off disk should recognise a row doing the same thing, and a
 * second vocabulary for one idea is a second thing to learn.
 *
 * ## The pass-through is the point
 *
 * `arrayRowSource` is four lines, and **every capture the app handles today
 * goes through it**. A capture that fits in RAM behaves exactly as it did:
 * every `rowAt` is `ready`, `request` does nothing, and no read is ever
 * issued. That is what makes this safe to land before anything reads from
 * disk - the new path is a shape, not a behaviour, until something provides a
 * different source.
 *
 * It is also what the sorted and searched views keep using. A sort over a
 * capture larger than memory is a different problem with a different answer
 * (`docs/specs`, the row-source step), and until that answer exists the list
 * sorts what it holds and says so - which is what it has always done.
 *
 * ## `rowAt` is synchronous, and a miss is not an error
 *
 * It is called from render, once per visible row, ~40 times a frame. It cannot
 * await anything. So a source that has to fetch answers `loading` **now** and
 * arranges for a re-render later; `request` is how the list tells it which
 * rows are about to be asked for, so the fetch is one coalesced read rather
 * than forty.
 *
 * There is deliberately no `ordinalOf`. The plan had one, and every caller for
 * it turned out to be a row that already knows its own index - the two states
 * that carry an ordinal are the two that have no packet to carry it for them.
 */
import type { Packet } from '../types/packet';

export type Row =
  | { state: 'ready'; packet: Packet }
  /** On its way. The row renders as a placeholder of the right height. */
  | { state: 'loading'; ordinal: number }
  /**
   * Gone, and not coming.
   *
   * A frame the capture store never held or can no longer read - a torn tail,
   * a discarded capture. Distinct from `loading` because one of them resolves
   * and the other does not, and a spinner that never stops is a worse answer
   * than a row that says so.
   */
  | { state: 'unavailable'; ordinal: number };

export interface RowSource {
  /** How many rows the list can scroll through. */
  readonly count: number;
  /**
   * Row `index`, synchronously. Out of range answers `unavailable`.
   *
   * Must be cheap and must not throw: this runs inside render.
   */
  rowAt(index: number): Row;
  /**
   * Tells the source which rows are about to be asked for, `to` exclusive.
   *
   * Called from an effect after the window moves, never from render. A source
   * that holds everything ignores it.
   */
  request(from: number, to: number): void;
  /**
   * Which row a frame is at, or -1.
   *
   * The keyboard needs it: "move down one" is a row away from the selected
   * frame, and the selected frame is an id. On the source rather than as a
   * free function because only the source can answer it cheaply - an array
   * scans itself, and a capture answers from the window's offset without
   * touching the millions of rows below it.
   *
   * -1 for a frame the source cannot place, which is not the same as one it
   * does not have: a frame on disk that no cached chunk covers is real and
   * unlocatable, and the caller treats it the same way it treats nothing
   * selected.
   */
  indexOfId(id: number): number;
}

/** The one row every out-of-range read gets. Shared, so it is not allocated. */
const OUT_OF_RANGE: Row = { state: 'unavailable', ordinal: -1 };

/**
 * A source over an array already in hand.
 *
 * The whole of the read path for a capture that fits in RAM, and for every
 * sorted or searched view of one. Rows are wrapped on the way out rather than
 * stored wrapped: the array is `sortedPackets`, rebuilt by a `useMemo` on
 * every flush, and pre-wrapping it would allocate one object per frame per
 * flush to describe a state that is always the same one.
 */
export function arrayRowSource(packets: readonly Packet[]): RowSource {
  return {
    count: packets.length,
    rowAt(index: number): Row {
      const packet = packets[index];
      return packet === undefined ? OUT_OF_RANGE : { state: 'ready', packet };
    },
    request(): void { /* it is all here */ },
    // A scan, which is what the list did before the seam existed and costs the
    // same. Not a binary search on id: this array may be sorted by any column,
    // or filtered, so its ids are not necessarily ascending.
    indexOfId(id: number): number { return packets.findIndex((p) => p.id === id); },
  };
}

/** The packet at `index`, or null when the row is not ready. */
export function packetAt(source: RowSource, index: number): Packet | null {
  if (index < 0 || index >= source.count) return null;
  const row = source.rowAt(index);
  return row.state === 'ready' ? row.packet : null;
}

/**
 * The rows in `[from, to)`, for the slice the list renders.
 *
 * Clamped rather than trusting the caller, because the caller is
 * `virtualWindow` output against a count that can shrink underneath it - the
 * exact mismatch that module's header describes.
 */
export function rowSlice(source: RowSource, from: number, to: number): Row[] {
  const start = Math.max(0, from);
  const end = Math.min(source.count, to);
  const out: Row[] = [];
  for (let i = start; i < end; i++) out.push(source.rowAt(i));
  return out;
}
