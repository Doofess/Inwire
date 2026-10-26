/**
 * A stream's frames from the whole capture (ADR 0055): what is sealed on disk,
 * found through the prefix's stream id, then what is still only in RAM. Paged,
 * with progress, because one stream can be most of a capture.
 *
 * The RAM window overlaps the end of the disk - the Worker's buffer holds
 * frames the store has sealed too - so a RAM frame is added only when its id
 * is past the last one read back. Reading the ids rather than diffing the two
 * sets is what keeps this one pass: both halves arrive in id order.
 *
 * `signal.cancelled` is read between pages, not inside one, so a cancelled
 * load returns on the next boundary with whatever it had from disk - and
 * nothing from RAM, because RAM frames appended behind an unfinished disk read
 * would leave a hole between the two that reads as frames the capture lost.
 * The caller that cancels is a view going away or changing stream, and it
 * discards the result; what it gets back is still contiguous.
 */
import type { Packet } from '../../types/packet';
import type { StreamSummary } from './streamDigest';
import { inFlow, type QuicSummary, type UdpSummary } from './flowSummary';

export interface StreamFrameSource {
  streamOrdinals(streamId: number, fromId: number, toId: number, startChunk: number):
    Promise<{ ordinals: number[]; nextChunk: number | null }>;
  /** A UDP flow's or QUIC connection's positions, a bounded page of chunks, from the rows. */
  flowOrdinals(kind: 'udp' | 'quic' | 'dhcp', key: number, fromId: number, toId: number, startChunk: number):
    Promise<{ ordinals: number[]; nextChunk: number | null; searched: number }>;
  readRowsFor(ordinals: readonly number[]): Promise<Map<number, Packet>>;
}

/** Ordinals per `readRowsFor`, so a page of rows crosses the port at a time. */
const ROW_PAGE = 256;

/** Streams whose frames the pane keeps, most recently used last. */
export const KEPT_STREAMS = 2;

/**
 * Frames one kept stream may hold. A stream past it is read again when it is
 * opened again rather than held: a million-frame stream is hundreds of
 * megabytes of rows in the renderer, kept for a convenience a page-by-page
 * read already makes cheap.
 */
export const KEPT_FRAMES_MAX = 500_000;

/**
 * A kept stream's frames, marked most recently used; undefined when not kept.
 * The key is whatever names a stream uniquely: a TCP stream id and a UDP key
 * are both small integers, so a caller holding both kinds keys by kind too.
 */
export function recallFrames<K>(kept: Map<K, Packet[]>, key: K): Packet[] | undefined {
  const frames = kept.get(key);
  if (frames !== undefined) { kept.delete(key); kept.set(key, frames); }
  return frames;
}

/** Keeps a stream's frames, dropping the least recently used past `KEPT_STREAMS`. */
export function keepFrames<K>(kept: Map<K, Packet[]>, key: K, frames: Packet[]): void {
  kept.delete(key);
  if (frames.length > KEPT_FRAMES_MAX) return;
  kept.set(key, frames);
  while (kept.size > KEPT_STREAMS) kept.delete(kept.keys().next().value as K);
}

/**
 * Whether a page of progress should reach the views.
 *
 * Never after a cancel: a page of the stream being left can resolve after the
 * next stream is on screen, and publishing it would put the old frames under
 * the new stream's summary - a ladder marking frames "removed by the ring"
 * that were never in this stream. And no more often than `intervalMs`: a
 * stream of a hundred thousand frames is four hundred pages, and each one
 * published is a copy of the frames so far and a fold of them.
 *
 * The first page passes whenever it comes; the clock is the caller's.
 */
export function progressGate(signal: { cancelled: boolean }, intervalMs: number): (now: number) => boolean {
  let last = -Infinity;
  return (now) => {
    if (signal.cancelled || now - last < intervalMs) return false;
    last = now;
    return true;
  };
}

/**
 * Frames in id order: disk rows first, then the RAM rows of the stream whose
 * ids are past the last disk id.
 *
 * A row the store could not answer (an ordinal in a hole, or one the ring
 * deleted between the two requests) is skipped rather than invented.
 *
 * `onProgress` is handed the count and the array being filled, by reference,
 * after each page of rows - so a view can draw the stream from its first page
 * rather than after its last. A caller that keeps what it was handed copies
 * it; the next page is appended to the same array. A UDP flow or QUIC
 * connection also reports after a page that found no frames, and adds how far
 * the store's search has got (0..1) as a third argument: a sparse flow can sit
 * on the same count for many pages.
 */
export async function loadStreamFrames(
  summary: StreamSummary | UdpSummary | QuicSummary, ram: readonly Packet[], source: StreamFrameSource,
  onProgress?: (loaded: number, soFar: readonly Packet[], searched?: number) => void, signal?: { cancelled: boolean },
): Promise<Packet[]> {
  // A TCP summary has no `kind`; a UDP or QUIC one names it and its key.
  const flow = 'kind' in summary ? summary : null;
  const frames: Packet[] = [];
  // From chunk 0: the store begins at the stream's first chunk itself (it
  // holds the index; this side has none), so the first page is not spent on
  // chunks before it.
  let chunk: number | null = 0;
  while (chunk !== null && !signal?.cancelled) {
    const page: { ordinals: number[]; nextChunk: number | null; searched?: number } = flow === null
      ? await source.streamOrdinals((summary as StreamSummary).streamId, summary.firstId, summary.lastId, chunk)
      : await source.flowOrdinals(flow.kind, flow.key, summary.firstId, summary.lastId, chunk);
    // A sparse flow finds nothing for many pages, so progress by frames alone
    // would sit still: a flow reports after EVERY page, with how far it has searched.
    if (flow !== null && page.ordinals.length === 0 && !signal?.cancelled) onProgress?.(frames.length, frames, page.searched);
    for (let i = 0; i < page.ordinals.length && !signal?.cancelled; i += ROW_PAGE) {
      const ordinals = page.ordinals.slice(i, i + ROW_PAGE);
      const rows = await source.readRowsFor(ordinals);
      for (const ordinal of ordinals) {
        const row = rows.get(ordinal);
        if (row !== undefined) frames.push(row);
      }
      // A page that resolved after the cancel is not reported: the caller has
      // moved on, and what it is showing now is not this stream.
      if (!signal?.cancelled) onProgress?.(frames.length, frames, page.searched); // undefined for TCP
    }
    chunk = page.nextChunk;
  }
  if (signal?.cancelled) return frames;
  const lastDisk = frames.length > 0 ? frames[frames.length - 1].id : 0;
  for (const p of ram) {
    if (p.id <= lastDisk) continue;
    if (flow === null) {
      if (p.streamId === (summary as StreamSummary).streamId && p.frameProtocols?.includes('tcp')) frames.push(p);
    } else {
      // The digest's own membership test (`inFlow`, also the store's), so a RAM
      // frame is a flow's exactly when the store would have said so.
      if (inFlow(p, flow.kind, flow.key)) frames.push(p);
    }
  }
  return frames;
}
