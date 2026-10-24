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

export interface StreamFrameSource {
  streamOrdinals(streamId: number, fromId: number, toId: number, startChunk: number):
    Promise<{ ordinals: number[]; nextChunk: number | null }>;
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

/** A kept stream's frames, marked most recently used; undefined when not kept. */
export function recallFrames(kept: Map<number, Packet[]>, streamId: number): Packet[] | undefined {
  const frames = kept.get(streamId);
  if (frames !== undefined) { kept.delete(streamId); kept.set(streamId, frames); }
  return frames;
}

/** Keeps a stream's frames, dropping the least recently used past `KEPT_STREAMS`. */
export function keepFrames(kept: Map<number, Packet[]>, streamId: number, frames: Packet[]): void {
  kept.delete(streamId);
  if (frames.length > KEPT_FRAMES_MAX) return;
  kept.set(streamId, frames);
  while (kept.size > KEPT_STREAMS) kept.delete(kept.keys().next().value as number);
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
 * it; the next page is appended to the same array.
 */
export async function loadStreamFrames(
  summary: StreamSummary, ram: readonly Packet[], source: StreamFrameSource,
  onProgress?: (loaded: number, soFar: readonly Packet[]) => void, signal?: { cancelled: boolean },
): Promise<Packet[]> {
  const frames: Packet[] = [];
  // From chunk 0: the store begins at the stream's first chunk itself (it
  // holds the index; this side has none), so the first page is not spent on
  // chunks before it.
  let chunk: number | null = 0;
  while (chunk !== null && !signal?.cancelled) {
    const page = await source.streamOrdinals(summary.streamId, summary.firstId, summary.lastId, chunk);
    for (let i = 0; i < page.ordinals.length && !signal?.cancelled; i += ROW_PAGE) {
      const ordinals = page.ordinals.slice(i, i + ROW_PAGE);
      const rows = await source.readRowsFor(ordinals);
      for (const ordinal of ordinals) {
        const row = rows.get(ordinal);
        if (row !== undefined) frames.push(row);
      }
      // A page that resolved after the cancel is not reported: the caller has
      // moved on, and what it is showing now is not this stream.
      if (!signal?.cancelled) onProgress?.(frames.length, frames);
    }
    chunk = page.nextChunk;
  }
  if (signal?.cancelled) return frames;
  const lastDisk = frames.length > 0 ? frames[frames.length - 1].id : 0;
  for (const p of ram) {
    if (p.id > lastDisk && p.streamId === summary.streamId && p.frameProtocols?.includes('tcp')) frames.push(p);
  }
  return frames;
}
