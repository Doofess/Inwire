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
      onProgress?.(frames.length, frames);
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
