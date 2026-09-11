/**
 * A frame's bytes, wherever they currently are.
 *
 * At a 50,000-frame cap the buffer can afford to hold every frame's bytes, and
 * does. At a million it cannot: raw frames are 1,176 B each, so a full buffer is
 * 1.17 GB of them on top of 2.3 GB of summaries
 * (`docs/decisions/0013-what-a-million-frames-actually-cost.md`).
 *
 * The way out is not to move them somewhere else - a dedicated Worker shares the
 * page's process, so that relocates the cost rather than removing it - but to
 * stop holding them at all. **They are already on disk.** The capture store
 * writes every frame's bytes as they arrive and indexes them by frame id, so a
 * frame whose bytes have been dropped from memory can have them back for the
 * price of a read.
 *
 * This module is the seam that makes that possible. Every main-thread consumer
 * of `Packet.rawBytes` goes through here instead, so the day the buffer starts
 * dropping bytes, none of them has to change again.
 *
 * **It is deliberately correct before the buffer drops anything.** Today every
 * packet still carries its bytes, so every call takes the synchronous path and
 * the disk is never touched. Introducing the seam and introducing the eviction
 * in one step would mean debugging both at once.
 *
 * ## The disk under it moved, and this module did not
 *
 * It reads from the **capture store** now (OPFS) rather than from IndexedDB,
 * and the seam is why that was three lines. The reason it had to move is not
 * that OPFS is faster: `sessionStore`'s 512 MB budget **evicts the oldest
 * frames**, and `evictOldBytes` may only drop the bytes of a frame the store
 * can supply again - so every frame the budget had evicted kept its bytes in
 * RAM for the rest of the capture, squeezed between a floor that rose faster
 * than the window's and a window that could not pass it. The capture store
 * evicts nothing, so its range only grows and eviction can always proceed.
 */
import { captureStore } from './capture/captureClient';
import type { Packet } from '../types/packet';

/** Bytes a frame no longer has and the store cannot supply. */
export const NO_BYTES = new Uint8Array(0);

/** True when this packet is still carrying its own bytes. */
export function hasBytes(packet: Packet): boolean {
  return packet.rawBytes.byteLength > 0;
}

/**
 * Whether a frame's bytes could be read back if they were dropped.
 *
 * False for frames the store never had or no longer has - trimmed away, or
 * evicted by the storage budget. A caller showing "no bytes" can use this to
 * say *why*, which is the difference between "this frame carried none" and
 * "this capture outgrew its storage limit".
 */
export function bytesAreRecoverable(id: number): boolean {
  const range = captureStore.storedRange;
  return range !== null && id >= range.first && id <= range.last;
}

/**
 * One frame's bytes.
 *
 * Synchronous when the packet still has them, which today is always. Falls back
 * to a read, and to an empty array when the store cannot supply them either -
 * never a throw, because a frame whose bytes are gone is a thing to render, not
 * an error to handle.
 */
export async function packetBytes(packet: Packet): Promise<Uint8Array> {
  if (hasBytes(packet)) return packet.rawBytes;
  const found = await captureStore.readBytes([packet.id]);
  return found.get(packet.id) ?? NO_BYTES;
}

/**
 * Bytes for many frames at once, keyed by frame id.
 *
 * For the consumers that want a whole stream or a whole capture - Follow
 * Stream, export, the replay bundle. One read for the lot rather than one per
 * frame, and packets that still carry their own bytes never reach the store at
 * all, so a capture small enough to hold in memory does no IO.
 */
export async function packetsBytes(packets: readonly Packet[]): Promise<Map<number, Uint8Array>> {
  const out = new Map<number, Uint8Array>();
  const missing: number[] = [];
  for (const packet of packets) {
    if (hasBytes(packet)) out.set(packet.id, packet.rawBytes);
    else missing.push(packet.id);
  }
  if (missing.length === 0) return out;
  for (const [id, bytes] of await captureStore.readBytes(missing)) out.set(id, bytes);
  return out;
}

/**
 * Drops the bytes of frames old enough to be read back instead of held.
 *
 * **Mutates the packets rather than replacing them**, which is deliberate and is
 * the only version that works. Replacing `packets[i]` with a byte-less copy
 * frees nothing while anything else still points at the original - and the
 * display filter's cache holds exactly that, a second array of references to
 * the same frames. Mutating in place means every holder drops them at once.
 *
 * It is safe because it changes nothing anyone renders from: `Packet.rawBytes`
 * feeds the hex dump and the byte-range highlighter, both of which live in the
 * detail pane, and the detail pane reads the packet `usePacketDetail` hands it -
 * which fetches the bytes back. Identity is untouched, so React re-renders
 * nothing and no memo is invalidated.
 *
 * Three rules, and the first two are what keep it from destroying anything:
 *
 *  - **Only frames the store can supply again.** The stored range is the ids
 *    actually on disk; a frame outside it - one from a restored session, an
 *    import, or a chunk still waiting behind the patch horizon - would lose
 *    its bytes outright.
 *  - **Only frames outside the resident window**, so the recent frames anyone
 *    is likely to click still answer without a read.
 *  - **Oldest first, stopping at the first frame already done**, so a flush
 *    costs the frames it newly evicts rather than a pass over the buffer.
 *
 * Returns the bytes freed, for a caller that wants to say so.
 */
export function evictOldBytes(
  packets: readonly Packet[],
  residentFrames: number,
  storedRange: { first: number; last: number } | null,
): number {
  if (storedRange === null) return 0;
  const limit = packets.length - residentFrames;
  if (limit <= 0) return 0;

  let freed = 0;
  for (let i = limit - 1; i >= 0; i--) {
    const packet = packets[i];
    // Everything older than this has been through here already: eviction only
    // ever moves forward, so the first frame without bytes ends the walk.
    if (!hasBytes(packet)) break;
    if (packet.id < storedRange.first || packet.id > storedRange.last) continue;
    freed += packet.rawBytes.byteLength;
    (packet as { rawBytes: Uint8Array }).rawBytes = NO_BYTES;
  }
  return freed;
}
