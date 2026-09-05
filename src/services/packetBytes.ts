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
 * stop holding them at all. **They are already on disk.** `toStoredFrame` writes
 * `raw` for every frame and the store is keyed by frame id, so a frame whose
 * bytes have been dropped from memory can have them back for the price of a
 * read.
 *
 * This module is the seam that makes that possible. Every main-thread consumer
 * of `Packet.rawBytes` goes through here instead, so the day the buffer starts
 * dropping bytes, none of them has to change again.
 *
 * **It is deliberately correct before the buffer drops anything.** Today every
 * packet still carries its bytes, so every call takes the synchronous path and
 * the disk is never touched. Introducing the seam and introducing the eviction
 * in one step would mean debugging both at once.
 */
import { readFrameBytes, storedIdRange } from './sessionStore';
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
  const range = storedIdRange();
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
  const found = await readFrameBytes([packet.id]);
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
  for (const [id, bytes] of await readFrameBytes(missing)) out.set(id, bytes);
  return out;
}
