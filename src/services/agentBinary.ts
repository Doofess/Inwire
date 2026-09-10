/**
 * The binary packet frame, browser side (`local-agent/packet_batch.py`).
 *
 * Until agent 3.2.0 every captured frame arrived as its own JSON text message
 * with the bytes base64-encoded inside it, and the browser ran `JSON.parse`
 * and `atob` per frame on the main thread inside the socket handler - before
 * anything could be batched, at wire rate rather than at the flush cadence.
 * The agent's own log records what that cost: 260,000+ frames dropped in one
 * session because the client could not keep up.
 *
 * Now many frames arrive in one binary message and the metadata that was only
 * ever a fallback is not sent at all: whenever the bytes were present the
 * browser re-dissected the frame itself and overwrote every field the agent
 * had guessed at. Control messages stay JSON text - there are a handful a
 * second at most, and they are the ones a human ever reads off the wire.
 *
 * Layout, little-endian, read with a DataView so nothing needs to be aligned:
 *
 *     magic    4 bytes   'IWP1'
 *     version  u8        2
 *     flags    u8        reserved
 *     count    u16       records in this frame
 *
 *   then `count` records of:
 *
 *     seq        u32     per-capture sequence number (docs/decisions/0005)
 *     iface      u16     index into the interface list in hello/state
 *     capLen     u16     bytes actually present
 *     origExtra  u16     wire length MINUS capLen; 0 unless truncated
 *     tsUs       f64     capture time, epoch microseconds
 *     bytes      capLen  the frame
 *
 * **The record is 18 bytes and was 24.** Two reserved bytes on a layout that
 * needs no alignment; a u32 for a `capLen` that cannot exceed a snaplen; and a
 * second u32 repeating, on every untruncated frame there is, what `capLen`
 * already said. Measured on a real 300,228-frame capture that is 7.21 MB of
 * framing down to 5.40 MB - **0.53% of the stream**, since a frame averaged
 * 1,101 bytes and framing was never going to matter beside that; 6% of each
 * record on the 78,480 frames at or under 100 bytes, which is where it shows.
 * `seq` and `tsUs` could be batch-relative deltas for six bytes more and are
 * not: a record is encoded on the agent's SNIFFER thread and does not know
 * which batch it will land in, and a record whose meaning depended on its
 * batch could not be dropped or re-batched freely - which is what the agent's
 * queue does whenever a viewer falls behind.
 *
 * `local-agent/test_protocol.py` asserts the encoder's bytes and
 * `scripts/agent/binary.ts` asserts this decoder against the same fixed
 * vectors, so the two cannot drift apart while both still pass.
 */

/** 'IWP1', as the u32 a DataView reads at offset 0 in little-endian order. */
const MAGIC_LE = 0x31_50_57_49;
export const BATCH_VERSION = 2;
export const BATCH_HEADER_BYTES = 8;
export const BATCH_RECORD_BYTES = 18;

export interface BinaryFrame {
  /** Per-capture sequence number; ties on `tsUs` resolve by it. */
  seq: number;
  /** Index into the interface list the agent sent in hello/state. */
  iface: number;
  /** Capture time, epoch microseconds. */
  tsUs: number;
  /** Length on the wire, which a snaplen may have truncated. */
  origLen: number;
  /**
   * The frame itself, as a view over the received buffer - not a copy. The
   * dissector takes a view (`DissectInput.bytes`), so nothing is copied
   * between the socket and the parser. A caller that keeps a frame past the
   * batch must copy it; `retain` below is that copy.
   */
  bytes: Uint8Array;
}

export class BinaryFrameError extends Error {}

/**
 * True when a message is one of these rather than JSON.
 *
 * Cheap enough to run on every message: a length check and one 32-bit read.
 * Anything that is not tagged is handed to the JSON parser, which is what a
 * 3.1 agent's per-packet messages still need.
 */
export function isPacketBatch(buffer: ArrayBuffer): boolean {
  if (buffer.byteLength < BATCH_HEADER_BYTES) return false;
  return new DataView(buffer).getUint32(0, true) === MAGIC_LE;
}

/**
 * Every frame in one batch.
 *
 * Throws rather than returning what it managed to read: a truncated batch
 * means the socket delivered something this build does not understand, and
 * dissecting the prefix would put frames into the buffer with no way to tell
 * they are the survivors of a message that was wrong.
 */
export function decodePacketBatch(buffer: ArrayBuffer): BinaryFrame[] {
  if (buffer.byteLength < BATCH_HEADER_BYTES) {
    throw new BinaryFrameError(`packet batch is ${buffer.byteLength} bytes, shorter than its header`);
  }
  const view = new DataView(buffer);
  if (view.getUint32(0, true) !== MAGIC_LE) {
    throw new BinaryFrameError('not a packet batch');
  }
  const version = view.getUint8(4);
  if (version !== BATCH_VERSION) {
    throw new BinaryFrameError(`packet batch version ${version} is not one this build reads`);
  }
  const count = view.getUint16(6, true);
  const frames: BinaryFrame[] = new Array(count);

  let offset = BATCH_HEADER_BYTES;
  for (let i = 0; i < count; i++) {
    if (offset + BATCH_RECORD_BYTES > buffer.byteLength) {
      throw new BinaryFrameError(`packet batch ends inside record ${i + 1} of ${count}`);
    }
    const seq = view.getUint32(offset, true);
    const iface = view.getUint16(offset + 4, true);
    const capLen = view.getUint16(offset + 6, true);
    // The wire length as its excess over what was captured, so the common case
    // - nothing truncated - is two zero bytes rather than a second copy of the
    // number two fields up.
    const origLen = capLen + view.getUint16(offset + 8, true);
    const tsUs = view.getFloat64(offset + 10, true);
    offset += BATCH_RECORD_BYTES;
    if (offset + capLen > buffer.byteLength) {
      throw new BinaryFrameError(`record ${i + 1} claims ${capLen} bytes, past the end of the batch`);
    }
    // A view, not a copy: this is the whole reason the bytes travel binary.
    frames[i] = { seq, iface, tsUs, origLen, bytes: new Uint8Array(buffer, offset, capLen) };
    offset += capLen;
  }
  if (offset !== buffer.byteLength) {
    throw new BinaryFrameError(`packet batch has ${buffer.byteLength - offset} bytes after its last record`);
  }
  return frames;
}

/**
 * A frame's bytes, detached from the batch buffer.
 *
 * A `BinaryFrame.bytes` is a view, so holding one holds the whole batch -
 * up to a quarter-megabyte for a single 60-byte ARP frame. Anything that
 * outlives the batch (the frame store, the ordering window) copies first.
 */
export function retain(frame: BinaryFrame): Uint8Array {
  return frame.bytes.slice();
}
