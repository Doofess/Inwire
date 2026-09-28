/**
 * The binary packet frame, app side (`local-agent/packet_batch.py`).
 *
 * Until agent 3.2.0 every captured frame arrived as its own JSON text message
 * with the bytes base64-encoded inside it, and the client ran `JSON.parse` and
 * `atob` per frame on the main thread inside the socket handler - before
 * anything could be batched, at wire rate rather than at the flush cadence.
 * The agent's own log records what that cost: 260,000+ frames dropped in one
 * session because the client could not keep up.
 *
 * Now many frames arrive in one binary message and the metadata that was only
 * ever a fallback is not sent at all: whenever the bytes were present the app
 * re-dissected the frame itself and overwrote every field the agent had guessed
 * at (ADR 0010). Control messages stay JSON text - there are a handful a second
 * at most, and they are the ones a human ever reads off the wire.
 *
 * Layout, little-endian, read with a DataView so nothing needs to be aligned:
 *
 *     magic    4 bytes   'IWP1'
 *     version  u8        4
 *     flags    u8        reserved
 *     count    u16       records in this frame
 *
 *   then `count` records of:
 *
 *     seq        u32     per-capture sequence number (docs/decisions/0005)
 *     iface      u16     index into the interface list in hello/state
 *     capLen     u32     bytes actually present
 *     origLen    u32     length on the wire
 *     tsNs       u64     capture time, epoch nanoseconds
 *     bytes      capLen  the frame
 *
 * **Both lengths are 32 bits since version 4** (ADR 0052), and the record is
 * 22 bytes. The agent captures at dumpcap's 262,144-byte snaplen and writes the
 * same frames into its own pcapng, so the wire carries a frame longer than
 * 65,535 bytes - an offloaded send can be - where version 3 refused one.
 *
 * **`tsNs` was an f64 of microseconds until version 3**, which could not have
 * carried what the driver measures: epoch nanoseconds are past 2^53, and even
 * epoch microseconds are 0.25 us apart in a double. It is read here as two
 * u32 halves and split into whole microseconds and a nanosecond remainder -
 * exact for any stamp before the year 2255, and without a BigInt per frame on
 * the path every captured frame takes. Which of those nanoseconds were
 * measured is the adapter's `tsPrecision`, not this record's business.
 *
 * **The record was 18 bytes in versions 2 and 3, and 24 before.** Two reserved bytes on a layout that
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
export const BATCH_VERSION = 4;
export const BATCH_HEADER_BYTES = 8;
export const BATCH_RECORD_BYTES = 22;

export interface BinaryFrame {
  /** Per-capture sequence number; ties on `tsUs` resolve by it. */
  seq: number;
  /** Index into the interface list the agent sent in hello/state. */
  iface: number;
  /** Capture time, whole epoch microseconds. */
  tsUs: number;
  /** The nanoseconds past `tsUs`, 0 to 999. */
  tsNsRem: number;
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
 * The one thing `tsc` cannot say about this module's two entry points.
 *
 * Both declare an `ArrayBuffer`, and **TypeScript 5.8 finds a `Uint8Array`
 * structurally assignable to one** - `byteLength` and `slice` are the whole of
 * what `ArrayBuffer` declares and a typed array has both. So the annotation is
 * documentation, not a guard, and `new DataView(...)` is what actually refuses:
 * at runtime, with `First argument to DataView constructor must be an
 * ArrayBuffer`, naming neither the caller nor the fix.
 *
 * That is not hypothetical. `scripts/agent/agent-compare.ts` shipped passing
 * `frame.payload` straight in; `npm run lint` passed; the script threw on the
 * first batch it was ever handed, so it had never once reached its own
 * assertions.
 *
 * **Refusing a view rather than converting it is the point.** A typed array
 * arriving here is usually a window into a larger buffer - a `FrameReader`
 * payload, a slab of socket data - and converting one by reading `.buffer`
 * would decode from the wrong offset *in silence*, which is exactly what
 * `pipeline.worker.ts`'s `asArrayBuffer` exists to prevent. The caller knows
 * its own offsets and this does not, so this says so instead of guessing.
 *
 * `ArrayBuffer.isView` rather than `instanceof ArrayBuffer`: it reads an
 * internal slot and so is realm-independent. A real `ArrayBuffer` crosses two
 * structured-clone boundaries on the frame path, and an `instanceof` against
 * the wrong realm's prototype would reject a buffer that is perfectly good.
 */
function refuseAView(buffer: ArrayBuffer, caller: string): void {
  if (!ArrayBuffer.isView(buffer)) return;
  const view = buffer as unknown as ArrayBufferView;
  throw new BinaryFrameError(
    `${caller} takes an ArrayBuffer and was given ${view.constructor.name}, which is a view. `
    + 'Pass `b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)`: reading `.buffer` '
    + 'alone decodes from the wrong offset whenever the view is into a larger buffer.',
  );
}

/**
 * True when a message is one of these rather than JSON.
 *
 * Cheap enough to run on every message: a length check and one 32-bit read.
 * Anything that is not tagged is handed to the JSON parser, which is what a
 * 3.1 agent's per-packet messages still need.
 */
export function isPacketBatch(buffer: ArrayBuffer): boolean {
  refuseAView(buffer, 'isPacketBatch');
  if (buffer.byteLength < BATCH_HEADER_BYTES) return false;
  return new DataView(buffer).getUint32(0, true) === MAGIC_LE;
}

/**
 * Every frame in one batch.
 *
 * Throws rather than returning what it managed to read: a truncated batch
 * means the link delivered something this build does not understand, and
 * dissecting the prefix would put frames into the buffer with no way to tell
 * they are the survivors of a message that was wrong.
 */
export function decodePacketBatch(buffer: ArrayBuffer): BinaryFrame[] {
  refuseAView(buffer, 'decodePacketBatch');
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
    const capLen = view.getUint32(offset + 6, true);
    const origLen = view.getUint32(offset + 10, true);
    // hi * 2^32 + lo nanoseconds, divided by 1000 without leaving integers:
    // 2^32 is 4,294,967 thousands and 296 over, so the carry into the
    // remainder is `hi * 296 + lo`, which stays well under 2^53.
    const lo = view.getUint32(offset + 14, true);
    const hi = view.getUint32(offset + 18, true);
    const carry = hi * 296 + lo;
    const tsUs = hi * 4_294_967 + Math.floor(carry / 1000);
    const tsNsRem = carry % 1000;
    offset += BATCH_RECORD_BYTES;
    if (offset + capLen > buffer.byteLength) {
      throw new BinaryFrameError(`record ${i + 1} claims ${capLen} bytes, past the end of the batch`);
    }
    // A view, not a copy: this is the whole reason the bytes travel binary.
    frames[i] = { seq, iface, tsUs, tsNsRem, origLen, bytes: new Uint8Array(buffer, offset, capLen) };
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
