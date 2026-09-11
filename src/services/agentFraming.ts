/**
 * Message framing for the pipe to the capture agent.
 *
 * ## What this replaces, and why
 *
 * The agent was a WebSocket server on `ws://localhost:8999`, and a loopback
 * TCP port is reachable by every process on the machine. That single fact is
 * why the pairing token exists, why the origin allowlist exists, and why the
 * user had to paste a 64-character string into Settings once - `Origin` is a
 * header the client writes, so it "keeps an ordinary web page out and stops
 * nothing that can set a header".
 *
 * A named pipe with an ACL asks the operating system the question instead, and
 * the kernel's answer needs no secret. The token, the allowlist and the
 * pairing panel are deleted rather than ported.
 *
 * What the WebSocket also gave for free was **framing** - message boundaries
 * and a text/binary distinction - and a pipe is a byte stream with neither. So
 * this file, and its exact counterpart `local-agent/pipe_frame.py`.
 *
 * ## The layout
 *
 * ```
 *   length  u32   bytes that follow, this field excluded
 *   kind    u8    0 = JSON control message, 1 = binary packet batch
 *   payload …     `length - 1` bytes
 * ```
 *
 * Little-endian, matching `packet_batch.py`. The kind byte is one byte rather
 * than a separate channel because the alternative - inferring JSON from a
 * leading `{` - would make a malformed batch that happens to start with 0x7b
 * into a parse error rather than a framing error.
 *
 * **Nothing above this changes.** The 18-byte record in `agentBinary.ts` and
 * `packet_batch.py`, every control message in `agentProtocol.ts`, and the
 * fixed byte vectors both ends assert are all transport-agnostic and are
 * untouched by the move. This is the only new thing on the wire.
 *
 * ## A declared length is not a length to trust
 *
 * `MAX_FRAME_BYTES` is checked **before** anything is allocated. The agent is
 * a privileged service and the app is not the only thing that could ever write
 * to a pipe handle; a four-byte header claiming 4 GB must be a refusal, not an
 * out-of-memory.
 */

export const FRAME_HEADER_BYTES = 5;

/** JSON control message, UTF-8. */
export const FRAME_JSON = 0;
/** A binary packet batch - `agentBinary.ts` decodes the payload. */
export const FRAME_BINARY = 1;

/**
 * The largest single message either end will accept.
 *
 * A batch is bounded by `MAX_BATCH_BYTES` (256 kB) and a control message by
 * the adapter snapshot, which is measured at ~6 kB. Eight megabytes is far
 * above both and far below anything that could hurt.
 */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;

export interface AgentFrame {
  kind: typeof FRAME_JSON | typeof FRAME_BINARY;
  payload: Uint8Array;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Wraps a control message. */
export function encodeJsonFrame(value: unknown): Uint8Array {
  return encodeFrame(FRAME_JSON, encoder.encode(JSON.stringify(value)));
}

export function encodeFrame(kind: number, payload: Uint8Array): Uint8Array {
  // Refused on the way out as well as on the way in, so the two ends behave
  // identically - `pipe_frame.py` raises here too. An asymmetry in a format
  // with two implementations is how they start disagreeing.
  if (kind !== FRAME_JSON && kind !== FRAME_BINARY) {
    throw new Error(`agent framing: unknown frame kind ${kind}`);
  }
  if (payload.length + 1 > MAX_FRAME_BYTES) {
    throw new Error(`agent framing: a ${payload.length}-byte payload is past the ceiling`);
  }
  const out = new Uint8Array(FRAME_HEADER_BYTES + payload.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, payload.length + 1, true);
  out[4] = kind;
  out.set(payload, FRAME_HEADER_BYTES);
  return out;
}

/** The text of a JSON frame. */
export function frameText(frame: AgentFrame): string {
  return decoder.decode(frame.payload);
}

/**
 * Reassembles frames from a byte stream that arrives in arbitrary pieces.
 *
 * A pipe read boundary has nothing to do with a message boundary: one read can
 * carry half a header, and another can carry nine whole batches. Both happen
 * under load, and a decoder that assumed one read was one message would work
 * perfectly until the machine got busy.
 */
export class FrameReader {
  private buffer = new Uint8Array(0);

  /** Feeds bytes in and returns whatever whole frames they completed. */
  push(chunk: Uint8Array): AgentFrame[] {
    this.buffer = concat(this.buffer, chunk);
    const frames: AgentFrame[] = [];

    for (;;) {
      if (this.buffer.length < FRAME_HEADER_BYTES) break;
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
      const declared = view.getUint32(0, true);
      // Checked before the payload is waited for, let alone copied.
      if (declared < 1 || declared > MAX_FRAME_BYTES) {
        throw new Error(`agent framing: a frame declared ${declared} bytes`);
      }
      const total = 4 + declared;
      if (this.buffer.length < total) break;

      const kind = this.buffer[4];
      if (kind !== FRAME_JSON && kind !== FRAME_BINARY) {
        throw new Error(`agent framing: unknown frame kind ${kind}`);
      }
      // `slice`, not `subarray`: these outlive the buffer they came from, and
      // a view would pin the whole accumulated chunk behind every frame.
      frames.push({ kind, payload: this.buffer.slice(FRAME_HEADER_BYTES, total) });
      this.buffer = this.buffer.subarray(total);
    }

    // Copy the remainder out of the accumulated chunk, so the bytes already
    // handed over can be collected rather than held by a trailing view.
    if (this.buffer.length > 0 && this.buffer.byteOffset > 0) {
      this.buffer = this.buffer.slice();
    }
    return frames;
  }

  /** Bytes held waiting for the rest of their frame. For assertions. */
  get pending(): number { return this.buffer.length; }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
