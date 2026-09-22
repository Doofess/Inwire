/**
 * What a message body actually says, once Content-Encoding is undone.
 *
 * Kept apart from `http1.ts` on purpose: that file's job is framing - where
 * this message ends and the next begins - and framing is what a request
 * smuggling bug lives in. Decoding is a separate question asked of bytes that
 * have already been delimited, and mixing the two would put a decompressor on
 * the path that decides message boundaries.
 *
 * ## What is decoded, and what is only named
 *
 * `gzip` and `deflate` are undone with `fflate`, which this repository already
 * ships for the capture format. **`br` and `zstd` are named and not decoded**,
 * and that is a decision rather than a gap:
 *
 * - The platform answer is `DecompressionStream`, which has no brotli at all
 *   and is asynchronous where dissection is synchronous from end to end. An
 *   async decompressor cannot be called from here without making the whole
 *   dissection path async, which is a change to every caller.
 * - A brotli or zstd implementation is ~200 KB of synchronous JS or wasm for
 *   a minority of bodies, against **the dependency rule** in `CLAUDE.md`: a
 *   shipped dependency has to beat the platform API it replaces, and this one
 *   would be carried by every user to read a body some of them never see.
 *
 * There is a way out that does not need either, written down so the next
 * reader does not have to find it again: decoding could move into the tree
 * REPLAY (`services/pipeline/replay.ts`), which runs on demand for one frame
 * and is allowed to be slow and to be async. That is where brotli belongs if
 * it is ever wanted.
 *
 * ## The expert note is graded, and the grading is load-bearing
 *
 * "An encoding this build does not implement" is `Unverifiable` - nothing is
 * known to be wrong, the tool simply did not look. "We tried and it threw" is
 * `Broken`. Getting that backwards would paint every frame of a brotli-served
 * CDN download as damaged, and `scripts/expert/categories.ts` holds a rule
 * that no category may paint more than half the list.
 */
import { gunzipSync, inflateSync, unzlibSync } from 'fflate';

export interface DecodedBody {
  /** The bytes to read, decompressed when that was possible. */
  bytes: Uint8Array;
  /** The Content-Encoding as the sender spelled it, lower-cased. */
  encoding: string;
  /** True when `bytes` differs from what was on the wire. */
  decompressed: boolean;
  /**
   * Set when the encoding is one this build does not implement. The bytes are
   * the compressed ones, and the caller says so rather than pretending.
   */
  unsupported?: string;
  /** Set when decompression was attempted and failed, with the reason. */
  error?: string;
}

/** Encodings that mean "as-is", including the empty header. */
const IDENTITY = new Set(['', 'identity', 'none']);

/**
 * Undoes Content-Encoding.
 *
 * **Every call into `fflate` is wrapped**, because a body truncated by a
 * capture that started mid-transfer is not an exceptional case here - it is
 * the ordinary one on any capture of a download already in progress, and an
 * exception escaping this function would take the frame's whole tree with it.
 * A failure becomes a row, which is the only form a reader can act on.
 */
export function decodeHttpBody(raw: Uint8Array, contentEncoding: string | undefined): DecodedBody {
  // A comma-separated list is legal and is applied left to right, so the LAST
  // one is the outermost and the only one that can be undone first. Anything
  // more than one layer is rare enough that naming it beats half-undoing it.
  const header = (contentEncoding ?? '').toLowerCase().trim();
  const layers = header.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  const encoding = layers.length === 0 ? '' : layers[layers.length - 1];

  if (IDENTITY.has(encoding)) return { bytes: raw, encoding: encoding || 'identity', decompressed: false };
  if (layers.length > 1) {
    return { bytes: raw, encoding: header, decompressed: false, unsupported: `${layers.length} stacked encodings` };
  }

  if (encoding === 'gzip' || encoding === 'x-gzip') {
    try {
      return { bytes: gunzipSync(raw), encoding, decompressed: true };
    } catch (cause) {
      return { bytes: raw, encoding, decompressed: false, error: reasonOf(cause) };
    }
  }

  if (encoding === 'deflate') {
    // **Two formats wear this name.** RFC 9110 says `deflate` is zlib-wrapped;
    // a long tail of servers send raw deflate with no zlib header. Trying zlib
    // first and falling back is what the reference does, and it is the only
    // way to read both - the two are told apart by whether the zlib header
    // parses, not by anything the sender said.
    try {
      return { bytes: unzlibSync(raw), encoding, decompressed: true };
    } catch {
      try {
        return { bytes: inflateSync(raw), encoding: `${encoding} (raw)`, decompressed: true };
      } catch (cause) {
        return { bytes: raw, encoding, decompressed: false, error: reasonOf(cause) };
      }
    }
  }

  return { bytes: raw, encoding, decompressed: false, unsupported: encoding };
}

function reasonOf(cause: unknown): string {
  const text = cause instanceof Error ? cause.message : String(cause);
  // fflate's messages are terse codes like "invalid block type"; they are more
  // use than "Error" and short enough to put in a row.
  return text.length > 120 ? `${text.slice(0, 117)}...` : text;
}
