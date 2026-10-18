/**
 * A raw-deflate inflate that cannot be made to allocate more than it is told to
 * (the Worker's half of `rollupCodec`'s `Inflate`).
 *
 * The bytes are the sidecar's, and a deflate stream of a few kilobytes can name
 * gigabytes. node's zlib has `maxOutputLength`; the Worker has fflate, and
 * fflate has no such option, so this is what was measured instead of assumed:
 *
 * - **`inflateSync(data, { out })` does not throw when `out` is too small.** It
 *   fills `out` and returns a view of it, silently truncated, and the allocation
 *   is the one the caller made. Probed on fflate 0.8.3 with a 1,001 byte `out`:
 *   a stream inflating to 1,000 bytes returns 1,000; streams inflating to 1,001,
 *   1,002, 50,000 and 200,000,000 bytes all return 1,001.
 * - **The streaming `Inflate` bounds nothing.** It emits a whole stream's output
 *   as one chunk, so aborting "past `maxOutput`" happens after the allocation.
 *
 * So the bound is a buffer one byte longer than the limit and a length check on
 * what comes back: a result of `maxOutput + 1` is the only proof that the stream
 * wanted more, and it is refused. The most the stream can make this function
 * allocate is `maxOutput + 1` bytes, whatever it claims. A corrupt stream throws
 * on its own, from fflate.
 */
import { inflateSync } from 'fflate';

export function boundedInflate(bytes: Uint8Array, maxOutput: number): Uint8Array {
  if (!Number.isSafeInteger(maxOutput) || maxOutput < 0) throw new RangeError('maxOutput is a non-negative safe integer');
  const out = new Uint8Array(maxOutput + 1);
  const inflated = inflateSync(bytes, { out });
  if (inflated.length > maxOutput) throw new RangeError(`the stream inflates past the ${maxOutput} bytes it is allowed`);
  // A copy at the real length: the view shares the whole `out` buffer.
  return inflated.slice();
}
