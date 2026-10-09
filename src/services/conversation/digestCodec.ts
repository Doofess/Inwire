/**
 * `streams.iwdig`: the stream digest's snapshot (ADR 0055).
 *
 * A cache, never a source. Anything wrong with it - a torn write, a newer
 * format, a checksum that does not match - reads as `null`, and the store
 * folds the digest again from the capture's rows.
 */
import { fnv1a } from '../dissect/frameRecord';
import type { DigestSnapshotData } from './streamDigest';

export const DIGEST_FORMAT = 1;
const MAGIC = 0x47445749;
const HEADER = 16;
// Built once, as `chunkCodec.ts` builds its pair: a codec's cost is in its
// constructor (`scripts/perf/hot-path-allocations.ts`).
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function encodeDigest(data: DigestSnapshotData, deflate: (b: Uint8Array) => Uint8Array): Uint8Array {
  const body = deflate(textEncoder.encode(JSON.stringify(data)));
  const out = new Uint8Array(HEADER + body.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, MAGIC, true);
  view.setUint16(4, DIGEST_FORMAT, true);
  view.setUint32(8, body.length, true);
  view.setUint32(12, fnv1a(body), true);
  out.set(body, HEADER);
  return out;
}

export function decodeDigest(bytes: Uint8Array, inflate: (b: Uint8Array) => Uint8Array): DigestSnapshotData | null {
  if (bytes.length < HEADER) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== MAGIC || view.getUint16(4, true) !== DIGEST_FORMAT) return null;
  const length = view.getUint32(8, true);
  if (HEADER + length !== bytes.length) return null;
  const body = bytes.subarray(HEADER);
  if (fnv1a(body) !== view.getUint32(12, true)) return null;
  try {
    const data = JSON.parse(textDecoder.decode(inflate(body))) as DigestSnapshotData;
    return typeof data.throughId === 'number' && Array.isArray(data.entries) ? data : null;
  } catch {
    return null;
  }
}
