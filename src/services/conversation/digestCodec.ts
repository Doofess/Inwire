/**
 * `streams.iwdig`: the stream digest's snapshot (ADR 0055).
 *
 * A cache, never a source. Anything wrong with it - a torn write, a newer or
 * older format, a checksum that does not match - reads as `null`, and the
 * store folds the digest again from the capture's rows.
 *
 * Format 4 is a header, four numbers, and a run of independently deflated
 * chunks of at most `CHUNK_ENTRIES` entries each; each entry is tagged with its
 * kind (TCP stream, UDP flow, QUIC connection, TLS summary). Format 3 had no TLS
 * kind and reads as null, or a reopened capture would claim no TLS. Format 2 had no captureEnd and
 * untagged TCP entries, and reads as null like any other format. Format 1 was one JSON text
 * of every entry, which V8 refuses past about 512 MB ("Invalid string length"):
 * 300,000 closed streams, or 500,000 refused ones, made Stop's snapshot throw
 * (final review I3). No string, array or buffer here grows with the stream
 * count except the output itself, which is the compressed size.
 *
 *   header  u32 magic, u16 format, u16 0, u32 body length, u32 fnv1a(body)
 *   body    f64 throughId, f64 version, u32 entry count, f64 captureEnd,
 *           then per chunk: u32 compressed length, the deflated JSON array
 *
 * Each entry is its own JSON, so the encoding says nothing about the shape of
 * `machine`; it is whatever `TcpMachineState` is.
 */
import { fnv1a } from '../dissect/frameRecord';
import type { DigestSnapshot, DigestSnapshotData, TaggedEntry } from './streamDigest';

export const DIGEST_FORMAT = 4;
const MAGIC = 0x47445749;
const HEADER = 16;
const META = 28;
/** About 0.5 MB of JSON a chunk; the largest string this module ever holds. */
const CHUNK_ENTRIES = 512;
// Built once, as `chunkCodec.ts` builds its pair: a codec's cost is in its
// constructor (`scripts/perf/hot-path-allocations.ts`).
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function encodeDigest(data: DigestSnapshotData, deflate: (b: Uint8Array) => Uint8Array): Uint8Array {
  const chunks: Uint8Array[] = [];
  let compressed = 0;
  let count = 0;
  let batch: TaggedEntry[] = [];
  const flush = (): void => {
    if (batch.length === 0) return;
    const z = deflate(textEncoder.encode(JSON.stringify(batch)));
    chunks.push(z);
    compressed += 4 + z.length;
    batch = [];
  };
  for (const entry of data.entries) {
    batch.push(entry);
    count++;
    if (batch.length === CHUNK_ENTRIES) flush();
  }
  flush();

  const out = new Uint8Array(HEADER + META + compressed);
  const view = new DataView(out.buffer);
  view.setFloat64(HEADER, data.throughId, true);
  view.setFloat64(HEADER + 8, data.version, true);
  view.setUint32(HEADER + 16, count, true);
  view.setFloat64(HEADER + 20, data.captureEnd, true);
  let at = HEADER + META;
  for (const z of chunks) {
    view.setUint32(at, z.length, true);
    out.set(z, at + 4);
    at += 4 + z.length;
  }
  const body = out.subarray(HEADER);
  view.setUint32(0, MAGIC, true);
  view.setUint16(4, DIGEST_FORMAT, true);
  view.setUint32(8, body.length, true);
  view.setUint32(12, fnv1a(body), true);
  return out;
}

export function decodeDigest(bytes: Uint8Array, inflate: (b: Uint8Array) => Uint8Array): DigestSnapshot | null {
  if (bytes.length < HEADER + META) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== MAGIC || view.getUint16(4, true) !== DIGEST_FORMAT) return null;
  const length = view.getUint32(8, true);
  if (HEADER + length !== bytes.length) return null;
  if (fnv1a(bytes.subarray(HEADER)) !== view.getUint32(12, true)) return null;
  const throughId = view.getFloat64(HEADER, true);
  const version = view.getFloat64(HEADER + 8, true);
  const count = view.getUint32(HEADER + 16, true);
  const captureEnd = view.getFloat64(HEADER + 20, true);
  if (!Number.isFinite(throughId) || !Number.isFinite(version) || !Number.isFinite(captureEnd)) return null;
  try {
    const entries: TaggedEntry[] = [];
    let at = HEADER + META;
    while (at < bytes.length) {
      if (at + 4 > bytes.length) return null;
      const z = view.getUint32(at, true);
      at += 4;
      if (at + z > bytes.length) return null;
      const chunk: unknown = JSON.parse(textDecoder.decode(inflate(bytes.subarray(at, at + z))));
      if (!Array.isArray(chunk)) return null;
      for (const entry of chunk as TaggedEntry[]) entries.push(entry);
      at += z;
    }
    return entries.length === count ? { throughId, version, captureEnd, entries } : null;
  } catch {
    return null;
  }
}
