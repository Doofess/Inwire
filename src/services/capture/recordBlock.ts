/**
 * One chunk's frame records, as the fifth capture file stores them.
 *
 * A frame record (`dissect/frameRecord.ts`, ADR 0049) is what its first
 * dissection learned from the frames before it, kept so its tree can be built
 * again from that frame alone. They are written a chunk at a time beside the
 * chunk's other blocks, in the chunk's frame order: a varint count, a varint
 * length per frame, then the records back to back. A length of 0 is a frame
 * with no record - one sealed before its record arrived, or dissected by a
 * build that did not make them - and reads back as `null`.
 *
 * Not compressed here, for the reason `chunkCodec.ts` gives: the writer
 * deflates it, which keeps this pure and synchronous. Records compress well -
 * 4,096 frames asking the trackers the same few questions - to 33-64 B a frame
 * on the real fixtures (`scripts/pipeline/revisit.ts`).
 */

function varintLength(n: number): number {
  let length = 1;
  while (n >= 0x80) { n = Math.floor(n / 0x80); length += 1; }
  return length;
}

function writeVarint(into: Uint8Array, at: number, n: number): number {
  while (n >= 0x80) {
    into[at++] = (n % 0x80) | 0x80;
    n = Math.floor(n / 0x80);
  }
  into[at++] = n;
  return at;
}

export function encodeRecordBlock(records: readonly (Uint8Array | null)[]): Uint8Array {
  let size = varintLength(records.length);
  for (const r of records) {
    const length = r?.length ?? 0;
    size += varintLength(length) + length;
  }
  const out = new Uint8Array(size);
  let at = writeVarint(out, 0, records.length);
  for (const r of records) at = writeVarint(out, at, r?.length ?? 0);
  for (const r of records) {
    if (r !== null && r.length > 0) {
      out.set(r, at);
      at += r.length;
    }
  }
  return out;
}

export function decodeRecordBlock(block: Uint8Array): (Uint8Array | null)[] {
  let at = 0;
  const varint = (): number => {
    let n = 0;
    let scale = 1;
    for (;;) {
      if (at >= block.length) throw new RangeError('recordBlock: truncated');
      const b = block[at++];
      n += (b & 0x7f) * scale;
      if (b < 0x80) return n;
      scale *= 0x80;
    }
  };
  const count = varint();
  const lengths: number[] = new Array(count);
  for (let i = 0; i < count; i++) lengths[i] = varint();
  const out: (Uint8Array | null)[] = new Array(count);
  for (let i = 0; i < count; i++) {
    const length = lengths[i];
    if (length === 0) {
      out[i] = null;
      continue;
    }
    if (at + length > block.length) throw new RangeError('recordBlock: record past the end');
    out[i] = block.slice(at, at + length);
    at += length;
  }
  if (at !== block.length) throw new RangeError('recordBlock: trailing bytes');
  return out;
}
