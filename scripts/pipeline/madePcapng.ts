/**
 * pcapng files made here, in the agent's layout, for the catch-up scripts
 * (`catch-up.ts`, `read-parse.ts`). A helper module: it has no `process.exit`,
 * so `scripts/check.ts` does not run it.
 */
import type { SeqFrame } from '../../src/services/pipeline/catchUp';

/** A section header: little endian, version 1.0, no options. */
export function shbBlock(): Uint8Array {
  const out = new Uint8Array(28);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0x0a0d0d0a, true); v.setUint32(4, 28, true); v.setUint32(8, 0x1a2b3c4d, true);
  v.setUint16(12, 1, true); v.setUint16(14, 0, true);
  v.setBigInt64(16, -1n, true); v.setUint32(24, 28, true);
  return out;
}

/** An interface description block: a name and nanosecond stamps (if_tsresol 9). */
export function idbBlock(nameText: string): Uint8Array {
  const name = new TextEncoder().encode(nameText);
  const namePad = (4 - (name.length % 4)) % 4;
  const idbOptions = 4 + name.length + namePad + 4 + 4 + 4;
  const idbLength = 16 + idbOptions + 4;
  const out = new Uint8Array(idbLength);
  const v = new DataView(out.buffer);
  v.setUint32(0, 1, true); v.setUint32(4, idbLength, true);
  v.setUint16(8, 1, true); v.setUint32(12, 0, true);
  let o = 16;
  v.setUint16(o, 2, true); v.setUint16(o + 2, name.length, true); out.set(name, o + 4); o += 4 + name.length + namePad;
  v.setUint16(o, 9, true); v.setUint16(o + 2, 1, true); v.setUint8(o + 4, 9); o += 8;
  v.setUint16(o, 0, true); v.setUint16(o + 2, 0, true); o += 4;
  v.setUint32(o, idbLength, true);
  return out;
}

/** The agent's layout: SHB, one IDB with a name and nanosecond stamps. */
export function fileHeader(): Uint8Array {
  return concat([shbBlock(), idbBlock('\\Device\\NPF_{TEST}')]);
}

export function epb(frame: SeqFrame): Uint8Array {
  const pad = (4 - (frame.bytes.length % 4)) % 4;
  const length = 32 + frame.bytes.length + pad;
  const out = new Uint8Array(length);
  const v = new DataView(out.buffer);
  const ns = BigInt(frame.tsUs) * 1000n + BigInt(frame.tsNsRem);
  v.setUint32(0, 6, true); v.setUint32(4, length, true);
  v.setUint32(8, 0, true);
  v.setUint32(12, Number(ns >> 32n), true); v.setUint32(16, Number(ns & 0xffffffffn), true);
  v.setUint32(20, frame.bytes.length, true); v.setUint32(24, frame.origLen, true);
  out.set(frame.bytes, 28);
  v.setUint32(length - 4, length, true);
  return out;
}

/** A Custom Block: no frame, skipped by every reader, and 32 bytes no frame's size includes. */
export function customBlock(): Uint8Array {
  const out = new Uint8Array(32);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0x00000bad, true); v.setUint32(4, 32, true); v.setUint32(8, 32473, true);
  v.setUint32(28, 32, true);
  return out;
}

export function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0x1_0000_0000; };
}

/** Frames made here: varied lengths and bytes, a nanosecond clock. */
export function madeFrames(n: number): SeqFrame[] {
  const random = rng(7);
  const out: SeqFrame[] = [];
  let ns = 1_790_000_000_000_000_000n;
  for (let seq = 0; seq < n; seq++) {
    const bytes = new Uint8Array(60 + Math.floor(random() * 1400));
    for (let i = 0; i < bytes.length; i++) bytes[i] = (seq * 31 + i * 7) & 0xff;
    ns += BigInt(1 + Math.floor(random() * 20_000));
    out.push({ seq, tsUs: Number(ns / 1000n), tsNsRem: Number(ns % 1000n), origLen: bytes.length + (seq % 5 === 0 ? 100 : 0), bytes });
  }
  return out;
}
