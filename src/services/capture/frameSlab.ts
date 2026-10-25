import type { RawFrame } from './captureWriter';

/**
 * A flush's frames as columns (#17): five buffers cross the store's port
 * instead of an object and a view per frame. `ends[i]` is frame i's end in
 * `bytes`; it starts at `ends[i - 1]`, or 0. `rings` is null when no frame has
 * a ring, else `[epoch, file, seq]` per frame with epoch -1 for none.
 */
export interface FrameSlab {
  ids: Float64Array;
  tsUs: Float64Array;
  ends: Uint32Array;
  bytes: Uint8Array;
  rings: Float64Array | null;
}

/** Copies the frames into a fresh, exactly-sized slab; their views may sit anywhere. */
export function packFrames(frames: readonly RawFrame[]): FrameSlab {
  const n = frames.length;
  const ids = new Float64Array(n);
  const tsUs = new Float64Array(n);
  const ends = new Uint32Array(n);
  let total = 0;
  let anyRing = false;
  for (let i = 0; i < n; i++) {
    total += frames[i].bytes.length;
    if (frames[i].ring !== undefined) anyRing = true;
  }
  const bytes = new Uint8Array(total);
  const rings = anyRing ? new Float64Array(n * 3) : null;
  let at = 0;
  for (let i = 0; i < n; i++) {
    const f = frames[i];
    ids[i] = f.id;
    tsUs[i] = f.tsUs;
    bytes.set(f.bytes, at);
    at += f.bytes.length;
    ends[i] = at;
    if (rings !== null) {
      const r = f.ring;
      rings[i * 3] = r === undefined ? -1 : r.epoch;
      rings[i * 3 + 1] = r === undefined ? 0 : r.file;
      rings[i * 3 + 2] = r === undefined ? 0 : r.seq;
    }
  }
  return { ids, tsUs, ends, bytes, rings };
}

/** The frames back; each one's `bytes` is a `subarray` of the slab's. */
export function unpackFrames(slab: FrameSlab): RawFrame[] {
  const { ids, tsUs, ends, bytes, rings } = slab;
  const out: RawFrame[] = new Array(ids.length);
  let from = 0;
  for (let i = 0; i < ids.length; i++) {
    const frame: RawFrame = { id: ids[i], tsUs: tsUs[i], bytes: bytes.subarray(from, ends[i]) };
    from = ends[i];
    if (rings !== null && rings[i * 3] !== -1) {
      frame.ring = { epoch: rings[i * 3], file: rings[i * 3 + 1], seq: rings[i * 3 + 2] };
    }
    out[i] = frame;
  }
  return out;
}
