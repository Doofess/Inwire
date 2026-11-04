/**
 * How the burst drives cut what they send into the agent's batches, out of
 * the drive so `agent-batches.ts` can hold it to what the agent sends.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface BatchBounds {
  records: number;
  bytes: number;
}

export interface TickFrame {
  seq: number;
  tsNs: bigint;
  bytes: Uint8Array;
}

/**
 * The real agent's batch bounds, read out of `agent-rs/src/session.rs` rather
 * than repeated, so a replay cannot drift from them. `ui-burst-drive.ts` used
 * to send up to 2,000 frames (~2 MB) a batch against the agent's 512 records
 * and 256 kB, and main's deframing made 120,000 a second look like a
 * main-process limit when it was the drive's.
 */
export function agentBatchBounds(): BatchBounds {
  const source = readFileSync(path.join(import.meta.dirname, '../../agent-rs/src/session.rs'), 'utf8');
  const found = new Map<string, number>();
  for (const [, name, value] of source.matchAll(/pub const (MAX_BATCH_RECORDS|MAX_BATCH_BYTES): usize = ([\d_ *]+);/g)) {
    found.set(name, value.split('*').reduce((product, factor) => product * Number(factor.replace(/[_ ]/g, '')), 1));
  }
  const records = found.get('MAX_BATCH_RECORDS');
  const bytes = found.get('MAX_BATCH_BYTES');
  if (!records || !bytes) throw new Error('agentBatches: MAX_BATCH_RECORDS or MAX_BATCH_BYTES not found in agent-rs/src/session.rs');
  return { records, bytes };
}

/**
 * One tick's `count` frames, numbered on from `firstSeq` and stamped from
 * `base` (epoch nanoseconds), cut into batches as `session.rs`'s `drain` cuts
 * them: add while under both bounds, so a batch can overrun the byte bound by
 * its last record. `frameAt(k)` gives the tick's k-th frame's bytes.
 *
 * Stamps run a microsecond a frame across the whole tick, never from each
 * batch's start: the ordering window sorts by time, and batches that each
 * began at `base` came out of it interleaved (`agent-batches.ts`).
 */
export function cutTick(
  count: number, base: bigint, firstSeq: number, frameAt: (k: number) => Uint8Array, bounds: BatchBounds,
): TickFrame[][] {
  const batches: TickFrame[][] = [];
  let k = 0;
  while (k < count) {
    const batch: TickFrame[] = [];
    let size = 0;
    while (k < count && batch.length < bounds.records && size < bounds.bytes) {
      const bytes = frameAt(k);
      batch.push({ seq: firstSeq + k, tsNs: base + BigInt(k * 1000), bytes });
      size += bytes.length;
      k++;
    }
    batches.push(batch);
  }
  return batches;
}
