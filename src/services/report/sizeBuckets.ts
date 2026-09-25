/**
 * The frame-length buckets, shared by the Graphs tab and the report.
 *
 * Lifted out of `PacketSizeChart` so an export can state the same distribution
 * the pane draws: two copies of a bucket table disagree the first time one of
 * them is edited, and a report whose histogram differs from the app's is a
 * report nobody can check.
 *
 * The boundaries are not arbitrary: 64 is the Ethernet minimum, 1518 the
 * classic MTU-plus-header maximum, and the last bucket is everything above
 * that, which on a live link means either jumbo frames or segmentation offload
 * handing you a 64KB pseudo-frame.
 */
import type { Packet } from '../../types/packet';

export interface SizeBucket {
  /** For a table, which has room for the range. */
  label: string;
  /** For a histogram axis, which does not. */
  short: string;
  min: number;
  max: number;
}

export const SIZE_BUCKETS: readonly SizeBucket[] = [
  { label: 'up to 64 B', short: '64', min: 0, max: 64 },
  { label: '65 - 128 B', short: '128', min: 65, max: 128 },
  { label: '129 - 256 B', short: '256', min: 129, max: 256 },
  { label: '257 - 512 B', short: '512', min: 257, max: 512 },
  { label: '513 - 1024 B', short: '1K', min: 513, max: 1024 },
  { label: '1025 - 1518 B', short: '1.5K', min: 1025, max: 1518 },
  { label: 'over 1518 B (jumbo)', short: 'JUMBO', min: 1519, max: Infinity },
];

/** The bucket a length falls in, or -1 for one no bucket holds. */
export function sizeBucketIndex(length: number): number {
  for (let i = 0; i < SIZE_BUCKETS.length; i++) {
    if (length >= SIZE_BUCKETS[i].min && length <= SIZE_BUCKETS[i].max) return i;
  }
  return -1;
}

export interface SizeDistribution {
  /** One count per `SIZE_BUCKETS` entry, in order. */
  counts: number[];
  /** Every frame folded, including any no bucket held. */
  total: number;
}

/** Bucket counts are running sums, so the fold is the whole computation. */
export class SizeFold {
  private readonly counts = new Array<number>(SIZE_BUCKETS.length).fill(0);
  private total = 0;

  add(packet: Packet): void {
    const i = sizeBucketIndex(packet.length);
    if (i >= 0) this.counts[i] += 1;
    this.total += 1;
  }

  result(): SizeDistribution {
    return { counts: [...this.counts], total: this.total };
  }
}
