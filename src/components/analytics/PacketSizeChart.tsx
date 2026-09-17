import React from 'react';
import { Packet } from '../../types/packet';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';

/**
 * How frame lengths are distributed across the capture.
 *
 * Lifted out of the Statistics modal, which is gone. It was a real measurement
 * sitting behind a modal reachable only from a maximize button on another
 * widget, which is roughly the least discoverable place in the app. It became a
 * dock widget, and when the dock went it landed where it belonged all along:
 * the **Graphs tab of the Statistics pane**, beside the traffic timeline and in
 * the same pane as the tables that aggregate the same buffer. `GraphsTab` is
 * the only thing that renders it, and carries the argument for the placement.
 *
 * The buckets are the ones that modal used, and they are not arbitrary: 64 is
 * the Ethernet minimum, 1518 the classic MTU-plus-header maximum, and the last
 * bucket is everything above that, which on a live link means either jumbo
 * frames or segmentation offload handing you a 64KB pseudo-frame.
 *
 * Counted incrementally rather than with the modal's `useMemo` over the whole
 * buffer: bucket counts are running sums, so nothing here ever needed
 * re-reading. See useIncrementalAggregate.
 */

export type SizeChart = 'bars' | 'table';

interface SizeBucket {
  /** For the table, which has room for the range. */
  label: string;
  /** For the histogram axis, which does not. */
  short: string;
  min: number;
  max: number;
}

const BUCKETS: readonly SizeBucket[] = [
  { label: 'up to 64 B', short: '64', min: 0, max: 64 },
  { label: '65 - 128 B', short: '128', min: 65, max: 128 },
  { label: '129 - 256 B', short: '256', min: 129, max: 256 },
  { label: '257 - 512 B', short: '512', min: 257, max: 512 },
  { label: '513 - 1024 B', short: '1K', min: 513, max: 1024 },
  { label: '1025 - 1518 B', short: '1.5K', min: 1025, max: 1518 },
  { label: 'over 1518 B (jumbo)', short: 'JUMBO', min: 1519, max: Infinity },
];

interface PacketSizeChartProps {
  packets: Packet[];
  chart: SizeChart;
}

export const PacketSizeChart: React.FC<PacketSizeChartProps> = ({ packets, chart }) => {
  const { counts, total } = useIncrementalAggregate(
    packets,
    () => ({ counts: new Array<number>(BUCKETS.length).fill(0), total: 0 }),
    (acc, p) => {
      for (let i = 0; i < BUCKETS.length; i++) {
        if (p.length >= BUCKETS[i].min && p.length <= BUCKETS[i].max) {
          acc.counts[i] += 1;
          break;
        }
      }
      acc.total += 1;
    },
    (acc) => ({ counts: acc.counts, total: acc.total }),
  );

  const share = (n: number) => (total > 0 ? (n / total) * 100 : 0);

  if (chart === 'table') {
    return (
      <div className="h-full overflow-y-auto custom-scrollbar">
        <table className="w-full text-left border-collapse font-mono text-[10px]">
          <thead>
            <tr className="sticky top-0 bg-card text-muted-foreground font-sans">
              <th className="py-1 pr-1 font-semibold">Frame length</th>
              <th className="py-1 px-1 text-right font-semibold">Frames</th>
              <th className="py-1 pl-1 text-right font-semibold">%</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {BUCKETS.map((bucket, i) => (
              <tr key={bucket.label}>
                <td className="py-1 pr-1 text-foreground">{bucket.label}</td>
                <td className="py-1 px-1 text-right text-foreground">
                  {counts[i].toLocaleString()}
                </td>
                <td className="py-1 pl-1 text-right text-muted-foreground">
                  {share(counts[i]).toFixed(1)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Scaled to the tallest bucket rather than to 100%, because a distribution is
  // read by its SHAPE. Against a fixed 100% scale a capture that is 70% small
  // frames draws one tall bar and six stubs, and the difference between those
  // six - which is the whole question - is a pixel or two.
  const peak = Math.max(1, ...counts);

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 min-h-0 flex items-end justify-between gap-1">
        {BUCKETS.map((bucket, i) => (
          <div
            key={bucket.label}
            className="flex-1 min-w-0 h-full flex flex-col justify-end items-center gap-1 group"
            title={`${bucket.label}: ${counts[i].toLocaleString()} frames (${share(counts[i]).toFixed(1)}%)`}
          >
            <span className="text-[9px] font-mono text-muted-foreground tabular-nums opacity-0 group-hover:opacity-100 transition-opacity">
              {share(counts[i]).toFixed(0)}%
            </span>
            <div
              className="w-full rounded-t-sm bg-primary/80 group-hover:bg-primary transition-all duration-300"
              // A visible sliver for an empty bucket, so the axis below always
              // has something to belong to and the chart never looks unloaded.
              style={{ height: `${Math.max(2, (counts[i] / peak) * 100)}%` }}
            />
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between gap-1 pt-1 mt-1 border-t border-border">
        {BUCKETS.map((bucket) => (
          <span
            key={bucket.short}
            className="flex-1 min-w-0 text-center text-[9px] font-mono uppercase tracking-tight text-muted-foreground truncate"
          >
            {bucket.short}
          </span>
        ))}
      </div>
    </div>
  );
};
