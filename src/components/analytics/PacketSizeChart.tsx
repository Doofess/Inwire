import React from 'react';
import { Packet } from '../../types/packet';
import { MICRO_LABEL } from '../common/typography';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';
import { SIZE_BUCKETS as BUCKETS, sizeBucketIndex } from '../../services/report/sizeBuckets';

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
 * The buckets are the ones that modal used, and live in
 * `services/report/sizeBuckets.ts` so the exported report counts the same
 * distribution this draws.
 *
 * Counted incrementally rather than with the modal's `useMemo` over the whole
 * buffer: bucket counts are running sums, so nothing here ever needed
 * re-reading. See useIncrementalAggregate.
 */

export type SizeChart = 'bars' | 'table';

interface PacketSizeChartProps {
  packets: Packet[];
  chart: SizeChart;
}

export const PacketSizeChart: React.FC<PacketSizeChartProps> = ({ packets, chart }) => {
  const { counts, total } = useIncrementalAggregate(
    packets,
    () => ({ counts: new Array<number>(BUCKETS.length).fill(0), total: 0 }),
    (acc, p) => {
      const i = sizeBucketIndex(p.length);
      if (i >= 0) acc.counts[i] += 1;
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
            className={`flex-1 min-w-0 text-center ${MICRO_LABEL} truncate`}
          >
            {bucket.short}
          </span>
        ))}
      </div>
    </div>
  );
};
