import React from 'react';
import {
  filterPercentage, scanPercentage, usePacketCounts,
} from '../../services/packetCounts';

/**
 * The packet counter, as a dock widget.
 *
 * It was a badge in the filter bar reading `PACKETS: 2,224 / 2,224  100.0%`.
 * Everything it said is still here; what changed is that it is a panel you
 * choose to have open rather than a fixture of the row above the list.
 *
 * **It subscribes for itself**, through `usePacketCounts`, and that is not a
 * convenience. `Dock` is the application's only `React.memo` boundary, and it
 * holds because `DashboardWidgetContext` is memoised on inputs that change
 * rarely. A frame count in that context would change its identity on every
 * 100ms flush and re-render all six widgets for a number one of them shows -
 * the regression fixed in `b0ce1fc`, reintroduced by the tidier route. See
 * `services/packetCounts.ts`.
 *
 * The arithmetic is there too, for the same reason: `filterPercentage` has two
 * ends a naive `filtered / total` gets wrong, and an assertion script can reach
 * a service but not a component.
 */
export const PacketCountsCard: React.FC = () => {
  const counts = usePacketCounts();
  const scanning = counts.scan?.status === 'scanning';
  const scanPct = scanPercentage(counts.scan);

  return (
    <div className="flex flex-col gap-2 font-mono">
      {/* The two numbers, at the size the question deserves. In the filter bar
          these were 12px because they shared a row with a text field; a card is
          the one place they can be read at a glance from across a desk. */}
      <div className="flex items-baseline gap-1.5">
        <span className="text-xl font-semibold tabular-nums text-foreground">
          {counts.filtered.toLocaleString()}
        </span>
        <span className="text-sm text-muted-foreground">/</span>
        <span className="text-sm tabular-nums text-muted-foreground">
          {counts.total.toLocaleString()}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {scanning ? (
          <span
            className="text-[10px] px-1.5 py-0.5 rounded bg-warning/20 text-warning font-bold"
            title={
              counts.scan?.status === 'scanning'
                ? `Filtering the stored capture: ${counts.scan.framesDone.toLocaleString()} of `
                  + `${counts.scan.frameCount.toLocaleString()} frames`
                : undefined
            }
          >
            {/* Indeterminate until the first progress message, which is 150,000
                frames in. A percentage of an unknown total is a number, and a
                wrong one. */}
            SCANNING{scanPct === null ? '' : ` ${scanPct}%`}
          </span>
        ) : (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary font-bold">
            {filterPercentage(counts)}%
          </span>
        )}

        {counts.scan?.status === 'failed' && (
          <span
            className="text-[10px] px-1.5 py-0.5 rounded bg-destructive/20 text-destructive font-bold"
            title={counts.scan.message}
          >
            STORED FRAMES NOT SEARCHED
          </span>
        )}

        {/* A capture that grew after the scan started, which while one is
            running it always does. Clickable rather than automatic: a scan that
            re-ran itself would be a whole-capture pass about once a second,
            competing with the frames still arriving. */}
        {counts.uncovered > 0 && counts.onRescan !== undefined && (
          <button
            type="button"
            onClick={counts.onRescan}
            className="text-[10px] px-1.5 py-0.5 rounded bg-warning/20 text-warning font-bold
              hover:bg-warning/30 transition-colors cursor-pointer"
            title={`${counts.uncovered.toLocaleString()} stored frames arrived after this filter was `
              + 'run over the capture. Click to run it again.'}
          >
            +{counts.uncovered.toLocaleString()} UNSEARCHED
          </button>
        )}
      </div>

      {/* The label goes UNDER the numbers here, where the badge had it in front.
          A card has a heading of its own from `WidgetCard`, so a second
          "PACKETS:" above the figures would be the title twice. */}
      <p className="text-[10px] leading-snug text-muted-foreground">
        Rows the display filter selected, out of the whole capture.
      </p>
    </div>
  );
};
