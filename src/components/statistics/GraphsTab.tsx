import React from 'react';
import type { Packet } from '../../types/packet';
import { TrafficTimelineChart } from '../analytics/TrafficTimelineChart';
import { PacketSizeChart } from '../analytics/PacketSizeChart';
import {
  GRAPH_INTERVALS, OVERLAY_FILTER_MAX, graphStore,
} from '../../services/graphPrefs';
import { usePreferenceStore } from '../../services/preferenceStore';

/**
 * The Graphs tab: throughput over time, and the frame-size distribution.
 *
 * ## What this replaces
 *
 * Two dock widgets - Traffic timeline and Packet sizes - and the dock itself.
 * The charts are the same components, unchanged inside: `TrafficTimelineChart`
 * still owns its D3 draw, its ResizeObserver, its anomaly marks and its
 * render-tier fallback, and `PacketSizeChart` still owns its seven buckets.
 * What moved is where they are drawn and who sets their options.
 *
 * ## Why a tab rather than a pane of its own
 *
 * Because it answers the question this pane already exists to answer. Statistics
 * is titled "Capture Statistics" and every other tab here is an aggregate over
 * the whole buffer - a hierarchy, a conversation table, an endpoint table. A
 * throughput plot is the same aggregate drawn as a line instead of a row, and it
 * was on the other side of the window from the tables it belongs with purely
 * because the dock was a column and the tables were a view.
 *
 * ## The controls are on the charts
 *
 * Every option these two had lived in Settings -> Interface, generated from the
 * widget catalogue, because a 352px card header had room for exactly one
 * control. There is no card and no catalogue now, so they are all here, next to
 * the thing they change.
 *
 * That includes **the overlay filter**, which is the one that was worth
 * surfacing: a second series drawn over the first, showing how much of the
 * traffic matches an expression. It is what makes this an I/O graph rather than
 * a throughput plot, and it is the one question the app's own display filter
 * cannot answer - filtering the app removes the total the answer is measured
 * against.
 *
 * ## Why it aggregates the whole buffer
 *
 * `packets` is the whole buffer, matching every other tab here and deliberately
 * not `filteredPackets`. The pane's own header already says what that means when
 * the buffer has dropped frames. A chart that silently answered for the filtered
 * subset would be the same chart with different numbers and no way to tell.
 */
const PILL = 'px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer';

/**
 * One row of mutually exclusive pills.
 *
 * Generic over the value so a caller cannot pair a label list with the wrong
 * setter - these are four separate controls over three different unions, and
 * the one thing worth having the compiler check is that each writes its own.
 */
function PillGroup<T extends string | number>({
  label, value, options, onChange,
}: {
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (next: T) => void;
}): React.ReactElement {
  return (
    <div className="flex items-center gap-1.5 shrink-0">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <div className="flex items-center gap-0.5">
        {options.map((o) => (
          <button
            key={String(o.value)}
            type="button"
            onClick={() => onChange(o.value)}
            aria-pressed={value === o.value}
            className={`${PILL} ${
              value === o.value
                ? 'bg-accent text-primary font-bold'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

const CARD = 'flex flex-col min-h-0 rounded-lg border border-border bg-card overflow-hidden';
const CARD_HEAD = 'flex items-center flex-wrap gap-x-4 gap-y-1.5 px-3 py-2 '
  + 'border-b border-border shrink-0';
const CARD_TITLE = 'text-[11px] font-bold uppercase tracking-tighter text-foreground mr-auto';

export interface GraphsTabProps {
  /** The whole buffer, like every other tab in this pane. */
  packets: Packet[];
  isDark: boolean;
  /**
   * The resolved theme's name. Not used for styling - it is what makes the
   * timeline's imperative D3 draw re-run on a theme change. `isDark` alone
   * cannot do it if two dark themes are ever added back.
   */
  themeKey?: string;
}

export const GraphsTab: React.FC<GraphsTabProps> = ({ packets, isDark, themeKey }) => {
  const [prefs, patch] = usePreferenceStore(graphStore);

  return (
    // Two cards in a column, each taking half the height. `min-h-0` on both the
    // column and the cards is load-bearing: the timeline measures its own
    // container, so a flex child that refuses to shrink would let the SVG push
    // the pane taller than the window and the second chart off the bottom.
    <div className="flex-1 min-h-0 flex flex-col gap-3 p-3 overflow-hidden">
      <section className={`${CARD} flex-1`} aria-label="Throughput over time">
        <div className={CARD_HEAD}>
          <h3 className={CARD_TITLE}>Throughput</h3>
          <PillGroup
            label="Measure"
            value={prefs.metric}
            onChange={(metric) => patch({ metric })}
            options={[
              { value: 'packets' as const, label: 'Packets' },
              { value: 'bytes' as const, label: 'Bytes' },
            ]}
          />
          <PillGroup
            label="Chart"
            value={prefs.chart}
            onChange={(chart) => patch({ chart })}
            options={[
              { value: 'area' as const, label: 'Area' },
              { value: 'bars' as const, label: 'Bars' },
            ]}
          />
          <PillGroup
            label="Interval"
            value={prefs.interval}
            onChange={(interval) => patch({ interval })}
            options={GRAPH_INTERVALS.map((s) => ({
              value: s,
              label: s < 60 ? `${s}s` : `${s / 60}m`,
            }))}
          />
        </div>

        {/* The overlay filter, on its own row because it is a field rather than
            a set of pills and because it is the control that changes what the
            chart IS. Uncontrolled-looking but controlled: the store is written
            on every keystroke, and `createPreferenceStore` debounces the write
            to disk itself, so there is no second debounce needed here. */}
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border shrink-0">
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground shrink-0">
            Overlay
          </span>
          <input
            value={prefs.overlayFilter}
            onChange={(e) => patch({ overlayFilter: e.target.value.slice(0, OVERLAY_FILTER_MAX) })}
            spellCheck={false}
            placeholder="A display filter, drawn as a second series over the total - tcp.port == 443"
            className="flex-1 min-w-0 bg-transparent border-none outline-none
              text-[11px] font-mono text-foreground placeholder:text-muted-foreground/60"
          />
          {prefs.overlayFilter !== '' && (
            <button
              type="button"
              onClick={() => patch({ overlayFilter: '' })}
              className={`${PILL} text-muted-foreground hover:text-foreground shrink-0`}
            >
              Clear
            </button>
          )}
        </div>

        <div className="flex-1 min-h-0 p-2">
          <TrafficTimelineChart
            packets={packets}
            isDark={isDark}
            themeKey={themeKey}
            metric={prefs.metric}
            chart={prefs.chart}
            intervalSeconds={prefs.interval}
            overlayFilter={prefs.overlayFilter}
          />
        </div>
      </section>

      <section className={`${CARD} flex-1`} aria-label="Frame size distribution">
        <div className={CARD_HEAD}>
          <h3 className={CARD_TITLE}>Frame sizes</h3>
          {/* No bucket-count control, and that is a limit rather than an
              omission: `PacketSizeChart`'s seven buckets are a fixed table
              (64 / 128 / 256 / 512 / 1K / 1.5K / jumbo) chosen to match the
              boundaries that mean something on Ethernet, not an arbitrary
              division of the range. Making the count configurable means
              replacing that table with arithmetic, which would trade the one
              thing the chart currently says - "these are the sizes that matter"
              - for a number nobody has a reason to pick. */}
          <PillGroup
            label="Chart"
            value={prefs.sizeChart}
            onChange={(sizeChart) => patch({ sizeChart })}
            options={[
              { value: 'bars' as const, label: 'Bars' },
              { value: 'table' as const, label: 'Table' },
            ]}
          />
        </div>
        <div className="flex-1 min-h-0 overflow-auto custom-scrollbar p-2">
          <PacketSizeChart packets={packets} chart={prefs.sizeChart} />
        </div>
      </section>
    </div>
  );
};
