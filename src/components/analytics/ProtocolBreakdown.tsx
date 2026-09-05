import React, { useMemo } from 'react';
import * as d3 from 'd3';
import { Packet } from '../../types/packet';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';
import { protocolColor } from '../../services/protocolColors';

/**
 * What the capture is made of, drawn three ways.
 *
 * Was `ProtocolDonutChart`, which drew ranked bars and had never contained a
 * donut. The three charts are one aggregate seen three ways rather than three
 * widgets, because the question - which protocols, in what proportion - is the
 * same one; only the shape of the answer differs, and which shape you want
 * depends on what you are doing rather than on anything this component knows.
 *
 * `table` is the protocol hierarchy that used to live in the Statistics modal,
 * minus the two rows at the top of it that were **fabricated**: a "Frame /
 * Ethernet II" row hardcoded to 100%, and an "Internet Protocol Version 4" row
 * hardcoded to 98.4% and `Math.floor(totalPackets * 0.98)`. Neither number was
 * measured from anything. A table of real counts with two invented rows above
 * them is worse than no table.
 */

export type BreakdownMetric = 'packets' | 'bytes';
export type BreakdownChart = 'bars' | 'donut' | 'table';

interface ProtocolBreakdownProps {
  packets: Packet[];
  metric: BreakdownMetric;
  chart: BreakdownChart;
  top: number;
  onSelectProtocol: (protocol: string) => void;
  selectedProtocolFilter?: string;
  /** The active theme's name - the donut's slice colours come from it. */
  themeKey?: string;
}

interface ProtocolDatum {
  /** What the packet list calls it: "TLSv1.2", "QUIC", "ICMPv6". */
  label: string;
  /**
   * The coarse type, kept only to look up a colour.
   *
   * The display label is the specific one, but `protocolColor` is keyed by the
   * twelve-member `ProtocolType` union - so carrying both is what lets a QUIC
   * slice here be the same colour as a QUIC arc on the map.
   */
  protocol: string;
  count: number;
  bytes: number;
}

/*
 * Bars are the theme's accent, not a hue per row.
 *
 * A ranked list already carries the comparison in its lengths and its ordering,
 * so a hue per row is a second encoding of something the layout has said - and
 * eight saturated bars stacked in a small card read as decoration.
 *
 * The DONUT is the opposite case and does colour per protocol, for the same
 * reason the map does: slices of a ring have no shared baseline and no reading
 * order, so colour is the only thing that can tell them apart. Those colours
 * come from `protocolColors.ts`, so a QUIC slice and a QUIC arc match.
 */
const BAR_COLOR = 'bg-primary';

/** Bytes, at the width a 352px card gives a right-aligned number. */
function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}K`;
  return `${bytes}B`;
}

export const ProtocolBreakdown: React.FC<ProtocolBreakdownProps> = ({
  packets,
  metric,
  chart,
  top,
  onSelectProtocol,
  selectedProtocolFilter,
  themeKey,
}) => {
  /**
   * The breakdown, folded one packet at a time rather than recounted from
   * packet zero on every dashboard tick - see useIncrementalAggregate.
   *
   * Both totals are carried whether or not the current metric needs them: they
   * are two running sums per protocol, and folding only the selected one would
   * mean re-reading the whole buffer the moment somebody switched metric.
   *
   * The running totals come from the accumulator rather than `packets.length`,
   * so the percentages are always over exactly the packets that were counted.
   */
  const { rows, totalCount, totalBytes } = useIncrementalAggregate(
    packets,
    () => ({ byLabel: new Map<string, ProtocolDatum>(), count: 0, bytes: 0 }),
    (acc, p) => {
      const label = p.protocolLabel ?? p.protocol;
      let row = acc.byLabel.get(label);
      if (!row) {
        row = { label, protocol: p.protocol, count: 0, bytes: 0 };
        acc.byLabel.set(label, row);
      }
      row.count += 1;
      row.bytes += p.length;
      acc.count += 1;
      acc.bytes += p.length;
    },
    (acc) => ({
      rows: Array.from(acc.byLabel.values()),
      totalCount: acc.count,
      totalBytes: acc.bytes,
    }),
  );

  const value = (row: ProtocolDatum) => (metric === 'bytes' ? row.bytes : row.count);
  const total = metric === 'bytes' ? totalBytes : totalCount;

  // Sorted and cut here rather than in the fold, because the fold's result is
  // memoized on the packet feed and this depends on the metric as well.
  const ranked = useMemo(
    () =>
      [...rows]
        .sort((a, b) => (metric === 'bytes' ? b.bytes - a.bytes : b.count - a.count))
        .slice(0, top),
    [rows, metric, top],
  );

  const percent = (row: ProtocolDatum) => (total > 0 ? (value(row) / total) * 100 : 0);
  const isSelected = (row: ProtocolDatum) =>
    !!selectedProtocolFilter?.toLowerCase().includes(row.label.toLowerCase());

  if (chart === 'donut') {
    return (
      <DonutView
        ranked={ranked}
        total={total}
        metric={metric}
        themeKey={themeKey}
        onSelectProtocol={onSelectProtocol}
        isSelected={isSelected}
        value={value}
      />
    );
  }

  if (chart === 'table') {
    return (
      <div className="h-full overflow-y-auto custom-scrollbar -mx-1">
        <table className="w-full text-left border-collapse font-mono text-[10px]">
          <thead>
            {/* Sticky, because this scrolls inside a card: a header that
                scrolls away leaves four columns of bare numbers. */}
            <tr className="sticky top-0 bg-card text-muted-foreground font-sans text-[10px]">
              <th className="py-1 px-1 font-semibold">Protocol</th>
              <th className="py-1 px-1 text-right font-semibold">Packets</th>
              <th className="py-1 px-1 text-right font-semibold">%</th>
              <th className="py-1 px-1 text-right font-semibold">Bytes</th>
              <th className="py-1 px-1 text-right font-semibold">%</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {ranked.map((row) => (
              <tr
                key={row.label}
                onClick={() => onSelectProtocol(row.label.toLowerCase())}
                className={`cursor-pointer transition-colors ${
                  isSelected(row) ? 'bg-accent' : 'hover:bg-accent/50'
                }`}
              >
                <td className="py-1 px-1 font-semibold text-foreground flex items-center gap-1.5">
                  <span
                    aria-hidden
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: protocolColor(row.protocol, themeKey) }}
                  />
                  <span className="truncate">{row.label}</span>
                </td>
                <td className="py-1 px-1 text-right text-foreground">{row.count.toLocaleString()}</td>
                <td className="py-1 px-1 text-right text-muted-foreground">
                  {(totalCount > 0 ? (row.count / totalCount) * 100 : 0).toFixed(1)}
                </td>
                <td className="py-1 px-1 text-right text-foreground">{formatBytes(row.bytes)}</td>
                <td className="py-1 px-1 text-right text-muted-foreground">
                  {(totalBytes > 0 ? (row.bytes / totalBytes) * 100 : 0).toFixed(1)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto custom-scrollbar space-y-2.5 pr-0.5">
      {ranked.map((row) => (
        <div
          key={row.label}
          onClick={() => onSelectProtocol(row.label.toLowerCase())}
          className={`space-y-1.5 p-1 rounded transition-colors cursor-pointer ${
            isSelected(row) ? 'bg-accent' : 'hover:bg-accent/50'
          }`}
        >
          <div className="flex justify-between text-[11px] font-mono gap-2">
            <span className="font-semibold text-foreground/90 truncate">{row.label}</span>
            {/* The value beside a bar is not the accent, and neither are the
                byte totals in Top Talkers: these are the numbers the heading is
                about, and painting them the accent puts them in competition
                with the one accent-coloured thing in the card that is actually
                interactive. Weight carries the hierarchy; the bar already
                carries the comparison. */}
            <span className="font-bold text-muted-foreground shrink-0">
              {percent(row).toFixed(1)}%
            </span>
          </div>
          <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
            <div
              className={`h-full ${BAR_COLOR} transition-all duration-300`}
              style={{ width: `${Math.max(4, percent(row))}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
};

/**
 * The ring, plus the legend that makes it readable.
 *
 * Drawn with `d3.pie`/`d3.arc` into plain JSX rather than with a charting
 * library: d3 is already in the bundle for the traffic timeline, and the two
 * declared chart packages in package.json - recharts and lightweight-charts -
 * are imported by nothing, so reaching for one would have added a whole library
 * to the bundle for one ring. Path strings are computed and rendered as React
 * elements, so there is no imperative draw and nothing to keep in sync.
 *
 * A ring rather than a pie because the middle is where the total goes, and a
 * total is the one number a proportion chart cannot show.
 */
const DonutView: React.FC<{
  ranked: ProtocolDatum[];
  total: number;
  metric: BreakdownMetric;
  themeKey?: string;
  onSelectProtocol: (protocol: string) => void;
  isSelected: (row: ProtocolDatum) => boolean;
  value: (row: ProtocolDatum) => number;
}> = ({ ranked, total, metric, themeKey, onSelectProtocol, isSelected, value }) => {
  const SIZE = 104;
  const arcs = useMemo(() => {
    const pie = d3
      .pie<ProtocolDatum>()
      .value(value)
      // Already sorted by the caller, and re-sorting here would put the slices
      // in a different order from the legend beside them.
      .sort(null)
      .padAngle(0.02);
    const arc = d3
      .arc<d3.PieArcDatum<ProtocolDatum>>()
      .innerRadius(SIZE / 2 - 16)
      .outerRadius(SIZE / 2 - 2)
      .cornerRadius(2);
    return pie(ranked).map((slice) => ({ datum: slice.data, path: arc(slice) ?? '' }));
  }, [ranked, value]);

  const shown = ranked.reduce((sum, row) => sum + value(row), 0);

  return (
    <div className="h-full flex items-center gap-3">
      <svg
        width={SIZE}
        height={SIZE}
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        className="shrink-0"
        role="img"
        aria-label={`Protocol share by ${metric}`}
      >
        <g transform={`translate(${SIZE / 2},${SIZE / 2})`}>
          {arcs.map(({ datum, path }) => (
            <path
              key={datum.label}
              d={path}
              fill={protocolColor(datum.protocol, themeKey)}
              className="cursor-pointer transition-opacity"
              opacity={isSelected(datum) ? 1 : 0.85}
              onClick={() => onSelectProtocol(datum.label.toLowerCase())}
            >
              <title>{`${datum.label} - ${
                total > 0 ? ((value(datum) / total) * 100).toFixed(1) : '0.0'
              }%`}</title>
            </path>
          ))}
          {/* The share these slices actually account for. Without it the ring
              silently claims to be the whole capture when it is the top N of
              it, which for a busy capture can be well under half. */}
          <text
            textAnchor="middle"
            className="fill-foreground font-mono font-bold"
            style={{ fontSize: 13 }}
            dy="-1"
          >
            {total > 0 ? `${Math.round((shown / total) * 100)}%` : '--'}
          </text>
          <text
            textAnchor="middle"
            className="fill-muted-foreground font-mono uppercase"
            style={{ fontSize: 7, letterSpacing: '0.08em' }}
            dy="11"
          >
            of {metric}
          </text>
        </g>
      </svg>

      <ul className="flex-1 min-w-0 h-full overflow-y-auto custom-scrollbar space-y-1 py-0.5">
        {ranked.map((row) => (
          <li key={row.label}>
            <button
              type="button"
              onClick={() => onSelectProtocol(row.label.toLowerCase())}
              className={`w-full flex items-center gap-1.5 px-1 py-0.5 rounded text-[10px] font-mono transition-colors cursor-pointer ${
                isSelected(row) ? 'bg-accent' : 'hover:bg-accent/50'
              }`}
            >
              <span
                aria-hidden
                className="w-2 h-2 rounded-[2px] shrink-0"
                style={{ background: protocolColor(row.protocol, themeKey) }}
              />
              <span className="truncate text-foreground/90">{row.label}</span>
              <span className="ml-auto shrink-0 font-bold text-muted-foreground">
                {total > 0 ? ((value(row) / total) * 100).toFixed(1) : '0.0'}%
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};
