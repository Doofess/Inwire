import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Packet } from '../../types/packet';
import {
  TbActivity,
  TbAlertTriangle,
  TbMaximize,
} from 'react-icons/tb';
import { ZoomControls } from './ZoomControls';
import type { WidgetVariant } from './dashboardWidgets';
import { useElementSize } from '../../lib/useElementSize';
import { prefersReducedMotion } from '../../lib/motion';
import { useThemeToken } from '../../lib/themeColor';

interface TrafficTimelineProps {
  packets: Packet[];
  isCapturing: boolean;
  isDark: boolean;
  /** The active theme's name. Not used for styling - it exists so this
   *  imperative D3 draw re-runs when the theme changes. isDark alone cannot
   *  do that: Dark and Mono are both dark, so it stays true across a switch
   *  between them and the chart would keep the previous accent. */
  themeKey?: string;
  /**
   * How much room this has been given. See GeoMap for the full reasoning.
   *
   * `full` means the parent has already framed it, so this renders its body
   * with no scrim and no card of its own - but at the taller layout, because
   * the space is there.
   */
  variant?: WidgetVariant;
  /** Open this widget in the dashboard's shared overlay. See GeoMap. */
  onExpand?: () => void;
}

interface TimelineBucket {
  timeSec: number;
  timeLabel: string;
  packetCount: number;
  byteCount: number;
  kbps: number;
  hasAnomaly: boolean;
  anomalyTitle?: string;
  firstPacket?: Packet;
}

export const TrafficTimelineChart: React.FC<TrafficTimelineProps> = ({
  packets,
  isCapturing,
  isDark,
  themeKey,
  variant = 'card',
  onExpand,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  /**
   * The box the SVG is drawn into.
   *
   * Measured rather than computed, because it is now sized by an aspect ratio:
   * the dashboard column can be dragged to any width, and the chart keeps its
   * shape by taking its height from that width. Neither number is a constant
   * this component could know.
   */
  const plotRef = useRef<HTMLDivElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGRectElement, unknown> | null>(null);
  const zoomRectNodeRef = useRef<SVGRectElement | null>(null);
  const [metric, setMetric] = useState<'packets' | 'bandwidth'>('packets');
  const [hoveredBucket, setHoveredBucket] = useState<TimelineBucket | null>(null);
  // "Has room for the tall layout" - which now means one thing: the dashboard
  // overlay is what framed us.
  const roomy = variant === 'full';
  const [zoomTransform, setZoomTransform] = useState<d3.ZoomTransform>(d3.zoomIdentity);
  const [visibleDomain, setVisibleDomain] = useState<[number, number]>([0, 10]);
  const plot = useElementSize(plotRef);

  /**
   * The accent, as state rather than read inline during the draw.
   *
   * Read inline it could come back empty for one unlucky draw - a CSS swap, a
   * paint before styles land - and silently become the hardcoded cyan, which
   * on the mono theme is a blue line where the accent is white, and it stayed
   * that way until a click forced a redraw. As state it never regresses to the
   * fallback, and a late resolution redraws the chart by itself.
   */
  const accent = useThemeToken('--primary', '#f97316');
  // The axis used to be a hardcoded pair of slate greys chosen by `isDark`,
  // which meant it was the one thing in this chart that did not follow the
  // theme - visibly wrong on a warm ground, where every neutral around it is
  // warm and this one was blue.
  const axis = useThemeToken('--muted-foreground', '#a8a29e');
  // The theme's own alert colour rather than a hardcoded rose, so an alert on
  // the timeline is the same red as an alert everywhere else in the app.
  const alert = useThemeToken('--destructive', '#f43f5e');

  // D3 transitions are JavaScript writing values every frame, so the CSS
  // reduced-motion rule does not apply to them. Zero duration keeps the same
  // call path and simply lands immediately.
  const zoomDuration = () => (prefersReducedMotion() ? 0 : 200);

  const handleZoomIn = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(zoomDuration()).call(zoomBehaviorRef.current.scaleBy, 1.5);
  };

  const handleZoomOut = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(zoomDuration()).call(zoomBehaviorRef.current.scaleBy, 1 / 1.5);
  };

  const handleResetZoom = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(zoomDuration()).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  // Compute time bounds & buckets
  const { buckets, maxTime } = React.useMemo(() => {
    if (packets.length === 0) return { buckets: [], minTime: 0, maxTime: 10 };

    const bucketMap = new Map<number, { count: number; bytes: number; hasAnomaly: boolean; anomalyTitle?: string; firstPacket?: Packet }>();

    let minT = Math.floor(packets[0].relativeTime);
    let maxT = Math.ceil(packets[packets.length - 1].relativeTime);
    if (maxT - minT < 10) maxT = minT + 10;

    // Sliding 60-second window or full range
    const startSec = Math.max(0, maxT - 60);
    for (let t = startSec; t <= maxT; t++) {
      bucketMap.set(t, { count: 0, bytes: 0, hasAnomaly: false });
    }

    for (const p of packets) {
      const sec = Math.floor(p.relativeTime);
      const existing = bucketMap.get(sec) || { count: 0, bytes: 0, hasAnomaly: false };
      existing.count += 1;
      existing.bytes += p.length;
      if (!existing.firstPacket) existing.firstPacket = p;

      if (p.status === 'alert' || (p.anomalies && p.anomalies.length > 0)) {
        existing.hasAnomaly = true;
        existing.anomalyTitle = p.anomalies?.[0]?.title || 'Security Alert';
      }
      bucketMap.set(sec, existing);
    }

    const result: TimelineBucket[] = [];
    const sortedKeys = Array.from(bucketMap.keys()).sort((a, b) => a - b);
    for (const k of sortedKeys) {
      const b = bucketMap.get(k)!;
      result.push({
        timeSec: k,
        timeLabel: `${k}s`,
        packetCount: b.count,
        byteCount: b.bytes,
        kbps: (b.bytes * 8) / 1024,
        hasAnomaly: b.hasAnomaly,
        anomalyTitle: b.anomalyTitle,
        firstPacket: b.firstPacket,
      });
    }

    return { buckets: result, minTime: minT, maxTime: maxT };
  }, [packets]);

  // During active capture `buckets` recomputes on literally every incoming
  // packet, and the draw effect below fully tears down and rebuilds the SVG
  // (axes, gradient, area path, grid) on each run. Doing that on every
  // packet - rather than at most a few times a second - meant the
  // `clientWidth` read at the top of that effect kept forcing a synchronous
  // layout flush against the previous run's still-pending DOM writes
  // (measured via Chrome's performance trace: ~650ms of forced reflow
  // attributed to this exact effect during a single capture session) -
  // the dominant cause of the reported UI stutter during capture. Coalesce
  // bursts into one redraw per DRAW_THROTTLE_MS: the ref always holds the
  // latest buckets, but the draw effect only fires on the throttled copy.
  //
  // `packets` now also arrives pre-throttled from App.tsx (see
  // DASHBOARD_REFRESH_MS there), so this layer no longer does much for the
  // capture case. It is kept because it guards a second set of triggers that
  // one does not: metric, isExpanded and zoomTransform all rebuild the same
  // SVG, and a zoom gesture fires them far faster than any packet arrives.
  const DRAW_THROTTLE_MS = 150;
  const [throttledBuckets, setThrottledBuckets] = useState<TimelineBucket[]>(buckets);
  const latestBucketsRef = useRef(buckets);
  const bucketsThrottleRef = useRef<number | null>(null);
  latestBucketsRef.current = buckets;

  useEffect(() => {
    if (bucketsThrottleRef.current !== null) return;
    bucketsThrottleRef.current = window.setTimeout(() => {
      setThrottledBuckets(latestBucketsRef.current);
      bucketsThrottleRef.current = null;
    }, DRAW_THROTTLE_MS);
  }, [buckets]);

  // Render D3 chart
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || throttledBuckets.length === 0) return;

    // The measured box, with the old constants as the answer for the frame
    // before the observer has reported - not as the answer forever, which is
    // what they were.
    const containerWidth = plot.width || containerRef.current.clientWidth || 320;
    const height = plot.height || (roomy ? 360 : 120);
    const margin = { top: 10, right: 12, bottom: 20, left: 30 };
    const width = containerWidth - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', containerWidth)
      .attr('height', height)
      .attr('viewBox', `0 0 ${containerWidth} ${height}`);

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    // X Scale (base domain, then rescaled by the current zoom transform)
    const xExtent = d3.extent(throttledBuckets, (d: TimelineBucket) => d.timeSec) as [number, number];
    const baseXScale = d3.scaleLinear().domain([xExtent[0] || 0, xExtent[1] || 10]).range([0, width]);
    const xScale = zoomTransform.rescaleX(baseXScale);
    setVisibleDomain(xScale.domain() as [number, number]);

    // Y Scale
    const yVal = (d: TimelineBucket) => (metric === 'packets' ? d.packetCount : d.kbps);
    const maxY = Math.max(8, d3.max(throttledBuckets, yVal) || 8);
    const yScale = d3.scaleLinear().domain([0, maxY * 1.15]).range([innerHeight, 0]);

    // Grid lines
    g.append('g')
      .attr('class', 'grid')
      .attr('opacity', 0.15)
      .call(
        d3
          .axisLeft(yScale)
          .ticks(3)
          .tickSize(-width)
          .tickFormat(() => '')
      );

    // Gradient
    const defs = svg.append('defs');
    const gradId = `area-gradient-${metric}`;
    const gradient = defs
      .append('linearGradient')
      .attr('id', gradId)
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');

    if (metric === 'packets') {
      gradient.append('stop').attr('offset', '0%').attr('stop-color', accent).attr('stop-opacity', 0.6);
      gradient.append('stop').attr('offset', '100%').attr('stop-color', accent).attr('stop-opacity', 0.01);
    } else {
      gradient.append('stop').attr('offset', '0%').attr('stop-color', '#10b981').attr('stop-opacity', 0.6);
      gradient.append('stop').attr('offset', '100%').attr('stop-color', '#10b981').attr('stop-opacity', 0.01);
    }

    // Area & Line
    const area = d3
      .area<TimelineBucket>()
      .x(d => xScale(d.timeSec))
      .y0(innerHeight)
      .y1(d => yScale(yVal(d)))
      .curve(d3.curveMonotoneX);

    const line = d3
      .line<TimelineBucket>()
      .x(d => xScale(d.timeSec))
      .y(d => yScale(yVal(d)))
      .curve(d3.curveMonotoneX);

    g.append('path').datum(throttledBuckets).attr('fill', `url(#${gradId})`).attr('d', area);
    g.append('path')
      .datum(throttledBuckets)
      .attr('fill', 'none')
      .attr('stroke', metric === 'packets' ? accent : '#10b981')
      .attr('stroke-width', 2)
      .attr('d', line);

    // Alerts, painted INTO the graph rather than dotted on top of it.
    //
    // This used to be a rose circle sitting above the line at each anomalous
    // bucket. A dot marks a point; an alert is a stretch of TIME, and a spike
    // that lasted four seconds looked exactly like one that lasted one. Redrawing
    // the line and its fill in the alert colour over the affected span says how
    // long it went on, and does it in the shape the eye is already following.
    const alertRuns: [number, number][] = [];
    throttledBuckets.forEach((d, i) => {
      if (!d.hasAnomaly || yVal(d) <= 0) return;
      const last = alertRuns[alertRuns.length - 1];
      // Contiguous buckets become one band, so a sustained alert reads as a
      // single stretch instead of a row of separate marks.
      if (last && last[1] === i - 1) last[1] = i;
      else alertRuns.push([i, i]);
    });

    if (alertRuns.length > 0) {
      const alertGradId = `${gradId}-alert`;
      const alertGradient = defs
        .append('linearGradient')
        .attr('id', alertGradId)
        .attr('x1', '0%').attr('y1', '0%')
        .attr('x2', '0%').attr('y2', '100%');
      alertGradient.append('stop').attr('offset', '0%').attr('stop-color', alert).attr('stop-opacity', 0.55);
      alertGradient.append('stop').attr('offset', '100%').attr('stop-color', alert).attr('stop-opacity', 0.01);

      alertRuns.forEach(([from, to], runIndex) => {
        // Half a bucket of padding at each end, so the band covers the segments
        // leading into and out of the alert rather than stopping dead on the
        // sample points.
        const step = throttledBuckets.length > 1
          ? Math.abs(xScale(throttledBuckets[1].timeSec) - xScale(throttledBuckets[0].timeSec))
          : 8;
        const x0 = xScale(throttledBuckets[from].timeSec) - step / 2;
        const x1 = xScale(throttledBuckets[to].timeSec) + step / 2;

        const clipId = `${gradId}-alert-clip-${runIndex}`;
        defs.append('clipPath')
          .attr('id', clipId)
          .append('rect')
          .attr('x', x0)
          .attr('y', 0)
          .attr('width', Math.max(0, x1 - x0))
          .attr('height', innerHeight);

        g.append('path')
          .datum(throttledBuckets)
          .attr('fill', `url(#${alertGradId})`)
          .attr('d', area)
          .attr('clip-path', `url(#${clipId})`)
          .style('pointer-events', 'none');
        g.append('path')
          .datum(throttledBuckets)
          .attr('fill', 'none')
          .attr('stroke', alert)
          .attr('stroke-width', 2.5)
          .attr('d', line)
          .attr('clip-path', `url(#${clipId})`)
          .style('pointer-events', 'none');
      });
    }

    // The tooltip's hit targets. Invisible, and in the same places the dots
    // were: the bands are drawn with pointer-events disabled so they cannot
    // swallow the zoom overlay's gestures, which leaves nothing to hover.
    const anomalyBuckets = throttledBuckets.filter(d => d.hasAnomaly && yVal(d) > 0);
    g.selectAll<SVGCircleElement, TimelineBucket>('.anomaly-hit')
      .data(anomalyBuckets)
      .enter()
      .append('circle')
      .attr('class', 'anomaly-hit')
      .attr('cx', (d: TimelineBucket) => xScale(d.timeSec))
      .attr('cy', (d: TimelineBucket) => yScale(yVal(d)))
      .attr('r', 7)
      .attr('fill', 'transparent')
      .on('mouseenter', (_, d: TimelineBucket) => setHoveredBucket(d))
      .on('mouseleave', () => setHoveredBucket(null));

    // X Axis
    const xAxis = d3.axisBottom(xScale).ticks(4).tickFormat(d => `${d}s`);
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .attr('color', axis)
      .call(xAxis)
      .selectAll('text')
      .attr('font-size', '9px')
      // .style, not .attr: a presentation attribute would take the raw string,
      // and this needs the theme's mono stack rather than the OS default.
      .style('font-family', 'var(--font-mono)');

    // Y Axis
    const yAxis = d3.axisLeft(yScale).ticks(3).tickFormat(d => {
      const n = Number(d);
      if (metric === 'bandwidth') return `${n >= 1000 ? (n / 1000).toFixed(1) + 'M' : n.toFixed(0)}k`;
      return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`;
    });
    g.append('g')
      .attr('color', axis)
      .call(yAxis)
      .selectAll('text')
      .attr('font-size', '9px')
      // .style, not .attr: a presentation attribute would take the raw string,
      // and this needs the theme's mono stack rather than the OS default.
      .style('font-family', 'var(--font-mono)');

    // Zoom & Pan: transparent overlay rect captures wheel-zoom and drag-pan
    // gestures over the plot area. The behavior is re-seeded (silently, before
    // the 'zoom' listener is attached) to the current React zoomTransform on
    // every redraw, since the rect itself is a fresh DOM node each time.
    const zoomBehavior = d3
      .zoom<SVGRectElement, unknown>()
      .scaleExtent([1, 20])
      .translateExtent([[0, 0], [width, innerHeight]])
      .extent([[0, 0], [width, innerHeight]]);

    const zoomRect = g
      .append('rect')
      .attr('width', width)
      .attr('height', innerHeight)
      .attr('fill', 'transparent')
      .attr('cursor', zoomTransform.k > 1 ? 'grab' : 'default')
      .style('pointer-events', 'all')
      .call(zoomBehavior);

    zoomBehavior.transform(zoomRect, zoomTransform);
    zoomBehavior.on('zoom', event => setZoomTransform(event.transform));

    zoomBehaviorRef.current = zoomBehavior;
    zoomRectNodeRef.current = zoomRect.node();
    // `accent` is a dependency, not just a value read inside: that is what
    // makes a theme resolving after the first paint redraw the chart.
  }, [throttledBuckets, metric, isDark, themeKey, roomy, zoomTransform, accent, axis, alert, plot.width, plot.height]);

  const body = (
    <>
      {/* Title & Metric Toggles */}
      <div className={`flex items-center justify-between ${roomy ? 'pr-9' : ''}`}>
        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5 font-mono">
          <TbActivity className="w-3.5 h-3.5 text-foreground" />
          <span>Traffic Timeline</span>
        </h3>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setMetric('packets')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'packets' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            PKT/S
          </button>
          <button
            onClick={() => setMetric('bandwidth')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'bandwidth' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            KBPS
          </button>
          {/* Expand only - the overlay owns closing, in the same place for
              every widget, however the widget was opened. */}
          {onExpand && !roomy && (
            <button
              onClick={onExpand}
              data-widget-expand=""
              className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground transition-colors ml-1 cursor-pointer"
              aria-label="Expand chart"
              title="Expand chart"
            >
              <TbMaximize className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* SVG Canvas */}
      {/* An aspect ratio in the card, a fixed height in the overlay. The card
          is what gets dragged, and 44/15 is the shape the old 120px height gave
          at the column's default width - so a dashboard nobody has resized
          looks exactly as it did. The overlay is a fixed-size window, so there
          is nothing there for a ratio to track. */}
      <div
        ref={plotRef}
        className={`relative w-full overflow-hidden ${roomy ? 'h-[360px]' : 'aspect-[44/15]'}`}
      >
        <svg ref={svgRef} className="w-full h-full" />

        {/* Zoom in and out belong to the expanded view, the same way the geo
            map's do: this chart is 120px tall in the panel, where three buttons
            are a third of its height and there is nothing to look closer at
            anyway.

            RESET is not gated with them, and that is deliberate. The wheel
            still zooms the compact chart - hiding a button does not remove the
            gesture - so gating the way back on being expanded would let someone
            zoom in by accident and have no visible route out. It appears only
            when there is something to undo, so it costs nothing the rest of the
            time. */}
        <ZoomControls
          onZoomIn={roomy ? handleZoomIn : undefined}
          onZoomOut={roomy ? handleZoomOut : undefined}
          onReset={zoomTransform.k !== 1 ? handleResetZoom : undefined}
        />

        {hoveredBucket && (
          <div
            className="absolute top-1 left-1 text-xs px-2 py-1 rounded border pointer-events-none shadow-xl bg-popover border-border text-popover-foreground"
          >
            <div className="font-mono text-[10px] text-primary font-bold">T = {hoveredBucket.timeLabel}</div>
            <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
              <span>{hoveredBucket.packetCount} pkts</span> • <span>{hoveredBucket.kbps.toFixed(1)} Kbps</span>
            </div>
            {hoveredBucket.hasAnomaly && (
              <div className="text-rose-400 font-bold text-[10px] mt-0.5 flex items-center gap-1">
                <TbAlertTriangle className="w-3 h-3 text-rose-400" />
                {hoveredBucket.anomalyTitle}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Timeline bounds (reflects the current zoomed/panned view) */}
      <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
        <span>T={Math.round(visibleDomain[0])}s</span>
        <span className="text-primary font-bold">
          T={Math.round(visibleDomain[1])}s{Math.round(visibleDomain[1]) >= maxTime ? ' (NOW)' : ''}
        </span>
      </div>
    </>
  );

  // The overlay already drew the frame, so this is just the contents at the
  // tall layout. One branch, reached by both doors.
  if (variant === 'full') {
    return (
      <div ref={containerRef} className="w-full h-full p-4 select-none space-y-2.5">
        {body}
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="rounded-lg border p-3.5 transition-colors select-none bg-card border-border text-card-foreground shadow-sm space-y-2.5"
    >
      {body}
    </div>
  );
};
