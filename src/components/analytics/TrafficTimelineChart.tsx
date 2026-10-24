import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Packet } from '../../types/packet';
import { CATEGORY_LABELS, categoryOfPacket, isFaultCategory } from '../../services/expertInfo';
import { TriangleAlert } from 'lucide-react';
import { ZoomControls } from './ZoomControls';
import { useElementSize } from '../../lib/useElementSize';
import { prefersReducedMotion } from '../../lib/motion';
import { useThemeToken } from '../../lib/themeColor';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';
import { useDebouncedValue } from '../../lib/useDebouncedValue';
import { FilterEngine } from '../../services/filterEngine';
import { timelineIndex } from '../../services/report/timeline';
import { MICRO_LABEL } from '../common/typography';

export type TimelineMetric = 'packets' | 'bytes';
export type TimelineChart = 'area' | 'bars';

interface TrafficTimelineProps {
  packets: Packet[];
  isDark: boolean;
  /** The active theme's name. Not used for styling - it exists so this
   *  imperative D3 draw re-runs when the theme changes. isDark alone cannot
   *  do that: Dark and Mono are both dark, so it stays true across a switch
   *  between them and the chart would keep the previous accent. */
  themeKey?: string;
  /**
   * What the Y axis counts, and how the series is drawn.
   *
   * Both were local state - a PKT/S / KBPS pair of pills, and no chart choice
   * at all. They are stored settings now, which is what lets the same widget
   * appear twice in one dashboard as a packet-rate area and a byte-rate
   * histogram.
   */
  metric: TimelineMetric;
  chart: TimelineChart;
  /**
   * Bucket width in seconds.
   *
   * Was hardcoded to one, which is the wrong answer at both ends of the range:
   * a microburst is invisible at one-second resolution, and an hour-long
   * capture is 3,600 buckets of noise.
   */
  intervalSeconds?: number;
  /**
   * A display filter for a SECOND series, drawn over the first.
   *
   * This is what makes the widget an I/O graph rather than a throughput chart:
   * "how much of this traffic is X, over time" is the question it exists to
   * answer, and it cannot be answered by filtering the whole app - that would
   * remove the total the answer is measured against.
   *
   * Empty means one series, which is what the chart has always drawn.
   */
  overlayFilter?: string;
}

interface TimelineBucket {
  timeSec: number;
  timeLabel: string;
  packetCount: number;
  byteCount: number;
  /** The part of this bucket matching the overlay filter, if there is one. */
  matchCount: number;
  matchBytes: number;
  kbps: number;
  hasAnomaly: boolean;
  anomalyTitle?: string;
  firstPacket?: Packet;
}

export const TrafficTimelineChart: React.FC<TrafficTimelineProps> = ({
  packets,
  isDark,
  themeKey,
  metric,
  chart,
  intervalSeconds = 1,
  overlayFilter = '',
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
  const [hoveredBucket, setHoveredBucket] = useState<TimelineBucket | null>(null);
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
  // Bandwidth was drawn in a hardcoded `#10b981` - the one colour in this
  // chart that followed nothing, which is exactly the fault the axis comment
  // above records and fixes for the axis. Same token every success state in
  // the app uses, so switching metric changes hue with the theme rather than
  // against it.
  const bandwidth = useThemeToken('--success', '#10b981');

  // D3 transitions are JavaScript writing values every frame, so the CSS
  // reduced-motion rule does not apply to them. Zero duration keeps the same
  // call path and simply lands immediately.
  const zoomDuration = () => (prefersReducedMotion() ? 0 : 200);

  const handleResetZoom = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(zoomDuration()).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  /**
   * How far back the axis reaches when the capture is shorter than this. Only
   * a floor for the empty chart - a longer capture keeps every second it has.
   */
  const MIN_AXIS_SECONDS = 10;
  /**
   * The bucket width, clamped. A stored config is untrusted input and a zero
   * or negative interval divides the whole capture into one bucket at index
   * Infinity.
   */
  const bucketSeconds = Number.isFinite(intervalSeconds) && intervalSeconds > 0
    ? Math.min(intervalSeconds, 3600)
    : 1;
  /** How much empty axis is drawn ahead of the newest packet. */
  const SEEDED_WINDOW_SECONDS = 60;

  /**
   * Per-second buckets, folded one packet at a time.
   *
   * This used to walk the whole buffer on every dashboard tick to rebuild
   * counts that had not changed - a packet's second, length and anomaly are
   * fixed the moment it arrives. The fold keeps the bucket map across ticks and
   * reads only the packets that arrived during the tick; what still runs every
   * tick is the finalize below, which is O(seconds captured) rather than
   * O(packets). See useIncrementalAggregate.
   *
   * `first`/`last` are carried in the accumulator rather than read off
   * `packets`, so finalize needs nothing but the fold - and so that a trim,
   * which restarts the fold, moves the axis with it.
   */
  /**
   * The overlay's predicate, compiled once per SETTLED filter string.
   *
   * An expression that does not compile yields null rather than throwing, and
   * the chart then draws one series - the same as an empty filter. The filter
   * is typed a character at a time, so most of what this sees is an incomplete
   * expression, and a chart that vanished while a filter was being written
   * would be unusable.
   *
   * The debounce is what keeps that tolerance cheap, and it is on the WORK
   * rather than on the field: `GraphsTab` writes the store and renders the
   * input on every keystroke, so the box never drops a character. What waits
   * is the compile and everything downstream of it.
   *
   * Downstream is the expensive half. This matcher is a reset dependency of
   * `useIncrementalAggregate` below, and a reset re-folds the entire buffer
   * from zero, synchronously, during render - 16.6ms at a 21,903-frame buffer,
   * more at the 50,000 cap, on the main thread while a capture flushes at
   * 10Hz. Undebounced, every prefix of `tcp.port == 443` that happens to
   * compile pays that in full: `tcp`, `tcp.port`, `tcp.port == 4`, and so on.
   * Prefixes that do NOT compile are free, because two nulls are the same
   * identity and the memo's consumer never sees a change - which is why the
   * cost is invisible on a filter typed slowly and obvious on one typed
   * fluently.
   *
   * 250ms because it has to outlast the gap between keystrokes inside a
   * typed phrase while staying under what reads as lag once the typing stops.
   * The draw is throttled at 150ms further down, so a settled filter reaches
   * the screen within one frame budget of that.
   */
  const settledOverlayFilter = useDebouncedValue(overlayFilter, 250);
  const overlayMatcher = React.useMemo(() => {
    const trimmed = settledOverlayFilter.trim();
    if (!trimmed) return null;
    try {
      return FilterEngine.compileFilter(trimmed);
    } catch {
      return null;
    }
  }, [settledOverlayFilter]);

  const { buckets, maxTime } = useIncrementalAggregate(
    packets,
    () => ({
      seconds: new Map<number, { count: number; bytes: number; match: number; matchBytes: number; hasAnomaly: boolean; anomalyTitle?: string; firstPacket?: Packet }>(),
      first: Number.NaN,
      last: Number.NaN,
    }),
    (acc, p) => {
      if (Number.isNaN(acc.first)) acc.first = p.relativeTime;
      acc.last = p.relativeTime;

      // Bucket INDEX, not seconds: the axis multiplies back by the interval.
      // Shared with the report's timeline, so both put a frame in one bucket.
      const sec = timelineIndex(p.relativeTime, bucketSeconds);
      let bucket = acc.seconds.get(sec);
      if (!bucket) {
        bucket = { count: 0, bytes: 0, match: 0, matchBytes: 0, hasAnomaly: false };
        acc.seconds.set(sec, bucket);
      }
      bucket.count += 1;
      bucket.bytes += p.length;
      if (!bucket.firstPacket) bucket.firstPacket = p;

      if (overlayMatcher) {
        // A rule that throws on one frame must not stop the fold; it simply
        // did not match that frame.
        try {
          if (overlayMatcher(p)) { bucket.match += 1; bucket.matchBytes += p.length; }
        } catch { /* not a match */ }
      }

      const category = categoryOfPacket(p);
      if (isFaultCategory(category)) {
        bucket.hasAnomaly = true;
        bucket.anomalyTitle = CATEGORY_LABELS[category!];
      }
    },
    (acc) => {
      if (acc.seconds.size === 0) return { buckets: [] as TimelineBucket[], maxTime: MIN_AXIS_SECONDS };

      // Everything below counts in bucket INDEXES and converts to seconds on
      // the way out, so the axis is in seconds whatever the interval is.
      const minIndex = timelineIndex(acc.first, bucketSeconds);
      let maxIndex = Math.ceil(acc.last / bucketSeconds);
      const minSpan = Math.ceil(MIN_AXIS_SECONDS / bucketSeconds);
      if (maxIndex - minIndex < minSpan) maxIndex = minIndex + minSpan;

      // A quiet stretch has to be drawn as a quiet stretch rather than as a gap
      // the area chart closes over, so the trailing window is filled in whether
      // or not any packet landed in it.
      const seconds = new Set(acc.seconds.keys());
      const seeded = Math.ceil(SEEDED_WINDOW_SECONDS / bucketSeconds);
      for (let t = Math.max(0, maxIndex - seeded); t <= maxIndex; t++) seconds.add(t);

      const result: TimelineBucket[] = [];
      for (const k of Array.from(seconds).sort((a, b) => a - b)) {
        const b = acc.seconds.get(k) ?? { count: 0, bytes: 0, match: 0, matchBytes: 0, hasAnomaly: false };
        const at = k * bucketSeconds;
        result.push({
          timeSec: at,
          // Sub-second buckets need a decimal or every label in a burst reads
          // the same; whole-second ones must not grow one.
          timeLabel: bucketSeconds < 1 ? `${at.toFixed(1)}s` : `${at}s`,
          packetCount: b.count,
          byteCount: b.bytes,
          matchCount: b.match,
          matchBytes: b.matchBytes,
          kbps: (b.bytes * 8) / 1024,
          hasAnomaly: b.hasAnomaly,
          anomalyTitle: b.anomalyTitle,
          firstPacket: b.firstPacket,
        });
      }

      return { buckets: result, maxTime: maxIndex * bucketSeconds };
    },
    // Both change what is already folded in, so a change to either has to be
    // answered by folding again from zero - which is what listing them does.
    [bucketSeconds, overlayMatcher],
  );

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
    const height = plot.height || 120;
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

    const seriesColor = metric === 'packets' ? accent : bandwidth;
    gradient.append('stop').attr('offset', '0%').attr('stop-color', seriesColor).attr('stop-opacity', 0.6);
    gradient.append('stop').attr('offset', '100%').attr('stop-color', seriesColor).attr('stop-opacity', 0.01);

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

    // The overlay: the part of each bucket matching the widget's filter,
    // drawn against the SAME y scale as the total so the two are comparable by
    // height. That is the whole point of a second series - a chart of the
    // filtered traffic on its own axis would answer "how much X" without
    // answering "how much of this".
    const overlayVal = (d: TimelineBucket) => (metric === 'packets' ? d.matchCount : (d.matchBytes * 8) / 1024);
    const hasOverlay = overlayMatcher !== null && throttledBuckets.some((d) => overlayVal(d) > 0);

    if (chart === 'bars') {
      // One column per second, sized from the same scales the area uses, so
      // switching chart type moves nothing but the marks. The width is derived
      // from the zoomed spacing between adjacent seconds rather than from a
      // constant: zoomed in, the columns have to grow with the gaps or the
      // chart turns into a row of hairlines with daylight between them.
      const step = Math.abs(xScale(1) - xScale(0));
      const barWidth = Math.max(1, Math.min(step * 0.7, 24));
      g.selectAll('rect.nv-bar')
        .data(throttledBuckets.filter((d) => yVal(d) > 0))
        .join('rect')
        .attr('class', 'nv-bar')
        .attr('x', (d) => xScale(d.timeSec) - barWidth / 2)
        .attr('y', (d) => yScale(yVal(d)))
        .attr('width', barWidth)
        .attr('height', (d) => Math.max(1, innerHeight - yScale(yVal(d))))
        .attr('rx', Math.min(2, barWidth / 2))
        // An anomalous second is coloured rather than marked, for the same
        // reason the area chart repaints its span below: the bar IS the
        // second, so there is nothing to point at that the bar is not.
        .attr('fill', (d) => (d.hasAnomaly ? alert : seriesColor))
        .attr('opacity', hasOverlay ? 0.35 : 0.85);

      if (hasOverlay) {
        // Drawn over the total's column, from the same baseline, so the
        // matching share reads as a proportion of the bar it sits inside.
        g.selectAll('rect.nv-bar-overlay')
          .data(throttledBuckets.filter((d) => overlayVal(d) > 0))
          .join('rect')
          .attr('class', 'nv-bar-overlay')
          .attr('x', (d) => xScale(d.timeSec) - barWidth / 2)
          .attr('y', (d) => yScale(overlayVal(d)))
          .attr('width', barWidth)
          .attr('height', (d) => Math.max(1, innerHeight - yScale(overlayVal(d))))
          .attr('rx', Math.min(2, barWidth / 2))
          .attr('fill', alert)
          .attr('opacity', 0.9);
      }
    } else {
      g.append('path').datum(throttledBuckets).attr('fill', `url(#${gradId})`).attr('d', area);
      g.append('path')
        .datum(throttledBuckets)
        .attr('fill', 'none')
        .attr('stroke', seriesColor)
        .attr('stroke-width', 2)
        .attr('opacity', hasOverlay ? 0.45 : 1)
        .attr('d', line);

      if (hasOverlay) {
        const overlayLine = d3
          .line<TimelineBucket>()
          .x((d) => xScale(d.timeSec))
          .y((d) => yScale(overlayVal(d)))
          .curve(d3.curveMonotoneX);
        g.append('path')
          .datum(throttledBuckets)
          .attr('fill', 'none')
          .attr('stroke', alert)
          .attr('stroke-width', 2)
          .attr('d', overlayLine);
      }
    }

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

    // Only the area chart needs this pass. A bar chart has already said which
    // seconds were anomalous by colouring those bars, and painting a band over
    // them as well would be the same fact drawn twice.
    if (alertRuns.length > 0 && chart !== 'bars') {
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
      if (metric === 'bytes') return `${n >= 1000 ? (n / 1000).toFixed(1) + 'M' : n.toFixed(0)}k`;
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
  }, [throttledBuckets, metric, chart, overlayMatcher, isDark, themeKey, zoomTransform, accent, axis, alert, bandwidth, plot.width, plot.height]);

  return (
    <div ref={containerRef} className="h-full flex flex-col gap-1.5">
      {/* The plot fills whatever the card gives it, rather than asserting a
          shape of its own. It used to carry an aspect ratio in the card and a
          hardcoded 360px in the overlay - two numbers this component chose,
          neither of which survives a dashboard where the card's height comes
          from the registry and the popout bubble's from its content. */}
      <div ref={plotRef} className="relative flex-1 min-h-0 w-full overflow-hidden">
        <svg ref={svgRef} className="w-full h-full" />

        {/* Zoom in and out are gone with the expanded window that used to be
            the only place they appeared: at card height three stacked buttons
            are a third of the chart.

            RESET stays, and that is deliberate. The wheel still zooms the card
            - removing a button does not remove the gesture - so without this
            somebody who zooms in by accident has no visible way back. It
            appears only when there is something to undo, so it costs nothing
            the rest of the time. */}
        <ZoomControls onReset={zoomTransform.k !== 1 ? handleResetZoom : undefined} />

        {hoveredBucket && (
          <div className="absolute top-1 left-1 text-xs px-2 py-1 rounded border pointer-events-none shadow-xl bg-popover border-border text-popover-foreground">
            <div className="text-[10px] text-primary font-bold">T = {hoveredBucket.timeLabel}</div>
            <div className="text-[10px] text-muted-foreground mt-0.5">
              <span>{hoveredBucket.packetCount} pkts</span> - <span>{hoveredBucket.kbps.toFixed(1)} Kbps</span>
            </div>
            {overlayMatcher && (
              <div className="text-[10px] mt-0.5 text-danger-muted">
                {hoveredBucket.matchCount} matching
                {hoveredBucket.packetCount > 0 && (
                  <span className="text-muted-foreground">
                    {' '}({((hoveredBucket.matchCount / hoveredBucket.packetCount) * 100).toFixed(0)} %)
                  </span>
                )}
              </div>
            )}
            {hoveredBucket.hasAnomaly && (
              <div className="text-danger-muted font-bold text-[10px] mt-0.5 flex items-center gap-1">
                <TriangleAlert className="w-3 h-3 text-danger" />
                {hoveredBucket.anomalyTitle}
              </div>
            )}
          </div>
        )}
      </div>

      {/* The window currently in view, which zoom and pan move. */}
      <div className={`flex items-center justify-between ${MICRO_LABEL} shrink-0`}>
        <span>T={Math.round(visibleDomain[0])}s</span>
        <span className="font-bold">
          T={Math.round(visibleDomain[1])}s{Math.round(visibleDomain[1]) >= maxTime ? ' (NOW)' : ''}
        </span>
      </div>
    </div>
  );
};
