import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Packet } from '../../types/packet';
import {
  TbActivity,
  TbAlertTriangle,
  TbMaximize,
  TbX,
  TbPlus,
  TbMinus,
  TbRotate,
} from 'react-icons/tb';

interface TrafficTimelineProps {
  packets: Packet[];
  isCapturing: boolean;
  isDark: boolean;
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
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGRectElement, unknown> | null>(null);
  const zoomRectNodeRef = useRef<SVGRectElement | null>(null);
  const [metric, setMetric] = useState<'packets' | 'bandwidth'>('packets');
  const [hoveredBucket, setHoveredBucket] = useState<TimelineBucket | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [zoomTransform, setZoomTransform] = useState<d3.ZoomTransform>(d3.zoomIdentity);
  const [visibleDomain, setVisibleDomain] = useState<[number, number]>([0, 10]);

  const handleZoomIn = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(200).call(zoomBehaviorRef.current.scaleBy, 1.5);
  };

  const handleZoomOut = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(200).call(zoomBehaviorRef.current.scaleBy, 1 / 1.5);
  };

  const handleResetZoom = () => {
    if (!zoomRectNodeRef.current || !zoomBehaviorRef.current) return;
    d3.select(zoomRectNodeRef.current).transition().duration(200).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
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

    const containerWidth = containerRef.current.clientWidth || 320;
    const height = isExpanded ? 360 : 120;
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
      gradient.append('stop').attr('offset', '0%').attr('stop-color', '#06b6d4').attr('stop-opacity', 0.6);
      gradient.append('stop').attr('offset', '100%').attr('stop-color', '#06b6d4').attr('stop-opacity', 0.01);
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
      .attr('stroke', metric === 'packets' ? '#06b6d4' : '#10b981')
      .attr('stroke-width', 2)
      .attr('d', line);

    // Anomaly / Spike Alert Indicators
    const anomalyBuckets = throttledBuckets.filter(d => d.hasAnomaly && yVal(d) > 0);
    g.selectAll<SVGCircleElement, TimelineBucket>('.anomaly-pulse')
      .data(anomalyBuckets)
      .enter()
      .append('circle')
      .attr('class', 'anomaly-pulse')
      .attr('cx', (d: TimelineBucket) => xScale(d.timeSec))
      .attr('cy', (d: TimelineBucket) => yScale(yVal(d)))
      .attr('r', 4.5)
      .attr('fill', '#f43f5e')
      .attr('stroke', isDark ? '#020617' : '#ffffff')
      .attr('stroke-width', 1.5)
      .on('mouseenter', (_, d: TimelineBucket) => setHoveredBucket(d))
      .on('mouseleave', () => setHoveredBucket(null));

    // X Axis
    const xAxis = d3.axisBottom(xScale).ticks(4).tickFormat(d => `${d}s`);
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .attr('color', isDark ? '#94a3b8' : '#64748b')
      .call(xAxis)
      .selectAll('text')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace');

    // Y Axis
    const yAxis = d3.axisLeft(yScale).ticks(3).tickFormat(d => {
      const n = Number(d);
      if (metric === 'bandwidth') return `${n >= 1000 ? (n / 1000).toFixed(1) + 'M' : n.toFixed(0)}k`;
      return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`;
    });
    g.append('g')
      .attr('color', isDark ? '#94a3b8' : '#64748b')
      .call(yAxis)
      .selectAll('text')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace');

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
  }, [throttledBuckets, metric, isDark, isExpanded, zoomTransform]);

  const body = (
    <>
      {/* Title & Metric Toggles */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5 font-mono">
          <TbActivity className="w-3.5 h-3.5 text-foreground" />
          <span>Traffic Timeline</span>
        </h3>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setMetric('packets')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'packets' ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            PKT/S
          </button>
          <button
            onClick={() => setMetric('bandwidth')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'bandwidth' ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            KBPS
          </button>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground transition-colors ml-1"
            title={isExpanded ? "Close expanded view" : "Expand chart"}
          >
            {isExpanded ? <TbX className="w-3.5 h-3.5" /> : <TbMaximize className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className={`relative w-full overflow-hidden ${isExpanded ? 'h-[360px]' : 'h-[120px]'}`}>
        <svg ref={svgRef} className="w-full h-full" />

        {/* Zoom Controls */}
        <div className="absolute top-1 right-1 flex flex-col gap-1 z-10">
          <button
            onClick={handleZoomIn}
            className="p-1 rounded border transition-colors bg-secondary border-border hover:bg-accent text-foreground"
            title="Zoom in"
          >
            <TbPlus className="w-3 h-3" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1 rounded border transition-colors bg-secondary border-border hover:bg-accent text-foreground"
            title="Zoom out"
          >
            <TbMinus className="w-3 h-3" />
          </button>
          {zoomTransform.k !== 1 && (
            <button
              onClick={handleResetZoom}
              className="p-1 rounded border transition-colors bg-secondary border-border hover:bg-accent text-foreground"
              title="Reset zoom"
            >
              <TbRotate className="w-3 h-3" />
            </button>
          )}
        </div>

        {hoveredBucket && (
          <div
            className="absolute top-1 left-1 text-xs px-2 py-1 rounded border pointer-events-none shadow-xl bg-popover border-border text-popover-foreground"
          >
            <div className="font-mono text-[10px] text-cyan-400 font-bold">T = {hoveredBucket.timeLabel}</div>
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
        <span className="text-cyan-400 font-bold">
          T={Math.round(visibleDomain[1])}s{Math.round(visibleDomain[1]) >= maxTime ? ' (NOW)' : ''}
        </span>
      </div>
    </>
  );

  if (isExpanded) {
    return (
      <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
        <div
          ref={containerRef}
          className="w-full max-w-6xl rounded-lg border p-4 transition-colors select-none bg-card border-border text-card-foreground shadow-2xl space-y-2.5"
        >
          {body}
        </div>
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
