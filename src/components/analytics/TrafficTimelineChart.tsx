import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Packet } from '../../types/packet';
import {
  Activity,
  AlertTriangle,
  RefreshCw,
  Zap,
  ArrowRight,
  Clock,
  Compass,
  Play,
  RotateCcw,
  Sparkles,
  Search,
} from 'lucide-react';

interface TrafficTimelineProps {
  packets: Packet[];
  isCapturing: boolean;
  onTimeWindowSelect?: (startTime: number | null, endTime: number | null) => void;
  onJumpToPacket?: (packet: Packet) => void;
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
  onTimeWindowSelect,
  onJumpToPacket,
  isDark,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [metric, setMetric] = useState<'packets' | 'bandwidth'>('packets');
  const [selectedRange, setSelectedRange] = useState<[number, number] | null>(null);
  const [activeJumpTime, setActiveJumpTime] = useState<number | null>(null);
  const [hoveredBucket, setHoveredBucket] = useState<TimelineBucket | null>(null);
  const [customJumpInput, setCustomJumpInput] = useState('');
  const [windowSpan, setWindowSpan] = useState<number>(5); // default ±5s span

  // Compute time bounds & buckets
  const { buckets, minTime, maxTime, anomalyEvents } = React.useMemo(() => {
    if (packets.length === 0) return { buckets: [], minTime: 0, maxTime: 10, anomalyEvents: [] };

    const bucketMap = new Map<number, { count: number; bytes: number; hasAnomaly: boolean; anomalyTitle?: string; firstPacket?: Packet }>();
    const anomalies: { sec: number; title: string; packet: Packet }[] = [];
    
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

      if (p.status === 'alert' || p.anomaly) {
        existing.hasAnomaly = true;
        existing.anomalyTitle = p.anomaly?.title || 'Security Alert';
        if (!anomalies.some(a => a.sec === sec)) {
          anomalies.push({
            sec,
            title: p.anomaly?.title || 'Security Spike',
            packet: p,
          });
        }
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

    return { buckets: result, minTime: minT, maxTime: maxT, anomalyEvents: anomalies.slice(-4) };
  }, [packets]);

  // Jump to specific time offset handler
  const handleJumpToOffset = (targetSec: number, span = windowSpan) => {
    setActiveJumpTime(targetSec);
    const t0 = Math.max(0, Math.floor(targetSec - span / 2));
    const t1 = Math.ceil(targetSec + span / 2);
    setSelectedRange([t0, t1]);

    if (onTimeWindowSelect) {
      onTimeWindowSelect(t0, t1);
    }

    // Find closest packet to targetSec and trigger inspection
    if (onJumpToPacket && packets.length > 0) {
      let closest = packets[0];
      let minDiff = Math.abs(packets[0].relativeTime - targetSec);
      for (const p of packets) {
        const diff = Math.abs(p.relativeTime - targetSec);
        if (diff < minDiff) {
          minDiff = diff;
          closest = p;
        }
      }
      onJumpToPacket(closest);
    }
  };

  const handleCustomJumpSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const val = parseFloat(customJumpInput);
    if (!isNaN(val) && val >= 0) {
      handleJumpToOffset(val);
      setCustomJumpInput('');
    }
  };

  const handleResetZoom = () => {
    setSelectedRange(null);
    setActiveJumpTime(null);
    if (onTimeWindowSelect) onTimeWindowSelect(null, null);
  };

  // Render D3 chart
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || buckets.length === 0) return;

    const containerWidth = containerRef.current.clientWidth || 320;
    const height = 120;
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

    // X Scale
    const xExtent = d3.extent(buckets, (d: TimelineBucket) => d.timeSec) as [number, number];
    const xScale = d3.scaleLinear().domain([xExtent[0] || 0, xExtent[1] || 10]).range([0, width]);

    // Y Scale
    const yVal = (d: TimelineBucket) => (metric === 'packets' ? d.packetCount : d.kbps);
    const maxY = Math.max(8, d3.max(buckets, yVal) || 8);
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

    g.append('path').datum(buckets).attr('fill', `url(#${gradId})`).attr('d', area);
    g.append('path')
      .datum(buckets)
      .attr('fill', 'none')
      .attr('stroke', metric === 'packets' ? '#06b6d4' : '#10b981')
      .attr('stroke-width', 2)
      .attr('d', line);

    // Active Jump Target Marker Line
    if (activeJumpTime !== null && activeJumpTime >= (xExtent[0] || 0) && activeJumpTime <= (xExtent[1] || 10)) {
      const jumpX = xScale(activeJumpTime);
      g.append('line')
        .attr('x1', jumpX)
        .attr('x2', jumpX)
        .attr('y1', 0)
        .attr('y2', innerHeight)
        .attr('stroke', '#38bdf8')
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', '3,3');

      g.append('circle')
        .attr('cx', jumpX)
        .attr('cy', 4)
        .attr('r', 4)
        .attr('fill', '#38bdf8')
        .attr('stroke', '#020617')
        .attr('stroke-width', 1.5);
    }

    // Anomaly / Spike Alert Indicators
    const anomalyBuckets = buckets.filter(d => d.hasAnomaly && yVal(d) > 0);
    g.selectAll<SVGCircleElement, TimelineBucket>('.anomaly-pulse')
      .data(anomalyBuckets)
      .enter()
      .append('circle')
      .attr('class', 'anomaly-pulse')
      .attr('cx', (d: TimelineBucket) => xScale(d.timeSec))
      .attr('cy', (d: TimelineBucket) => yScale(yVal(d)))
      .attr('r', 4.5)
      .attr('fill', '#f43f5e')
      .attr('stroke', '#020617')
      .attr('stroke-width', 1.5)
      .attr('cursor', 'pointer')
      .on('click', (_, d: TimelineBucket) => handleJumpToOffset(d.timeSec))
      .on('mouseenter', (_, d: TimelineBucket) => setHoveredBucket(d))
      .on('mouseleave', () => setHoveredBucket(null));

    // X Axis
    const xAxis = d3.axisBottom(xScale).ticks(4).tickFormat(d => `${d}s`);
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .attr('color', isDark ? '#64748b' : '#94a3b8')
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
      .attr('color', isDark ? '#64748b' : '#94a3b8')
      .call(yAxis)
      .selectAll('text')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace');

    // Brush Tool
    const brush = d3
      .brushX()
      .extent([
        [0, 0],
        [width, innerHeight],
      ])
      .on('end', event => {
        if (!event.selection) {
          if (!activeJumpTime) {
            setSelectedRange(null);
            if (onTimeWindowSelect) onTimeWindowSelect(null, null);
          }
          return;
        }
        const [x0, x1] = event.selection as [number, number];
        const t0 = Math.max(0, Math.floor(xScale.invert(x0)));
        const t1 = Math.ceil(xScale.invert(x1));
        setSelectedRange([t0, t1]);
        setActiveJumpTime((t0 + t1) / 2);
        if (onTimeWindowSelect) onTimeWindowSelect(t0, t1);
      });

    g.append('g').attr('class', 'brush').call(brush);
  }, [buckets, metric, isDark, activeJumpTime]);

  // Available quick-jump presets relative to current capture
  const nowSec = maxTime;
  const tMinus60 = Math.max(0, nowSec - 60);
  const tMinus30 = Math.max(0, nowSec - 30);
  const tMinus10 = Math.max(0, nowSec - 10);

  return (
    <div
      ref={containerRef}
      className={`rounded-lg border p-3.5 transition-colors select-none ${
        isDark ? 'bg-slate-900/90 border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      } shadow-sm space-y-2.5`}
    >
      {/* Title & Metric Toggles */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5 font-mono">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Traffic Timeline</span>
        </h3>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setMetric('packets')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'packets' ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            PKT/S
          </button>
          <button
            onClick={() => setMetric('bandwidth')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-all cursor-pointer ${
              metric === 'bandwidth' ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            KBPS
          </button>
        </div>
      </div>

      {/* 🚀 QUICK-JUMP NAVIGATION BAR */}
      <div className="bg-slate-950/80 rounded-md border border-slate-800 p-2 space-y-2">
        {/* Top Row: Quick Presets & Live Jump */}
        <div className="flex items-center justify-between gap-1.5">
          <div className="flex items-center gap-1 text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider shrink-0">
            <Compass className="w-3.5 h-3.5 text-cyan-400 animate-spin-slow" />
            <span>Quick-Jump:</span>
          </div>

          <div className="flex items-center gap-1 overflow-x-auto custom-scrollbar text-[10px] font-mono">
            <button
              onClick={() => handleJumpToOffset(0)}
              className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:text-cyan-300 transition-colors shrink-0 cursor-pointer"
              title="Jump to beginning of packet capture (T=0s)"
            >
              ⏮ T=0s
            </button>

            {nowSec > 35 && (
              <button
                onClick={() => handleJumpToOffset(tMinus30)}
                className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:text-cyan-300 transition-colors shrink-0 cursor-pointer"
                title={`Jump to -30s (T=${tMinus30}s)`}
              >
                -30s
              </button>
            )}

            {nowSec > 15 && (
              <button
                onClick={() => handleJumpToOffset(tMinus10)}
                className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:text-cyan-300 transition-colors shrink-0 cursor-pointer"
                title={`Jump to -10s (T=${tMinus10}s)`}
              >
                -10s
              </button>
            )}

            <button
              onClick={() => handleJumpToOffset(nowSec)}
              className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/30 font-bold transition-colors shrink-0 cursor-pointer flex items-center gap-1"
              title="Jump to current live time head"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              <span>LIVE</span>
            </button>
          </div>
        </div>

        {/* Second Row: Direct Seconds Jump Input & Window Span */}
        <div className="flex items-center justify-between gap-2 pt-1 border-t border-slate-800/80">
          <form onSubmit={handleCustomJumpSubmit} className="flex items-center gap-1 flex-1">
            <span className="text-[10px] text-slate-500 font-mono shrink-0">Offset:</span>
            <div className="flex items-center bg-slate-900 rounded border border-slate-700 px-1.5 py-0.5 flex-1 max-w-[100px]">
              <input
                type="number"
                step="0.1"
                min="0"
                max={maxTime}
                value={customJumpInput}
                onChange={e => setCustomJumpInput(e.target.value)}
                placeholder={`${nowSec.toFixed(1)}s`}
                className="w-full bg-transparent text-[11px] font-mono text-slate-100 outline-none placeholder:text-slate-600"
              />
              <span className="text-[10px] text-slate-500 font-mono">s</span>
            </div>
            <button
              type="submit"
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 font-bold text-[10px] font-mono transition-colors cursor-pointer"
            >
              Go
            </button>
          </form>

          {/* Span Window Selector */}
          <div className="flex items-center gap-1 text-[10px] font-mono shrink-0">
            <span className="text-slate-500">Span:</span>
            {[2, 5, 10].map(s => (
              <button
                key={s}
                onClick={() => {
                  setWindowSpan(s);
                  if (activeJumpTime !== null) handleJumpToOffset(activeJumpTime, s);
                }}
                className={`px-1.5 py-0.5 rounded text-[9px] font-bold transition-colors cursor-pointer ${
                  windowSpan === s
                    ? 'bg-cyan-500 text-slate-950'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                ±{s}s
              </button>
            ))}
          </div>
        </div>

        {/* Third Row: Anomaly Quick Jump Pills (if threats exist) */}
        {anomalyEvents.length > 0 && (
          <div className="flex items-center gap-1.5 pt-1 border-t border-slate-800/80 overflow-x-auto custom-scrollbar">
            <span className="text-[9px] font-mono font-bold text-rose-400 uppercase tracking-tight shrink-0 flex items-center gap-1">
              <AlertTriangle className="w-2.5 h-2.5" />
              <span>Spikes:</span>
            </span>
            {anomalyEvents.map(evt => (
              <button
                key={evt.sec}
                onClick={() => handleJumpToOffset(evt.sec)}
                className="px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 hover:bg-rose-500/25 text-rose-300 text-[9px] font-mono transition-colors shrink-0 flex items-center gap-1 cursor-pointer"
                title={`Jump to ${evt.title} at ${evt.sec}s`}
              >
                <span>⚡ {evt.sec}s</span>
                <span className="truncate max-w-[60px] opacity-80">{evt.title}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full h-[120px] overflow-hidden">
        <svg ref={svgRef} className="w-full h-full" />

        {hoveredBucket && (
          <div
            className={`absolute top-1 right-1 text-xs px-2 py-1 rounded border pointer-events-none shadow-xl ${
              isDark ? 'bg-slate-950 border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900'
            }`}
          >
            <div className="font-mono text-[10px] text-cyan-400 font-bold">T = {hoveredBucket.timeLabel}</div>
            <div className="text-[10px] text-slate-300 font-mono mt-0.5">
              <span>{hoveredBucket.packetCount} pkts</span> • <span>{hoveredBucket.kbps.toFixed(1)} Kbps</span>
            </div>
            {hoveredBucket.hasAnomaly && (
              <div className="text-rose-400 font-bold text-[10px] mt-0.5 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-rose-400" />
                {hoveredBucket.anomalyTitle}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Timeline bounds & Reset action */}
      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono uppercase tracking-wider">
        <span>T={minTime}s</span>
        {selectedRange ? (
          <button
            onClick={handleResetZoom}
            className="text-amber-400 hover:text-amber-300 flex items-center gap-1 normal-case font-bold cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Zoom [{selectedRange[0]}s-{selectedRange[1]}s]</span>
          </button>
        ) : (
          <span className="text-slate-400">Drag to brush or click jump</span>
        )}
        <span className="text-cyan-400 font-bold">T={maxTime}s (NOW)</span>
      </div>
    </div>
  );
};
