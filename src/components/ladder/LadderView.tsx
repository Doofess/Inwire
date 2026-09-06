import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
// From `d3`, which is a direct dependency, rather than `d3-scale`, which is
// only reachable through it. It supplies the tick placement and the domain
// mapping and nothing else - React owns every element, the same split
// `TrafficTimelineChart` uses.
import { scaleLinear } from 'd3';
import type { ExpertCategory, Packet } from '../../types/packet';
import { clientEnd, streamPackets, type StreamTarget } from '../../services/followStream';
import {
  arrowsThatFit, initialWindow, ladderExtent, layoutLadder, panWindow,
  windowAround, zoomWindow,
  type LadderArrow, type LadderWindow,
} from './ladderLayout';

/**
 * One conversation as a ladder: two lanes, time running down, an arrow per
 * frame.
 *
 * The view the packet list cannot be. A list is ordered by time and says
 * nothing about *shape* - a request answered four seconds later, a side that
 * went quiet, a retransmission burst, a handshake - all of which are obvious
 * as geometry and invisible as rows. This is the same frames, drawn so the
 * shape is the thing you see first.
 *
 * ## Only what is on screen exists
 *
 * A stream can be a hundred thousand frames. `streamPackets` selects them once
 * - one pass over the buffer, returning references - and `layoutLadder`
 * positions only those inside the current time window, a few hundred at most.
 * Zooming and panning re-run the layout, never the selection.
 *
 * ## Why SVG and why D3 for one thing
 *
 * D3 supplies the time scale and nothing else; React owns every element, the
 * same split `TrafficTimelineChart` already uses. SVG rather than divs because
 * arrows need line caps, markers and diagonal hit-testing, all of which are
 * one attribute each here and a pile of transforms in HTML.
 *
 * ## Transit frames are not shown
 *
 * A ladder is about two endpoints. A frame this machine merely overheard
 * belongs to neither lane, and inventing a lane for it would be inventing a
 * participant. Such frames are not on this stream's five-tuple anyway.
 */

const LANE_INSET = 132;
const TOP_PAD = 16;
const BOTTOM_PAD = 16;
/** Enough for a label between the lanes without crowding either. */
const MIN_HEIGHT = 240;

/**
 * An arrow's stroke, when the frame carries a finding worth showing.
 *
 * This used to be a fourth private copy of the severity palette. It reads the
 * shared category set now, and only for the categories that mean something
 * went wrong - a keep-alive or an unverifiable checksum recolouring an arrow
 * would drown the one thing the lane colours are for, which is direction.
 */
const CATEGORY_STROKE: Partial<Record<ExpertCategory, string>> = {
  Broken: 'var(--color-rose-500, #f43f5e)',
  Reset: 'var(--color-red-600, #dc2626)',
  Security: 'var(--color-fuchsia-500, #d946ef)',
  Loss: 'var(--color-amber-500, #f59e0b)',
};

interface LadderViewProps {
  target: StreamTarget;
  packets: Packet[];
  /** The frame selected elsewhere, highlighted here. */
  selectedId?: number;
  /** Clicking an arrow selects that frame in the packet list. */
  onSelectFrame?: (id: number) => void;
}

export const LadderView: React.FC<LadderViewProps> = ({
  target, packets, selectedId, onSelectFrame,
}) => {
  // One pass over the buffer, when the target changes and not on every zoom.
  // The result is references into the buffer, so this costs the array and
  // nothing else.
  const frames = useMemo(() => streamPackets(packets, target), [packets, target]);
  const client = useMemo(() => clientEnd(frames, target), [frames, target]);
  const extent = useMemo(() => ladderExtent(frames), [frames]);

  const [window, setWindow] = useState<LadderWindow>(extent);
  const [size, setSize] = useState({ width: 720, height: 480 });
  const boxRef = useRef<HTMLDivElement | null>(null);

  // A new conversation opens on a window that FITS, not on the whole stream.
  // A busy conversation is a thousand frames over two minutes, and drawing all
  // of them into a viewport with room for a dozen is not a dense view of the
  // conversation - it is an unreadable one. The minimap says where in the whole
  // this sits.
  //
  // It also has to be reset per stream: opening a second one would otherwise
  // inherit the first's window, which is a range of seconds that may not exist
  // in the new one - an empty ladder that looks broken.
  useEffect(() => {
    setWindow(initialWindow(frames, plotHeightRef.current));
  }, [frames]);

  useLayoutEffect(() => {
    const box = boxRef.current;
    if (box === null) return;
    const observer = new ResizeObserver(() => {
      setSize({
        width: box.clientWidth,
        height: Math.max(box.clientHeight, MIN_HEIGHT),
      });
    });
    observer.observe(box);
    return () => observer.disconnect();
  }, []);

  const plotHeight = Math.max(size.height - TOP_PAD - BOTTOM_PAD, 1);
  // Read inside the effect above without making it a dependency: the window is
  // chosen once per stream, and re-choosing it every time the panel is resized
  // would throw away a zoom the user had set.
  const plotHeightRef = useRef(plotHeight);
  plotHeightRef.current = plotHeight;
  // Capped at what the viewport can show. The window alone cannot bound this:
  // a window sized to seventeen frames at the quiet start of a connection is
  // ninety seconds wide, and ninety seconds later in the same conversation
  // holds a thousand. See `layoutLadder`.
  const layout = useMemo(
    () => layoutLadder(frames, client, window, plotHeight, arrowsThatFit(plotHeight)),
    [frames, client, window, plotHeight],
  );

  /**
   * Following the selection, but only when it is not already visible.
   *
   * Re-centring on every selection would fight the user: clicking an arrow
   * selects the frame, which would then scroll the arrow they just clicked
   * into the middle and move everything under the pointer.
   */
  useEffect(() => {
    if (selectedId === undefined) return;
    const frame = frames.find((f) => f.id === selectedId);
    if (frame === undefined) return;
    if (frame.relativeTime >= window.from && frame.relativeTime <= window.to) return;
    setWindow((current) => windowAround(frame.relativeTime, current, extent));
  }, [selectedId, frames, extent]);

  const onWheel = useCallback((event: React.WheelEvent) => {
    const box = boxRef.current;
    if (box === null) return;
    event.preventDefault();
    const bounds = box.getBoundingClientRect();
    const anchor = Math.min(Math.max(
      (event.clientY - bounds.top - TOP_PAD) / plotHeight, 0), 1);
    // Shift is pan, plain wheel is zoom - the convention every timeline in the
    // app already uses, and the one a trackpad's vertical gesture expects.
    setWindow((current) => event.shiftKey
      ? panWindow(current, extent, event.deltaY > 0 ? 0.2 : -0.2)
      : zoomWindow(current, extent, event.deltaY > 0 ? 1.25 : 0.8, anchor));
  }, [extent, plotHeight]);

  const timeScale = useMemo(
    () => scaleLinear().domain([window.from, window.to]).range([0, plotHeight]),
    [window, plotHeight],
  );

  const svgHeight = Math.max(size.height, layout.contentHeight + TOP_PAD + BOTTOM_PAD);
  const clientX = LANE_INSET;
  const serverX = Math.max(size.width - LANE_INSET, LANE_INSET + 120);
  const zoomed = (window.to - window.from) < (extent.to - extent.from) - 1e-9;

  if (frames.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-xs text-muted-foreground">
        No frames on this stream.
      </div>
    );
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col">
      {/* Lane headers, outside the scrolling area so they stay put. */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-border
        text-[11px] font-mono bg-secondary/40 shrink-0">
        <span className="text-rose-500 font-semibold truncate" style={{ maxWidth: 260 }}>
          {client.address}:{client.port}
        </span>
        <span className="text-muted-foreground">
          {layout.arrows.length} of {frames.length} frames
          {zoomed && ' · wheel to zoom, shift-wheel to pan'}
        </span>
        <span className="text-sky-500 font-semibold truncate text-right" style={{ maxWidth: 260 }}>
          {client.address === target.addressA
            ? `${target.addressB}:${target.portB}`
            : `${target.addressA}:${target.portA}`}
        </span>
      </div>

      {/* Frames above and below the window, said rather than left to be
          inferred from a scrollbar that is not there. */}
      {layout.before > 0 && (
        <button onClick={() => setWindow((c) => panWindow(c, extent, -0.5))}
          className="text-[11px] py-0.5 text-muted-foreground hover:text-foreground
            border-b border-border shrink-0">
          ↑ {layout.before} earlier {layout.before === 1 ? 'frame' : 'frames'}
        </button>
      )}

      {/* `overflow-y-auto`, not hidden. Nudging apart a burst can push the
          last arrow below the viewport, and clipping it would be a
          conversation that appears to stop - which is a thing conversations
          really do, so it must never be faked. */}
      <div ref={boxRef} onWheel={onWheel}
        className="flex-1 min-h-0 relative overflow-y-auto overflow-x-hidden
          cursor-crosshair custom-scrollbar">
        <svg width={size.width} height={svgHeight} className="block">
          <defs>
            <marker id="ladder-head-r" viewBox="0 0 8 8" refX="7" refY="4"
              markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="context-stroke" />
            </marker>
            <marker id="ladder-head-l" viewBox="0 0 8 8" refX="7" refY="4"
              markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="context-stroke" />
            </marker>
          </defs>

          {/* The lanes. Drawn first so every arrow sits on top of them. */}
          <line x1={clientX} y1={0} x2={clientX} y2={svgHeight}
            stroke="currentColor" strokeOpacity={0.25} strokeWidth={2} />
          <line x1={serverX} y1={0} x2={serverX} y2={svgHeight}
            stroke="currentColor" strokeOpacity={0.25} strokeWidth={2} />

          <g transform={`translate(0, ${TOP_PAD})`}>
            {/* A time tick every so often, so the vertical axis means
                something. Five is enough to read a gap without becoming a
                grid that competes with the arrows. */}
            {timeScale.ticks(5).map((t) => (
              <g key={t} transform={`translate(0, ${timeScale(t)})`}>
                <line x1={0} x2={size.width} stroke="currentColor" strokeOpacity={0.07} />
                <text x={4} y={-3} fontSize={9} fill="currentColor" fillOpacity={0.45}
                  fontFamily="ui-monospace, monospace">{t.toFixed(3)}s</text>
              </g>
            ))}

            {layout.arrows.map((arrow) => (
              <Arrow key={arrow.packet.id} arrow={arrow}
                clientX={clientX} serverX={serverX}
                selected={arrow.packet.id === selectedId}
                onSelect={onSelectFrame} />
            ))}
          </g>
        </svg>
      </div>

      {layout.after > 0 && (
        <button onClick={() => setWindow((c) => panWindow(c, extent, 0.5))}
          className="text-[11px] py-0.5 text-muted-foreground hover:text-foreground
            border-t border-border shrink-0">
          ↓ {layout.after} later {layout.after === 1 ? 'frame' : 'frames'}
        </button>
      )}

      <Minimap frames={frames} extent={extent} window={window} onWindow={setWindow} />
    </div>
  );
};

const Arrow: React.FC<{
  arrow: LadderArrow;
  clientX: number;
  serverX: number;
  selected: boolean;
  onSelect?: (id: number) => void;
}> = ({ arrow, clientX, serverX, selected, onSelect }) => {
  const toServer = arrow.from === 'client';
  const x1 = toServer ? clientX : serverX;
  const x2 = toServer ? serverX : clientX;
  const colour = (arrow.category !== null ? CATEGORY_STROKE[arrow.category] : undefined)
    ?? (toServer ? 'var(--color-rose-500, #f43f5e)' : 'var(--color-sky-500, #0ea5e9)');

  // Thickness carries the frame's size, which is what makes a bulk transfer
  // look different from an exchange of acknowledgements at a glance. Capped
  // and floored: below 1px an arrow disappears, and above 4 it stops reading
  // as a line. Square-rooted because frame sizes span three orders of
  // magnitude and a linear map would make every ACK invisible.
  const width = Math.min(4, Math.max(1, Math.sqrt(arrow.length) / 12));

  return (
    <g
      onClick={() => onSelect?.(arrow.packet.id)}
      className={onSelect ? 'cursor-pointer' : undefined}
      opacity={selected ? 1 : 0.92}
    >
      {/* An invisible fat line under the visible one: a 1px arrow is almost
          impossible to hit with a mouse, and widening the drawn line to make
          it clickable would destroy the size encoding. */}
      <line x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
        stroke="transparent" strokeWidth={12} />
      {selected && (
        <rect x={Math.min(x1, x2)} y={arrow.y - 8} width={Math.abs(x2 - x1)} height={16}
          fill="currentColor" fillOpacity={0.09} rx={3} />
      )}
      <line
        x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
        stroke={colour} strokeWidth={selected ? width + 1.5 : width}
        markerEnd={`url(#${toServer ? 'ladder-head-r' : 'ladder-head-l'})`}
      />
      {/* The label sits above its own arrow rather than beside it, so a long
          Info line does not push the lanes apart. */}
      <text
        x={(x1 + x2) / 2} y={arrow.y - 4} textAnchor="middle"
        fontSize={10} fontFamily="ui-monospace, monospace"
        fill="currentColor" fillOpacity={selected ? 0.95 : 0.75}
      >
        {arrow.flags ? `[${arrow.flags}] ` : ''}{truncate(arrow.info, 78)}
      </text>
      <text
        x={(x1 + x2) / 2} y={arrow.y + 11} textAnchor="middle"
        fontSize={9} fontFamily="ui-monospace, monospace"
        fill="currentColor" fillOpacity={0.4}
      >
        #{arrow.packet.id} · {arrow.length} B
        {arrow.crowded ? ' · ordered, not to scale' : ''}
      </text>
      <title>
        {`Frame ${arrow.packet.id} at ${arrow.time.toFixed(6)}s, ${arrow.length} bytes\n`}
        {`${arrow.from === 'client' ? 'client → server' : 'server → client'}\n`}
        {arrow.info}
      </title>
    </g>
  );
};

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * The whole stream as one strip, with the visible window marked.
 *
 * Without it, zooming in loses all sense of where you are - a ladder showing
 * forty frames of a hundred thousand looks the same wherever it is. Every
 * frame is one tick, so bursts and silences are visible at a glance and the
 * strip doubles as a density plot.
 */
const Minimap: React.FC<{
  frames: readonly Packet[];
  extent: LadderWindow;
  window: LadderWindow;
  onWindow: (w: LadderWindow) => void;
}> = ({ frames, extent, window, onWindow }) => {
  const width = 100;
  const span = extent.to - extent.from;
  const at = (t: number) => ((t - extent.from) / span) * width;

  // One tick per frame is too many to draw for a large stream and
  // indistinguishable anyway at this width - it is bucketed to the pixel.
  const buckets = useMemo(() => {
    const counts = new Array<number>(width).fill(0);
    for (const frame of frames) {
      const index = Math.min(width - 1, Math.max(0, Math.floor(at(frame.relativeTime))));
      counts[index]++;
    }
    const peak = Math.max(1, ...counts);
    return counts.map((c) => c / peak);
  }, [frames, extent]);

  const jump = (event: React.MouseEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const fraction = (event.clientX - bounds.left) / bounds.width;
    const time = extent.from + span * fraction;
    onWindow(windowAround(time, window, extent));
  };

  return (
    <div onClick={jump} title="Click to jump"
      className="h-8 shrink-0 border-t border-border bg-secondary/30 relative cursor-pointer">
      <svg viewBox={`0 0 ${width} 10`} preserveAspectRatio="none"
        className="w-full h-full block">
        {buckets.map((v, i) => v > 0 && (
          <rect key={i} x={i} y={10 - v * 10} width={1} height={v * 10}
            fill="currentColor" fillOpacity={0.35} />
        ))}
        <rect
          x={at(window.from)} width={Math.max(at(window.to) - at(window.from), 0.6)}
          y={0} height={10}
          fill="var(--color-primary, #f97316)" fillOpacity={0.22}
          stroke="var(--color-primary, #f97316)" strokeOpacity={0.7} strokeWidth={0.3}
        />
      </svg>
    </div>
  );
};
