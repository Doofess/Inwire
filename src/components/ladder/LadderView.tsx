import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
// From `d3`, which is a direct dependency, rather than `d3-scale`, which is
// only reachable through it. It supplies the tick placement and the domain
// mapping and nothing else - React owns every element, the same split
// `TrafficTimelineChart` uses.
import { scaleLinear } from 'd3';
import { TriangleAlert } from 'lucide-react';
import type { Packet } from '../../types/packet';
import type { ClientEnd } from '../../services/followStream';
import type { Endpoint } from '../../services/conversation/clientSide';
import type { StreamSummary } from '../../services/conversation/streamDigest';
import type { ColorRulesEngine } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';
import {
  arrowsThatFit, initialWindow, ladderExtent, layoutLadder, panWindow,
  windowAround, zoomWindow,
  type LadderArrow, type LadderWindow,
} from './ladderLayout';
import { foldRuns, itemPacket, type LadderItem } from './ladderRuns';
import { lanePills, markLadder, ROW_ABOVE, type LadderMark, type LanePill } from './ladderMarks';

/**
 * One conversation as a ladder: two lanes, time running down, an arrow per
 * frame, a band per quiet run, and each side's state written on its lane as it
 * changes (ADR 0055).
 *
 * The view the packet list cannot be. A list is ordered by time and says
 * nothing about *shape* - a request answered four seconds later, a side that
 * went quiet, a retransmission burst, a handshake - all of which are obvious
 * as geometry and invisible as rows. This is the same frames, drawn so the
 * shape is the thing you see first.
 *
 * ## Colour comes from the colour rules and nowhere else
 *
 * An arrow's label is a chip painted exactly as that frame's row is painted in
 * the packet list: `ColorRulesEngine.getPacketStyle` under the current packet
 * theme. Direction is the lane and the arrowhead. The rose/sky pair this used
 * to colour direction with, and the four category strokes over it, are gone:
 * the owner's rule is that an arrow should look like its row, and a second
 * palette for the same frame was a second thing to learn.
 *
 * ## Only what is on screen exists
 *
 * A stream can be a hundred thousand frames. The pane hands them over once,
 * `foldRuns` folds the quiet runs into bands - breaking on a flag, a finding,
 * a change of direction or of matched rule - and `layoutLadder` positions only
 * the items inside the current time window, a few hundred at most. The gap
 * markers and the state pills are placed over that window too. Zooming and
 * panning re-run the layout, never the fold.
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

/** The chip over an arrow: 10px text with this much air either side, this tall. */
const CHIP_PAD = 5;
const CHIP_HEIGHT = 13;
/** The expert marker beside a chip, and the room kept for it. */
const MARKER_SIZE = 10;
const MARKER_ROOM = MARKER_SIZE + 4;
/** The most label a chip carries, however wide the lanes are apart. */
const LABEL_MAX = 78;

/** A state pill on a lane: 9px text. */
const PILL_PAD = 5;
const PILL_HEIGHT = 14;
/** Air between a lane and its first pill, and between pills on one row. */
const PILL_GAP = 6;
const PILL_SPACING = 4;

/** 10px Cascadia Mono, until it has been measured. */
const FALLBACK_CHAR_WIDTH = 6;

/**
 * The width of one character of the mono face at 10px, measured once per
 * family. Everything with a background here - the chips, the pills, the gap
 * markers' rules - is sized from its text, and SVG has no `fit-content`.
 * A 9px line scales this by 0.9.
 */
const charWidths = new Map<string, number>();
function monoCharWidth(family: string): number {
  const known = charWidths.get(family);
  if (known !== undefined) return known;
  let width = FALLBACK_CHAR_WIDTH;
  const context = document.createElement('canvas').getContext('2d');
  if (context !== null) {
    context.font = `10px ${family}`;
    width = context.measureText('0').width || FALLBACK_CHAR_WIDTH;
  }
  charWidths.set(family, width);
  return width;
}

interface LadderViewProps {
  /**
   * The stream's frames in capture order: the whole capture's, read through
   * the digest, or the buffer's where there is no digest to read through.
   */
  frames: Packet[];
  /** Set while the frames are still being read; the ladder draws what has arrived. */
  loading: { loaded: number; total: number } | null;
  client: ClientEnd;
  server: Endpoint;
  /** The digest's summary of this stream, or null for UDP and for a capture with no store. */
  summary: StreamSummary | null;
  colorEngine: ColorRulesEngine;
  packetTheme: PacketTheme;
  /** The frame selected elsewhere, highlighted here. */
  selectedId?: number;
  /** Clicking an arrow selects that frame in the packet list. */
  onSelectFrame?: (id: number) => void;
  /** A frame named from outside the ladder - the state map's hover - lit the way the pointer lights one. */
  highlightFrameId?: number | null;
  /** The arrow under the pointer, for the state map; null when none is. */
  onHoverFrame?: (id: number | null) => void;
  /** A frame to bring into the window, exactly as the selection is brought. */
  scrollToFrameId?: number | null;
  /**
   * Bands opened by their first frame's id. The pane holds the set rather
   * than this view, so a band stays open across the tabs and across a reload
   * of the frames; an id rather than an index because a live stream grows
   * under the fold.
   */
  expanded: ReadonlySet<number>;
  onToggleBand: (firstId: number) => void;
  /** Opens a band and never closes one: for a frame named from outside that a closed band is hiding. */
  onOpenBand: (firstId: number) => void;
}

export const LadderView: React.FC<LadderViewProps> = ({
  frames, loading, client, server, summary, colorEngine, packetTheme,
  selectedId, onSelectFrame, highlightFrameId, onHoverFrame, scrollToFrameId,
  expanded, onToggleBand, onOpenBand,
}) => {
  // A band breaks where the matched rule changes, so its chip takes one rule's
  // colour and never an average. `getMatchedRuleName` caches on the packet, so
  // the fold asks the chain once per frame and the chips not at all.
  const ruleKeyOf = useCallback((p: Packet) => colorEngine.getMatchedRuleName(p) ?? '', [colorEngine]);
  const items = useMemo(() => foldRuns(frames, client, ruleKeyOf, expanded), [frames, client, ruleKeyOf, expanded]);
  const extent = useMemo(() => ladderExtent(items), [items]);
  // Read by the opening-window effect, which must not re-run on every fold:
  // opening a band changes the items and must not reset the window it was
  // opened in.
  const itemsRef = useRef(items);
  itemsRef.current = items;

  const [window, setWindow] = useState<LadderWindow>(extent);
  const [size, setSize] = useState({ width: 720, height: 480 });
  const [charWidth, setCharWidth] = useState(FALLBACK_CHAR_WIDTH);
  const boxRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const hasFrames = frames.length > 0;

  // A new conversation opens on a window that FITS, not on the whole stream.
  // A busy conversation is a thousand frames over two minutes, and drawing all
  // of them into a viewport with room for a dozen is not a dense view of the
  // conversation - it is an unreadable one. The minimap says where in the whole
  // this sits.
  //
  // It is chosen once per stream, which is keyed on the stream's FIRST FRAME:
  // the same object across every flush of a live capture and every page of a
  // load, and a different one for a different stream. Keying on the array
  // would re-choose it ten times a second during a capture, throwing away any
  // zoom the user had set. While the stream is still loading it is re-chosen
  // on each page, because the first choice was made from one page and nobody
  // has had time to zoom.
  const firstFrame = frames[0];
  const settling = loading !== null ? frames : null;
  // The selection is followed once when it changes, and again each time the
  // window is re-chosen - this effect runs before the follow below in the same
  // commit, so a re-chosen window ends on the selection rather than on the
  // stream's start. Keyed on the id rather than re-run on every flush, or a
  // live capture would pull a window somebody had panned away back to the
  // selection ten times a second.
  const followedRef = useRef<number | undefined>(undefined);
  useEffect(() => {
    followedRef.current = undefined;
    setWindow(initialWindow(itemsRef.current, plotHeightRef.current));
  }, [firstFrame, client, settling]);

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
    // The box exists only once there are frames, and a stream read from disk
    // opens with none - so the observer is attached when the box appears, not
    // on mount alone.
  }, [hasFrames]);

  useLayoutEffect(() => {
    const svg = svgRef.current;
    if (svg !== null) setCharWidth(monoCharWidth(getComputedStyle(svg).fontFamily));
  }, [hasFrames]);

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
    () => layoutLadder(items, window, plotHeight, arrowsThatFit(plotHeight)),
    [items, window, plotHeight],
  );
  const marked = useMemo(
    () => markLadder(layout, frames, summary, loading === null),
    [layout, frames, summary, loading],
  );
  const pills = useMemo(
    () => (summary === null ? [] : lanePills(marked.arrows, summary.steps)),
    [marked, summary],
  );

  /**
   * Bringing a frame into the window, but only when it is not already visible.
   *
   * Re-centring on every selection would fight the user: clicking an arrow
   * selects the frame, which would then scroll the arrow they just clicked
   * into the middle and move everything under the pointer. The state map's
   * click follows the same rule, for the same reason.
   */
  const bringIntoView = useCallback((id: number): boolean => {
    const frame = frames.find((f) => f.id === id);
    if (frame === undefined) return false;
    setWindow((current) => {
      if (frame.relativeTime >= current.from && frame.relativeTime <= current.to) return current;
      return windowAround(frame.relativeTime, current, extent);
    });
    return true;
  }, [frames, extent]);
  useEffect(() => {
    if (selectedId === undefined || selectedId === followedRef.current) return;
    // Recorded only once found: a frame still on its way from disk is followed
    // by the page that brings it.
    if (bringIntoView(selectedId)) followedRef.current = selectedId;
  }, [selectedId, bringIntoView]);
  const scrolledRef = useRef<number | null>(null);
  useEffect(() => {
    if (scrollToFrameId === undefined || scrollToFrameId === null || scrollToFrameId === scrolledRef.current) return;
    if (bringIntoView(scrollToFrameId)) scrolledRef.current = scrollToFrameId;
  }, [scrollToFrameId, bringIntoView]);

  // A frame named from outside that a closed band is hiding opens the band:
  // the selection must be drawn selected, and a frame the state map points at
  // must be there to point at. The pane's set is the one source of what is
  // open, so this asks rather than folding differently.
  //
  // Once per id, not once per fold: the ref remembers the last id each source
  // opened a band for, so a band the user then closes over the selected frame
  // stays closed until the selection moves. Only an opening is remembered. An
  // id held by a row clears the slot rather than filling it, so the band a
  // later fold puts that frame into opens the moment it exists, and an id
  // opened once, closed, and selected again after a row was selected between
  // opens again. An id whose frame is not here yet leaves the slot alone, so
  // the page that brings it opens its band.
  const autoOpened = useRef<(number | undefined)[]>([undefined, undefined, undefined]);
  useEffect(() => {
    [selectedId, highlightFrameId, scrollToFrameId].forEach((id, source) => {
      if (id === autoOpened.current[source]) return;
      if (id === undefined || id === null) { autoOpened.current[source] = undefined; return; }
      const holder = holding(items, id);
      if (holder === null) return;
      if (holder === 'row') { autoOpened.current[source] = undefined; return; }
      autoOpened.current[source] = id;
      onOpenBand(holder.first.id);
    });
  }, [items, selectedId, highlightFrameId, scrollToFrameId, onOpenBand]);

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

  const plotTop = TOP_PAD + marked.topRoom;
  const svgHeight = Math.max(size.height, marked.contentHeight + plotTop + BOTTOM_PAD);
  const clientX = LANE_INSET;
  const serverX = Math.max(size.width - LANE_INSET, LANE_INSET + 120);
  const zoomed = (window.to - window.from) < (extent.to - extent.from) - 1e-9;
  const placedPills = useMemo(
    () => placePills(pills, charWidth, clientX, serverX),
    [pills, charWidth, clientX, serverX],
  );

  if (!hasFrames) {
    return (
      <div className="flex-1 flex items-center justify-center text-xs text-muted-foreground">
        {loading !== null ? readingText(loading) : 'No frames on this stream.'}
      </div>
    );
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col">
      {/* Lane headers, outside the scrolling area so they stay put. The role
          in the foreground and the address beneath it: the roles are what the
          lanes mean, and when the client is a guess the header says so, because
          getting the ends backwards mislabels the whole conversation. */}
      <div className="flex items-start justify-between gap-4 px-4 py-1.5 border-b border-border
        text-[11px] font-mono bg-secondary/40 shrink-0">
        <div className="min-w-0 max-w-[260px]">
          <div className="text-foreground font-semibold">
            {client.basis === 'first-speaker' ? 'client is a guess: first to speak' : 'client'}
          </div>
          <div className="text-muted-foreground truncate">{client.address}:{client.port}</div>
        </div>
        <span className="text-muted-foreground text-center pt-px">
          {loading !== null
            ? readingText(loading)
            : `${layout.arrows.length} of ${items.length} rows · ${frames.length.toLocaleString()} frames`}
          {zoomed && ' · wheel to zoom, shift-wheel to pan'}
        </span>
        <div className="min-w-0 max-w-[260px] text-right">
          <div className="text-foreground font-semibold">server</div>
          <div className="text-muted-foreground truncate">{server.address}:{server.port}</div>
        </div>
      </div>

      {/* Frames above and below the window, said rather than left to be
          inferred from a scrollbar that is not there. */}
      {layout.before > 0 && (
        <button onClick={() => setWindow((c) => panWindow(c, extent, -0.5))}
          className="text-[11px] py-0.5 text-muted-foreground hover:text-foreground active:opacity-70
            border-b border-border shrink-0">
          ↑ {layout.before} earlier {layout.before === 1 ? 'row' : 'rows'}
        </button>
      )}

      {/* `overflow-y-auto`, not hidden. Nudging apart a burst can push the
          last arrow below the viewport, and clipping it would be a
          conversation that appears to stop - which is a thing conversations
          really do, so it must never be faked. */}
      <div ref={boxRef} onWheel={onWheel}
        className="flex-1 min-h-0 relative overflow-y-auto overflow-x-hidden
          cursor-crosshair custom-scrollbar">
        <svg ref={svgRef} width={size.width} height={svgHeight} className="block font-mono">
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

          <g transform={`translate(0, ${plotTop})`}>
            {/* A time tick every so often, so the vertical axis means
                something. Five is enough to read a gap without becoming a
                grid that competes with the arrows. */}
            {timeScale.ticks(5).map((t) => (
              <g key={t} transform={`translate(0, ${timeScale(t)})`}>
                <line x1={0} x2={size.width} stroke="currentColor" strokeOpacity={0.07} />
                <text x={4} y={-3} fontSize={9} fill="currentColor" fillOpacity={0.45}>
                  {t.toFixed(3)}s
                </text>
              </g>
            ))}

            {marked.marks.map((mark) => (
              <GapMarker key={`${mark.kind}:${mark.y}`} mark={mark}
                width={size.width} charWidth={charWidth} />
            ))}

            {marked.arrows.map((arrow) => {
              const packet = itemPacket(arrow.item);
              const isFrame = arrow.item.kind === 'frame';
              return (
                <Arrow key={packet.id} arrow={arrow}
                  clientX={clientX} serverX={serverX} charWidth={charWidth}
                  style={colorEngine.getPacketStyle(packet, packetTheme)}
                  surface={packetTheme.surface}
                  selected={isFrame && packet.id === selectedId}
                  highlighted={isFrame && packet.id === highlightFrameId}
                  onSelect={onSelectFrame} onToggleBand={onToggleBand} onHover={onHoverFrame} />
              );
            })}

            {placedPills.map(({ pill, x, width }) => (
              <StatePill key={`${pill.side}:${pill.frameId}:${pill.to}`}
                pill={pill} x={x} width={width} />
            ))}
          </g>
        </svg>
      </div>

      {layout.after > 0 && (
        <button onClick={() => setWindow((c) => panWindow(c, extent, 0.5))}
          className="text-[11px] py-0.5 text-muted-foreground hover:text-foreground active:opacity-70
            border-t border-border shrink-0">
          ↓ {layout.after} later {layout.after === 1 ? 'row' : 'rows'}
        </button>
      )}

      <Minimap frames={frames} extent={extent} window={window} onWindow={setWindow} />
    </div>
  );
};

function readingText(loading: { loaded: number; total: number }): string {
  return `Reading ${loading.loaded.toLocaleString()} of ${loading.total.toLocaleString()} frames`;
}

/** What holds frame `id`: its own row, the closed band it folded into, or nothing when it is not here. */
function holding(items: readonly LadderItem[], id: number): 'row' | Extract<LadderItem, { kind: 'band' }> | null {
  for (const item of items) {
    if (item.kind === 'frame') { if (item.packet.id === id) return 'row'; }
    else if (id >= item.first.id && id <= item.last.id) return item;
  }
  return null;
}

/**
 * Where each pill goes on its row. Two pills for one lane on one row sit side
 * by side, the later state nearest the lane, so the second's position depends
 * on the first's width - which is why this is a pass over all of them rather
 * than arithmetic on each.
 */
function placePills(
  pills: readonly LanePill[], charWidth: number, clientX: number, serverX: number,
): { pill: LanePill; x: number; width: number }[] {
  const taken = new Map<string, number>();
  const placed: { pill: LanePill; x: number; width: number }[] = [];
  // Slot 0 first on every row, so each slot finds the room the one before it took.
  const inOrder = [...pills].sort((a, b) => a.slot - b.slot);
  for (const pill of inOrder) {
    const width = pill.text.length * charWidth * 0.9 + 2 * PILL_PAD;
    const row = `${pill.side}:${pill.y}`;
    const offset = taken.get(row) ?? PILL_GAP;
    const x = pill.side === 'client' ? clientX - offset - width : serverX + offset;
    taken.set(row, offset + width + PILL_SPACING);
    placed.push({ pill, x, width });
  }
  return placed;
}

const Arrow: React.FC<{
  arrow: LadderArrow;
  clientX: number;
  serverX: number;
  charWidth: number;
  /** How this frame's row is painted in the packet list: empty when no rule matched. */
  style: { background?: string; color?: string; borderColor?: string };
  surface: PacketTheme['surface'];
  selected: boolean;
  highlighted: boolean;
  onSelect?: (id: number) => void;
  /** A band opens and closes on a click; a frame selects. */
  onToggleBand: (firstId: number) => void;
  onHover?: (id: number | null) => void;
}> = ({ arrow, clientX, serverX, charWidth, style, surface, selected, highlighted, onSelect, onToggleBand, onHover }) => {
  const toServer = arrow.from === 'client';
  const x1 = toServer ? clientX : serverX;
  const x2 = toServer ? serverX : clientX;
  const { item } = arrow;
  const packet = itemPacket(item);
  const isBand = item.kind === 'band';
  const onClick = isBand
    ? () => onToggleBand(item.first.id)
    : onSelect === undefined ? undefined : () => onSelect(packet.id);
  const number = isBand ? `#${item.first.id}–#${item.last.id}` : `#${packet.id}`;
  const lit = selected || highlighted;
  // A band is many frames and names none of them to the state map.
  const hover = isBand ? undefined : onHover;

  // The line is the rule's fill at full strength over a faint outline in the
  // text colour, so a pale rule - most of them, on Day - still reads against
  // the ground. A frame no rule matched is drawn in the text colour alone.
  const colour = style.background ?? 'currentColor';

  // Thickness carries the frame's size, which is what makes a bulk transfer
  // look different from an exchange of acknowledgements at a glance. Capped
  // and floored: below 1px an arrow disappears, and above 4 it stops reading
  // as a line. Square-rooted because frame sizes span three orders of
  // magnitude and a linear map would make every ACK invisible.
  const width = Math.min(4, Math.max(1, Math.sqrt(arrow.length) / 12));
  const strokeWidth = lit ? width + 1.5 : width;

  // The chip: the Info line in the row's own colours, sized from its text and
  // cut to what fits between the lanes with the expert marker's room kept.
  const mid = (x1 + x2) / 2;
  const span = Math.abs(x2 - x1);
  const maxChars = Math.max(8, Math.min(LABEL_MAX, Math.floor((span - 2 * CHIP_PAD - MARKER_ROOM) / charWidth)));
  const label = truncate(`${arrow.flags ? `[${arrow.flags}] ` : ''}${arrow.info}`, maxChars);
  const chipWidth = label.length * charWidth + 2 * CHIP_PAD;
  const chipTop = arrow.y - ROW_ABOVE;

  return (
    <g
      onClick={onClick}
      onMouseEnter={hover === undefined ? undefined : () => hover(packet.id)}
      onMouseLeave={hover === undefined ? undefined : () => hover(null)}
      className={onClick ? 'cursor-pointer' : undefined}
      opacity={lit ? 1 : 0.92}
    >
      {/* An invisible fat line under the visible one: a 1px arrow is almost
          impossible to hit with a mouse, and widening the drawn line to make
          it clickable would destroy the size encoding. */}
      <line x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
        stroke="transparent" strokeWidth={12} />
      {lit && (
        <rect x={Math.min(x1, x2)} y={arrow.y - 8} width={span} height={16}
          fill="currentColor" fillOpacity={0.09} rx={3} />
      )}
      {isBand ? (
        <>
          {/* A band is a bar from lane to lane in its one rule's colour, with
              an arrowhead for the way it went. */}
          <rect x={Math.min(x1, x2)} y={arrow.y - 3} width={span} height={6}
            stroke="currentColor" strokeOpacity={0.25} strokeWidth={1} fill="none" />
          <rect x={Math.min(x1, x2)} y={arrow.y - 3} width={span} height={6}
            fill={colour} fillOpacity={0.55} />
          <line x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
            stroke={colour} strokeWidth={1}
            markerEnd={`url(#${toServer ? 'ladder-head-r' : 'ladder-head-l'})`} />
        </>
      ) : (
        <>
          <line x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
            stroke="currentColor" strokeOpacity={0.25} strokeWidth={strokeWidth + 2} />
          <line
            x1={x1} y1={arrow.y} x2={x2} y2={arrow.y}
            stroke={colour} strokeWidth={strokeWidth}
            markerEnd={`url(#${toServer ? 'ladder-head-r' : 'ladder-head-l'})`}
          />
        </>
      )}
      {/* The label sits above its own arrow rather than beside it, so a long
          Info line does not push the lanes apart. The selection's ring is the
          list's own, `--primary`. */}
      <rect x={mid - chipWidth / 2} y={chipTop} width={chipWidth} height={CHIP_HEIGHT} rx={3}
        fill={style.background ?? surface.background}
        stroke={selected ? 'var(--primary)' : (style.borderColor ?? 'var(--border)')}
        strokeWidth={selected ? 1.5 : 1} />
      <text
        x={mid} y={chipTop + 9.5} textAnchor="middle" fontSize={10}
        fill={style.color ?? surface.foreground}
      >
        {label}
      </text>
      {arrow.category !== null && (
        <TriangleAlert x={mid + chipWidth / 2 + 4} y={chipTop + 1.5}
          size={MARKER_SIZE} style={{ strokeWidth: 1 }} color="currentColor">
          <title>{arrow.category}</title>
        </TriangleAlert>
      )}
      <text
        x={mid} y={arrow.y + 11} textAnchor="middle" fontSize={9}
        fill="currentColor" fillOpacity={0.4}
      >
        {number} · {Math.round(arrow.length)} B
        {arrow.crowded ? ' · ordered, not to scale' : ''}
      </text>
      <title>
        {isBand
          ? `Frames ${item.first.id} to ${item.last.id} from ${arrow.time.toFixed(6)}s, click to open\n`
          : `Frame ${packet.id} at ${arrow.time.toFixed(6)}s, ${arrow.length} bytes\n`}
        {`${arrow.from === 'client' ? 'client → server' : 'server → client'}\n`}
        {arrow.info}
      </title>
    </g>
  );
};

/**
 * One side's state, written on its lane at the row of the frame that moved it.
 *
 * A state seen sent is drawn plainly. One the side reached by receiving a
 * segment, or one nothing on the wire shows, is italic inside a dashed border
 * and says so in its title - the discipline of ADR 0055 §4, that the view
 * never claims more than the capture holds.
 */
const StatePill: React.FC<{ pill: LanePill; x: number; width: number }> = ({ pill, x, width }) => {
  const assumed = pill.evidence !== 'sent';
  return (
    <g>
      <rect x={x} y={pill.y - PILL_HEIGHT / 2} width={width} height={PILL_HEIGHT} rx={PILL_HEIGHT / 2}
        fill="var(--secondary)" stroke="var(--border)"
        strokeDasharray={assumed ? '3 2' : undefined} />
      <text x={x + width / 2} y={pill.y + 3.5} textAnchor="middle" fontSize={9}
        fill="var(--foreground)" fontStyle={assumed ? 'italic' : undefined}>
        {pill.text}
      </text>
      <title>
        {`${pill.side} → ${pill.to} at frame #${pill.frameId}`}
        {pill.note !== null ? `\n${pill.note}` : ''}
      </title>
    </g>
  );
};

/** A full-width row saying where the capture is blind: the text, then a dashed rule to the edge. */
const GapMarker: React.FC<{ mark: LadderMark; width: number; charWidth: number }> = ({ mark, width, charWidth }) => {
  const textWidth = mark.text.length * charWidth * 0.9;
  return (
    <g className="text-muted-foreground">
      <text x={8} y={mark.y + 3.5} fontSize={9} fill="currentColor">{mark.text}</text>
      <line x1={8 + textWidth + 8} x2={width - 8} y1={mark.y} y2={mark.y}
        stroke="currentColor" strokeOpacity={0.6} strokeDasharray="4 3" />
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
          fill="var(--primary)" fillOpacity={0.22}
          stroke="var(--primary)" strokeOpacity={0.7} strokeWidth={0.3}
        />
      </svg>
    </div>
  );
};
