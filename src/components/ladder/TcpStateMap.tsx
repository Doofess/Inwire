import React, { useMemo, useState } from 'react';
import { PanelRightClose } from 'lucide-react';
import type { Side } from '../../services/conversation/tcpStates';
import type { StreamSummary } from '../../services/conversation/streamDigest';
import { Segmented } from '../ui/segmented';
import { STATE_EDGES, STATE_NODES, type MapEdge } from './tcpStateGraph';
import {
  drawnEdges, edgeGeometry, edgeLabel, hoverTarget, isImplied, labelLines, nodeBox, sidePath,
  MAP_WIDTH, VIEW, type EdgeGeometry,
} from './tcpStateMapModel';

/**
 * The RFC 793 state diagram, docked beside the ladder, with one side's path
 * through it drawn in the theme's accent (ADR 0055 §1).
 *
 * The ladder says when and who; this says where in the protocol each step
 * landed, which is the half a list of frames cannot show - that a FIN moved
 * one side to FIN_WAIT_1 and the other to CLOSE_WAIT, and that the connection
 * then ended at CLOSED by a reset rather than by the ACK the figure expects.
 *
 * ## Linked both ways
 *
 * The arrow under the pointer on the ladder lights the edge its frame walked
 * here, and clicking a visited state scrolls the ladder to the frame that
 * entered it. One side at a time: the Client | Server switch chooses, and a
 * hovered frame that moved only the other side marks that side's tab rather
 * than lighting nothing.
 *
 * ## What it claims and what it does not
 *
 * Every edge the capture only implied - the listener nobody can see, a
 * handshake that happened before the capture started - is dashed, and so is
 * TIME_WAIT's timeout, which no segment ever shows (§4). The caption says so.
 *
 * ## Colour
 *
 * Text is `currentColor`, taken from the theme through the `text-*` class on
 * its group; the taken path is `var(--primary)`; the current state is the
 * rail's active fill, the accent at 20%. No literal anywhere, so both themes
 * are one drawing. `tcpStateMapModel.ts` decides everything but the pixels.
 */

const CELL = MAP_WIDTH / VIEW.w;
const MAP_HEIGHT = Math.round(MAP_WIDTH * VIEW.h / VIEW.w);
/** Pixels to cells. */
const px = (n: number): number => n / CELL;

/** Laid out once: the figure never changes, only which of it is drawn how. */
const GEOMETRY: ReadonlyMap<string, EdgeGeometry> = new Map(STATE_EDGES.map((edge) => [edge.id, edgeGeometry(edge)]));

interface TcpStateMapProps {
  summary: StreamSummary;
  /** The arrow under the pointer on the ladder, or null. */
  hoverFrameId: number | null;
  /** A visited state was clicked: the frame that entered it, for the ladder to scroll to. */
  onPickState: (frameId: number) => void;
  /** Collapses the map, where the pane lets it be collapsed; the button is hidden where it does not. */
  onCollapse?: () => void;
}

export const TcpStateMap: React.FC<TcpStateMapProps> = ({ summary, hoverFrameId, onPickState, onCollapse }) => {
  const [side, setSide] = useState<Side>('client');
  /** The state node holding keyboard focus, which draws its own ring. */
  const [ringed, setRinged] = useState<string | null>(null);
  const { steps } = summary;
  const path = useMemo(() => sidePath(steps, side), [steps, side]);
  const hover = useMemo(() => hoverTarget(steps, side, hoverFrameId), [steps, side, hoverFrameId]);
  const edges = useMemo(() => drawnEdges(path), [path]);
  const other: Side = side === 'client' ? 'server' : 'client';

  // Taken edges over untaken, and the lit one over everything, so the path is
  // never under a dim line and the hover is never under the path.
  const ordered = useMemo(() => {
    const rank = (edge: MapEdge): number => (edge.id === hover.edgeId ? 2 : path.taken.has(edge.id) ? 1 : 0);
    return [...edges].sort((a, b) => rank(a) - rank(b));
  }, [edges, path, hover]);

  return (
    <div className="flex flex-col gap-2 px-3 py-2" data-state-map={side}>
      <div className="flex items-center justify-between gap-2">
        <Segmented<Side>
          size="sm"
          ariaLabel="Whose states the map shows"
          value={side}
          onValueChange={setSide}
          options={[
            { value: 'client', label: 'Client', ...(hover.otherSide && other === 'client' ? { mark: 'this frame moved the client too' } : {}) },
            { value: 'server', label: 'Server', ...(hover.otherSide && other === 'server' ? { mark: 'this frame moved the server too' } : {}) },
          ]}
        />
        {onCollapse !== undefined && (
          <button
            type="button"
            onClick={onCollapse}
            aria-label="Hide the state map"
            title="Hide the state map"
            className="@min-[1180px]:hidden p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent active:opacity-70"
          >
            <PanelRightClose className="w-4 h-4" />
          </button>
        )}
      </div>

      <svg
        width={MAP_WIDTH} height={MAP_HEIGHT}
        viewBox={`${VIEW.x} ${VIEW.y} ${VIEW.w} ${VIEW.h}`}
        className="block font-mono text-foreground select-none"
        aria-label={`${side}'s path through the TCP states`}
      >
        <defs>
          <marker id="state-head-dim" viewBox="0 0 8 8" refX="7" refY="4" markerWidth={px(7)} markerHeight={px(7)}
            markerUnits="userSpaceOnUse" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="currentColor" fillOpacity={0.25} />
          </marker>
          <marker id="state-head-taken" viewBox="0 0 8 8" refX="7" refY="4" markerWidth={px(8)} markerHeight={px(8)}
            markerUnits="userSpaceOnUse" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="var(--primary)" />
          </marker>
        </defs>

        {ordered.map((edge) => {
          const walked = path.taken.get(edge.id);
          const taken = walked !== undefined;
          // The timeout is expected of a side that ends in TIME_WAIT: drawn as
          // the path's own, dashed, because it was never seen.
          const expectedOn = edge.expected === true && path.current === 'TIME_WAIT';
          const on = taken || expectedOn;
          const lit = hover.edgeId === edge.id;
          const g = GEOMETRY.get(edge.id)!;
          return (
            <path
              key={edge.id}
              d={g.d}
              fill="none"
              stroke={on ? 'var(--primary)' : 'currentColor'}
              strokeOpacity={on ? 1 : 0.18}
              strokeWidth={px(lit ? 3.5 : on ? 2 : 1)}
              strokeDasharray={isImplied(edge, walked) ? `${px(4)} ${px(3)}` : undefined}
              markerEnd={`url(#${on ? 'state-head-taken' : 'state-head-dim'})`}
              data-edge={edge.id}
              data-taken={on ? '' : undefined}
              data-lit={lit ? '' : undefined}
            />
          );
        })}

        {STATE_NODES.map((node) => {
          const box = nodeBox(node);
          const visited = path.visited.has(node.id);
          const current = path.current === node.id;
          const enteredAt = path.entered.get(node.id);
          const pick = enteredAt === undefined ? undefined : () => onPickState(enteredAt);
          return (
            // No outline: Chromium paints a focused <g>'s, a mouse click's
            // focus included, as a disc over a corner of the figure. The ring
            // is the box's own stroke instead, and only for the keyboard.
            <g
              key={node.id}
              className={`outline-none ${visited ? 'text-foreground' : 'text-muted-foreground'}`}
              data-state-node={node.id}
              data-visited={visited ? '' : undefined}
              data-current={current ? '' : undefined}
              {...(pick === undefined ? {} : {
                role: 'button',
                tabIndex: 0,
                'aria-label': `${node.label}, entered at frame ${enteredAt} - show it on the ladder`,
                onClick: pick,
                onKeyDown: (event: React.KeyboardEvent) => {
                  if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); pick(); }
                },
                onFocus: (event: React.FocusEvent<SVGGElement>) => {
                  if (event.currentTarget.matches(':focus-visible')) setRinged(node.id);
                },
                onBlur: () => setRinged(null),
                style: { cursor: 'pointer' },
              })}
            >
              <rect
                x={box.x} y={box.y} width={box.w} height={box.h} rx={px(4)}
                fill={current ? 'var(--primary)' : 'var(--card)'}
                fillOpacity={current ? 0.2 : 1}
                stroke={visited ? 'var(--primary)' : 'var(--border)'}
                strokeWidth={px(visited ? 1.5 : 1)}
                strokeDasharray={node.dashed ? `${px(3)} ${px(2)}` : undefined}
              />
              {ringed === node.id && (
                // index.css's ring, in the figure's units: 2px, 2px out.
                <rect
                  x={box.x - px(3)} y={box.y - px(3)} width={box.w + px(6)} height={box.h + px(6)} rx={px(6)}
                  fill="none" stroke="var(--ring)" strokeWidth={px(2)}
                />
              )}
              <text
                x={box.cx} y={box.cy} fontSize={px(10)} textAnchor="middle" dominantBaseline="central"
                fill="currentColor" fillOpacity={visited ? 1 : 0.8} fontWeight={current ? 600 : 400}
              >
                {node.label}
              </text>
              {enteredAt !== undefined && (
                <title>{`${node.label} - entered at frame #${enteredAt}. Click to show that frame on the ladder.`}</title>
              )}
            </g>
          );
        })}

        {/* Labels last, over every line: each knocks the lines out behind it
            with a halo in the column's own ground, so a label on its edge
            stays readable. */}
        {ordered.map((edge) => {
          const walked = path.taken.get(edge.id);
          const on = walked !== undefined || (edge.expected === true && path.current === 'TIME_WAIT');
          const lit = hover.edgeId === edge.id;
          const label = GEOMETRY.get(edge.id)!.label;
          if (label === null) return null;
          const lines = labelLines(edgeLabel(edge, walked), label.split);
          return (
            <text
              key={edge.id}
              x={label.x} y={label.y}
              fontSize={px(9)} textAnchor={label.anchor} dominantBaseline="middle"
              className={lit ? 'text-foreground' : 'text-muted-foreground'}
              fill="currentColor" fillOpacity={on || lit ? 1 : 0.55} fontWeight={lit ? 600 : 400}
              stroke="var(--card)" strokeWidth={px(3)} strokeLinejoin="round" paintOrder="stroke"
              data-edge-label={edge.id}
            >
              {lines.length === 1
                ? lines[0]
                : lines.map((line, i) => (
                  <tspan key={i} x={label.x} dy={i === 0 ? px(-5.5) : px(11)}>{line}</tspan>
                ))}
            </text>
          );
        })}
      </svg>

      <p className="text-[10px] leading-snug text-muted-foreground">
        States are inferred from one vantage point. Dashed: implied, not seen.
      </p>
    </div>
  );
};
