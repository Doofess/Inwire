/**
 * What the state map draws for one side of a stream, and where (ADR 0055).
 *
 * Pure, and separate from the component that draws it, for the ladder's
 * reason: the wrong edge lit under a hover, a node filled as current that the
 * side has left, or a path drawn through a state the side never visited each
 * look like a connection that really did that, and a React component is
 * unreachable from plain `tsx`.
 *
 * ## The edge a step walked
 *
 * `edgeFor` answers by the states and the cause. One case needs the evidence
 * as well: the machine starts every side in UNKNOWN, so a SYN the capture
 * *saw* leaves UNKNOWN exactly as one it inferred from a SYN+ACK does - and
 * the graph's `UNKNOWN>SYN_SENT` edge is the inferred one, labelled "SYN not
 * captured". A SYN seen sent is the RFC's active open, so it is drawn from
 * the top CLOSED node, which is where a captured handshake starts.
 *
 * ## Geometry
 *
 * Nodes sit on the grid `tcpStateGraph.ts` lays out, in cells. An edge is a
 * path from the border of one node to the border of the next, routed by hand
 * through the gaps the figure leaves - a formula that bent every edge the same
 * way ran the reuse edge through CLOSING and every reset through LAST_ACK.
 * `ROUTES` is that hand: a bezier's control points or a cornered route's
 * waypoints, and where the label sits, per edge; a straight line with the
 * label at its midpoint for anything it does not name.
 */
import type { Side, TcpTransition } from '../../services/conversation/tcpStates';
import type { StreamStep } from '../../services/conversation/streamDigest';
import { edgeFor, STATE_EDGES, STATE_NODES, type MapEdge, type MapNode, type MapNodeId } from './tcpStateGraph';

/**
 * The drawing's extent in cells. Wider than the grid because the outer
 * columns' nodes overhang their cells; taller for the arc over CLOSED at the
 * top and the labels under the bottom row.
 */
export const VIEW = { x: -0.5, y: -0.45, w: 6.0, h: 7.65 };

/**
 * The drawing's width in CSS pixels. The column it docks in is `w-[19.5rem]`
 * (312px), border-box with a 1px `border-l`, the map's own `px-3`, and a 5px
 * scrollbar when the pane is shorter than the map: 312 - 1 - 24 - 5 = 282. Text and
 * stroke widths are specified in pixels and divided by the cell size, so a
 * 9px label is 9px however the viewBox scales.
 */
export const MAP_WIDTH = 280;
export const NODE_W = 1.6;
export const NODE_H = 0.5;

export interface Box { x: number; y: number; w: number; h: number; cx: number; cy: number }

/** A node's rectangle, centred in its cell. */
export function nodeBox(node: MapNode): Box {
  const cx = node.col + 0.5;
  const cy = node.row + 0.5;
  return { x: cx - NODE_W / 2, y: cy - NODE_H / 2, w: NODE_W, h: NODE_H, cx, cy };
}

const NODE_BY_ID = new Map(STATE_NODES.map((n) => [n.id, n]));
export const nodeById = (id: MapNodeId): MapNode => NODE_BY_ID.get(id)!;

/** The node a step is drawn as entering: every CLOSED it reaches is the bottom one. */
export const enteredNode = (step: TcpTransition): MapNodeId => (step.to === 'CLOSED' ? 'CLOSED_END' : step.to);

/** The node a step is drawn as leaving: a SYN seen sent out of nowhere is an active open from CLOSED. */
export function leftNode(step: TcpTransition): MapNodeId {
  if (step.from === 'UNKNOWN' && step.cause === 'syn' && step.evidence === 'sent') return 'CLOSED';
  return step.from;
}

/** The edge a step walked, or undefined for a transition the graph has no edge for. */
export function stepEdge(step: TcpTransition): MapEdge | undefined {
  const from = leftNode(step);
  // `leftNode` never answers CLOSED_END, so `from` is a TcpState.
  return edgeFor(from as TcpTransition['from'], step.to, step.cause);
}

export interface SidePath {
  /** Edge id to the steps that walked it, in order. More than one under port reuse. */
  taken: Map<string, StreamStep[]>;
  /** Node id to the frame of the LAST step that entered it, which is the incarnation the fill describes. */
  entered: Map<MapNodeId, number>;
  /** Every node a step left or entered. */
  visited: Set<MapNodeId>;
  /** The side's last `to`, or null before its first step. */
  current: MapNodeId | null;
}

/** The chosen side's walk through the graph. */
export function sidePath(steps: readonly StreamStep[], side: Side): SidePath {
  const taken = new Map<string, StreamStep[]>();
  const entered = new Map<MapNodeId, number>();
  const visited = new Set<MapNodeId>();
  let current: MapNodeId | null = null;
  for (const step of steps) {
    if (step.side !== side) continue;
    const edge = stepEdge(step);
    if (edge !== undefined) {
      const walked = taken.get(edge.id);
      if (walked === undefined) taken.set(edge.id, [step]);
      else walked.push(step);
    }
    const to = enteredNode(step);
    visited.add(leftNode(step));
    visited.add(to);
    entered.set(to, step.frameId);
    current = to;
  }
  return { taken, entered, visited, current };
}

export interface HoverTarget {
  /** The edge the hovered frame walked on this side, or null. */
  edgeId: string | null;
  /** The other side has a step on this frame, which the switch says with a dot. */
  otherSide: boolean;
}

/** What a hovered frame lights on the chosen side, and whether the other side moved on it too. */
export function hoverTarget(steps: readonly StreamStep[], side: Side, hoverFrameId: number | null): HoverTarget {
  if (hoverFrameId === null) return { edgeId: null, otherSide: false };
  let edgeId: string | null = null;
  let otherSide = false;
  for (const step of steps) {
    if (step.frameId !== hoverFrameId) continue;
    if (step.side !== side) { otherSide = true; continue; }
    const edge = stepEdge(step);
    if (edge !== undefined) edgeId = edge.id;
  }
  return { edgeId, otherSide };
}

/** The edges drawn for a side: every ordinary edge, and a reset edge only where the side took it. */
export function drawnEdges(path: SidePath): MapEdge[] {
  return STATE_EDGES.filter((edge) => !edge.rst || path.taken.has(edge.id));
}

/**
 * What a taken edge's label says. A reset edge is labelled with who sent it,
 * read from the step's evidence: this side sent it, or it arrived.
 */
export function edgeLabel(edge: MapEdge, walked: readonly StreamStep[] | undefined): string {
  if (!edge.rst || walked === undefined || walked.length === 0) return edge.label;
  const sent = walked.filter((s) => s.evidence === 'sent').length;
  const who = sent === walked.length ? 'RST sent' : sent === 0 ? 'RST received' : 'RST';
  // One line is drawn however many times port reuse walked the edge; the count says so.
  return walked.length > 1 ? `${who} ×${walked.length}` : who;
}

/** Where a label sits, rounded: two labels with the same key overprint. */
function labelSlot(edge: MapEdge): string | null {
  const label = edgeGeometry(edge).label;
  return label === null ? null : `${label.x.toFixed(1)},${label.y.toFixed(1)},${label.anchor}`;
}

/**
 * The text each drawn reset edge's label gets; null where it falls silent.
 *
 * The reset routes run down two shared channels and along one floor, and the
 * hand-laid labels of several edges sit on the same spot: a stream whose port
 * is reused and reset from two different states used to print two labels on
 * top of each other. The lines may share a trunk (they leave different nodes,
 * so the branches say which is which), but a label cannot, so edges that
 * share a slot share ONE label, the total across them (`RST x3`), until one
 * of them is lit: then that edge speaks for itself and the rest fall silent.
 */
export function resetLabels(edges: readonly MapEdge[], path: SidePath, litId: string | null): Map<string, string | null> {
  const bySlot = new Map<string, MapEdge[]>();
  for (const edge of edges) {
    if (!edge.rst) continue;
    const slot = labelSlot(edge);
    if (slot === null) continue;
    const group = bySlot.get(slot);
    if (group === undefined) bySlot.set(slot, [edge]); else group.push(edge);
  }
  const out = new Map<string, string | null>();
  for (const group of bySlot.values()) {
    const leader = group.find((e) => e.id === litId) ?? group[0];
    // Every walk across the group, so the shared label still says who sent
    // the resets when they agree (`RST sent ×3`), and plain `RST` when not.
    const walks = group.flatMap((e) => path.taken.get(e.id) ?? []);
    for (const edge of group) {
      if (group.length === 1 || (edge === leader && litId === edge.id)) out.set(edge.id, edgeLabel(edge, path.taken.get(edge.id)));
      else if (edge === leader) out.set(edge.id, edgeLabel(edge, walks));
      else out.set(edge.id, null);
    }
  }
  return out;
}

/** Whether a taken edge is drawn dashed: one the capture implied rather than saw. */
export function isImplied(edge: MapEdge, walked: readonly StreamStep[] | undefined): boolean {
  if (edge.expected) return true;
  return walked !== undefined && walked.length > 0 && walked.every((s) => s.evidence === 'inferred');
}

export type Point = [number, number];
export type Anchor = 'start' | 'middle' | 'end';

interface Route {
  /** One control point for a quadratic, two for a cubic. */
  via?: [Point] | [Point, Point];
  /** Waypoints for a route that turns corners: straight runs joined by rounded corners. */
  through?: Point[];
  /**
   * Where the label sits: a point along the path (0..1) with a nudge in
   * cells, or an absolute place. `split` breaks it at its " / " or " (" into
   * two lines, for a label with no room beside its edge on one line. `false`
   * draws the edge bare, for an edge too short to carry its label anywhere
   * that reads as its own.
   */
  label?: { t?: number; dx?: number; dy?: number; at?: Point; anchor?: Anchor; split?: true } | false;
}

/** The radius a `through` route rounds its corners with. */
const CORNER = 0.2;
/** The two vertical channels between the columns, and the margin under the bottom row, that `through` routes run in. */
const LEFT = 1.5;
const RIGHT = 3.5;
const FLOOR = 6.95;

/**
 * The hand-laid routes. Coordinates are cells on the grid in
 * `tcpStateGraph.ts`; a node's box is 1.6 by 0.5, so the gap between two
 * columns' nodes is 0.4 cells wide and between two rows' is 0.5 tall. Resets
 * run down a channel to CLOSED - the right column's from the side, the left
 * column's along the floor - so none crosses a node; each is drawn only when
 * taken.
 */
const ROUTES: Record<string, Route> = {
  'UNKNOWN>ESTABLISHED': { through: [[LEFT, 1.5], [LEFT, 3.1]], label: { at: [1.3, 1.8], anchor: 'end', split: true } },
  // Shorter than its label, in the one corner where two edges leave the same
  // node: on the edge its halo erases it, and every clear place for it is a
  // cell away, beside the mid-stream edge. The dash and the node it enters
  // say "implied" and "LISTEN" already.
  'UNKNOWN>LISTEN': { via: [[1.4, 0.8]], label: false },
  'UNKNOWN>SYN_SENT': { via: [[1.7, -0.35], [5.65, -0.2]], label: { at: [3.3, -0.2] } },
  'CLOSED>LISTEN': { label: { dx: 0.14, anchor: 'start', split: true } },
  'CLOSED>SYN_SENT': { via: [[4.6, 0.8]], label: { at: [4.4, 2.0], anchor: 'end', split: true } },
  'LISTEN>SYN_RCVD': { label: { dx: 0.12, dy: -0.1, anchor: 'start' } },
  'SYN_SENT>SYN_RCVD': { via: [[2.5, 2.08]], label: { t: 0.5, dy: 0.15 } },
  'SYN_SENT>ESTABLISHED': { label: { t: 0.5, dy: 0.13 } },
  'SYN_RCVD>ESTABLISHED': { label: { t: 0.5, dx: -0.12, anchor: 'end' } },
  'SYN_RCVD>FIN_WAIT_1': { via: [[-0.1, 3.5]], label: { t: 0.5, dx: 0.1, dy: -0.12, anchor: 'start' } },
  'ESTABLISHED>FIN_WAIT_1': { label: { at: [1.25, 3.78], anchor: 'end', split: true } },
  'ESTABLISHED>CLOSE_WAIT': { label: { t: 0.5, dy: -0.13 } },
  'FIN_WAIT_1>FIN_WAIT_2': { label: { dx: -0.14, anchor: 'end' } },
  'FIN_WAIT_1>CLOSING': { label: { at: [1.6, 4.98], anchor: 'start' } },
  'FIN_WAIT_2>TIME_WAIT': { label: { at: [1.42, 5.86], anchor: 'end' } },
  'CLOSING>TIME_WAIT': { label: { dx: -0.14, anchor: 'end' } },
  'CLOSE_WAIT>LAST_ACK': { label: { dx: 0.14, anchor: 'start', split: true } },
  'LAST_ACK>CLOSED_END': { label: { dx: 0.25, anchor: 'start' } },
  'TIME_WAIT>CLOSED_END:timeout': { label: { at: [4.4, FLOOR + 0.03] } },
  // Up the left channel and over ESTABLISHED into SYN_SENT's side: the one way
  // from the bottom middle to the top right that crosses no node.
  'TIME_WAIT>SYN_SENT': { through: [[LEFT, 6.0], [LEFT, 3.0]], label: { at: [1.55, 4.1], anchor: 'start' } },
  'UNKNOWN>CLOSED_END:rst': { through: [[LEFT, 1.2], [LEFT, FLOOR], [RIGHT, FLOOR]], label: { at: [2.5, FLOOR + 0.03] } },
  'LISTEN>CLOSED_END:rst': { through: [[RIGHT, 1.5], [RIGHT, 6.0]], label: { at: [3.6, 3.55], anchor: 'start' } },
  'SYN_SENT>CLOSED_END:rst': { through: [[RIGHT, 3.0], [RIGHT, 6.0]], label: { at: [3.6, 3.55], anchor: 'start' } },
  'SYN_RCVD>CLOSED_END:rst': { through: [[LEFT, 2.9], [LEFT, FLOOR], [RIGHT, FLOOR]], label: { at: [2.5, FLOOR + 0.03] } },
  'ESTABLISHED>CLOSED_END:rst': { through: [[RIGHT, 3.9], [RIGHT, 6.0]], label: { at: [3.4, 4.6], anchor: 'end' } },
  'FIN_WAIT_1>CLOSED_END:rst': { through: [[LEFT, 4.7], [LEFT, FLOOR], [RIGHT, FLOOR]], label: { at: [2.5, FLOOR + 0.03] } },
  'FIN_WAIT_2>CLOSED_END:rst': { through: [[LEFT, 5.6], [LEFT, FLOOR], [RIGHT, FLOOR]], label: { at: [2.5, FLOOR + 0.03] } },
  'CLOSING>CLOSED_END:rst': { through: [[RIGHT, 5.6], [RIGHT, 6.0]], label: { at: [3.42, 5.98], anchor: 'end', split: true } },
  'CLOSE_WAIT>CLOSED_END:rst': { through: [[RIGHT, 4.6], [RIGHT, 6.0]], label: { at: [3.4, 4.6], anchor: 'end' } },
  'LAST_ACK>CLOSED_END:rst': { through: [[RIGHT, 5.6], [RIGHT, 6.0]], label: { at: [3.42, 5.98], anchor: 'end', split: true } },
  'TIME_WAIT>CLOSED_END:rst': { through: [[RIGHT, 6.6], [RIGHT, FLOOR]], label: { at: [2.5, FLOOR + 0.03] } },
};

/** One piece of a path - a line, a quadratic or a cubic - by its control polygon. */
export type Piece = Point[];

export interface EdgeGeometry {
  /** The path's `d`, in cells. */
  d: string;
  start: Point;
  end: Point;
  /** Where the label sits, or null for an edge drawn bare. */
  label: { x: number; y: number; anchor: Anchor; split: boolean } | null;
  /** The path's pieces, for sampling it. */
  pieces: Piece[];
}

/** A point on a bezier of any order - De Casteljau over its control polygon. */
function bezierAt(polygon: readonly Point[], t: number): Point {
  let points: Point[] = [...polygon];
  while (points.length > 1) {
    const next: Point[] = [];
    for (let i = 0; i < points.length - 1; i++) {
      next.push([points[i][0] + (points[i + 1][0] - points[i][0]) * t, points[i][1] + (points[i + 1][1] - points[i][1]) * t]);
    }
    points = next;
  }
  return points[0];
}

const distance = (a: Point, b: Point): number => Math.hypot(b[0] - a[0], b[1] - a[1]);

/** A piece's length, by sampling; exact for a line. */
function pieceLength(piece: Piece): number {
  if (piece.length === 2) return distance(piece[0], piece[1]);
  let length = 0;
  let last = piece[0];
  for (let i = 1; i <= 16; i++) {
    const next = bezierAt(piece, i / 16);
    length += distance(last, next);
    last = next;
  }
  return length;
}

/** A point along a whole path, `t` in 0..1 by arc length. */
export function pointAt(pieces: readonly Piece[], t: number): Point {
  const lengths = pieces.map(pieceLength);
  const total = lengths.reduce((a, b) => a + b, 0);
  let remaining = Math.min(Math.max(t, 0), 1) * total;
  for (let i = 0; i < pieces.length; i++) {
    if (remaining <= lengths[i] || i === pieces.length - 1) {
      return bezierAt(pieces[i], lengths[i] === 0 ? 0 : Math.min(remaining / lengths[i], 1));
    }
    remaining -= lengths[i];
  }
  const last = pieces[pieces.length - 1];
  return last[last.length - 1];
}

/** Where a ray from a box's centre in direction `(dx, dy)` leaves the box. */
function exit(box: Box, dx: number, dy: number): Point {
  if (dx === 0 && dy === 0) return [box.cx, box.cy + box.h / 2];
  const tx = dx === 0 ? Infinity : (box.w / 2) / Math.abs(dx);
  const ty = dy === 0 ? Infinity : (box.h / 2) / Math.abs(dy);
  const t = Math.min(tx, ty);
  return [box.cx + dx * t, box.cy + dy * t];
}

/** Straight runs through `points`, each corner between them rounded with a quadratic. */
function cornered(points: Point[]): Piece[] {
  const pieces: Piece[] = [];
  let at = points[0];
  for (let i = 1; i < points.length - 1; i++) {
    const corner = points[i];
    const before = points[i - 1];
    const after = points[i + 1];
    const din = distance(before, corner);
    const dout = distance(corner, after);
    const r = Math.min(CORNER, din / 2, dout / 2);
    const enter: Point = [corner[0] - ((corner[0] - before[0]) / din) * r, corner[1] - ((corner[1] - before[1]) / din) * r];
    const leave: Point = [corner[0] + ((after[0] - corner[0]) / dout) * r, corner[1] + ((after[1] - corner[1]) / dout) * r];
    pieces.push([at, enter], [enter, corner, leave]);
    at = leave;
  }
  pieces.push([at, points[points.length - 1]]);
  return pieces;
}

const f = ([x, y]: Point): string => `${x.toFixed(3)},${y.toFixed(3)}`;

function pathData(pieces: readonly Piece[]): string {
  const parts = [`M${f(pieces[0][0])}`];
  for (const piece of pieces) {
    if (piece.length === 2) parts.push(`L${f(piece[1])}`);
    else if (piece.length === 3) parts.push(`Q${f(piece[1])} ${f(piece[2])}`);
    else parts.push(`C${f(piece[1])} ${f(piece[2])} ${f(piece[3])}`);
  }
  return parts.join(' ');
}

/** An edge's path, from border to border, and its label's place. */
export function edgeGeometry(edge: MapEdge): EdgeGeometry {
  const from = nodeBox(nodeById(edge.from));
  const to = nodeBox(nodeById(edge.to));
  const route = ROUTES[edge.id] ?? {};
  const inner: Point[] = route.through ?? route.via ?? [];
  const first = inner[0] ?? [to.cx, to.cy];
  const last = inner[inner.length - 1] ?? [from.cx, from.cy];
  const start = exit(from, first[0] - from.cx, first[1] - from.cy);
  const end = exit(to, last[0] - to.cx, last[1] - to.cy);
  const pieces = route.through !== undefined
    ? cornered([start, ...route.through, end])
    : [[start, ...inner, end]];
  if (route.label === false) return { d: pathData(pieces), start, end, pieces, label: null };
  const label = route.label ?? {};
  const at = label.at ?? pointAt(pieces, label.t ?? 0.5);
  return {
    d: pathData(pieces), start, end, pieces,
    label: {
      x: at[0] + (label.dx ?? 0), y: at[1] + (label.dy ?? 0),
      anchor: label.anchor ?? 'middle', split: label.split === true,
    },
  };
}

/** A label's lines: one, or two when its route says to split it at " / " or " (". */
export function labelLines(text: string, split: boolean): string[] {
  if (!split) return [text];
  const slash = text.indexOf(' / ');
  if (slash > 0) return [text.slice(0, slash), text.slice(slash + 1)];
  const paren = text.indexOf(' (');
  if (paren > 0) return [text.slice(0, paren), text.slice(paren + 1)];
  const space = text.lastIndexOf(' ', Math.ceil(text.length / 2));
  return space > 0 ? [text.slice(0, space), text.slice(space + 1)] : [text];
}
