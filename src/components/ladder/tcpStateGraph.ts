/**
 * The RFC 793 state diagram as data, laid out on a grid the way the RFC's own
 * figure is (ADR 0055). Positions are grid cells; `TcpStateMap` scales them.
 *
 * CLOSED appears twice, as it does in the figure: once at the top where a
 * connection starts, and once at the bottom where it ends, so the drawing
 * reads top to bottom without an edge looping back across it.
 */
import type { TcpState, TransitionCause } from '../../services/conversation/tcpStates';

export type MapNodeId = TcpState | 'CLOSED_END';

export interface MapNode { id: MapNodeId; label: string; col: number; row: number; dashed?: boolean }
export interface MapEdge {
  id: string;
  from: MapNodeId;
  to: MapNodeId;
  /** As the RFC labels it: what was received / what was sent. */
  label: string;
  /** Drawn only when this connection took it. */
  rst?: true;
  /** Never observed on the wire, only implied (TIME_WAIT's timeout). */
  expected?: true;
}

export const STATE_NODES: MapNode[] = [
  { id: 'UNKNOWN', label: 'not captured', col: 0, row: 0, dashed: true },
  { id: 'CLOSED', label: 'CLOSED', col: 2, row: 0 },
  { id: 'LISTEN', label: 'LISTEN', col: 2, row: 1 },
  { id: 'SYN_RCVD', label: 'SYN_RCVD', col: 0, row: 2 },
  { id: 'SYN_SENT', label: 'SYN_SENT', col: 4, row: 2 },
  { id: 'ESTABLISHED', label: 'ESTABLISHED', col: 2, row: 3 },
  { id: 'FIN_WAIT_1', label: 'FIN_WAIT_1', col: 0, row: 4 },
  { id: 'CLOSE_WAIT', label: 'CLOSE_WAIT', col: 4, row: 4 },
  { id: 'FIN_WAIT_2', label: 'FIN_WAIT_2', col: 0, row: 5 },
  { id: 'CLOSING', label: 'CLOSING', col: 2, row: 5 },
  { id: 'LAST_ACK', label: 'LAST_ACK', col: 4, row: 5 },
  { id: 'TIME_WAIT', label: 'TIME_WAIT', col: 2, row: 6 },
  { id: 'CLOSED_END', label: 'CLOSED', col: 4, row: 6 },
];

const e = (from: MapNodeId, to: MapNodeId, label: string, extra: Partial<MapEdge> = {}): MapEdge =>
  ({ id: `${from}>${to}`, from, to, label, ...extra });

const RST_FROM: TcpState[] = [
  'UNKNOWN', 'LISTEN', 'SYN_SENT', 'SYN_RCVD', 'ESTABLISHED', 'FIN_WAIT_1', 'FIN_WAIT_2',
  'CLOSING', 'CLOSE_WAIT', 'LAST_ACK', 'TIME_WAIT',
];

export const STATE_EDGES: MapEdge[] = [
  e('UNKNOWN', 'ESTABLISHED', 'joined mid-stream'),
  e('UNKNOWN', 'LISTEN', 'listening (implied)'),
  e('UNKNOWN', 'SYN_SENT', 'SYN not captured'),
  e('CLOSED', 'LISTEN', 'passive open'),
  e('CLOSED', 'SYN_SENT', 'active open / SYN'),
  e('LISTEN', 'SYN_RCVD', 'SYN / SYN+ACK'),
  e('SYN_SENT', 'SYN_RCVD', 'SYN / SYN+ACK'),
  e('SYN_SENT', 'ESTABLISHED', 'SYN+ACK / ACK'),
  e('SYN_RCVD', 'ESTABLISHED', 'ACK'),
  e('SYN_RCVD', 'FIN_WAIT_1', 'close / FIN'),
  e('ESTABLISHED', 'FIN_WAIT_1', 'close / FIN'),
  e('ESTABLISHED', 'CLOSE_WAIT', 'FIN / ACK'),
  e('FIN_WAIT_1', 'FIN_WAIT_2', 'ACK'),
  e('FIN_WAIT_1', 'CLOSING', 'FIN / ACK'),
  e('FIN_WAIT_2', 'TIME_WAIT', 'FIN / ACK'),
  e('CLOSING', 'TIME_WAIT', 'ACK'),
  e('CLOSE_WAIT', 'LAST_ACK', 'close / FIN'),
  e('LAST_ACK', 'CLOSED_END', 'ACK'),
  // The machine reaches CLOSED from TIME_WAIT only by RST, so edgeFor keys on the
  // RST edge; the timeout gets its own id so the two do not collide.
  e('TIME_WAIT', 'CLOSED_END', 'timeout (expected)', { id: 'TIME_WAIT>CLOSED_END:timeout', expected: true }),
  e('TIME_WAIT', 'SYN_SENT', 'reused / SYN'),
  ...RST_FROM.map((from) => e(from, 'CLOSED_END', 'RST', { id: `${from}>CLOSED_END:rst`, rst: true })),
];

// Two tables, by what the transition was: an RST edge answers only an `rst`
// cause, and every other cause takes the ordinary edge for the pair. Where a
// pair has no ordinary edge (only a reset can reach CLOSED from TIME_WAIT), the
// RST edge answers. `expected` edges are never walked: the machine takes no
// timeouts.
const ORDINARY = new Map<string, MapEdge>();
const RESET = new Map<string, MapEdge>();
for (const edge of STATE_EDGES) {
  if (edge.expected) continue;
  const key = `${edge.from}>${edge.to}`;
  if (edge.rst) RESET.set(key, edge);
  else ORDINARY.set(key, edge);
}

/**
 * The edge a transition walked. Every transition to CLOSED ends at the bottom
 * node. A `cause` of `'rst'` gets the reset edge for the pair; any other cause
 * gets the ordinary edge, falling back to the reset edge only where no ordinary
 * one exists.
 */
export function edgeFor(from: TcpState, to: TcpState, cause?: TransitionCause): MapEdge | undefined {
  const target: MapNodeId = to === 'CLOSED' ? 'CLOSED_END' : to;
  const key = `${from}>${target}`;
  if (cause === 'rst') return RESET.get(key);
  return ORDINARY.get(key) ?? RESET.get(key);
}
