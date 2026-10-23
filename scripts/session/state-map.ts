/**
 * Assertion tests for what the state map draws for one side (ADR 0055 §1).
 *
 *   npx tsx scripts/session/state-map.ts
 *
 * Four things are held here, and each fails invisibly on the screen:
 *
 *   - **The edge a step walked.** A SYN the capture saw is the RFC's active
 *     open out of CLOSED; drawn from UNKNOWN it would carry the label "SYN not
 *     captured" on a handshake that was. A reset walks a reset edge.
 *   - **One side's path.** Which edges are taken, which nodes were visited,
 *     which is current, and which frame entered each - the frame a click
 *     scrolls the ladder to. Under port reuse a node is entered twice and the
 *     map answers for the incarnation its fill describes, the last.
 *   - **The link from the ladder.** A hovered frame lights the edge it walked
 *     on the chosen side; one that moved only the other side lights nothing
 *     and marks that side's tab, so the link is never silent.
 *   - **The figure's geometry.** Every edge runs from its node's border to
 *     its node's border, no edge runs through a node that is not its own, and
 *     no label sits on a node, on another label, or on another edge's line.
 *     The routes are laid by hand, so this is what holds them laid.
 */
import type { StreamStep } from '../../src/services/conversation/streamDigest';
import { TcpStateMachine, type Side, type TcpSegment } from '../../src/services/conversation/tcpStates';
import { STATE_EDGES, STATE_NODES } from '../../src/components/ladder/tcpStateGraph';
import {
  drawnEdges, edgeGeometry, edgeLabel, hoverTarget, isImplied, labelLines, nodeBox, pointAt, sidePath, stepEdge,
  MAP_WIDTH, VIEW, NODE_H, NODE_W,
} from '../../src/components/ladder/tcpStateMapModel';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** The digest's own steps for a sequence of segments, from the real machine, frame ids from 1. */
function stepsOf(segments: [Side, string, number?][]): StreamStep[] {
  const machine = new TcpStateMachine();
  const steps: StreamStep[] = [];
  let seq = { client: 0, server: 0 };
  segments.forEach(([from, flags, len], i) => {
    const other = from === 'client' ? 'server' : 'client';
    const segment: TcpSegment = {
      from, syn: flags.includes('S'), ack: flags.includes('A'), fin: flags.includes('F'), rst: flags.includes('R'),
      seq: seq[from], len: len ?? 0, ackNo: seq[other],
    };
    if (segment.syn || segment.fin) seq = { ...seq, [from]: seq[from] + 1 };
    if (len !== undefined) seq = { ...seq, [from]: seq[from] + len };
    for (const t of machine.apply(segment)) steps.push({ ...t, frameId: i + 1, time: (i + 1) / 1000 });
  });
  return steps;
}

const HANDSHAKE: [Side, string, number?][] = [['client', 'S'], ['server', 'SA'], ['client', 'A']];
const CLEAN_CLOSE: [Side, string, number?][] = [
  ...HANDSHAKE, ['client', 'A', 100], ['client', 'FA'], ['server', 'FA'], ['client', 'A'],
];

const edgeIds = (steps: StreamStep[], side: Side) => steps.filter((s) => s.side === side).map((s) => stepEdge(s)?.id ?? null);

// --- The edge a step walked ----------------------------------------------------------------
{
  const steps = stepsOf(CLEAN_CLOSE);
  check('a captured handshake\'s client opens actively from CLOSED, then is ESTABLISHED by the SYN+ACK',
    edgeIds(steps, 'client').slice(0, 2), ['CLOSED>SYN_SENT', 'SYN_SENT>ESTABLISHED']);
  check('...under the RFC\'s labels', steps.filter((s) => s.side === 'client').slice(0, 2).map((s) => stepEdge(s)?.label),
    ['active open / SYN', 'SYN+ACK / ACK']);
  check('its server listens, implied, then SYN_RCVD, then ESTABLISHED',
    edgeIds(steps, 'server').slice(0, 3), ['UNKNOWN>LISTEN', 'LISTEN>SYN_RCVD', 'SYN_RCVD>ESTABLISHED']);
  check('the client\'s close walks FIN_WAIT_1, FIN_WAIT_2 and TIME_WAIT',
    edgeIds(steps, 'client').slice(2), ['ESTABLISHED>FIN_WAIT_1', 'FIN_WAIT_1>FIN_WAIT_2', 'FIN_WAIT_2>TIME_WAIT']);
  check('the server\'s close walks CLOSE_WAIT, LAST_ACK and the bottom CLOSED',
    edgeIds(steps, 'server').slice(3), ['ESTABLISHED>CLOSE_WAIT', 'CLOSE_WAIT>LAST_ACK', 'LAST_ACK>CLOSED_END']);
  checkTrue('every step of a clean close has an edge', steps.every((s) => stepEdge(s) !== undefined));

  const missed = stepsOf([['server', 'SA'], ['client', 'A']]);
  check('a SYN+ACK answering a SYN the capture missed puts the client in SYN_SENT from UNKNOWN - "SYN not captured"',
    edgeIds(missed, 'client')[0], 'UNKNOWN>SYN_SENT');
  check('...which is the inferred edge, and the seen SYN\'s is not',
    [stepEdge(missed.find((s) => s.side === 'client')!)?.label, stepEdge(steps.find((s) => s.side === 'client')!)?.label],
    ['SYN not captured', 'active open / SYN']);

  const reset = stepsOf([...HANDSHAKE, ['server', 'RA']]);
  check('a reset walks the reset edge, on both sides',
    [edgeIds(reset, 'server').at(-1), edgeIds(reset, 'client').at(-1)],
    ['ESTABLISHED>CLOSED_END:rst', 'ESTABLISHED>CLOSED_END:rst']);
  const refused = stepsOf([['client', 'S'], ['server', 'RA']]);
  check('a refused SYN resets out of SYN_SENT and LISTEN',
    [edgeIds(refused, 'client').at(-1), edgeIds(refused, 'server').at(-1)],
    ['SYN_SENT>CLOSED_END:rst', 'LISTEN>CLOSED_END:rst']);
  const coldReset = stepsOf([['client', 'R']]);
  check('a reset as the first thing seen leaves UNKNOWN by its reset edge, not by an active open',
    edgeIds(coldReset, 'client'), ['UNKNOWN>CLOSED_END:rst']);
  const joined = stepsOf([['client', 'A', 100], ['server', 'A']]);
  check('a stream joined mid-way is ESTABLISHED out of UNKNOWN on both sides',
    [edgeIds(joined, 'client'), edgeIds(joined, 'server')], [['UNKNOWN>ESTABLISHED'], ['UNKNOWN>ESTABLISHED']]);
}

// --- One side's path ----------------------------------------------------------------------------
{
  const steps = stepsOf(CLEAN_CLOSE);
  const client = sidePath(steps, 'client');
  check('the client\'s taken edges, in order',
    [...client.taken.keys()],
    ['CLOSED>SYN_SENT', 'SYN_SENT>ESTABLISHED', 'ESTABLISHED>FIN_WAIT_1', 'FIN_WAIT_1>FIN_WAIT_2', 'FIN_WAIT_2>TIME_WAIT']);
  // ESTABLISHED at frame 3, the client's own ACK, not at the SYN+ACK: the
  // machine moves a side when it sends.
  check('...each walked by one step, naming its frame',
    [...client.taken.values()].map((walked) => walked.map((s) => s.frameId)), [[1], [3], [5], [6], [7]]);
  check('the nodes it visited, left and entered alike',
    [...client.visited], ['CLOSED', 'SYN_SENT', 'ESTABLISHED', 'FIN_WAIT_1', 'FIN_WAIT_2', 'TIME_WAIT']);
  check('its current state is its last step\'s', client.current, 'TIME_WAIT');
  check('each state was entered at the frame of the step that entered it',
    [...client.entered], [['SYN_SENT', 1], ['ESTABLISHED', 3], ['FIN_WAIT_1', 5], ['FIN_WAIT_2', 6], ['TIME_WAIT', 7]]);
  checkTrue('UNKNOWN is not among them: the handshake was seen', !client.visited.has('UNKNOWN'));

  const server = sidePath(steps, 'server');
  check('the server ends at the bottom CLOSED', server.current, 'CLOSED_END');
  check('...entered at the last ACK\'s frame', server.entered.get('CLOSED_END'), 7);
  checkTrue('...having started from UNKNOWN, since nothing shows a listener', server.visited.has('UNKNOWN'));
  checkTrue('...and the sides do not share steps',
    [...client.taken.keys()].every((id) => !server.taken.has(id)));

  const none = sidePath([], 'client');
  check('no steps: nothing taken, nothing visited, no current state',
    [none.taken.size, none.visited.size, none.current], [0, 0, null]);

  // Port reuse: the same five-tuple opens again after a clean close. The
  // states are entered twice; the fill describes the second incarnation and
  // so does the frame a click goes to.
  const reused = stepsOf([...CLEAN_CLOSE, ['client', 'S'], ['server', 'SA'], ['client', 'A']]);
  const again = sidePath(reused, 'client');
  check('under reuse the client takes the reuse edge out of TIME_WAIT', again.taken.has('TIME_WAIT>SYN_SENT'), true);
  check('...ESTABLISHED is entered by the second incarnation\'s frame', again.entered.get('ESTABLISHED'), 10);
  check('...and the edge into it was walked twice', again.taken.get('SYN_SENT>ESTABLISHED')?.map((s) => s.frameId), [3, 10]);
  check('...with the current state the second incarnation\'s', again.current, 'ESTABLISHED');
}

// --- The link from the ladder ------------------------------------------------------------------
{
  const steps = stepsOf(CLEAN_CLOSE);
  check('hovering the client\'s FIN lights its FIN_WAIT_1 edge on the client side',
    hoverTarget(steps, 'client', 5), { edgeId: 'ESTABLISHED>FIN_WAIT_1', otherSide: true });
  check('...and the CLOSE_WAIT edge on the server side', hoverTarget(steps, 'server', 5),
    { edgeId: 'ESTABLISHED>CLOSE_WAIT', otherSide: true });
  check('hovering the client\'s SYN on the server side lights the implied listen it caused, and marks the client',
    hoverTarget(steps, 'server', 1), { edgeId: 'UNKNOWN>LISTEN', otherSide: true });
  check('hovering the handshake\'s last ACK on the server side lights nothing - the server was moved by it, but received',
    hoverTarget(steps, 'server', 3), { edgeId: 'SYN_RCVD>ESTABLISHED', otherSide: true });
  check('hovering the data frame lights nothing anywhere', [hoverTarget(steps, 'client', 4), hoverTarget(steps, 'server', 4)],
    [{ edgeId: null, otherSide: false }, { edgeId: null, otherSide: false }]);
  check('no hover: nothing', hoverTarget(steps, 'client', null), { edgeId: null, otherSide: false });
  check('a frame that moved only the other side marks it',
    hoverTarget(stepsOf([...HANDSHAKE, ['client', 'A', 100], ['client', 'FA']]), 'server', 5).otherSide, true);
}

// --- Which edges are drawn, how they are labelled, which are implied -------------------------
{
  const clean = sidePath(stepsOf(CLEAN_CLOSE), 'client');
  const drawn = drawnEdges(clean);
  checkTrue('a clean close draws no reset edge', drawn.every((e) => !e.rst));
  check('...and every ordinary edge', drawn.length, STATE_EDGES.filter((e) => !e.rst).length);
  const reset = stepsOf([...HANDSHAKE, ['server', 'RA']]);
  const byReset = drawnEdges(sidePath(reset, 'client'));
  check('a reset draws its one reset edge', byReset.filter((e) => e.rst).map((e) => e.id), ['ESTABLISHED>CLOSED_END:rst']);

  const edge = STATE_EDGES.find((e) => e.id === 'ESTABLISHED>CLOSED_END:rst')!;
  check('a reset the side received is labelled so', edgeLabel(edge, sidePath(reset, 'client').taken.get(edge.id)), 'RST received');
  check('...and one it sent', edgeLabel(edge, sidePath(reset, 'server').taken.get(edge.id)), 'RST sent');
  check('an untaken reset edge keeps the graph\'s label', edgeLabel(edge, undefined), 'RST');
  const fin = STATE_EDGES.find((e) => e.id === 'ESTABLISHED>FIN_WAIT_1')!;
  check('an ordinary edge keeps its label whether taken or not',
    [edgeLabel(fin, clean.taken.get(fin.id)), edgeLabel(fin, undefined)], ['close / FIN', 'close / FIN']);

  const timeout = STATE_EDGES.find((e) => e.expected)!;
  checkTrue('the timeout is implied, taken or not', isImplied(timeout, undefined) && isImplied(timeout, []));
  const listen = STATE_EDGES.find((e) => e.id === 'UNKNOWN>LISTEN')!;
  const server = sidePath(stepsOf(CLEAN_CLOSE), 'server');
  checkTrue('the implied listen is dashed when taken', isImplied(listen, server.taken.get(listen.id)));
  checkTrue('a seen SYN is not', !isImplied(STATE_EDGES.find((e) => e.id === 'CLOSED>SYN_SENT')!, clean.taken.get('CLOSED>SYN_SENT')));
  checkTrue('a received FIN is not either: the segment was seen', !isImplied(
    STATE_EDGES.find((e) => e.id === 'ESTABLISHED>CLOSE_WAIT')!, server.taken.get('ESTABLISHED>CLOSE_WAIT')));
  checkTrue('an untaken ordinary edge is not implied', !isImplied(fin, undefined));
}

// --- Labels in lines -----------------------------------------------------------------------------
{
  check('a label is one line unless split', labelLines('active open / SYN', false), ['active open / SYN']);
  check('split at its slash, the slash leading the second line', labelLines('active open / SYN', true), ['active open', '/ SYN']);
  check('split at its parenthesis', labelLines('listening (implied)', true), ['listening', '(implied)']);
  check('split at the space nearest its middle', labelLines('joined mid-stream', true), ['joined', 'mid-stream']);
  check('a word does not split', labelLines('RST', true), ['RST']);
}

// --- The figure's geometry -----------------------------------------------------------------------
//
// Estimated as the drawing is: 9px mono text at the map's own scale, every
// node 1.6 by 0.5 cells. A label box that overlaps a node, another ordinary
// label, or a sample of another ordinary edge's line is a label nobody can
// read; a reset edge is held against the ordinary ones only, since one is
// drawn at a time.
{
  // The column is `w-[19.5rem]` (312px), border-box with a 1px `border-l`, the
  // map's `px-3` inside it, and a 5px `custom-scrollbar` once the pane is
  // shorter than the map. A wider drawing scrolls sideways at every width.
  checkTrue('the map fits its column with the scrollbar showing', MAP_WIDTH <= 312 - 1 - 2 * 12 - 5);
  const CELL = MAP_WIDTH / VIEW.w;
  const CHAR = 5.3 / CELL;
  const LINE = 10 / CELL;
  type Box = { id: string; x1: number; y1: number; x2: number; y2: number };
  const overlaps = (a: Box, b: Box) => a.x1 < b.x2 && b.x1 < a.x2 && a.y1 < b.y2 && b.y1 < a.y2;
  const nodes: Box[] = STATE_NODES.map((n) => {
    const b = nodeBox(n);
    return { id: n.id, x1: b.x, y1: b.y, x2: b.x + b.w, y2: b.y + b.h };
  });
  const geometry = new Map(STATE_EDGES.map((e) => [e.id, edgeGeometry(e)]));
  const labelBoxes = (edgeId: string, text: string): Box[] => {
    const label = geometry.get(edgeId)!.label;
    if (label === null) return [];
    const lines = labelLines(text, label.split);
    return lines.map((line, i) => {
      const w = line.length * CHAR;
      const y = label.y + (lines.length === 2 ? (i === 0 ? -LINE * 0.55 : LINE * 0.55) : 0);
      const x1 = label.anchor === 'start' ? label.x : label.anchor === 'end' ? label.x - w : label.x - w / 2;
      return { id: `${edgeId}#${i}`, x1, y1: y - LINE / 2, x2: x1 + w, y2: y + LINE / 2 };
    });
  };
  const samples = (edgeId: string) => Array.from({ length: 80 }, (_, i) => pointAt(geometry.get(edgeId)!.pieces, i / 79));
  const onBorder = (box: Box, [x, y]: [number, number]) => {
    const e = 1e-6;
    const onX = Math.abs(x - box.x1) < e || Math.abs(x - box.x2) < e;
    const onY = Math.abs(y - box.y1) < e || Math.abs(y - box.y2) < e;
    return (onX && y >= box.y1 - e && y <= box.y2 + e) || (onY && x >= box.x1 - e && x <= box.x2 + e);
  };
  const ordinary = STATE_EDGES.filter((e) => !e.rst);
  const inView = (b: Box) => b.x1 >= VIEW.x && b.x2 <= VIEW.x + VIEW.w && b.y1 >= VIEW.y && b.y2 <= VIEW.y + VIEW.h;

  checkTrue('nodes are 1.6 by 0.5 cells, centred in their cells', STATE_NODES.every((n) => {
    const b = nodeBox(n);
    return b.w === NODE_W && b.h === NODE_H && b.cx === n.col + 0.5 && b.cy === n.row + 0.5;
  }));
  checkTrue('every node is inside the view', nodes.every(inView));
  const problems: string[] = [];
  for (const edge of STATE_EDGES) {
    const g = geometry.get(edge.id)!;
    const from = nodes.find((n) => n.id === edge.from)!;
    const to = nodes.find((n) => n.id === edge.to)!;
    if (!onBorder(from, g.start)) problems.push(`${edge.id} does not start on ${edge.from}'s border`);
    if (!onBorder(to, g.end)) problems.push(`${edge.id} does not end on ${edge.to}'s border`);
    const line = samples(edge.id);
    for (const n of nodes) {
      if (n.id === edge.from || n.id === edge.to) continue;
      if (line.some(([x, y]) => x > n.x1 && x < n.x2 && y > n.y1 && y < n.y2)) problems.push(`${edge.id} runs through ${n.id}`);
    }
    if (line.some(([x, y]) => x < VIEW.x || x > VIEW.x + VIEW.w || y < VIEW.y || y > VIEW.y + VIEW.h)) {
      problems.push(`${edge.id} leaves the view`);
    }
    const text = edge.rst ? 'RST received' : edge.label;
    for (const box of labelBoxes(edge.id, text)) {
      if (!inView(box)) problems.push(`${box.id} leaves the view`);
      for (const n of nodes) if (overlaps(box, n)) problems.push(`${box.id} sits on ${n.id}`);
      for (const other of ordinary) {
        if (other.id === edge.id) continue;
        if (edge.rst || edge.id < other.id) {
          for (const ob of labelBoxes(other.id, other.label)) if (overlaps(box, ob)) problems.push(`${box.id} sits on ${ob.id}`);
        }
        if (samples(other.id).some(([x, y]) => x > box.x1 && x < box.x2 && y > box.y1 && y < box.y2)) {
          problems.push(`${box.id} is crossed by ${other.id}`);
        }
      }
    }
  }
  check('every edge runs border to border, through no other node, inside the view, with its label clear of every node, label and other edge',
    problems, []);

  // A label knocks the lines behind it out with a halo, its own edge's too: on
  // an edge barely longer than its label, the halo erases the edge, and a taken
  // path goes missing exactly where it was drawn to be seen.
  const hidden: string[] = [];
  for (const edge of STATE_EDGES) {
    const boxes = labelBoxes(edge.id, edge.rst ? 'RST received' : edge.label);
    if (boxes.length === 0) continue;
    const line = samples(edge.id);
    const under = line.filter(([x, y]) => boxes.some((b) => x > b.x1 && x < b.x2 && y > b.y1 && y < b.y2)).length;
    if (under / line.length > 0.5) hidden.push(`${edge.id} is ${Math.round((under / line.length) * 100)}% under its own label`);
  }
  check('no label hides most of its own edge', hidden, []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All state map checks passed.');
process.exit(0);
