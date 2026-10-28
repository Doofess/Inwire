/**
 * Assertions for the state map's reset edges under port reuse (ADR 0055 stage 1 minors).
 *
 *   npx tsx scripts/session/state-map-reset.ts
 *
 * Held here: a stream whose 4-tuple is reused and reset more than once draws
 * ONE line per edge, so the label counts the walks (`RST sent x2`); and reset
 * edges whose hand-laid labels share a spot share one label instead of
 * printing over each other, which `resetLabels` decides.
 */
import { readFileSync } from 'node:fs';
import type { StreamStep } from '../../src/services/conversation/streamDigest';
import { TcpStateMachine, type Side, type TcpSegment } from '../../src/services/conversation/tcpStates';
import { STATE_EDGES } from '../../src/components/ladder/tcpStateGraph';
import { drawnEdges, edgeGeometry, edgeLabel, resetLabels, sidePath } from '../../src/components/ladder/tcpStateMapModel';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}

function stepsOf(segments: [Side, string][]): StreamStep[] {
  const machine = new TcpStateMachine();
  const steps: StreamStep[] = [];
  segments.forEach(([from, flags], i) => {
    const segment: TcpSegment = {
      from, syn: flags.includes('S'), ack: flags.includes('A'), fin: flags.includes('F'), rst: flags.includes('R'),
      seq: i * 1000, len: 0, ackNo: i * 1000,
    };
    for (const t of machine.apply(segment)) steps.push({ ...t, frameId: i + 1, time: (i + 1) / 1000 });
  });
  return steps;
}

const LABEL = '×';
const slotOf = (id: string) => {
  const l = edgeGeometry(STATE_EDGES.find((e) => e.id === id)!).label;
  return l === null ? null : `${l.x.toFixed(1)},${l.y.toFixed(1)},${l.anchor}`;
};

// --- Port reuse: the same reset edge walked twice -------------------------------------------
{
  // Reset the established connection, reuse the tuple, establish it, reset again.
  const handshake: [Side, string][] = [['client', 'S'], ['server', 'SA'], ['client', 'A']];
  const steps = stepsOf([...handshake, ['server', 'R'], ...handshake, ['server', 'R']]);
  const path = sidePath(steps, 'client');
  const rstEdges = [...path.taken.keys()].filter((id) => id.endsWith(':rst'));
  check('two resets on one edge draw one reset edge', rstEdges, ['ESTABLISHED>CLOSED_END:rst']);
  const edge = STATE_EDGES.find((e) => e.id === rstEdges[0])!;
  check('...whose label counts both walks', edgeLabel(edge, path.taken.get(edge.id)), `RST received ${LABEL}2`);
  check('...and a single walk carries no count', edgeLabel(edge, path.taken.get(edge.id)!.slice(0, 1)), 'RST received');
  const mixed = [{ ...path.taken.get(edge.id)![0], evidence: 'sent' as const }, path.taken.get(edge.id)![0]];
  check('...and mixed evidence says plain RST', edgeLabel(edge, mixed), `RST ${LABEL}2`);
}

// --- Labels that share a slot ---------------------------------------------------------------
{
  const byId = (id: string) => STATE_EDGES.find((e) => e.id === id)!;
  const a = byId('LISTEN>CLOSED_END:rst');
  const b = byId('SYN_SENT>CLOSED_END:rst');
  const c = byId('ESTABLISHED>CLOSED_END:rst');
  check('the fixture really has two reset labels on one spot', slotOf(a.id) === slotOf(b.id) && slotOf(a.id) !== slotOf(c.id), true);

  const step = (evidence: 'sent' | 'received'): StreamStep =>
    ({ side: 'client', from: 'ESTABLISHED', to: 'CLOSED', cause: 'rst', evidence, frameId: 1, time: 0 } as unknown as StreamStep);
  const path = sidePath([], 'client');
  path.taken.set(a.id, [step('received')]);
  path.taken.set(b.id, [step('received'), step('received')]);
  path.taken.set(c.id, [step('sent')]);
  const edges = drawnEdges(path);

  const labels = resetLabels(edges, path, null);
  check('a lone edge keeps its own label', labels.get(c.id), 'RST sent');
  check('edges sharing a spot print one label, the total, saying who when they agree',
    [labels.get(a.id), labels.get(b.id)], [`RST received ${LABEL}3`, null]);
  path.taken.set(a.id, [step('sent')]);
  check('...and plain RST when they do not',
    resetLabels(edges, path, null).get(a.id), `RST ${LABEL}3`);
  path.taken.set(a.id, [step('received')]);
  const visible = [...labels.values()].filter((t) => t !== null).length;
  check('three drawn reset edges on two spots print two labels', visible, 2);

  const lit = resetLabels(edges, path, b.id);
  check('the lit edge speaks for itself and its neighbour falls silent', [lit.get(a.id), lit.get(b.id)], [null, `RST received ${LABEL}2`]);
  check('an edge not drawn has no label to place', resetLabels(drawnEdges(sidePath([], 'client')), sidePath([], 'client'), null).size, 0);
}

// --- The pane, read as source (a component is unreachable from tsx) -------------------------
{
  const pane = readFileSync('src/components/stream-follower/StreamFollowerPane.tsx', 'utf8');
  const map = readFileSync('src/components/ladder/TcpStateMap.tsx', 'utf8');
  check("the map says when steps were dropped", map.includes("summary.stepsDropped > 0"), true);
  check('a map put away is not mounted: the aside renders only when docked or open',
    pane.includes("{(docked || mapOpen) && (") && pane.indexOf("<aside", pane.indexOf("(docked || mapOpen)")) - pane.indexOf("(docked || mapOpen)") < 60, true);
  check('the Client | Server choice lives in the pane, so it survives the unmount',
    pane.includes("side={mapSide}") && pane.includes("onSideChange={setMapSide}"), true);
}

if (failures) { console.log(`${failures} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
