/**
 * Every transition the machine can make has an edge on the map (ADR 0055).
 *
 *   npx tsx scripts/conversation/state-graph.ts
 */
import { TcpStateMachine, type TcpSegment } from '../../src/services/conversation/tcpStates';
import { STATE_EDGES, STATE_NODES, edgeFor } from '../../src/components/ladder/tcpStateGraph';

let failures = 0;
const fail = (m: string) => { failures++; console.log(`FAIL  ${m}`); };

// A small LCG so a failure is reproducible from its seed.
let seed = 0x5eed;
const rand = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32);
const flagSets = ['S', 'SA', 'A', 'FA', 'F', 'RA', 'R', 'A'];
const missing = new Set<string>();
const wrongReset = new Set<string>();
for (let run = 0; run < 20_000; run++) {
  const m = new TcpStateMachine();
  let seq = { client: 0, server: 0 };
  for (let i = 0; i < 12; i++) {
    const from = rand() < 0.5 ? 'client' : 'server';
    const flags = flagSets[Math.floor(rand() * flagSets.length)];
    const other = from === 'client' ? 'server' : 'client';
    const segment: TcpSegment = {
      from, syn: flags.includes('S'), ack: flags.includes('A'), fin: flags.includes('F'), rst: flags.includes('R'),
      ...(rand() < 0.8 ? { seq: seq[from], len: 0, ackNo: seq[other] + (rand() < 0.5 ? 1 : 0) } : {}),
    };
    if (segment.syn || segment.fin) seq[from]++;
    for (const t of m.apply(segment)) {
      const edge = edgeFor(t.from, t.to, t.cause);
      if (edge === undefined) missing.add(`${t.from}>${t.to}`);
      else if (t.cause === 'rst' && edge.rst !== true) wrongReset.add(`${t.from}>${t.to}`);
    }
  }
}
if (missing.size > 0) fail(`transitions with no edge: ${[...missing].sort().join(', ')}`);
else console.log('PASS  every transition from 20,000 random runs has an edge');
if (wrongReset.size > 0) fail(`reset transitions answered by a non-reset edge: ${[...wrongReset].sort().join(', ')}`);
else console.log('PASS  every reset transition from 20,000 random runs is drawn as a reset');

const lastAckAck = edgeFor('LAST_ACK', 'CLOSED', 'ack');
const lastAckRst = edgeFor('LAST_ACK', 'CLOSED', 'rst');
if (lastAckAck?.id !== 'LAST_ACK>CLOSED_END' || lastAckAck.rst) fail(`LAST_ACK>CLOSED by ack is ${lastAckAck?.id}`);
else if (lastAckRst?.id !== 'LAST_ACK>CLOSED_END:rst' || lastAckRst.rst !== true) fail(`LAST_ACK>CLOSED by rst is ${lastAckRst?.id}`);
else console.log('PASS  LAST_ACK to CLOSED is the ACK edge on ack and the RST edge on rst');

const ids = new Set(STATE_NODES.map((n) => n.id));
for (const e of STATE_EDGES) {
  if (!ids.has(e.from) || !ids.has(e.to)) fail(`edge ${e.id} names a node that does not exist`);
}
if (new Set(STATE_EDGES.map((e) => e.id)).size !== STATE_EDGES.length) fail('edge ids repeat');
const cells = new Set(STATE_NODES.map((n) => `${n.col},${n.row}`));
if (cells.size !== STATE_NODES.length) fail('two nodes share a grid cell');
if (failures === 0) console.log('PASS  edges name real nodes, ids are unique, cells are distinct');

process.exit(failures === 0 ? 0 : 1);
