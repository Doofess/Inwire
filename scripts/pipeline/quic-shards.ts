/**
 * QUIC on the shards (ADR 0053 phase 5): the ops that carry a datagram's
 * numbers, the shard's stand-in for the QUIC order, and the coordinator's
 * routing, forgetting and counting.
 *
 *   npx tsx scripts/pipeline/quic-shards.ts
 *
 * The coordinator here has shards whose messages are held until `deliver()`,
 * so a short header can be dispatched behind a long header that is still
 * queued - the race the numbering exists for - and the ops it sent can be read.
 * Every run is also held to the single Worker: each frame's columns, field bag
 * and tree, as one core dissects it. `parallel.ts` holds the whole fixtures to
 * that; this holds the corners it does not reach (an eviction a shard holds,
 * a lane-0 flow, a QinQ short header of a sharded flow).
 */
import { MAX_QUIC_FLOWS, Sequencer, quicFlowKey } from '../../src/services/dissect/sequencer';
import { ShardMiss, ShardQuicOrder, type QuicNumbering } from '../../src/services/dissect/shardNumbering';
import { Coordinator, coordinatorSequencer, type CoordFrame, type Merged } from '../../src/services/pipeline/coordinator';
import { Shard, shardEnv } from '../../src/services/pipeline/shard';
import { OP_QUIC, OP_QUIC_FORGET, OpWriter, readOps, type FromShard, type ToShard, type WireFrame } from '../../src/services/pipeline/shardProtocol';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import { keyLog } from '../../src/services/tls/keyLog';
import type { Packet, ProtocolLayer } from '../../src/types/packet';
import { render } from './arrival';
import { quicFrame, quicPayload } from './quicCapture';
import { FIXED_ENV, trackers } from './virtualShards';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`);
}

const SERVER = '198.51.100.1';
const hex = (bytes: ArrayLike<number>) => Buffer.from(Array.from(bytes)).toString('hex');
/** A connection id unique to n, so no two flows share one. */
const cid = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff, 1, 2, 3, 4];

function wireFrame(id: number, bytes: Uint8Array): WireFrame {
  return { id, bytes, tsUs: 1_000_000 + id, relativeTime: id / 1e6, timeDelta: 1e-6, origLen: bytes.length, linktype: 1, facts: {} };
}

const facts = { index: 3, pnum: 4, sinceFirst: 0.5, sincePrev: 0.25 };

// --- the ops -------------------------------------------------------------

{
  const eth = { a: 'ea', b: 'eb', facts };
  const ip = { a: '192.0.2.1', b: '192.0.2.2', facts };
  const udp = { a: '192.0.2.1:50000', b: '192.0.2.2:443', facts };
  const flow = 'flow-a|flow-b';
  const full: QuicNumbering = { flow, known: true, resolveAt: 43, matched: 'aabb', long: false, number: 7 };
  const bare: QuicNumbering = { flow, known: false, resolveAt: -1, matched: undefined, long: true, number: undefined };
  const writer = new OpWriter();
  writer.quic(wireFrame(1, new Uint8Array(60).fill(1)), 'ip', eth, ip, udp, full);
  writer.quic(wireFrame(2, new Uint8Array(60).fill(2)), 'ipv6', eth, ip, udp, bare);
  const ops = [...readOps(structuredClone(writer.seal()))];
  const same = (a: unknown, b: unknown) => JSON.stringify(a, (_, v) => (v === undefined ? '__undefined' : v))
    === JSON.stringify(b, (_, v) => (v === undefined ? '__undefined' : v));
  check('ops: a QUIC frame reads back with its flow, known, match, long and number, and undefined stays undefined',
    ops[0]?.kind === OP_QUIC && same(ops[0].quic, full) && ops[0].udp!.a === udp.a && ops[0].udp!.b === udp.b
      && same(ops[0].udp!.facts, facts) && ops[0].family === 'ip' && ops[0].key === flow
      && same(ops[1]?.quic, bare) && ops[1].family === 'ipv6',
    JSON.stringify(ops.map((op) => op.quic)));

  const mixed = new OpWriter();
  mixed.tcp(wireFrame(1, new Uint8Array(4)), 'ip', eth, ip, 'k', 0);
  mixed.quicForget(flow);
  mixed.tcp(wireFrame(2, new Uint8Array(4)), 'ip', eth, ip, 'k', 0);
  const read = [...readOps(structuredClone(mixed.seal()))];
  const kinds = read.map((op) => op.kind);
  check('ops: a QUIC forget carries its flow, between TCP ops that read back unchanged',
    kinds.join() === '0,4,0' && read[1].key === flow && read[0].streamId === 0 && read[2].frame!.id === 2
      && read[2].key === 'k' && read[0].udp === undefined,
    kinds.join());
}

// --- the shard's order ---------------------------------------------------

{
  const f = 'f|g';
  const b = new Uint8Array(80);
  const q: QuicNumbering = { flow: f, known: true, resolveAt: 43, matched: 'aa', long: true, number: 5 };
  const o = new ShardQuicOrder();
  o.numbered(q);
  check('shard: the numbered answers come back once',
    o.isKnown(f) === true && o.match(f, b, 43) === 'aa' && o.noteLongHeader(f, [], false).number === 5 && o.done());

  const misses = (run: (o: ShardQuicOrder) => void): boolean => {
    const order = new ShardQuicOrder();
    order.numbered(q);
    try {
      run(order);
      return false;
    } catch (err) {
      return err instanceof ShardMiss;
    }
  };
  const short: QuicNumbering = { ...q, long: false, number: 2 };
  check('shard: another flow, another offset or a second match is a ShardMiss',
    misses((order) => order.isKnown('other'))
      && misses((order) => order.match(f, b, 44))
      && misses((order) => { order.match(f, b, 43); order.match(f, b, 43); })
      && misses((order) => order.connectionForFlow(f, undefined))
      && (() => { const order = new ShardQuicOrder(); order.numbered(short); try { order.noteLongHeader(f, [], false); return false; } catch (e) { return e instanceof ShardMiss; } })()
      && (() => { try { new ShardQuicOrder().isKnown(f); return false; } catch (e) { return e instanceof ShardMiss; } })(),
    'a miss that did not throw ShardMiss');

  const unasked = new ShardQuicOrder();
  check('shard: a number never asked is reported', (unasked.numbered(q), !unasked.done()));
}

// --- the coordinator, with shards that answer when told ------------------

interface Logged { kind: number; key: string | null; frameId?: number; quic?: QuicNumbering }

interface Rig {
  coordinator: Coordinator;
  merged: Map<number, Merged>;
  sent: Logged[][];
  forgot: string[];
  feed: (frames: Uint8Array[]) => void;
  deliver: () => void;
}

function rig(shards: number, assign?: (key: string, shards: number) => number): Rig {
  const toShard: ToShard[][] = Array.from({ length: shards }, () => []);
  const toCoordinator: { shard: number; message: FromShard }[] = [];
  const workers = Array.from({ length: shards }, (_, s) => new Shard((message, transfer) => {
    toCoordinator.push({ shard: s, message: structuredClone(message, { transfer: transfer as ArrayBuffer[] }) });
  }, { shards, env: FIXED_ENV, withTrees: true }));
  const sequencer = coordinatorSequencer();
  const lane = trackers(sequencer);
  const forgot: string[] = [];
  const forget = lane.quic.forget.bind(lane.quic);
  lane.quic.forget = (flow: string) => { forgot.push(flow); forget(flow); };
  const sent: Logged[][] = Array.from({ length: shards }, () => []);
  const merged = new Map<number, Merged>();
  const coordinator = new Coordinator({
    shards, route: 'connection', ...(assign ? { assign } : {}), trackers: lane, sequencer,
    env: shardEnv(FIXED_ENV, shards), ifaceOf: () => undefined, withTrees: true,
    send: (shard, message, transfer) => {
      const clone = structuredClone(message, { transfer: transfer as ArrayBuffer[] });
      if (clone.type === 'batch' && clone.ops !== null) {
        for (const op of readOps(clone.ops)) {
          sent[shard].push({
            kind: op.kind, key: op.key,
            ...(op.frame ? { frameId: op.frame.id } : {}), ...(op.quic ? { quic: op.quic } : {}),
          });
        }
      }
      toShard[shard].push(clone);
    },
    emit: (m) => { merged.set(m.id, m); },
  });
  coordinator.decodeRows = true;
  let next = 1;
  return {
    coordinator, merged, sent, forgot,
    // One frame a call, so a batch is sealed behind the one before it, whose answer is not yet in.
    feed: (frames) => {
      for (const bytes of frames) {
        const frame: CoordFrame = wireFrame(next++, bytes.slice());
        coordinator.dispatch([frame]);
      }
    },
    deliver: () => {
      for (;;) {
        let moved = false;
        for (let s = 0; s < shards; s++) {
          const message = toShard[s].shift();
          if (message !== undefined) { workers[s].handle(message); moved = true; }
        }
        const back = toCoordinator.shift();
        if (back !== undefined) { coordinator.receive(back.shard, back.message); moved = true; }
        if (!moved) return;
      }
    },
  };
}

function describe(packet: Packet | undefined, layers: ProtocolLayer[] | undefined, error?: string): string {
  if (packet === undefined) return `error ${error}`;
  const fields = packet.fields ?? {};
  return JSON.stringify([
    packet.id, packet.source, packet.destination, packet.sourcePort, packet.destPort,
    packet.protocol, packet.protocolLabel, packet.info, packet.status, packet.length,
    packet.frameProtocols, packet.analysisFlags, Object.keys(fields).map((k) => [k, fields[k]]),
  ]) + '\n' + render(layers ?? []);
}

/** What the single Worker says of every frame. */
function oneCore(frames: Uint8Array[]): string[] {
  const dissector = new FrameDissector(trackers(new Sequencer()), FIXED_ENV, null);
  return frames.map((bytes, i) => {
    const f = wireFrame(i + 1, bytes.slice());
    try {
      const d = dissector.dissect({
        id: f.id, bytes: f.bytes, tsUs: f.tsUs, relativeTime: f.relativeTime, timeDelta: f.timeDelta,
        origLen: f.origLen, linktype: f.linktype, facts: f.facts,
      });
      return describe(d.packet, d.packet.layers);
    } catch (err) {
      return `error failed to dissect a captured frame: ${String(err)}`;
    }
  });
}

/** The frames' digests as merged, in id order. */
function mergedDigests(r: Rig, count: number): string[] {
  return Array.from({ length: count }, (_, i) => {
    const m = r.merged.get(i + 1);
    if (m === undefined) return `missing ${i + 1}`;
    return describe(m.packet, m.lane === 0 ? m.packet?.layers : m.layers, m.error);
  });
}

/** The run's output is the single Worker's, frame for frame, and no number went unasked. */
function agrees(r: Rig, frames: Uint8Array[]): boolean {
  const want = oneCore(frames);
  const got = mergedDigests(r, frames.length);
  const at = want.findIndex((w, i) => w !== got[i]);
  if (at !== -1) console.log(`        frame ${at + 1} differs`);
  return at === -1 && r.coordinator.quicMismatch === 0 && r.coordinator.barrierMismatch === 0;
}

const lanesOf = (r: Rig, ids: number[]) => new Set(ids.map((id) => r.merged.get(id)?.lane));

keyLog.clear();

// A short header dispatched behind its long header, which is still queued.
{
  const c = cid(1), s = cid(2);
  let turn = 0;
  const r = rig(2, () => turn++ % 2);
  const frames = [
    quicFrame('192.0.2.10', 50000, SERVER, 443, quicPayload('initial', { dcid: c, scid: s }), {}),
    quicFrame('192.0.2.10', 50000, SERVER, 443, quicPayload('short', { dcid: s }), {}),
  ];
  r.feed(frames);
  const ops0 = r.sent.find((ops) => ops.length > 0) ?? [];
  const idle = r.sent.filter((ops) => ops.length > 0).length;
  check('race: a short header dispatched behind its queued long header goes to the same shard, known and matched',
    idle === 1 && ops0.length === 2 && ops0[1].quic?.known === true && ops0[1].quic.matched === hex(s)
      && ops0[1].quic.number === ops0[0].quic?.number && ops0[0].quic?.long === true && ops0[1].quic.long === false,
    JSON.stringify(r.sent.map((ops) => ops.map((op) => op.quic))));
  r.deliver();
  check('race: after delivery both merge from the shard, as one core dissects them',
    r.coordinator.perLane[0] === 0 && agrees(r, frames), `lanes ${r.coordinator.perLane.join(' / ')}`);
}

// 4,097 flows: the first is forgotten by the last, on whichever lane holds it.
const host = (i: number) => `10.100.${Math.floor(i / 250)}.${(i % 250) + 1}`;
const initialOf = (i: number, o: { qinq?: boolean } = {}) =>
  quicFrame(host(i), 51000, SERVER, 443, quicPayload('initial', { dcid: cid(1000 + i), scid: cid(100000 + i), payload: 16 }), o);
const flowOf = (i: number) => quicFlowKey(host(i), 51000, SERVER, 443);
const EVICTING = MAX_QUIC_FLOWS; // the 4,097th flow's index

{
  // Flows 0 and 1 on shard 0, the rest on shard 1: flow 0's forget goes to shard 0, ahead of its next frame.
  const r = rig(2, (key) => (key === flowOf(0) || key === flowOf(1) ? 0 : 1));
  const frames: Uint8Array[] = [];
  for (let i = 0; i <= EVICTING; i++) frames.push(initialOf(i));
  frames.push(quicFrame(host(1), 51000, SERVER, 443, quicPayload('short', { dcid: cid(100001) }), {}));
  const shortOnForgotten = frames.length + 1;
  frames.push(quicFrame(host(0), 51000, SERVER, 443, quicPayload('short', { dcid: cid(100000) }), {}));
  const renewed = frames.length + 1;
  frames.push(quicFrame(host(0), 51000, SERVER, 443, quicPayload('initial', { dcid: cid(900000), scid: cid(900001), payload: 16 }), {}));
  r.feed(frames);
  // Delivered, so every batch has been sent and logged, in the order each shard was given them.
  r.deliver();
  const ops = r.sent[0];
  const forgetIndex = ops.findIndex((op) => op.kind === OP_QUIC_FORGET && op.key === flowOf(0));
  const nextFrameIndex = ops.findIndex((op, i) => i > forgetIndex && op.kind === OP_QUIC);
  check('evict: the 4,097th flow sends its forget to the shard holding the first, ahead of that shard\'s next frame',
    forgetIndex >= 0 && nextFrameIndex > forgetIndex && ops[nextFrameIndex].frameId === EVICTING + 2,
    `forget at ${forgetIndex}, next frame op at ${nextFrameIndex}`);
  const packet = r.merged.get(shortOnForgotten)?.packet;
  const number = r.merged.get(renewed)?.packet?.fields?.['quic.connection.number'];
  check('evict: the forgotten flow\'s short header is plain UDP on lane 0, and its next long header a new number',
    packet?.protocol === 'UDP' && r.merged.get(shortOnForgotten)?.lane === 0 && number === MAX_QUIC_FLOWS + 1 && agrees(r, frames),
    `protocol ${packet?.protocol}, number ${String(number)} (lane ${r.merged.get(renewed)?.lane}, id ${renewed}, ${r.merged.get(renewed)?.packet?.info})`);
}

{
  // Every flow on shard 0: the forget and the frame that caused it are one shard's, and the forget is first.
  const r = rig(2, () => 0);
  const frames: Uint8Array[] = [];
  for (let i = 0; i <= EVICTING; i++) frames.push(initialOf(i));
  r.feed(frames);
  r.deliver();
  const ops = r.sent[0];
  const forgetIndex = ops.findIndex((op) => op.kind === OP_QUIC_FORGET && op.key === flowOf(0));
  const causeIndex = ops.findIndex((op) => op.frameId === EVICTING + 1);
  check('evict: a forget for a flow on the evicting frame\'s own shard comes before that frame',
    forgetIndex >= 0 && causeIndex === forgetIndex + 1, `forget at ${forgetIndex}, cause at ${causeIndex}`);
  check('evict: ...and the run is the single Worker\'s', agrees(r, frames));
}

{
  // A flow lane 0 meets first (a QinQ long header) is pushed out by a shard's frame.
  const r = rig(2, () => 1);
  const frames: Uint8Array[] = [quicFrame('192.0.2.50', 52000, SERVER, 443,
    quicPayload('initial', { dcid: cid(77), scid: cid(78), payload: 16 }), { qinq: true })];
  for (let i = 0; i < MAX_QUIC_FLOWS; i++) frames.push(initialOf(i));
  r.feed(frames);
  r.deliver();
  check('evict: a lane-0 flow pushed out by a shard frame is forgotten by lane 0\'s tracker',
    r.forgot.includes(quicFlowKey('192.0.2.50', 52000, SERVER, 443)) && r.coordinator.perLane[0] === 1 && agrees(r, frames),
    `forgot ${r.forgot.length}, lane 0 frames ${r.coordinator.perLane[0]}`);
}

{
  // Asymmetric QinQ: each client Initial plain (a shard), each server Initial double-tagged (lane 0, crossLane).
  // The order forgets the oldest flows on the shard's dispatch; lane 0's half must be forgotten with them.
  const r = rig(1, () => 0);
  const frames: Uint8Array[] = [];
  const flows = MAX_QUIC_FLOWS + 500;
  for (let i = 0; i < flows; i++) {
    frames.push(initialOf(i));
    frames.push(quicFrame(SERVER, 443, host(i), 51000,
      quicPayload('initial', { dcid: cid(100000 + i), scid: cid(300000 + i), payload: 16 }), { qinq: true }));
  }
  r.feed(frames);
  r.deliver();
  const held = r.coordinator.lane0.trackers.quic.sessionFlows;
  check('cross: lane 0 forgets its half of a sharded flow the order forgets',
    r.coordinator.crossLane === flows && held <= MAX_QUIC_FLOWS, `crossLane ${r.coordinator.crossLane}, lane 0 sessions ${held}`);
}

// A sharded flow reached on lane 0, and a lane-0 flow reached by plain frames.
{
  const c = cid(31), s = cid(32);
  const r = rig(1);
  r.feed([
    quicFrame('192.0.2.20', 50020, SERVER, 443, quicPayload('initial', { dcid: c, scid: s }), {}),
    quicFrame('192.0.2.20', 50020, SERVER, 443, quicPayload('short', { dcid: s }), { qinq: true }),
  ]);
  r.deliver();
  check('cross: a QinQ short header of a sharded flow is counted as crossLane',
    r.coordinator.crossLane === 1 && r.coordinator.perLane[0] === 1, `crossLane ${r.coordinator.crossLane}`);
}

{
  const c = cid(41), s = cid(42);
  const r = rig(1);
  const frames = [
    quicFrame('192.0.2.21', 50021, SERVER, 443, quicPayload('initial', { dcid: c, scid: s }), { qinq: true }),
    quicFrame('192.0.2.21', 50021, SERVER, 443, quicPayload('short', { dcid: s }), {}),
    quicFrame('192.0.2.21', 50021, SERVER, 443, quicPayload('short', { dcid: c }), {}),
  ];
  r.feed(frames);
  r.deliver();
  check('home: a flow whose long header lane 0 met first keeps its plain short headers on lane 0',
    r.coordinator.perLane[1] === 0 && r.coordinator.perLane[0] === 3 && r.coordinator.crossLane === 0 && agrees(r, frames),
    `lanes ${r.coordinator.perLane.join(' / ')}`);
}

{
  let turn = 0;
  const r = rig(2, () => turn++ % 2);
  const frames = [
    quicFrame(SERVER, 443, '192.0.2.12', 50006, quicPayload('vn', { dcid: [], scid: [] }), {}),
    quicFrame('192.0.2.12', 50006, SERVER, 443, quicPayload('short', { dcid: cid(9) }), {}),
    quicFrame('192.0.2.12', 50006, SERVER, 443, quicPayload('short', { dcid: cid(9), payload: 70 }), {}),
  ];
  r.feed(frames);
  r.deliver();
  const lanes = lanesOf(r, [1, 2, 3]);
  check('vn: Version Negotiation and the short header after it go to one shard and dissect as one core',
    agrees(r, frames) && lanes.size === 1 && !lanes.has(0), `lanes ${[...lanes].join()}`);
}

keyLog.clear();
console.log(failures === 0 ? '\nAll QUIC shard checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
