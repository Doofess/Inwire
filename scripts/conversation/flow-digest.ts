/**
 * The stream digest folds UDP flows and QUIC connections beside its TCP
 * streams (ADR 0055, stage 2).
 *
 *   npx tsx scripts/conversation/flow-digest.ts
 *
 * Rows are built by hand, as `stream-digest.ts` does. A QUIC row carries
 * `quic.long.packet_type` as the raw two type bits of its last coalesced
 * packet and `quic.frame_type` as its last frame's type only, so these tests
 * state both the way the dissector leaves them.
 */
import { RECENT_FRAMES, StreamDigest } from '../../src/services/conversation/streamDigest';
import type { QuicSummary, UdpSummary } from '../../src/services/conversation/flowSummary';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

let nextId = 1;
const CLIENT = '10.0.0.2';
const SERVER = '93.184.216.34';

interface Spec {
  fromClient: boolean;
  /** Replaces the client's source port, for a migration. */
  clientPort?: number;
  fields?: Record<string, number | string>;
  time?: number;
  length?: number;
  extra?: Partial<Packet>;
}

function udpRow(s: Spec, stream: number | null = 3): Packet {
  const id = nextId++;
  const clientPort = s.clientPort ?? 50000;
  const fields: Record<string, number | string> = { ...(stream === null ? {} : { 'udp.stream': stream }), ...s.fields };
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: s.time ?? id / 1000,
    source: s.fromClient ? CLIENT : SERVER, destination: s.fromClient ? SERVER : CLIENT,
    sourcePort: s.fromClient ? clientPort : 5353, destPort: s.fromClient ? 5353 : clientPort,
    protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], fields,
    length: s.length ?? 80, info: '', status: 'ok', ...s.extra,
  } as Packet;
}

/** A QUIC row: `type` is the raw long-header type bits, absent for a short header. */
function quicRow(s: Spec & { type?: number; version?: number; frame?: number; conn?: number | null }): Packet {
  const fields: Record<string, number | string> = {
    ...(s.conn === null ? {} : { 'quic.connection.number': s.conn ?? 0 }),
    ...(s.type === undefined ? {} : { 'quic.long.packet_type': s.type }),
    ...(s.version === undefined ? {} : { 'quic.version': s.version }),
    ...(s.frame === undefined ? {} : { 'quic.frame_type': s.frame }),
    ...s.fields,
  };
  const r = udpRow({ ...s, fields }, 9);
  r.protocol = 'QUIC';
  r.frameProtocols = ['eth', 'ethertype', 'ip', 'udp', 'quic'];
  return r;
}

const V1 = 1;
const V2 = 0x6b3343cf;
const quicOf = (d: StreamDigest, n = 0): QuicSummary => d.getFlow('quic', n) as QuicSummary;
/** A new digest, and frame ids that start again from 1. */
function fresh(): StreamDigest { nextId = 1; return new StreamDigest(); }
const udpOf =(d: StreamDigest, n = 3): UdpSummary => d.getFlow('udp', n) as UdpSummary;

// ---- UDP.
{
  const d = fresh();
  d.feed(udpRow({ fromClient: true }));
  check('udp: one datagram is one-way', [udpOf(d).kind, udpOf(d).outcome], ['udp', 'one-way']);
}
{
  const d = fresh();
  d.feed(udpRow({ fromClient: true, length: 70 }));
  d.feed(udpRow({ fromClient: false, length: 130 }));
  const s = udpOf(d);
  check('udp: query and answer is request/response', s.outcome, 'request/response');
  check('udp: the client is the end that is not on a well-known port',
    [s.client, s.server, s.clientBasis], [{ address: CLIENT, port: 50000 }, { address: SERVER, port: 5353 }, 'well-known-port']);
  check('udp: per-direction counts', [s.toServer.packets, s.toClient.packets, s.toServer.bytes, s.toClient.bytes], [1, 1, 70, 130]);
  check('udp: ids, times and protocol', [s.firstId, s.lastId, s.protocol, s.key], [1, 2, 'UDP', 3]);
}
{
  const d = fresh();
  d.feed(udpRow({ fromClient: true }));
  d.feed(udpRow({ fromClient: true }));
  d.feed(udpRow({ fromClient: false }));
  check('udp: a retried query and one answer is request/response', udpOf(d).outcome, 'request/response');
}
{
  const d = fresh();
  for (let i = 0; i < 3; i++) { d.feed(udpRow({ fromClient: true })); d.feed(udpRow({ fromClient: false })); }
  check('udp: three each way is two-way', udpOf(d).outcome, 'two-way');
}
{
  const d = fresh();
  d.feed(udpRow({ fromClient: true }, null));
  check('udp: a row without udp.stream is not folded',
    [d.getFlow('udp', 0), d.changedSince(0).udp.length, d.changedSince(0).quic.length, d.changedSince(0).tcp.length], [undefined, 0, 0, 0]);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1, conn: 4 }));
  check('udp: a QUIC datagram is not a UDP flow', [d.getFlow('udp', 9), d.changedSince(0).udp.length, d.changedSince(0).quic.length], [undefined, 0, 1]);
  const bare = fresh();
  bare.feed(quicRow({ fromClient: true, type: 0, version: V1, conn: null }));
  check('udp: a QUIC row with no connection number stays UDP', [bare.changedSince(0).udp.length, bare.changedSince(0).quic.length], [1, 0]);
}

// ---- QUIC.
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  const s = quicOf(d);
  check('quic: client Initials only is no reply', [s.outcome, s.joinedMidStream, s.migrated], ['no reply', false, false]);
  check('quic: the sender of the first Initial is the client',
    [s.client, s.clientBasis, s.quicVersion, s.protocol], [{ address: CLIENT, port: 50000 }, 'well-known-port', 1, 'QUIC']);
  check('quic: one initial step for the client', s.phases.map((p) => [p.phase, p.side, p.frameId]), [['initial', 'client', 1]]);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 2, version: V1 }));
  const s = quicOf(d);
  check('quic: Initial both ways and server Handshake is handshake unfinished', s.outcome, 'handshake unfinished');
  check('quic: phases are per side, once each', s.phases.map((p) => [p.phase, p.side]),
    [['initial', 'client'], ['initial', 'server'], ['handshake', 'server']]);
}
{
  // A coalesced Initial+Handshake datagram shows its last packet, Handshake:
  // the side's Initial step is implied and is recorded at the same frame.
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 2, version: V1 }));
  check('quic: a Handshake row implies that side\'s Initial first',
    quicOf(d).phases.map((p) => [p.phase, p.side, p.frameId]),
    [['initial', 'client', 1], ['initial', 'server', 2], ['handshake', 'server', 2]]);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 2, version: V1 }));
  d.feed(quicRow({ fromClient: true }));
  check('quic: a short-header row makes it established', quicOf(d).outcome, 'established');
  check('quic: a short-header row is 1-rtt', quicOf(d).phases.at(-1), { phase: '1-rtt', side: 'client', frameId: 3, time: 0.003 });
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false }));
  d.feed(quicRow({ fromClient: false, frame: 0x1c }));
  check('quic: CONNECTION_CLOSE from the server is closed by server', quicOf(d).outcome, 'closed by server');
  const c = fresh();
  c.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  c.feed(quicRow({ fromClient: false }));
  c.feed(quicRow({ fromClient: true, frame: 0x1d }));
  check('quic: the application CONNECTION_CLOSE from the client is closed by client', quicOf(c).outcome, 'closed by client');
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 2, version: V1 }));
  d.feed(quicRow({ fromClient: true }));
  d.feed(quicRow({ fromClient: false }));
  d.feed(quicRow({ fromClient: true, frame: 0x06 }));
  check('quic: no keys never claims a close', [quicOf(d).outcome, quicOf(d).phases.some((p) => p.phase === 'closed')], ['established', false]);
  const hs = fresh();
  hs.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  hs.feed(quicRow({ fromClient: false, type: 2, version: V1 }));
  check('quic: ...and a handshake with no frames is not closed either', quicOf(hs).outcome, 'handshake unfinished');
}
{
  // v2 swaps the type bits: Initial is 1, Handshake 3, and 0 is Retry.
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 1, version: V2 }));
  d.feed(quicRow({ fromClient: false, type: 3, version: V2 }));
  const s = quicOf(d);
  check('quic: v2 type bits read as v2', [s.quicVersion, s.joinedMidStream, s.clientBasis, s.phases.map((p) => [p.phase, p.side])],
    [V2, false, 'well-known-port', [['initial', 'client'], ['initial', 'server'], ['handshake', 'server']]]);
  const r = fresh();
  r.feed(quicRow({ fromClient: true, type: 1, version: V2 }));
  r.feed(quicRow({ fromClient: false, type: 0, version: V2 }));
  check('quic: v2 type 0 is a Retry and no phase', [quicOf(r).phases.length, quicOf(r).outcome], [1, 'no reply']);
  const v1 = fresh();
  v1.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  v1.feed(quicRow({ fromClient: false, type: 3, version: V1 }));
  check('quic: v1 type 3 is a Retry and no phase', [quicOf(v1).phases.length, quicOf(v1).outcome], [1, 'no reply']);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 1, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 0, version: 0 }));
  check('quic: a 0-RTT row and a Version Negotiation row are no phase', [quicOf(d).phases.length, quicOf(d).outcome], [1, 'no reply']);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: false, type: 0, version: V1 }));
  d.feed(quicRow({ fromClient: true }));
  check('quic: a new client port sets migrated', [quicOf(d).migrated], [false]);
  d.feed(quicRow({ fromClient: true, clientPort: 61000 }));
  d.feed(quicRow({ fromClient: false, clientPort: 61000 }));
  const s = quicOf(d);
  check('quic: ...and it does', s.migrated, true);
  check('quic: ...the row is still listed under the first 5-tuple', [s.client, s.server], [{ address: CLIENT, port: 50000 }, { address: SERVER, port: 5353 }]);
  check('quic: ...the server\'s reply after migration goes toClient, the new port\'s rows toServer',
    [s.toServer.packets, s.toClient.packets], [3, 2]);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true }));
  d.feed(quicRow({ fromClient: false }));
  const s = quicOf(d);
  check('quic: no Initial seen is joined mid-stream', [s.joinedMidStream, s.outcome, s.clientBasis], [true, 'established', 'well-known-port']);
  const late = fresh();
  late.feed(quicRow({ fromClient: false, type: 0, version: V1 }));
  // The client's Initial was missed and the server's answering one heard
  // first: a well-known port outranks it, as it outranks a SYN for TCP.
  check('quic: a server\'s Initial heard first is the server\'s, by its port, and joined mid-stream',
    [quicOf(late).client, quicOf(late).clientBasis, quicOf(late).joinedMidStream],
    [{ address: CLIENT, port: 50000 }, 'well-known-port', true]);
  const ephemeral = fresh();
  ephemeral.feed({ ...quicRow({ fromClient: false, type: 0, version: V1 }), sourcePort: 40001, destPort: 50000 } as Packet);
  check('quic: with no well-known port, the first Initial\'s sender is the client',
    [quicOf(ephemeral).client, quicOf(ephemeral).clientBasis, quicOf(ephemeral).joinedMidStream],
    [{ address: SERVER, port: 40001 }, 'syn', false]);
}
{
  const d = fresh();
  d.feed(quicRow({ fromClient: true, type: 0, version: V1, extra: { protocolLabel: 'QUIC' } }));
  d.feed(quicRow({ fromClient: false, type: 0, version: V1, extra: { protocolLabel: 'HTTP3' } }));
  check('quic: the most specific label wins as TCP\'s does', quicOf(d).protocol, 'HTTP3');
}

// ---- captureEnd, versions, relabel, snapshots.
{
  nextId = 1;
  const d = fresh();
  d.feed(udpRow({ fromClient: true, time: 5 }));
  d.feed({ ...udpRow({ fromClient: true, time: 9 }), frameProtocols: ['eth', 'arp'], protocol: 'ARP' } as Packet);
  d.feed(udpRow({ fromClient: true, time: 7 }));
  check('captureEnd is the latest time of any row', d.captureEnd, 9);
  const at = d.captureEnd;
  d.feed({ ...udpRow({ fromClient: true, time: 100 }), id: 1 } as Packet);
  check('captureEnd ignores a repeated id', d.captureEnd, at);
}
{
  nextId = 1;
  const d = fresh();
  d.feed(udpRow({ fromClient: true }));
  const v = d.version;
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  const c = d.changedSince(v);
  check('one shared version covers every kind', [c.tcp.length, c.udp.length, c.quic.length, d.version > v], [0, 0, 1, true]);
  check('changedSince(0) returns all three', [d.changedSince(0).udp.length, d.changedSince(0).quic.length], [1, 1]);
  check('changedSince at the current version is empty', Object.values(d.changedSince(d.version)).map((a) => a.length), [0, 0, 0]);
}
{
  nextId = 1;
  const d = fresh();
  d.feed(udpRow({ fromClient: true, extra: { protocol: 'UDP' } }));
  const u = d.get(3);
  check('udp flows are not TCP streams', u, undefined);
  d.feed(quicRow({ fromClient: true, type: 0, version: V1 }));
  d.feed(udpRow({ fromClient: true }));
  d.feed(quicRow({ fromClient: false, type: 0, version: V1 }));
  const before = d.version;
  d.relabel(1, 'DNS');
  check('relabel reaches a UDP flow and a QUIC connection',
    [udpOf(d).protocol, quicOf(d).protocol, d.version > before], ['DNS', 'QUIC', true]);
  d.relabel(2, 'HTTP3');
  d.relabel(4, 'HTTP3');
  check('...each by its own id', [udpOf(d).protocol, quicOf(d).protocol], ['DNS', 'HTTP3']);
  d.relabel(3, 'UDP');
  check('...and UDP or TCP is never a better label', udpOf(d).protocol, 'DNS');
  check('the ring is still wide enough for the horizon', RECENT_FRAMES >= 100_000, true);
}
{
  nextId = 1;
  const d = fresh();
  d.feed(udpRow({ fromClient: true, time: 3 }));
  d.feed(quicRow({ fromClient: true, type: 0, version: V1, time: 4 }));
  d.feed(quicRow({ fromClient: false, type: 2, version: V1, time: 11.5 }));
  d.feed({ ...udpRow({ fromClient: true, time: 42.25 }), frameProtocols: ['eth', 'arp'], protocol: 'ARP' } as Packet);
  const back = StreamDigest.restore(JSON.parse(JSON.stringify(d.snapshot())));
  check('captureEnd survives a snapshot round trip', [back.captureEnd, d.captureEnd], [42.25, 42.25]);
  check('all three kinds survive it', [back.getFlow('udp', 3), back.getFlow('quic', 0)], [d.getFlow('udp', 3), d.getFlow('quic', 0)]);
  check('...with the same throughId and version', [back.throughId, back.version], [d.throughId, d.version]);
  back.feed(udpRow({ fromClient: false, time: 50 }));
  check('a restored digest keeps folding all kinds', [udpOf(back).outcome, back.captureEnd], ['request/response', 50]);
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
