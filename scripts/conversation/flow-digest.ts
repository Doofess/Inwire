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
import { flowKeyOf, inFlow, quicKeyOf, udpKeyOf, type QuicSummary, type UdpSummary } from '../../src/services/conversation/flowSummary';
import { tlsNote, type TlsSummary } from '../../src/services/conversation/tlsSummary';
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
  d.feed(quicRow({ fromClient: false, type: 2, version: V1, conn: 4 }));
  const u = d.getFlow('udp', 9) as UdpSummary;
  check('udp: a QUIC datagram also counts in its UDP flow',
    [u.toServer.packets, u.toClient.packets, u.outcome, d.changedSince(0).udp.length, d.changedSince(0).quic.length],
    [1, 1, 'request/response', 1, 1]);
  check('...and the QUIC summary is unchanged by it',
    [(d.getFlow('quic', 4) as QuicSummary).toServer.packets, (d.getFlow('quic', 4) as QuicSummary).toClient.packets, (d.getFlow('quic', 4) as QuicSummary).outcome],
    [1, 1, 'handshake unfinished']);
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
  check('one shared version covers every kind', [c.tcp.length, c.udp.length, c.quic.length, d.version > v], [0, 1, 1, true]);
  check('changedSince(0) returns all three (the QUIC datagram is also a UDP flow)', [d.changedSince(0).udp.length, d.changedSince(0).quic.length], [2, 1]);
  check('changedSince at the current version is empty', Object.values(d.changedSince(d.version)).map((a) => a.length), [0, 0, 0, 0]);
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
  check('...a QUIC datagram\'s relabel reaches both its flows', [(d.getFlow('udp', 9) as UdpSummary).protocol, quicOf(d).protocol], ['HTTP3', 'HTTP3']);
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

// ---- udpKeyOf, quicKeyOf and inFlow are the one membership rule.
{
  nextId = 1;
  const tcp = { ...udpRow({ fromClient: true }), frameProtocols: ['eth', 'ip', 'tcp'] } as Packet;
  check('a UDP row is in its udp.stream and not in a QUIC connection',
    [udpKeyOf(udpRow({ fromClient: true }, 5)), quicKeyOf(udpRow({ fromClient: true }, 5))], [5, null]);
  check('a QUIC row with a connection number is in both',
    [udpKeyOf(quicRow({ fromClient: true, conn: 4 })), quicKeyOf(quicRow({ fromClient: true, conn: 4 }))], [9, 4]);
  check('a QUIC row without a connection number is UDP only',
    [udpKeyOf(quicRow({ fromClient: true, conn: null })), quicKeyOf(quicRow({ fromClient: true, conn: null }))], [9, null]);
  const noStream = { ...quicRow({ fromClient: true, conn: 4 }), fields: { 'quic.connection.number': 4 } } as Packet;
  check('a row without udp.stream is in no UDP flow (a QUIC one is still in its connection)',
    [udpKeyOf(udpRow({ fromClient: true }, null)), udpKeyOf(noStream), quicKeyOf(noStream)], [null, null, 4]);
  check('a QUIC row with neither number is in nothing',
    [udpKeyOf({ ...noStream, fields: {} } as Packet), quicKeyOf({ ...noStream, fields: {} } as Packet)], [null, null]);
  check('a TCP row is in none', [udpKeyOf(tcp), quicKeyOf(tcp)], [null, null]);
  check('a UDP row without ports is in none',
    [udpKeyOf({ ...udpRow({ fromClient: true }), sourcePort: undefined } as Packet), quicKeyOf({ ...quicRow({ fromClient: true, conn: 4 }), destPort: undefined } as Packet)], [null, null]);
  const q = quicRow({ fromClient: true, conn: 4 });
  check('inFlow is the two keys\' equality',
    [inFlow(q, 'udp', 9), inFlow(q, 'quic', 4), inFlow(q, 'udp', 4), inFlow(q, 'quic', 9), inFlow(tcp, 'udp', 3)], [true, true, false, false, false]);
  check('flowKeyOf is the flow a frame opens as: QUIC first, then UDP',
    [flowKeyOf(q), flowKeyOf(quicRow({ fromClient: true, conn: null })), flowKeyOf(udpRow({ fromClient: true }, 5)), flowKeyOf(tcp)],
    [{ kind: 'quic', key: 4 }, { kind: 'udp', key: 9 }, { kind: 'udp', key: 5 }, null]);
  // The digest and the membership test agree on every row.
  const rows = [
    udpRow({ fromClient: true }, 5), quicRow({ fromClient: true, conn: 4 }), quicRow({ fromClient: true, conn: null }),
    udpRow({ fromClient: true }, null), noStream,
  ];
  const d = fresh();
  for (const r of rows) d.feed(r);
  const folded = [...d.changedSince(0).udp.map((s) => `udp:${s.key}`), ...d.changedSince(0).quic.map((s) => `quic:${s.key}`)].sort();
  const keyed = rows.flatMap((r) => [udpKeyOf(r), quicKeyOf(r)].flatMap((k, i) => k === null ? [] : [`${i === 0 ? 'udp' : 'quic'}:${k}`]));
  check('the digest folds exactly the flows the keys name', folded, [...new Set(keyed)].sort());
  const counts = [...d.changedSince(0).udp].map((s) => [s.key, s.toServer.packets]).sort();
  check('...and counts every UDP row with a stream in its UDP flow', counts, [[5, 1], [9, 2]]);
}

// ---- TLS on a TCP stream (stage 3).
{
  const TLS_STREAM = 11;
  /** A TCP row that carries TLS facts. `fields` are exactly what the dissector writes. */
  const tlsRow = (fromClient: boolean, fields: Record<string, number | string>, time?: number, over: Partial<Packet> = {}): Packet => {
    const id = nextId++;
    return {
      id, tsUs: id * 1000, timeDelta: 0, relativeTime: time ?? id / 1000,
      source: fromClient ? CLIENT : SERVER, destination: fromClient ? SERVER : CLIENT,
      sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
      protocol: 'TCP', protocolLabel: 'TLSv1.2', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp', 'tls'],
      fields: { 'tcp.flags.ack': 1, 'tcp.len': 100, ...fields }, length: 154, info: '', status: 'ok',
      streamId: TLS_STREAM, ...over,
    } as Packet;
  };
  const hello = (): Record<string, number | string> => ({ 'tls.record.content_type': 22, 'tls.handshake.type': 1, 'tls.handshake.ja4': 't13d1516h2_x_y' });
  const serverHello = (): Record<string, number | string> => ({ 'tls.record.content_type': 22, 'tls.handshake.type': 2, 'tls.handshake.ja3s': 'abc' });
  const alert = (desc: number, level: number): Record<string, number | string> =>
    ({ 'tls.record.content_type': 21, 'tls.alert_message.level': level, 'tls.alert_message.desc': desc });
  const app = (): Record<string, number | string> => ({ 'tls.record.content_type': 23 });
  const tlsOf = (d: StreamDigest, n = TLS_STREAM): TlsSummary | undefined => d.getTls(n);
  const steps = (s: TlsSummary | undefined) => s?.phases.map((p) => `${p.side}:${p.phase}`);

  {
    const d = fresh();
    d.feed(tlsRow(true, hello(), 1));
    d.feed(tlsRow(false, serverHello(), 2));
    const s = tlsOf(d)!;
    check('tls: ClientHello and ServerHello are two phases with their sides', steps(s), ['client:ClientHello', 'server:ServerHello']);
    check('...each with the first frame and time that showed it', s.phases.map((p) => [p.frameId, p.time]), [[1, 1], [2, 2]]);
    check('...keyed by tcp.stream, and no alert', [s.kind, s.key, s.fatalAlert], ['tls', TLS_STREAM, null]);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    d.feed(tlsRow(false, serverHello()));
    d.feed(tlsRow(false, { 'tls.record.content_type': 22, 'tls.handshake.type': 11, 'tls.x509.subject_cn': 'example.test' }));
    d.feed(tlsRow(true, app()));
    d.feed(tlsRow(false, app()));
    d.feed(tlsRow(true, app()));
    check('tls: application data from each side is a step each',
      steps(tlsOf(d)), ['client:ClientHello', 'server:ServerHello', 'server:Certificate', 'client:application data', 'server:application data']);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, { 'tls.record.content_type': 22, 'inwire.tls.decrypted': 1 }));
    check('tls: a decrypted record is application data', steps(tlsOf(d)), ['client:application data']);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    d.feed(tlsRow(false, alert(0, 1)));
    const s = tlsOf(d)!;
    check('tls: a readable close_notify is close_notify, not an alert',
      [steps(s), s.fatalAlert, s.phases[1].alertName], [['client:ClientHello', 'server:close_notify'], null, undefined]);
    d.feed(tlsRow(true, alert(0, 2)));
    check('...and a close_notify never sets fatalAlert, whatever its level', tlsOf(d)!.fatalAlert, null);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    d.feed(tlsRow(false, alert(40, 2)));
    d.feed(tlsRow(true, alert(42, 2)));
    const s = tlsOf(d)!;
    check('tls: a fatal alert names itself and sets fatalAlert',
      [steps(s), s.phases[1].alertName, s.fatalAlert],
      [['client:ClientHello', 'server:alert', 'client:alert'], 'Handshake Failure', { side: 'server', name: 'Handshake Failure' }]);
    const warn = fresh();
    warn.feed(tlsRow(false, alert(112, 1)));
    check('...a warning alert is a step and not fatal', [steps(tlsOf(warn)), tlsOf(warn)!.fatalAlert], [['server:alert'], null]);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    d.feed(tlsRow(false, serverHello()));
    d.feed(tlsRow(false, app()));
    d.feed(tlsRow(true, { 'tls.record.content_type': 21 }));
    const s = tlsOf(d)!;
    check('tls: an encrypted alert is not a failure',
      [steps(s), s.fatalAlert, tlsNote(s, 'closed cleanly')],
      [['client:ClientHello', 'server:ServerHello', 'server:application data', 'client:encrypted alert'], null, '']);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, app(), 1));
    const v1 = tlsOf(d)!.version;
    d.feed(tlsRow(true, app(), 2));
    d.feed(tlsRow(true, app(), 3));
    check('tls: a repeated phase from the same side is not a second step', [steps(tlsOf(d)), tlsOf(d)!.phases[0].frameId], [['client:application data'], 1]);
    check('...and a row that changes nothing leaves the TLS version alone', tlsOf(d)!.version, v1);
  }
  {
    // QUIC's TLS is QUIC's phases (ruling S3-1): a row with no tcp is not folded.
    const d = fresh();
    d.feed(tlsRow(true, hello(), 1, { frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'quic', 'tls'], protocol: 'QUIC', streamId: undefined }));
    check('tls: TLS inside QUIC is not folded as TLS', [d.changedSince(0).tls, tlsOf(d)], [[], undefined]);
    const noTls = fresh();
    noTls.feed(tlsRow(true, hello(), 1, { frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'] }));
    check('...nor is a TCP row that does not list tls', noTls.changedSince(0).tls, []);
    const plain = fresh();
    plain.feed(tlsRow(true, { 'tls.record.content_type': 22 }));
    check('...nor a TLS row that shows no phase', [plain.changedSince(0).tls, plain.get(TLS_STREAM) !== undefined], [[], true]);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    const s = tlsOf(d)!;
    check('tlsNote: unanswered only once the TCP stream is not open',
      [tlsNote(s, 'open'), tlsNote(s, 'no reply'), tlsNote(s, 'half-closed by client'), tlsNote(s, 'reset by server'), tlsNote(undefined, 'reset by server')],
      ['', ' · TLS unanswered', ' · TLS unanswered', ' · TLS unanswered', '']);
    d.feed(tlsRow(false, serverHello()));
    check('...an answered hello is no note', tlsNote(tlsOf(d), 'reset by server'), '');
    d.feed(tlsRow(false, alert(40, 2)));
    check('...a fatal alert is its own note, open or not', [tlsNote(tlsOf(d), 'open'), tlsNote(tlsOf(d), 'closed cleanly')], [' · TLS alert', ' · TLS alert']);
  }
  {
    const d = fresh();
    d.feed(tlsRow(true, hello()));
    const first = d.version;
    d.feed(tlsRow(false, serverHello()));
    check('changedSince answers a TLS summary changed after a version',
      [d.changedSince(0).tls.length, d.changedSince(first).tls.map((s) => s.key), d.changedSince(d.version).tls.length], [1, [TLS_STREAM], 0]);
    const back = StreamDigest.restore(JSON.parse(JSON.stringify(d.snapshot())));
    check('a snapshot round trip restores the TLS map', back.getTls(TLS_STREAM), d.getTls(TLS_STREAM));
    back.feed(tlsRow(true, app()));
    check('...and a restored digest keeps folding TLS', steps(back.getTls(TLS_STREAM)), ['client:ClientHello', 'server:ServerHello', 'client:application data']);
    const lone = StreamDigest.restore({
      throughId: 5, version: 5, captureEnd: 1,
      entries: [{ kind: 'tls', summary: { kind: 'tls', key: 99, phases: [], fatalAlert: null, version: 3 } }],
    });
    check('restore keeps a TLS entry whose TCP stream is absent', [lone.getTls(99)?.key, lone.get(99)], [99, undefined]);
  }
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
