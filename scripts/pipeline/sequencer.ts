/**
 * The Sequencer, held to the dissector it numbers for (ADR 0053 phase 2).
 *
 *   npx tsx scripts/pipeline/sequencer.ts [--burst some.pcapng]
 *
 * Five things, each the property phase 3 will lean on:
 *
 *   1. **The header parse never sends a frame to the TCP lane that the
 *      dissection numbers differently.** Every frame of every real fixture is
 *      dissected with a spy on the trackers; for each one `frameLane` sends to
 *      the TCP lane, the calls the dissection made to the cross-conversation
 *      numbering - `eth.stream`, `ip.stream`/`ipv6.stream`, `udp.stream`, and
 *      every TCP lookup - must be exactly the ones read from its headers. A
 *      frame it leaves on the sequential lane is never wrong, only slower, so
 *      the share of TCP frames it reaches is printed rather than asserted.
 *      The same holds for the QUIC lane: for each frame it reads onto it, the
 *      QUIC tracker's questions to the order are exactly the ones `readQuicRoute`
 *      read from the headers, against the order the earlier frames left.
 *   2. **Trackers sharing one Sequencer dissect byte for byte as trackers
 *      each holding their own** - what the Worker does now against what every
 *      older caller still does. A hash of every frame's columns, bag, tree,
 *      record, derived answers and patches (`frameDigest.ts`).
 *   3. **TCP's eviction numbers as the rule says**, on a capture of 20,000
 *      connections (`evictionCapture.ts`): `tcp.stream` for every segment
 *      against a model of the rule written out here - least recently seen goes
 *      past 16,384, a returning connection is new, numbers are never reused.
 *   4. **The frame clock** keeps both forms' arithmetic.
 *   5. **QUIC's flow registry** numbers connections and forgets flows as the
 *      tracker did before it moved here: the same rules, asserted on the order.
 *
 * The real fixtures are untracked (test/fixtures/README.md); without them
 * (1) and (2) skip and (3) and (4) still run. `--burst` adds any capture to
 * (1) and (2) - the 300,000-frame download ADR 0053 was measured on.
 */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, MAX_QUIC_FLOWS, MAX_TCP_CONNECTIONS, Sequencer, quicFlowKey, tcpConnectionKey } from '../../src/services/dissect/sequencer';
import { frameLane, isTcpFragment, type QuicLane, type TcpFragmentLane } from '../../src/services/dissect/frameLane';
import { readQuicRoute, type QuicRouted } from '../../src/services/dissect/quicRoute';
import type { FrameSources } from '../../src/services/dissect/frameRecord';
import type { Packet } from '../../src/types/packet';
import { FIXTURES } from './arrival';
import { digestCapture, type Trackers } from './frameDigest';
import { EVICTION_CONNECTIONS, evictionCapture } from './evictionCapture';
import { fragmentCapture } from './fragmentCapture';
import { quicCapture } from './quicCapture';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`);
}

const burstAt = process.argv.indexOf('--burst');
const captures = [
  ...FIXTURES.filter((f) => existsSync(f.path)).map((f) => ({ name: f.name, path: f.path })),
  ...(burstAt > 0 && process.argv[burstAt + 1] ? [{ name: 'burst', path: process.argv[burstAt + 1] }] : []),
];
const missing = FIXTURES.filter((f) => !existsSync(f.path) && !f.optional);
for (const f of missing) console.log(`SKIP  ${f.name}: ${f.path} is not present - see test/fixtures/README.md`);

// --- (1) the header parse against the dissection's own calls ---------------

/** The TCP tracker's lookups that name a connection by its four-tuple. */
const TUPLE_CALLS = new Set([
  'setWindowScaleShift', 'getWindowScaleShift', 'getRelativeSeq', 'getStreamId', 'noteFin',
  'isAtOrPastExpected', 'analyze', 'noteGap', 'ldapConversation', 'smb2Conversation',
  'peekBgpDirection', 'bgpDirection', 'peekTlsCursor', 'tlsCursor', 'tlsConversation',
  'getTlsStreamId', 'sshConversation', 'dcerpcConversation',
]);
const NUMBERING_L3 = new Set(['ethStream', 'ipStream', 'ipv6Stream', 'udpStream']);

/** The QUIC tracker's questions to the QUIC order, which the router predicts (ADR 0053 phase 5). */
const QUIC_CALLS = new Set(['isKnownFlow', 'matchConnectionId', 'noteLongHeader', 'connectionNumberForFlow']);

interface Call { group: 'tcp' | 'l3' | 'quic'; method: string; args: unknown[]; result?: unknown }

/** Wraps the sources a frame is dissected with so its numbering calls are logged. */
function spying(log: Call[]): (sources: FrameSources) => FrameSources {
  const wrap = <T extends object>(target: T, group: Call['group'], watch: (m: string) => boolean): T =>
    new Proxy(target, {
      get(t, prop, receiver) {
        const value = Reflect.get(t, prop, receiver);
        if (typeof value !== 'function' || typeof prop !== 'string' || !watch(prop)) return value;
        return (...args: unknown[]) => {
          const call: Call = { group, method: prop, args };
          log.push(call);
          call.result = (value as (...a: unknown[]) => unknown).apply(t, args);
          return call.result;
        };
      },
    });
  let cached: { from: FrameSources; to: FrameSources } | undefined;
  return (sources) => {
    if (cached?.from !== sources) {
      cached = {
        from: sources,
        to: {
          ...sources,
          tcp: wrap(sources.tcp, 'tcp', () => true),
          quic: wrap(sources.quic, 'quic', (m) => QUIC_CALLS.has(m)),
          l3: wrap(sources.l3, 'l3', (m) => NUMBERING_L3.has(m)),
        },
      };
    }
    return cached.to;
  };
}

/** What a frame on the TCP lane must have asked, and nothing else; null when it did. */
function disagreement(calls: Call[], packet: Packet, bytes: Uint8Array, linktype: number): string | null {
  const lane = frameLane(bytes, linktype);
  if (isTcpFragment(lane)) return fragmentDisagreement(calls, packet, lane);
  if (lane.lane !== 'tcp') return null;
  const l3 = calls.filter((c) => c.group === 'l3');
  const want = [
    `ethStream ${lane.srcMac} ${lane.dstMac}`,
    `${lane.family === 'ip' ? 'ipStream' : 'ipv6Stream'} ${lane.src} ${lane.dst}`,
  ];
  const got = l3.map((c) => `${c.method} ${c.args[0]} ${c.args[1]}`);
  if (got.join('|') !== want.join('|')) return `frame ${packet.id}: L3 numbering ${JSON.stringify(got)}, read ${JSON.stringify(want)}`;
  const tcp = calls.filter((c) => c.group === 'tcp' && TUPLE_CALLS.has(c.method));
  if (!tcp.some((c) => c.method === 'getStreamId')) return `frame ${packet.id}: no tcp.stream was asked for`;
  for (const c of tcp) {
    const [srcIp, srcPort, dstIp, dstPort] = c.args as [string, number, string, number];
    const { key } = tcpConnectionKey(srcIp, srcPort, dstIp, dstPort);
    if (key !== lane.key) return `frame ${packet.id}: ${c.method} on ${key}, read ${lane.key}`;
  }
  return null;
}

/**
 * A fragment of a TCP datagram is numbered in two halves (ADR 0053 phase 3):
 * its MAC and address pairs from its headers, like any segment, and the TCP
 * order only by the dissection that reassembles it - which must then touch one
 * connection and no other.
 */
function fragmentDisagreement(calls: Call[], packet: Packet, lane: TcpFragmentLane): string | null {
  const l3 = calls.filter((c) => c.group === 'l3').map((c) => `${c.method} ${c.args[0]} ${c.args[1]}`);
  const want = [`ethStream ${lane.srcMac} ${lane.dstMac}`, `${lane.family === 'ip' ? 'ipStream' : 'ipv6Stream'} ${lane.src} ${lane.dst}`];
  if (l3.join('|') !== want.join('|')) return `fragment ${packet.id}: L3 numbering ${JSON.stringify(l3)}, read ${JSON.stringify(want)}`;
  const keys = new Set(calls.filter((c) => c.group === 'tcp' && TUPLE_CALLS.has(c.method)).map((c) => {
    const [srcIp, srcPort, dstIp, dstPort] = c.args as [string, number, string, number];
    return tcpConnectionKey(srcIp, srcPort, dstIp, dstPort).key;
  }));
  return keys.size > 1 ? `fragment ${packet.id}: looked up ${[...keys].join(' and ')}` : null;
}

/**
 * What a frame on the QUIC lane must have asked the QUIC order, and nothing
 * else: exactly what `readQuicRoute` read from its headers, against the order
 * as the frames before it left it. Null when it did.
 */
function quicDisagreement(calls: Call[], packet: Packet, lane: QuicLane, route: QuicRouted | null): string | null {
  const l3 = calls.filter((c) => c.group === 'l3').map((c) => c.method);
  const want = ['ethStream', lane.family === 'ip' ? 'ipStream' : 'ipv6Stream', 'udpStream'];
  if (l3.join('|') !== want.join('|')) return `frame ${packet.id}: L3 numbering ${JSON.stringify(l3)}, read ${JSON.stringify(want)}`;
  const quic = calls.filter((c) => c.group === 'quic');
  for (const c of quic) {
    const [srcIp, srcPort, dstIp, dstPort] = c.args as [string, number, string, number];
    const flow = quicFlowKey(srcIp, srcPort, dstIp, dstPort);
    if (flow !== lane.flow) return `frame ${packet.id}: ${c.method} on ${flow}, read ${lane.flow}`;
  }
  const named = (method: string) => quic.filter((c) => c.method === method);
  const known = named('isKnownFlow');
  if (known.length !== 1) return `frame ${packet.id}: isKnownFlow asked ${known.length} times`;
  const dissectedAsQuic = packet.frameProtocols?.includes('quic') === true;
  if (dissectedAsQuic !== (route !== null)) return `frame ${packet.id}: dissected as QUIC ${dissectedAsQuic}, read ${route !== null}`;
  if (route === null) {
    return named('noteLongHeader').length + named('connectionNumberForFlow').length === 0
      ? null : `frame ${packet.id}: read as unclaimed, but numbered`;
  }
  if (known[0].result !== route.known) return `frame ${packet.id}: flow known ${String(known[0].result)}, read ${route.known}`;
  const matches = named('matchConnectionId');
  if (route.walk.resolveAt < 0) {
    if (matches.length !== 0) return `frame ${packet.id}: matched an id, read no short header`;
  } else if (matches.length !== 1 || matches[0].args[5] !== route.walk.resolveAt || matches[0].result !== route.matched) {
    return `frame ${packet.id}: matched ${JSON.stringify(matches.map((m) => [m.args[5], m.result]))}, read [${route.walk.resolveAt}, ${String(route.matched)}]`;
  }
  const notes = named('noteLongHeader');
  const numbers = named('connectionNumberForFlow');
  if (route.walk.long) {
    if (notes.length !== 1 || numbers.length !== 0) return `frame ${packet.id}: long header noted ${notes.length} times, numbered ${numbers.length}`;
    if (JSON.stringify(notes[0].args[4]) !== JSON.stringify(route.walk.connectionIds) || notes[0].args[5] !== route.walk.emptyDcid) {
      return `frame ${packet.id}: noted ${JSON.stringify(notes[0].args.slice(4))}, read ${JSON.stringify([route.walk.connectionIds, route.walk.emptyDcid])}`;
    }
  } else if (notes.length !== 0 || numbers.length !== 1 || numbers[0].args[4] !== route.matched) {
    return `frame ${packet.id}: short header noted ${notes.length}, numbered ${JSON.stringify(numbers.map((n) => n.args[4]))}, read ${String(route.matched)}`;
  }
  return null;
}

async function headerParse(name: string, path: string): Promise<void> {
  const log: Call[] = [];
  const spy = spying(log);
  let tcpFrames = 0;
  let onTcpLane = 0;
  let barriers = 0;
  let quicFrames = 0;
  let onQuicLane = 0;
  let readOnQuicLane = 0;
  let wrong: string | null = null;
  let quicWrong: string | null = null;
  // The router reads each frame against the order as the frames before it left
  // it, which is the Sequencer the dissection is about to ask.
  let shared: SharedTrackers | undefined;
  let ahead: { lane: QuicLane; route: QuicRouted | null } | undefined;
  await digestCapture(path, {
    trackers: () => (shared = sharedTrackers()).trackers,
    before: (bytes, linktype) => {
      const lane = frameLane(bytes, linktype);
      ahead = lane.lane === 'quic' ? { lane, route: readQuicRoute(bytes, lane, shared!.sequencer.quic) } : undefined;
    },
    wrap: (sources) => { log.length = 0; return spy(sources); },
    observe: (packet, bytes, linktype) => {
      const lane = frameLane(bytes, linktype);
      if (lane.lane === 'tcp') onTcpLane++;
      else if (isTcpFragment(lane)) barriers++;
      if (packet.frameProtocols?.includes('tcp')) tcpFrames++;
      wrong ??= disagreement(log, packet, bytes, linktype);
      if (packet.frameProtocols?.includes('quic')) quicFrames++;
      if (ahead !== undefined) {
        onQuicLane++;
        if (ahead.route !== null) readOnQuicLane++;
        quicWrong ??= quicDisagreement(log, packet, ahead.lane, ahead.route);
      }
    },
  });
  check(`${name}: every frame read onto the TCP lane is numbered as its headers said`, wrong === null, wrong ?? '');
  console.log(`        ${onTcpLane.toLocaleString()} of ${tcpFrames.toLocaleString()} TCP frames on the TCP lane`
    + `${barriers > 0 ? `, ${barriers} fragment barrier(s)` : ''}`);
  if (quicFrames > 0 || onQuicLane > 0) {
    check(`${name}: every frame read onto the QUIC lane asks the QUIC order exactly what the walk read`,
      quicWrong === null, quicWrong ?? '');
    console.log(`        ${readOnQuicLane.toLocaleString()} of ${quicFrames.toLocaleString()} QUIC frames on the QUIC lane`
      + ` (${(onQuicLane - readOnQuicLane).toLocaleString()} more read onto it and left to lane 0)`);
  }
}

// --- (2) one Sequencer shared, or one each ---------------------------------

interface SharedTrackers { trackers: Trackers; sequencer: Sequencer }

function sharedTrackers(): SharedTrackers {
  const sequencer = new Sequencer();
  return {
    sequencer,
    trackers: {
      tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(sequencer),
      dns: new DnsTracker(), l3: new L3Tracker(sequencer),
    },
  };
}

async function sharedAgrees(name: string, path: string): Promise<void> {
  const own = await digestCapture(path);
  const shared = await digestCapture(path, { trackers: () => sharedTrackers().trackers });
  const first = own.findIndex((h, i) => h !== shared[i]);
  check(`${name}: trackers sharing one Sequencer dissect all ${own.length.toLocaleString()} frames byte for byte`,
    first === -1 && own.length === shared.length, first === -1 ? '' : `frame ${first + 1} differs`);
}

// --- (3) eviction, against the rule written out -----------------------------

async function eviction(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-sequencer-'));
  try {
    const path = join(dir, 'eviction.pcap');
    writeFileSync(path, evictionCapture());
    const streams: number[] = [];
    const keys: string[] = [];
    let trackers: Trackers | undefined;
    await digestCapture(path, {
      trackers: () => (trackers = sharedTrackers().trackers),
      observe: (packet, bytes, linktype) => {
        const lane = frameLane(bytes, linktype);
        if (lane.lane !== 'tcp') return;
        keys.push(lane.key);
        streams.push(packet.streamId ?? Number.NaN);
      },
    });
    // The rule: first sight takes the next number; a sighting moves the
    // connection to the back; past the cap the front one is forgotten, and
    // coming back is a first sight again.
    const order = new Map<string, number>();
    let next = 0;
    let forgotten = 0;
    const expected = keys.map((key) => {
      let id = order.get(key);
      if (id === undefined) {
        id = next++;
        order.set(key, id);
        while (order.size > MAX_TCP_CONNECTIONS) { order.delete(order.keys().next().value!); forgotten++; }
      } else {
        order.delete(key);
        order.set(key, id);
      }
      return id;
    });
    const first = streams.findIndex((s, i) => s !== expected[i]);
    check(`eviction: tcp.stream on all ${streams.length.toLocaleString()} segments of ${EVICTION_CONNECTIONS.toLocaleString()} connections is the rule's`,
      first === -1, first === -1 ? '' : `segment ${first + 1}: ${streams[first]}, the rule says ${expected[first]}`);
    check('eviction: it did forget connections, as many as the rule', forgotten > 0 && trackers?.tcp.evictedConnections === forgotten,
      `${trackers?.tcp.evictedConnections} against ${forgotten}`);
    check('eviction: a connection that comes back is a new one', streams[EVICTION_CONNECTIONS + 1] >= EVICTION_CONNECTIONS,
      String(streams[EVICTION_CONNECTIONS + 1]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// --- (4) the frame clock -----------------------------------------------------

function clock(): void {
  const a = new FrameClock();
  const first = a.fromNanos(1_700_000_000_123_456_789n);
  const second = a.fromNanos(1_700_000_001_123_456_790n);
  check('clock: an import\'s first frame is at zero, and the next is a nanosecond-exact second later',
    first.relativeTime === 0 && first.timeDelta === 0 && second.relativeTime === 1.000000001 && second.timeDelta === 1.000000001);
  const b = new FrameClock();
  b.fromLive(5_000_000, 500);
  const later = b.fromLive(5_000_001, 0);
  const earlier = b.fromLive(5_000_000, 900);
  check('clock: live time keeps the nanoseconds, and a frame stamped earlier has no negative gap',
    later.relativeTime === 0.0000005 && earlier.timeDelta === 0 && earlier.relativeTime === 0.0000004);
  const c = new FrameClock();
  c.resumeLive(1_000_000, 3_000_000);
  const resumed = c.fromLive(3_500_000, 0);
  check('clock: a restored session carries on its own column', resumed.relativeTime === 2.5 && resumed.timeDelta === 0.5
    && c.liveStartUs === 1_000_000);
}

/** TCP in IP fragments, which none of the fixtures holds (`fragmentCapture.ts`). */
async function fragments(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-fragments-'));
  try {
    const path = join(dir, 'fragments.pcap');
    writeFileSync(path, fragmentCapture());
    await headerParse('fragments', path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** QUIC in every shape the router will have to tell apart (`quicCapture.ts`), dissected both ways. */
async function quicShared(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-quic-'));
  try {
    const path = join(dir, 'quic.pcap');
    writeFileSync(path, quicCapture());
    await headerParse('quic', path);
    await sharedAgrees('quic', path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// --- (5) QUIC's flow registry -------------------------------------------------

/**
 * The QUIC half of the Sequencer: which flows have carried a long header, which
 * connection ids those named, and the connection number each took. The same
 * rules `QuicFlowTracker` kept for itself, asserted directly on the order.
 */
function quicRegistry(): void {
  const order = new Sequencer().quic;
  const a = quicFlowKey('10.0.0.1', 50000, '10.0.0.2', 443);
  check('quic: a first long header takes number 0, and the flow is known',
    order.noteLongHeader(a, ['aa01'], false).number === 0 && order.isKnown(a));
  check('quic: a zero-length DCID answers with the flow\'s connection',
    order.noteLongHeader(a, ['bb02'], true).number === 0);
  const c = quicFlowKey('10.0.0.3', 50000, '10.0.0.2', 443);
  const d = quicFlowKey('10.0.0.4', 50000, '10.0.0.2', 443);
  const numberedC = order.noteLongHeader(c, ['cc'], false).number;
  const numberedD = order.noteLongHeader(d, ['dd'], false).number;
  check('quic: ids numbered apart and then seen together settle on the lower',
    numberedC === 1 && numberedD === 2 && order.noteLongHeader(c, ['dd', 'cc'], false).number === 1
      && order.connectionFor('dd') === 1 && order.connectionFor('cc') === 1);
  check('quic: a short header is matched by the flow\'s ids',
    order.match(a, Uint8Array.from([0x40, 0xaa, 0x01, 7]), 1) === 'aa01');
  const v = quicFlowKey('10.0.0.9', 1, '10.0.0.2', 443);
  const vn = order.noteLongHeader(v, [], true);
  check('quic: Version Negotiation registers its flow with no ids',
    order.isKnown(v) && order.connectionForFlow(v, undefined) === vn.number);

  // Eviction, on a fresh order: MAX_QUIC_FLOWS + 1 flows, one id each.
  const o = new Sequencer().quic;
  const idOf = (n: number): string => n.toString(16).padStart(8, '0');
  const flowOf = (n: number): string => quicFlowKey('10.1.0.1', 1000 + n, '10.1.0.2', 443);
  const first = flowOf(0);
  o.noteLongHeader(first, [idOf(0)], false);
  let last: ReturnType<typeof o.noteLongHeader> | undefined;
  for (let i = 1; i <= MAX_QUIC_FLOWS; i++) last = o.noteLongHeader(flowOf(i), [idOf(i)], false);
  check('quic: the 4,097th flow forgets the least recently noted one, and says so',
    last !== undefined && last.forgotten.length === 1 && last.forgotten[0] === first && o.evicted === 1);
  check('quic: a forgotten flow\'s ids no longer number',
    o.connectionFor(idOf(0)) === undefined && !o.isKnown(first));
  check('quic: a returning flow takes an unused number',
    o.noteLongHeader(first, [idOf(0)], false).number === MAX_QUIC_FLOWS + 1);
}

async function main(): Promise<void> {
  for (const { name, path } of captures) await headerParse(name, path);
  await fragments();
  for (const { name, path } of captures) await sharedAgrees(name, path);
  await quicShared();
  await eviction();
  clock();
  quicRegistry();
}

main().then(() => {
  console.log(failures === 0 ? '\nAll sequencer checks passed.' : `\n${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
