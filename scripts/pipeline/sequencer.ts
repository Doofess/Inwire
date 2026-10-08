/**
 * The Sequencer, held to the dissector it numbers for (ADR 0053 phase 2).
 *
 *   npx tsx scripts/pipeline/sequencer.ts [--burst some.pcapng]
 *
 * Four things, each the property phase 3 will lean on:
 *
 *   1. **The header parse never sends a frame to the TCP lane that the
 *      dissection numbers differently.** Every frame of every real fixture is
 *      dissected with a spy on the trackers; for each one `frameLane` sends to
 *      the TCP lane, the calls the dissection made to the cross-conversation
 *      numbering - `eth.stream`, `ip.stream`/`ipv6.stream`, `udp.stream`, and
 *      every TCP lookup - must be exactly the ones read from its headers. A
 *      frame it leaves on the sequential lane is never wrong, only slower, so
 *      the share of TCP frames it reaches is printed rather than asserted.
 *   2. **Trackers sharing one Sequencer dissect byte for byte as trackers
 *      each holding their own** - what the Worker does now against what every
 *      older caller still does. A hash of every frame's columns, bag, tree,
 *      record, derived answers and patches (`frameDigest.ts`).
 *   3. **TCP's eviction numbers as the rule says**, on a capture of 20,000
 *      connections (`evictionCapture.ts`): `tcp.stream` for every segment
 *      against a model of the rule written out here - least recently seen goes
 *      past 16,384, a returning connection is new, numbers are never reused.
 *   4. **The frame clock** keeps both forms' arithmetic.
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
import { FrameClock, MAX_TCP_CONNECTIONS, Sequencer, tcpConnectionKey } from '../../src/services/dissect/sequencer';
import { frameLane } from '../../src/services/dissect/frameLane';
import type { FrameSources } from '../../src/services/dissect/frameRecord';
import type { Packet } from '../../src/types/packet';
import { FIXTURES } from './arrival';
import { digestCapture, type Trackers } from './frameDigest';
import { EVICTION_CONNECTIONS, evictionCapture } from './evictionCapture';

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

interface Call { group: 'tcp' | 'l3'; method: string; args: unknown[] }

/** Wraps the sources a frame is dissected with so its numbering calls are logged. */
function spying(log: Call[]): (sources: FrameSources) => FrameSources {
  const wrap = <T extends object>(target: T, group: 'tcp' | 'l3', watch: (m: string) => boolean): T =>
    new Proxy(target, {
      get(t, prop, receiver) {
        const value = Reflect.get(t, prop, receiver);
        if (typeof value !== 'function' || typeof prop !== 'string' || !watch(prop)) return value;
        return (...args: unknown[]) => {
          log.push({ group, method: prop, args });
          return (value as (...a: unknown[]) => unknown).apply(t, args);
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

async function headerParse(name: string, path: string): Promise<void> {
  const log: Call[] = [];
  const spy = spying(log);
  let tcpFrames = 0;
  let onTcpLane = 0;
  let barriers = 0;
  let wrong: string | null = null;
  await digestCapture(path, {
    wrap: (sources) => { log.length = 0; return spy(sources); },
    observe: (packet, bytes, linktype) => {
      const lane = frameLane(bytes, linktype);
      if (lane.lane === 'tcp') onTcpLane++;
      else if (lane.fragmentOf === 'tcp') barriers++;
      if (packet.frameProtocols?.includes('tcp')) tcpFrames++;
      wrong ??= disagreement(log, packet, bytes, linktype);
    },
  });
  check(`${name}: every frame read onto the TCP lane is numbered as its headers said`, wrong === null, wrong ?? '');
  console.log(`        ${onTcpLane.toLocaleString()} of ${tcpFrames.toLocaleString()} TCP frames on the TCP lane`
    + `${barriers > 0 ? `, ${barriers} fragment barrier(s)` : ''}`);
}

// --- (2) one Sequencer shared, or one each ---------------------------------

function sharedTrackers(): Trackers {
  const sequencer = new Sequencer();
  return {
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  };
}

async function sharedAgrees(name: string, path: string): Promise<void> {
  const own = await digestCapture(path);
  const shared = await digestCapture(path, { trackers: sharedTrackers });
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
      trackers: () => (trackers = sharedTrackers()),
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

async function main(): Promise<void> {
  for (const { name, path } of captures) await headerParse(name, path);
  for (const { name, path } of captures) await sharedAgrees(name, path);
  await eviction();
  clock();
}

main().then(() => {
  console.log(failures === 0 ? '\nAll sequencer checks passed.' : `\n${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
