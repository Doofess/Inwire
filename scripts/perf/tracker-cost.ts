/**
 * What does the dissection pipeline retain that is NOT a `Packet`?
 *
 *   node --expose-gc --import tsx scripts/perf/tracker-cost.ts
 *   node --expose-gc --import tsx scripts/perf/tracker-cost.ts --connections 20000
 *
 * Every memory number this project has is per frame: 2,197 B of summary, 1,176 B
 * of raw bytes (`docs/decisions/0013`). All of them measure the buffer, and the
 * buffer is bounded - `trimToCap` slices the array, trims the session store and
 * evicts raw bytes the moment the cap is reached.
 *
 * **It never touches a tracker.** The five order-dependent trackers and the two
 * module-level annotation stores accumulate per *connection*, not per frame, and
 * `resetPipeline` - the only thing that clears them - fires on four events that
 * all mean "the buffer is gone" (clear, delete session, import, end of restore).
 * None of them means "the buffer got smaller". So a long capture trims frames
 * for ever while its tracker state only grows.
 *
 * That makes the interesting number bytes per *connection*, and the interesting
 * capture one with many short-lived connections rather than many frames. A
 * browsing workload is exactly that shape, which is why the two fixtures - two
 * browsing sessions with a few thousand frames each - understate it, and why
 * this script carries a synthetic workload as well.
 *
 * Two independent readings, because neither alone is trustworthy:
 *
 *   - **Heap attribution.** Feed the frames, discard every packet, then drop one
 *     tracker at a time and collect. What the heap gives back is what that
 *     tracker alone retained. It UNDER-counts anything shared: the address pool
 *     (`services/addressFormat.ts`) holds one string per distinct address, so a
 *     key built from pooled addresses is charged to the pool and not to the map
 *     holding it. That is the honest attribution - dropping the tracker really
 *     would not free those - and the pool is measured separately below.
 *   - **A census of entries**, walked reflectively rather than by name, so a
 *     renamed field shows up as itself instead of silently reading zero.
 *
 * A measurement, not an assertion: there is no right answer to hold it to, so
 * `check.ts` skips it by name the way it skips `throughput.ts` and
 * `clone-cost.ts`.
 *
 * The fixture pass needs the fixtures (test/fixtures/README.md) and skips
 * cleanly without them; the synthetic pass always runs.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService, decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { flowAnnotations } from '../../src/services/flowAnnotations';
import { annotatePacket } from '../../src/services/dissect/processFields';
import { clientFingerprints, learnOrLabelFingerprint } from '../../src/services/dissect/clientFingerprints';
import { clearAddressPool } from '../../src/services/addressFormat';

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const CONNECTIONS = Number(arg('connections', '5000'));
const FRAMES_PER_CONNECTION = Number(arg('frames-per-connection', '10'));

function heap(): number {
  if (global.gc) { global.gc(); global.gc(); global.gc(); }
  return process.memoryUsage().heapUsed;
}

function kb(bytes: number): string {
  return (bytes / 1024).toFixed(0).padStart(7) + ' KB';
}

// --- The census ---------------------------------------------------------------
//
// Walked reflectively: `private` in TypeScript is a compile-time promise and
// nothing more, so every field is an ordinary own property at runtime. Reading
// them by name would mean this script quietly reporting zero the day one is
// renamed; reading whatever is there means a new map shows up on its own.

interface CensusRow { path: string; kind: string; entries: number }

function sizeOf(value: unknown): { kind: string; entries: number } | null {
  if (value instanceof Map) return { kind: 'Map', entries: value.size };
  if (value instanceof Set) return { kind: 'Set', entries: value.size };
  if (Array.isArray(value)) return { kind: 'Array', entries: value.length };
  return null;
}

/**
 * One level down as well as the top: several of these are a map whose values
 * are themselves collections (`flowConnectionIds` is Map<string, Set>, `parts`
 * is Map<string, FragmentPart[]>, `lives` is Map<string, SocketLife[]>), and
 * the nested total is the half that grows without a bound of its own.
 */
function census(name: string, target: object): CensusRow[] {
  const rows: CensusRow[] = [];
  for (const [key, value] of Object.entries(target)) {
    const top = sizeOf(value);
    if (top === null) continue;
    rows.push({ path: `${name}.${key}`, kind: top.kind, entries: top.entries });
    if (value instanceof Map) {
      let nested = 0;
      let nestedKind = '';
      for (const inner of value.values()) {
        const size = sizeOf(inner);
        if (size === null) break;
        nested += size.entries;
        nestedKind = size.kind;
      }
      if (nestedKind) {
        rows.push({ path: `${name}.${key}[].*`, kind: nestedKind, entries: nested });
      }
    }
  }
  return rows;
}

// --- Frame builders for the synthetic workload -------------------------------

const MAC_CLIENT = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_ROUTER = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

function ipv4Frame(payload: number[], proto: number, src: number[], dst: number[]): Uint8Array {
  const totalLen = 20 + payload.length;
  const outbound = src[0] === 10;
  return new Uint8Array([
    ...(outbound ? MAC_ROUTER : MAC_CLIENT), ...(outbound ? MAC_CLIENT : MAC_ROUTER), 0x08, 0x00,
    0x45, 0x00, (totalLen >> 8) & 0xff, totalLen & 0xff,
    0x00, 0x01, 0x40, 0x00,
    0x40, proto, 0x00, 0x00,
    ...src, ...dst,
    ...payload,
  ]);
}

function tcpSegment(
  src: number[], sport: number, dst: number[], dport: number,
  seq: number, ack: number, flags: number, payloadBytes: number,
): Uint8Array {
  const tcp = [
    (sport >> 8) & 0xff, sport & 0xff,
    (dport >> 8) & 0xff, dport & 0xff,
    (seq >>> 24) & 0xff, (seq >>> 16) & 0xff, (seq >>> 8) & 0xff, seq & 0xff,
    (ack >>> 24) & 0xff, (ack >>> 16) & 0xff, (ack >>> 8) & 0xff, ack & 0xff,
    0x50, flags, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00,
    ...new Array(payloadBytes).fill(0x41),
  ];
  return ipv4Frame(tcp, 6, src, dst);
}

function icmpEcho(id: number, seq: number, target: number[]): Uint8Array {
  const icmp = [
    8, 0x00, 0x00, 0x00,
    (id >> 8) & 0xff, id & 0xff,
    (seq >> 8) & 0xff, seq & 0xff,
    0xde, 0xad, 0xbe, 0xef,
  ];
  return ipv4Frame(icmp, 1, [10, 0, 0, 9], target);
}

/**
 * A browsing workload's shape: many connections, each short.
 *
 * Every one opens with a full handshake, carries a few segments each way and
 * closes cleanly with FIN/ACK - so each connection is unambiguously OVER by the
 * end of the capture, and everything the trackers still hold for it afterwards
 * is state that nothing will ever ask for again.
 */
function syntheticFrames(connections: number, framesPerConnection: number): Uint8Array[] {
  const frames: Uint8Array[] = [];
  const exchanges = Math.max(0, Math.floor((framesPerConnection - 4) / 2));
  for (let i = 0; i < connections; i++) {
    const sport = 1024 + (i % 64000);
    const server = [93, 184, (i >> 8) & 0xff, i & 0xff];
    const client = [10, 0, (i >> 8) & 0x0f, 1 + (i & 0xff)];
    let seq = 1000;
    let ackSeq = 5000;
    frames.push(tcpSegment(client, sport, server, 443, seq, 0, 0x02, 0));          // SYN
    frames.push(tcpSegment(server, 443, client, sport, ackSeq, seq + 1, 0x12, 0)); // SYN-ACK
    seq += 1; ackSeq += 1;
    for (let e = 0; e < exchanges; e++) {
      frames.push(tcpSegment(client, sport, server, 443, seq, ackSeq, 0x18, 64));
      seq += 64;
      frames.push(tcpSegment(server, 443, client, sport, ackSeq, seq, 0x18, 128));
      ackSeq += 128;
    }
    frames.push(tcpSegment(client, sport, server, 443, seq, ackSeq, 0x11, 0));     // FIN, ACK
    frames.push(tcpSegment(server, 443, client, sport, ackSeq, seq + 1, 0x11, 0)); // FIN, ACK
  }
  return frames;
}

/** Unanswered echo requests - a ping sweep, which is a real thing people run. */
function sweepFrames(hosts: number): Uint8Array[] {
  const frames: Uint8Array[] = [];
  for (let i = 0; i < hosts; i++) {
    frames.push(icmpEcho(0x1234, i, [10, 1, (i >> 8) & 0xff, i & 0xff]));
  }
  return frames;
}

// --- The pass ------------------------------------------------------------------

interface Trackers {
  tcp?: TcpStreamTracker;
  icmp?: IcmpEchoTracker;
  quic?: QuicFlowTracker;
  dns?: DnsTracker;
  l3?: L3Tracker;
}

/**
 * Feeds frames through the real dissector and keeps NOTHING. Every packet is
 * dropped as soon as it is annotated, which is the point: whatever the heap is
 * still holding afterwards is held by a tracker, not by a buffer.
 */
function runFrames(frames: readonly Uint8Array[], t: Trackers): number {
  let tsUs = 1_700_000_000_000_000;
  let id = 1;
  for (const bytes of frames) {
    tsUs += 100;
    const { packet } = decodeRawEthernetPacket(
      bytes, id++, tsUs, (id - 1) / 10_000, 0.0001, bytes.length,
      t.tcp, t.icmp, t.quic, t.dns, undefined, undefined, t.l3,
    );
    annotatePacket(packet, flowAnnotations);
    learnOrLabelFingerprint(packet.fields, clientFingerprints, packet.layers);
    packet.layers = [];
  }
  return frames.length;
}

function freshTrackers(): Required<Trackers> {
  return {
    tcp: new TcpStreamTracker(),
    icmp: new IcmpEchoTracker(),
    quic: new QuicFlowTracker(),
    dns: new DnsTracker(),
    l3: new L3Tracker(),
  };
}

/**
 * What one tracker retains: the pass re-run, keeping only that one alive at the
 * end.
 *
 * The obvious version of this - run once, then drop the trackers one at a time
 * and watch the heap - does not work, and its failure is worth recording
 * because it is convincing. It charged 11 MB to `QuicFlowTracker` on a
 * synthetic capture containing **no QUIC at all**, whose census showed the QUIC
 * tracker holding zero entries; and on the inwire fixture the five deltas summed
 * to 1,056 KB against 441 KB actually retained. `heapUsed` after a collection is
 * not a clean read of what is reachable - it moves with what the collector
 * happened to finish - so a sequence of deltas attributes the pass's own garbage
 * to whichever step it lands on.
 *
 * So each tracker gets its own pass. Every tracker is PRESENT during it, which
 * matters: dissection changes shape without them (no fragment reassembly with
 * no `L3Tracker`, no TLS cursor with no `TcpStreamTracker`), and a measurement
 * of a different dissection is a measurement of nothing. Only the retention at
 * the end differs, so what is left is one tracker and the garbage of four.
 *
 * It still under-counts what is shared. The address pool holds one string per
 * distinct address, so a key built from pooled addresses stays alive whatever is
 * dropped, and is charged to the pool instead - which is the truthful answer to
 * "what would freeing this tracker actually free".
 */
function attribute(frames: readonly Uint8Array[]): { rows: { name: string; bytes: number }[]; floor: number } {
  const measure = (key: keyof Trackers | null): number => {
    flowAnnotations.clear();
    clientFingerprints.clear();
    clearAddressPool();

    const before = heap();
    let held: Trackers | undefined = freshTrackers();
    runFrames(frames, held);
    // Everything but the one under test becomes garbage here; `kept` is the
    // only reference that survives to the measurement below.
    const kept = key === null ? null : held[key];
    held = undefined;
    const after = heap();
    // Read after measuring, so the reference cannot be optimised away early.
    if (key !== null && kept === undefined) throw new Error('tracker vanished: ' + key);
    return after - before;
  };

  // A pass that keeps NOTHING. Whatever the heap still reports is the pass's
  // own residue - lazily-initialised module state, code the JIT compiled,
  // garbage a collection did not get to - and it is charged to every row
  // equally, so subtracting it is what turns five similar-looking numbers into
  // an attribution. It was ~250 KB when this was written, which is larger than
  // several of the trackers it would otherwise have swamped.
  const floor = measure(null);
  const rows = (['tcp', 'quic', 'l3', 'dns', 'icmp'] as (keyof Trackers)[])
    .map(key => ({ name: key, bytes: Math.max(0, measure(key) - floor) }));
  return { rows, floor };
}

function reportCensus(t: Required<Pick<Trackers, 'tcp' | 'quic' | 'l3' | 'dns' | 'icmp'>>): void {
  const rows: CensusRow[] = [
    ...census('tcp', t.tcp),
    ...census('quic', t.quic),
    ...census('l3', t.l3),
    ...census('dns', t.dns),
    ...census('icmp', t.icmp),
    ...census('flowAnnotations', flowAnnotations),
    ...census('clientFingerprints', clientFingerprints),
  ].filter(r => r.entries > 0);
  console.log('  entries retained');
  for (const row of rows.sort((a, b) => b.entries - a.entries)) {
    console.log('    ' + row.path.padEnd(34) + String(row.entries).padStart(9) + '  ' + row.kind);
  }
}

/** TCP streams plus QUIC flows plus outstanding echoes: the things state is kept per. */
function conversationsIn(t: Required<Trackers>): number {
  const size = (target: object, field: string): number => {
    const value = (target as Record<string, unknown>)[field];
    return value instanceof Map ? value.size : 0;
  };
  return size(t.tcp, 'connections')
    + size(t.quic, 'flowConnectionIds')
    + size(t.icmp, 'pendingRequests');
}

async function pass(name: string, frames: readonly Uint8Array[], unit: string): Promise<void> {
  // A clean slate: the module-level stores survive between passes and would
  // otherwise charge the second pass with the first one's state.
  flowAnnotations.clear();
  clientFingerprints.clear();
  clearAddressPool();

  const t = freshTrackers();

  const before = heap();
  const count = runFrames(frames, t);
  const after = heap();
  const total = after - before;
  const conversations = Math.max(1, conversationsIn(t));
  const evicted = t.tcp.evictedConnections;

  console.log(name);
  console.log('  frames ' + count.toLocaleString()
    + '   ' + unit + 's ' + conversations.toLocaleString()
    + '   ' + (count / conversations).toFixed(1) + ' frames/' + unit);
  console.log('  retained after the pass, every packet discarded   ' + kb(total));
  console.log();

  reportCensus(t);
  console.log();

  const { rows: parts, floor } = attribute(frames);

  // A number that cannot be defended is worse than no number. When the pass's
  // own residue is the size of what it retained, the difference between two
  // rows is residue and not attribution - which is the case for both fixtures,
  // because 47 and 30 conversations is simply too few to measure. Saying so is
  // the finding: **the fixtures cannot measure this**, which is exactly why the
  // synthetic workload above it exists.
  if (floor > total * 0.5) {
    console.log('  attribution suppressed: a ' + (floor / 1024).toFixed(0)
      + ' KB noise floor against ' + (total / 1024).toFixed(0) + ' KB retained.');
    console.log('  ' + conversations.toLocaleString() + ' ' + unit
      + 's is too few to measure above the pass\'s own residue; see the census above,');
    console.log('  and the synthetic workload for the per-' + unit + ' cost.');
    console.log();
    return;
  }

  console.log('  retained by each tracker alone, one pass each, less a '
    + (floor / 1024).toFixed(0) + ' KB noise floor');
  for (const part of parts) {
    console.log('    ' + part.name.padEnd(34) + kb(part.bytes)
      + '   ' + (part.bytes / conversations).toFixed(0).padStart(6) + ' B/' + unit);
  }
  console.log('    ' + 'TOTAL, measured directly'.padEnd(34) + kb(total)
    + '   ' + (total / conversations).toFixed(0).padStart(6) + ' B/' + unit);
  console.log();

  // The caps are the point, so report what they did rather than extrapolating
  // past them. An extrapolation with no eviction is what this looked like
  // before there were bounds, and printing one now would describe a version of
  // the code that no longer exists.
  if (evicted > 0) {
    console.log('  ' + evicted.toLocaleString() + ' ' + unit
      + 's evicted to stay inside the cap; ' + conversations.toLocaleString()
      + ' retained.');
    console.log('  That ceiling is the whole retention, however long the capture runs: '
      + (total / 1e6).toFixed(0) + ' MB.');
  } else {
    console.log('  nothing was evicted, so this is the cost as it grows:');
    for (const n of [10_000, 50_000, 200_000]) {
      console.log('    ' + String(n).padStart(9) + ' ' + unit + 's   '
        + ((total / conversations) * n / 1e6).toFixed(0).padStart(6)
        + ' MB of tracker state');
    }
  }
  console.log();
}

async function main() {
  if (!global.gc) {
    console.log('Run with --expose-gc, or the heap numbers are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/tracker-cost.ts');
    process.exit(1);
  }

  // --- Synthetic: the shape the fixtures do not have ---------------------------
  const synthetic = syntheticFrames(CONNECTIONS, FRAMES_PER_CONNECTION);
  await pass('synthetic: ' + CONNECTIONS.toLocaleString()
    + ' TCP connections, each opened and cleanly closed', synthetic, 'connection');

  // --- A ping sweep: state per PROBE, and no connection at all -----------------
  const SWEEP = 4096;
  await pass('synthetic: a ' + SWEEP.toLocaleString() + '-host ping sweep, no replies',
    sweepFrames(SWEEP), 'probe');

  // --- The real captures --------------------------------------------------------
  for (const [label, path] of Object.entries(FIXTURES)) {
    if (!existsSync(path)) {
      console.log('SKIP  fixture missing: ' + path + ' (see test/fixtures/README.md)');
      continue;
    }
    const buf = readFileSync(path);
    const parsed = await PcapService.parseCaptureFile(
      new File([new Uint8Array(buf)], 'fixture.pcap'), 1_000_000,
    );
    // Bytes only: the packets themselves must not be retained across the pass,
    // or the heap delta measures the buffer this script exists to look past.
    const frames = parsed.packets.map(p => p.rawBytes);
    await pass('fixture ' + label, frames, 'conversation');
  }
}

main();
