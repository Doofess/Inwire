/**
 * Where does the Worker's per-frame time actually go, and what rate can it hold?
 *
 *   npx tsx scripts/perf/throughput.ts [--fixture inwire|bulk] [--frames N]
 *
 * Every performance number this project has about the capture pipeline is a
 * total: `clone-cost.ts` says dissection costs ~170 us a frame and crossing the
 * boundary ~6 us, and stops there. That was enough to decide what crosses the
 * boundary (docs/decisions/0007). It is not enough to decide what to make
 * faster, because "dissection" is one word covering the ordering window, the
 * five trackers, the tree the Worker builds and immediately throws away, and
 * the two annotation passes over it.
 *
 * So this runs the Worker's ingest loop - the real OrderingWindow, the real
 * trackers, the real `decodeRawEthernetPacket`, the real annotators - over a
 * real capture, and times each stage separately with percentiles rather than a
 * mean. A mean hides the thing that actually causes drops: `flush()` is
 * synchronous, so it is the *tail* that overruns the 100 ms budget and starves
 * `ws.onmessage`, which is what makes the agent's queue overflow and
 * `droppedAgent` climb.
 *
 * It is a measurement, not an assertion - there is no right answer to hold it
 * to - so `check.ts` skips it by name, like `clone-cost.ts` and `wire-size.ts`.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { OrderingWindow } from '../../src/services/dissect/orderingWindow';
import { PcapService, decodeRawEthernetPacket, type InfoPatch } from '../../src/services/pcapParser';
import { flowAnnotations } from '../../src/services/flowAnnotations';
import { annotatePacket } from '../../src/services/dissect/processFields';
import { clientFingerprints, learnOrLabelFingerprint } from '../../src/services/dissect/clientFingerprints';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import type { Packet, ProtocolLayer } from '../../src/types/packet';

/** Mirrors the Worker's own constants, so the simulation is the real cadence. */
const FLUSH_MS = 100;
const ORDERING_HOLD_MS = 100;
const DETAIL_CACHE_FRAMES = 4000;
/** MAX_BATCH_RECORDS in the agent. */
const BATCH = 512;

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const fixtureName = arg('fixture', 'inwire');
const FIXTURE = FIXTURES[fixtureName];
if (!FIXTURE) {
  console.log('unknown fixture ' + fixtureName + '; expected one of ' + Object.keys(FIXTURES).join(', '));
  process.exit(1);
}
const MAX_FRAMES = Number(arg('frames', '1000000'));

/** One stage's per-frame timings, in microseconds. */
class Stage {
  private readonly samples: number[] = [];
  private total = 0;
  add(us: number) { this.samples.push(us); this.total += us; }
  get count() { return this.samples.length; }
  get mean() { return this.count ? this.total / this.count : 0; }
  /** The tail is what overruns a flush budget, so percentiles, not just a mean. */
  percentile(p: number): number {
    if (!this.count) return 0;
    const sorted = [...this.samples].sort((a, b) => a - b);
    return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
  }
}

interface Frame { tsUs: number; seq: number; arrivedAt: number; bytes: Uint8Array; origLen: number }

function percentileOf(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
    process.exit(0);
  }

  // The source frames. Parsed once without trees, purely to get each frame's
  // bytes and capture time back out of the file; the pipeline below then
  // re-dissects them from scratch with its own trackers, which is what the
  // Worker does with what arrives off the socket.
  const buf = readFileSync(FIXTURE);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), MAX_FRAMES,
  );
  const source: Frame[] = parsed.packets.map((p, i) => ({
    tsUs: p.tsUs, seq: i, arrivedAt: 0, bytes: p.rawBytes, origLen: p.length,
  }));
  if (source.length === 0) {
    console.log('SKIP  fixture parsed to zero frames');
    process.exit(0);
  }

  const push = new Stage();
  const dissect = new Stage();
  const annotate = new Stage();
  const boundary = new Stage();
  const boundaryTransfer = new Stage();
  const flushes: number[] = [];

  const ordering = new OrderingWindow<Frame>(ORDERING_HOLD_MS);
  const tcpTracker = new TcpStreamTracker();
  const icmpTracker = new IcmpEchoTracker();
  const quicTracker = new QuicFlowTracker();
  const dnsTracker = new DnsTracker();
  const l3Tracker = new L3Tracker();
  const treeCache = new Map<number, ProtocolLayer[]>();

  let nextId = 1;
  let captureStartUs: number | null = null;
  let lastPacketUs: number | null = null;
  let pendingPackets: Packet[] = [];
  const pendingInfoPatches: InfoPatch[] = [];
  let sink = 0;
  /** The slowest frames, so the tail can be attributed rather than guessed at. */
  const slow: { us: number; protocol: string; len: number; info: string }[] = [];

  // One frame through the Worker's ingest, stage by stage. This is
  // pipeline.worker.ts's `ingest()`, unrolled so each part can be timed.
  const ingest = (frame: Frame) => {
    if (captureStartUs === null) { captureStartUs = frame.tsUs; lastPacketUs = null; }
    const relativeTime = (frame.tsUs - captureStartUs) / 1_000_000;
    const timeDelta = lastPacketUs !== null ? Math.max(0, (frame.tsUs - lastPacketUs) / 1_000_000) : 0;
    lastPacketUs = frame.tsUs;
    const id = nextId++;

    const d0 = performance.now();
    const decoded = decodeRawEthernetPacket(
      frame.bytes, id, frame.tsUs, relativeTime, timeDelta, frame.origLen,
      tcpTracker, icmpTracker, quicTracker, dnsTracker, undefined, undefined, l3Tracker,
    );
    const dissectUs = (performance.now() - d0) * 1000;
    dissect.add(dissectUs);

    const packet = decoded.packet;
    // `flush()` is synchronous, so it is the tail that overruns a budget and
    // starves the socket - a mean says nothing about that. Keeping the worst
    // frames is what turns "p99 is 30x p50" into a name.
    if (dissectUs > 200) {
      slow.push({
        us: dissectUs, protocol: packet.protocol, len: packet.length,
        info: (packet.info ?? '').slice(0, 58),
      });
    }
    packet.tsPrecision = 6;

    const a0 = performance.now();
    annotatePacket(packet, flowAnnotations);
    learnOrLabelFingerprint(packet.fields, clientFingerprints, packet.layers);
    // The tree is cached for the most recent DETAIL_CACHE_FRAMES and dropped
    // for every other frame - ~92% of them at a 50k buffer. Kept here because
    // the eviction and the discard are part of what a frame costs today.
    treeCache.set(id, packet.layers);
    while (treeCache.size > DETAIL_CACHE_FRAMES) {
      const oldest = treeCache.keys().next();
      if (oldest.done) break;
      treeCache.delete(oldest.value);
    }
    packet.layers = [];
    annotate.add((performance.now() - a0) * 1000);

    pendingPackets.push(packet);
    if (decoded.infoPatches) for (const p of decoded.infoPatches) pendingInfoPatches.push(p);
  };

  // Frames arrive in batches and are released a flush at a time, in capture
  // order. `arrivedAt` is synthesised so the ordering window behaves exactly as
  // it does live: a frame is held ORDERING_HOLD_MS before it may be dissected.
  let clock = 0;
  const totalStart = performance.now();

  for (let i = 0; i < source.length; i += BATCH) {
    const batch = source.slice(i, i + BATCH);
    clock += FLUSH_MS;
    const p0 = performance.now();
    for (const frame of batch) ordering.push({ ...frame, arrivedAt: clock });
    push.add(((performance.now() - p0) * 1000) / batch.length);

    const f0 = performance.now();
    for (const frame of ordering.drain(clock + ORDERING_HOLD_MS)) ingest(frame);
    if (pendingPackets.length > 0) {
      const count = pendingPackets.length;
      // What crossing the boundary costs. structuredClone is what postMessage
      // does; no transfer list is passed today, which is Item 5 of the plan.
      const b0 = performance.now();
      sink += (structuredClone(pendingPackets) as Packet[]).length;
      boundary.add(((performance.now() - b0) * 1000) / count);

      // And the same batch with every frame's bytes moved rather than copied,
      // which is what a transfer list does. `retain()` gives each frame an
      // exactly-sized buffer of its own, so they are safe to detach - the
      // question this answers is whether it is worth doing.
      const copies = pendingPackets.map((p) => ({ ...p, rawBytes: p.rawBytes.slice() }));
      const buffers = [...new Set(copies.map((p) => p.rawBytes.buffer))]
        .filter((b) => b.byteLength > 0);
      const t0 = performance.now();
      sink += (structuredClone(copies, { transfer: buffers }) as Packet[]).length;
      boundaryTransfer.add(((performance.now() - t0) * 1000) / count);

      pendingPackets = [];
    }
    flushes.push(performance.now() - f0);
  }
  for (const frame of ordering.flush()) ingest(frame);
  const wallMs = performance.now() - totalStart;

  const n = nextId - 1;
  const perFrame = push.mean + dissect.mean + annotate.mean + boundary.mean;
  const pct = (s: Stage) => ((s.mean / perFrame) * 100).toFixed(1).padStart(5);
  const row = (label: string, s: Stage) =>
    console.log('  ' + label.padEnd(22) + s.mean.toFixed(2).padStart(8) + s.percentile(50).toFixed(2).padStart(9)
      + s.percentile(95).toFixed(2).padStart(9) + s.percentile(99).toFixed(2).padStart(9) + '   ' + pct(s) + '%');

  console.log('fixture                ' + FIXTURE);
  console.log('frames                 ' + n);
  console.log('wall                   ' + wallMs.toFixed(0) + ' ms');
  console.log();
  console.log('  stage                    mean      p50      p95      p99   share');
  console.log('  ' + '-'.repeat(68));
  row('ordering push', push);
  row('dissect (+trackers)', dissect);
  row('annotate + tree', annotate);
  row('boundary (clone)', boundary);
  row('  same, w/ transfer', boundaryTransfer);
  console.log('  ' + '-'.repeat(68));
  console.log('  ' + 'total'.padEnd(22) + perFrame.toFixed(2).padStart(8) + ' us/frame');
  console.log();
  console.log('flush duration         p50 ' + percentileOf(flushes, 50).toFixed(1) + ' ms   p95 '
    + percentileOf(flushes, 95).toFixed(1) + ' ms   max ' + Math.max(...flushes).toFixed(1) + ' ms');
  console.log('flushes over budget    ' + flushes.filter((f) => f > FLUSH_MS).length + ' of ' + flushes.length
    + '  (> ' + FLUSH_MS + ' ms)');
  console.log();
  // The number the whole programme is trying to move. Once a flush costs more
  // than FLUSH_MS the Worker stops reading its socket, the agent's bounded
  // deque overflows and droppedAgent starts counting - so the sustained
  // ceiling is one flush window's worth of frames, per flush window.
  // Item 5 asks for a transfer list on the frame batch. This says what it buys.
  console.log('transfer list saves    ' + (boundary.mean - boundaryTransfer.mean).toFixed(2)
    + ' us/frame  (' + (((boundary.mean - boundaryTransfer.mean) / perFrame) * 100).toFixed(2)
    + '% of a frame)');
  console.log();
  // Where the tail actually is. A p99 far from the median means some frames
  // cost thirty times what a frame costs, and which ones decides whether that
  // is fixable or inherent.
  if (slow.length > 0) {
    const byProtocol = new Map<string, { n: number; us: number }>();
    for (const f of slow) {
      const e = byProtocol.get(f.protocol) ?? { n: 0, us: 0 };
      e.n++; e.us += f.us;
      byProtocol.set(f.protocol, e);
    }
    console.log('frames over 200us      ' + slow.length + ' of ' + n
      + '  (' + ((slow.length / n) * 100).toFixed(2) + '%), '
      + (slow.reduce((a, f) => a + f.us, 0) / 1000).toFixed(0) + ' ms of '
      + ((dissect.mean * n) / 1000).toFixed(0) + ' ms total dissection');
    console.log('  by protocol:');
    for (const [proto, e] of [...byProtocol.entries()].sort((a, b) => b[1].us - a[1].us).slice(0, 6)) {
      console.log('    ' + proto.padEnd(10) + String(e.n).padStart(6) + ' frames'
        + (e.us / 1000).toFixed(0).padStart(7) + ' ms'
        + (e.us / e.n).toFixed(0).padStart(8) + ' us each');
    }
    console.log('  slowest frames:');
    for (const f of [...slow].sort((a, b) => b.us - a.us).slice(0, 6)) {
      console.log('    ' + f.us.toFixed(0).padStart(7) + ' us  ' + f.protocol.padEnd(8)
        + String(f.len).padStart(6) + ' B  ' + f.info);
    }
    console.log();
  }

  console.log('sustained Worker ceiling   ~' + Math.round(1_000_000 / perFrame).toLocaleString() + ' frames/s');
  console.log('  (dissection alone        ~' + Math.round(1_000_000 / dissect.mean).toLocaleString() + ' frames/s)');
  console.log('\n(sink ' + sink + ')');
}

main();
