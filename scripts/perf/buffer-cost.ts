/**
 * What does the main thread's packet buffer cost, and how does that scale?
 *
 *   npx tsx scripts/perf/buffer-cost.ts
 *
 * This is the go/no-go gate for moving raw bytes off the main thread (the plan's
 * Item 3) and for raising the buffer cap towards a million frames (Item 4).
 * Both were argued from ADR 0007's table, which was measured at a 50,000 cap and
 * ~19 frames/s of ingest. Neither argument survives being restated at the target
 * without being re-measured, so this measures it.
 *
 * Three things, at a range of buffer sizes:
 *
 *   commit      what one 100 ms flush costs, which is the O(buffer) work in
 *               App.tsx's flush effect: `concat`, the ICMP reply `.map`, and
 *               `applyInfoPatches`. Two of those are conditional; the concat is
 *               not, so it runs ten times a second whatever else happens.
 *   resident    bytes held per frame, split into the raw frame and everything
 *               else, because Item 3 moves exactly one of those two.
 *   headroom    how much of a 100 ms flush budget the commit alone consumes.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService, applyInfoPatchesInPlace, type InfoPatch } from '../../src/services/pcapParser';
import { applyIcmpRepliesInPlace } from '../../src/services/sessionRestore';
import type { Packet } from '../../src/types/packet';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';

/** App.tsx's cadence and cap constants. */
const PACKET_FLUSH_MS = 100;
const TRIM_SLACK = 0.05;
/** One Worker flush's worth of frames at a few thousand a second. */
const INCOMING = 500;

const SIZES = [10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000];

/**
 * Measured with `node --expose-gc`, over the inwire fixture's 12,858 distinct
 * frames: the heap the parse added, divided by the frames it produced. Stated
 * as a constant because measuring it inside this script would need --expose-gc
 * to be reliable, and a number that silently degrades to garbage without a flag
 * is worse than one that says where it came from.
 */
const SUMMARY_BYTES_PER_FRAME = 2342;

function heapUsed(): number {
  return process.memoryUsage().heapUsed;
}

function trimToCap<T>(packets: T[], cap: number): T[] {
  const slack = Math.max(1, Math.floor(cap * TRIM_SLACK));
  return packets.length > cap + slack ? packets.slice(packets.length - cap) : packets;
}

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
    process.exit(0);
  }

  const buf = readFileSync(FIXTURE);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), 1_000_000,
  );
  const sample = parsed.packets;
  if (sample.length === 0) { console.log('SKIP  no frames'); process.exit(0); }

  // Resident cost per frame.
  //
  // This was measured by growing an array of `{...sample[i % sample.length]}`
  // and dividing the heap difference out, which reported 209 B a frame and was
  // wrong by an order of magnitude: a shallow copy shares every string, every
  // `fields` object and every array with the packet it came from, so it
  // measured the cost of an object header and nothing the object points at. A
  // real capture's frames each own theirs.
  //
  // Measured properly - the heap the parse itself added, over frames that are
  // all different - it is 2,342 B a frame, and `Packet.fields` alone is 1,174 B
  // of that. The raw frames do not appear in `heapUsed` at all: an ArrayBuffer's
  // backing store is external, which is also why relocating bytes to a Worker
  // does not reduce a tab's memory - a dedicated Worker shares the renderer
  // process, so it changes which heap holds them and not how much is held.
  const heapBefore = heapUsed();
  const held: Packet[] = [];
  for (let i = 0; i < sample.length; i++) held.push(sample[i]);
  const heapAfter = heapUsed();
  void heapBefore; void heapAfter;
  const perFrameSummary = SUMMARY_BYTES_PER_FRAME;
  const perFrameBytes = sample.reduce((a, p) => a + p.rawBytes.byteLength, 0) / sample.length;
  held.length = 0;

  console.log('per frame, resident on the main thread');
  console.log('  raw frame bytes      ' + perFrameBytes.toFixed(0) + ' B  (external, not in heapUsed)');
  console.log('  summary object       ' + perFrameSummary.toFixed(0) + ' B  (of which fields ~1174 B)');
  console.log('  -> at 1M frames      ' + ((perFrameSummary + perFrameBytes) * 1e6 / 1e9).toFixed(1)
    + ' GB, and the summaries are the larger half');
  console.log();
  console.log('one flush, by buffer size');
  console.log('  frames      concat   icmp       patches     total    % of ' + PACKET_FLUSH_MS + 'ms   bytes held');
  console.log('  ' + '-'.repeat(84));

  for (const size of SIZES) {
    // A buffer of `size` frames, then one flush's worth arriving.
    let buffer: Packet[] = new Array(size);
    for (let i = 0; i < size; i++) buffer[i] = sample[i % sample.length];
    const incoming: Packet[] = [];
    for (let i = 0; i < INCOMING; i++) incoming.push(sample[i % sample.length]);

    // 1. The concat. Unconditional: it runs on every flush regardless.
    let t = performance.now();
    let next = buffer.concat(incoming);
    const concatMs = performance.now() - t;

    // 2 and 3: the two patch passes, exactly as App.tsx's flush runs them -
    // written into the array the concat just produced, which the flush owns.
    // Both used to be a `.map` over the whole buffer.
    const replies = [{ requestFrameId: next[Math.floor(size / 2)].id, replyId: size + 1 }];
    t = performance.now();
    applyIcmpRepliesInPlace(next, replies);
    const icmpMs = performance.now() - t;

    t = performance.now();
    applyInfoPatchesInPlace(next, [
      { frameId: next[Math.floor(size / 2)].id, suffix: ' x' } as InfoPatch,
    ]);
    const patchMs = performance.now() - t;

    next = trimToCap(next, size);
    const total = concatMs + icmpMs + patchMs;
    const bytesHeld = (perFrameBytes + perFrameSummary) * size;

    console.log('  ' + String(size).padStart(9)
      + concatMs.toFixed(1).padStart(9) + 'ms'
      + icmpMs.toFixed(1).padStart(9) + 'ms'
      + patchMs.toFixed(1).padStart(8) + 'ms'
      + total.toFixed(1).padStart(8) + 'ms'
      + ((total / PACKET_FLUSH_MS) * 100).toFixed(0).padStart(10) + '%'
      + (bytesHeld / 1e6).toFixed(0).padStart(12) + ' MB');

    buffer = [];
    next = [];
  }

  console.log();
  console.log('Note: the concat is unconditional; the other two run only when a reply or a');
  console.log('patch is pending, which during live capture is most flushes.');
}

main();
