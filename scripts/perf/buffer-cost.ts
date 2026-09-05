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

  // Resident cost per frame, measured rather than assumed. The buffer holds
  // real Packet objects, so the sample is grown to a fixed size and the heap
  // difference divided out.
  const heapBefore = process.memoryUsage().heapUsed;
  const held: Packet[] = [];
  for (let i = 0; i < 200_000; i++) held.push({ ...sample[i % sample.length] });
  const heapAfter = process.memoryUsage().heapUsed;
  const perFrameSummary = (heapAfter - heapBefore) / held.length;
  const perFrameBytes = sample.reduce((a, p) => a + p.rawBytes.byteLength, 0) / sample.length;
  held.length = 0;

  console.log('per frame, resident on the main thread');
  console.log('  raw frame bytes      ' + perFrameBytes.toFixed(0) + ' B');
  console.log('  summary object (est) ' + perFrameSummary.toFixed(0) + ' B  (shallow copy; shares strings)');
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
