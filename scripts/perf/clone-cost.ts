/**
 * How much does the worker boundary cost?
 *
 * Phase 11 moves dissection into a Worker, and the only question that decides
 * its shape is what crossing the boundary costs relative to what it saves. If
 * a structured clone of a dissected frame is cheap next to dissecting it, the
 * Worker can post whole `Packet`s and every existing consumer keeps working
 * untouched. If it is not, the tree and the bytes have to stay behind and be
 * fetched per frame, which touches the detail view, export, follow-stream and
 * session persistence.
 *
 *   npx tsx scripts/perf/clone-cost.ts
 *
 * Measured on the real fixtures, not on synthetic packets: the tree's size is
 * the whole point, and a made-up packet has whatever tree the maker felt like.
 */
import { readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';
const N = 20000;

function bytesOf(p: Packet): number {
  // Rough resident size: the raw frame plus a walk of the tree's strings.
  let n = p.rawBytes.byteLength;
  const visit = (fields: any[]) => {
    for (const f of fields) {
      n += (f.name?.length ?? 0) * 2 + String(f.value ?? '').length * 2 + 64;
      if (f.children) visit(f.children);
    }
  };
  for (const l of p.layers) { n += l.name.length * 2 + l.summary.length * 2 + 64; visit(l.fields); }
  return n;
}

async function main() {
  const buf = readFileSync(FIXTURE);
  const file = new File([new Uint8Array(buf)], 'fixture.pcap');

  const t0 = performance.now();
  const result = await PcapService.parseCaptureFile(file, N);
  const dissectMs = performance.now() - t0;
  const packets = result.packets.slice(0, N);

  const treeBytes = packets.reduce((a, p) => a + bytesOf(p), 0);
  const rawBytes = packets.reduce((a, p) => a + p.rawBytes.byteLength, 0);

  // Clone in batches the size of one flush, which is how it will actually happen.
  const BATCH = 500;
  const batches: Packet[][] = [];
  for (let i = 0; i < packets.length; i += BATCH) batches.push(packets.slice(i, i + BATCH));

  const t1 = performance.now();
  let sink = 0;
  for (const batch of batches) sink += (structuredClone(batch) as Packet[]).length;
  const cloneFullMs = performance.now() - t1;

  // The same batches with the tree left behind but the bytes still riding
  // along - which is what keeps export, follow-stream, the hex view and
  // session persistence working unchanged on the main thread.
  const noTree = batches.map((b) => b.map((p) => ({ ...p, layers: [] })));
  const t2 = performance.now();
  for (const batch of noTree) sink += (structuredClone(batch) as Packet[]).length;
  const cloneNoTreeMs = performance.now() - t2;

  // And with neither, for reference.
  const slim = batches.map((b) => b.map((p) => ({ ...p, layers: [], rawBytes: new Uint8Array(0) })));
  const t3 = performance.now();
  for (const batch of slim) sink += (structuredClone(batch) as Packet[]).length;
  const cloneSlimMs = performance.now() - t3;

  const per = (ms: number) => (ms / packets.length * 1000).toFixed(2);
  console.log(`frames                 ${packets.length}`);
  console.log(`raw frame bytes        ${(rawBytes / 1e6).toFixed(1)} MB`);
  console.log(`raw + tree (est)       ${(treeBytes / 1e6).toFixed(1)} MB  (${(treeBytes / packets.length).toFixed(0)} B/frame)`);
  console.log();
  console.log(`dissect                ${dissectMs.toFixed(0)} ms   ${per(dissectMs)} us/frame   ${(packets.length / dissectMs * 1000).toFixed(0)} pkt/s`);
  console.log(`clone, whole Packet    ${cloneFullMs.toFixed(0)} ms   ${per(cloneFullMs)} us/frame   = ${(cloneFullMs / dissectMs * 100).toFixed(1)}% of dissect`);
  console.log(`clone, no tree         ${cloneNoTreeMs.toFixed(0)} ms   ${per(cloneNoTreeMs)} us/frame   = ${(cloneNoTreeMs / dissectMs * 100).toFixed(1)}% of dissect`);
  console.log(`clone, no tree/bytes   ${cloneSlimMs.toFixed(0)} ms   ${per(cloneSlimMs)} us/frame   = ${(cloneSlimMs / dissectMs * 100).toFixed(1)}% of dissect`);
  console.log(`\n(sink ${sink})`);
}

main();
