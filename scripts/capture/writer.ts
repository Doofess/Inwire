/**
 * The capture writer: bytes at once, rows behind a patch horizon.
 *
 *   npx tsx scripts/capture/writer.ts
 *
 * This holds the fix for the defect both plan reviewers found independently and
 * called the biggest hole in the design: **write-through assumes a row is final
 * when the frame arrives, and it is not.** Four mechanisms amend an
 * already-emitted frame - `[TCP PDU reassembled in N]`, `[Reassembled in N]`,
 * `dns.response_in` and ICMP `(reply in N)` - and `dissect/types.ts` says why
 * they must: *"Single-pass dissection cannot see the future, so the frame that
 * learns the fact hands it back and the caller patches the list."*
 *
 * A row written the instant it was dissected loses every one of those, and it
 * loses them **silently** - the frame is still there, still says something
 * plausible, and just never mentions the segment it was reassembled into.
 *
 * So the checks below are of three kinds:
 *
 *  1. A patch reaching back across thousands of frames must land in the row
 *     that is eventually written, not merely in the copy held in RAM.
 *  2. A patch that arrives past the horizon must be **counted**, never
 *     silently dropped - a sealed chunk cannot be rewritten without breaking
 *     the append-only property the recovery rule depends on.
 *  3. And the horizon has to be long enough in practice, which is a
 *     measurement rather than an opinion: the last section dissects both
 *     fixtures with the real trackers and reports how far real patches
 *     actually reach.
 */
import { existsSync, readFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { deflateRawSync } from 'node:zlib';
import { CaptureWriter, type CaptureFiles } from '../../src/services/capture/captureWriter';
import { MemoryBlockFile, readExact } from '../../src/services/capture/blockFile';
import { CaptureIndex, recoverIndex } from '../../src/services/capture/captureIndex';
import { decodeChunk, applyPrefixes, CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import {
  PcapService, decodeRawEthernetPacket, applyInfoPatchesInPlace, type InfoPatch,
} from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
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
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

function files(): CaptureFiles & { all: MemoryBlockFile[] } {
  const index = new MemoryBlockFile();
  const pfx = new MemoryBlockFile();
  const sum = new MemoryBlockFile();
  const byt = new MemoryBlockFile();
  return { index, pfx, sum, byt, all: [index, pfx, sum, byt] };
}

/**
 * Reads a capture back the way a reader will: index, then chunk by chunk.
 *
 * Uses `node:zlib` to inflate what `fflate` deflated, which is a check in
 * itself - the two must agree on raw DEFLATE or the browser will not be able
 * to read what a test wrote.
 */
function readAll(f: CaptureFiles): Packet[] {
  const indexBytes = new Uint8Array(f.index.size());
  f.index.read(0, indexBytes);
  const index = CaptureIndex.parse(indexBytes);
  const out: Packet[] = [];
  for (let c = 0; c < index.chunkCount; c++) {
    const r = index.record(c);
    const summary = inflateRawSync(readExact(f.sum, r.sumOffset, r.sumLength));
    const prefix = inflateRawSync(readExact(f.pfx, r.pfxOffset, r.pfxLength));
    const packets = decodeChunk(new Uint8Array(summary));
    applyPrefixes(packets, new Uint8Array(prefix));
    out.push(...packets);
  }
  return out;
}

function frame(id: number, over: Partial<Packet> = {}): Packet {
  return {
    id,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: `frame ${id}`,
    status: 'ok',
    length: 100,
    tsUs: 1_000_000_000 + id * 1000,      // a frame every millisecond
    relativeTime: id / 1000,
    timeDelta: 0.001,
    interfaceName: 'eth0',
    layers: [],
    rawBytes: new Uint8Array(20).fill(id & 0xff),
    ...over,
  } as Packet;
}

console.log('--- bytes go down at once, rows wait ---\n');

{
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.append([frame(1), frame(2), frame(3)]);
  check('the frame bytes are on disk immediately', f.byt.size(), 60);
  check('...but no chunk has been sealed', f.pfx.size(), 0);
  check('...and the rows are staged', writer.stagedCount, 3);
  writer.finish();
  check('finish seals the partial tail', writer.stats.chunksWritten, 1);
  const back = readAll(f);
  check('and the frames read back', back.map((p) => p.id), [1, 2, 3]);
  check('...with their info', back.map((p) => p.info), ['frame 1', 'frame 2', 'frame 3']);
}

console.log('\n--- the patch horizon, which is the point ---\n');

{
  // A patch reaching back 3,000 frames - well inside a chunk boundary, and
  // exactly the reach a TLS record spanning a stalled stream produces.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 2_000_000, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= 4000; i++) batch.push(frame(i));
  writer.append(batch);
  // The leading space belongs to the suffix, not to the concatenation:
  // `applyInfoPatch` does `packet.info += patch.suffix` and every real producer
  // writes ` [Reassembled in N]` with the space already in it.
  writer.applyPatches([{ frameId: 1000, suffix: ' [TCP PDU reassembled in 4000]' }]);
  writer.finish();

  const back = readAll(f);
  check('the patched row is the one that was written',
    back.find((p) => p.id === 1000)?.info, 'frame 1000 [TCP PDU reassembled in 4000]');
  check('...and nothing else was touched',
    back.find((p) => p.id === 999)?.info, 'frame 999');
  check('the patch was counted as applied',
    [writer.stats.patchesApplied, writer.stats.patchesMissed], [1, 0]);
}

{
  // A protocolLabel patch - the ClientHello relabelled once the ServerHello
  // says which version was negotiated. A different field, same mechanism.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.append([frame(1, { protocolLabel: 'TLS' }), frame(2)]);
  writer.applyPatches([{ frameId: 1, protocolLabel: 'TLSv1.3' }]);
  writer.finish();
  check('a relabelled frame is written with its new label',
    readAll(f).find((p) => p.id === 1)?.protocolLabel, 'TLSv1.3');
}

{
  // The DNS case, which is a FIELD and not an Info suffix - Wireshark shows it
  // in the tree only, so a codec that carried Info but not the field would
  // pass the check above and still lose this.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.append([frame(1, { fields: { 'dns.id': 1 } }), frame(2)]);
  writer.applyPatches([{ frameId: 1, responseInFrame: 2 }]);
  writer.finish();
  const query = readAll(f).find((p) => p.id === 1);
  checkTrue('a dns.response_in patch survives to disk',
    query?.fields?.['dns.response_in'] === 2);
}

{
  // Past the horizon. A sealed chunk is deflated and its offsets are recorded;
  // rewriting it would break the append-only property recovery depends on. So
  // the patch is COUNTED, and kept for the overlay journal - never dropped.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, flushEveryChunks: 1, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 2; i++) batch.push(frame(i));
  writer.append(batch);
  check('with a zero horizon, whole chunks seal as they fill', writer.stats.chunksWritten, 2);
  writer.applyPatches([{ frameId: 5, suffix: ' TOO LATE' }]);
  check('a patch past the horizon is counted, not silently lost',
    [writer.stats.patchesApplied, writer.stats.patchesMissed], [0, 1]);
  check('...and is kept for the overlay journal',
    writer.missedPatches.map((p) => p.frameId), [5]);
  writer.finish();
  check('the row on disk is unpatched, which is why the journal exists',
    readAll(f).find((p) => p.id === 5)?.info, 'frame 5');
}

{
  // The frame-count bound. A quiet adapter produces frames minutes apart, and
  // without it the ring would hold them until the capture stopped.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 60_000_000, horizonFrames: CHUNK_FRAMES,
    deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 3; i++) batch.push(frame(i));
  writer.append(batch);
  checkTrue('the frame bound forces rows out even when time has not passed',
    writer.stats.chunksWritten >= 2);
  checkTrue('...and the ring stays bounded',
    writer.stagedCount <= CHUNK_FRAMES * 2);
}

console.log('\n--- the write path itself ---\n');

{
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, flushEveryChunks: 8, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 8; i++) batch.push(frame(i));
  writer.append(batch);
  // Flushing per batch is what starves the socket handler; the point of the
  // policy is that it happens rarely.
  check('eight chunks cost one flush, not eight', writer.stats.flushes, 1);
  writer.finish();
  checkTrue('finish flushes whatever is left', writer.stats.flushes >= 2);

  const indexBytes = new Uint8Array(f.index.size());
  f.index.read(0, indexBytes);
  const index = CaptureIndex.parse(indexBytes);
  check('every frame is accounted for in the index', index.frameCount, CHUNK_FRAMES * 8);
  check('ordinals run without gaps',
    [index.record(0).firstOrdinal, index.record(1).firstOrdinal, index.record(7).firstOrdinal],
    [0, CHUNK_FRAMES, CHUNK_FRAMES * 7]);

  // Bytes were written before the rows, so this is the property that says the
  // early write did not lose track of them.
  let contiguous = true;
  for (let c = 1; c < index.chunkCount; c++) {
    const prev = index.record(c - 1);
    if (index.record(c).bytOffset !== prev.bytOffset + prev.bytLength) contiguous = false;
  }
  checkTrue('each chunk\'s byte extent follows the one before it exactly', contiguous);
}

{
  // A crash between the data write and the index record - the one
  // inconsistency the write order permits.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 3; i++) batch.push(frame(i));
  writer.append(batch);
  writer.finish();

  const before = readAll(f).length;
  f.byt.truncate(f.byt.size() - 1);
  const { records, plan } = recoverIndex(f.index, f.pfx, f.sum, f.byt);
  check('a torn tail is detected', plan.keepRecords, records.length - 1);
  f.index.truncate(plan.indexLength);
  f.pfx.truncate(plan.pfxLength);
  f.sum.truncate(plan.sumLength);
  f.byt.truncate(plan.bytLength);
  const after = readAll(f).length;
  check('recovery costs exactly the torn chunk and nothing else',
    before - after, CHUNK_FRAMES);
}

console.log('\n--- against real frames, and how far patches really reach ---\n');

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

async function realCaptures(): Promise<void> {
  for (const [name, path] of Object.entries(FIXTURES)) {
    if (!existsSync(path)) {
      console.log(`SKIP  ${name}: ${path} not present (test/fixtures/README.md)`);
      continue;
    }
    const buf = readFileSync(path);
    // The RAW loop, not `parseCaptureFile` alone: that one applies patches
    // internally and hands back finished packets, which is exactly the
    // information this section needs to see BEFORE it is applied. So the file
    // is parsed once for its frames' bytes and times, then re-dissected here
    // against fresh trackers - the same shape `scripts/perf/throughput.ts`
    // uses, and for the same reason.
    const parsed = await PcapService.parseCaptureFile(
      new File([new Uint8Array(buf)], 'fixture.pcap'), Number.POSITIVE_INFINITY,
    );
    const extracted = {
      frames: parsed.packets.map((p) => ({ bytes: p.rawBytes, tsUs: p.tsUs, origLen: p.length })),
    };
    const tcp = new TcpStreamTracker();
    const icmp = new IcmpEchoTracker();
    const quic = new QuicFlowTracker();
    const dns = new DnsTracker();
    const l3 = new L3Tracker();

    const packets: Packet[] = [];
    const patches: InfoPatch[] = [];
    const tsById = new Map<number, number>();
    let id = 0;
    let startUs: number | null = null;
    let lastUs: number | null = null;
    for (const f of extracted.frames) {
      if (startUs === null) startUs = f.tsUs;
      const relativeTime = (f.tsUs - startUs) / 1e6;
      const timeDelta = lastUs === null ? 0 : Math.max(0, (f.tsUs - lastUs) / 1e6);
      lastUs = f.tsUs;
      id += 1;
      const decoded = decodeRawEthernetPacket(
        f.bytes, id, f.tsUs, relativeTime, timeDelta, f.origLen,
        tcp, icmp, quic, dns, undefined, undefined, l3,
      );
      packets.push(decoded.packet);
      tsById.set(id, f.tsUs);
      if (decoded.infoPatches) for (const p of decoded.infoPatches) patches.push({ ...p, _at: id } as InfoPatch);
    }

    // How far back do real patches reach? This is what sizes the horizon, and
    // it is the number the design was guessing at.
    let maxFrames = 0, maxUs = 0;
    for (const p of patches) {
      const at = (p as InfoPatch & { _at: number })._at;
      const reachFrames = at - p.frameId;
      const reachUs = (tsById.get(at) ?? 0) - (tsById.get(p.frameId) ?? 0);
      if (reachFrames > maxFrames) maxFrames = reachFrames;
      if (reachUs > maxUs) maxUs = reachUs;
    }
    console.log(`      ${name}: ${patches.length.toLocaleString()} patches;`
      + ` furthest reach ${maxFrames.toLocaleString()} frames / ${(maxUs / 1000).toFixed(0)} ms`);

    // The whole path, at the default horizon, **interleaved the way the flush
    // actually runs**. Appending all 14,782 frames and then applying every
    // patch is not a simulation of anything: the time bound seals chunks
    // during the append, so every patch arrives after its target has gone. It
    // reported 4,791 misses, which measured the test rather than the writer.
    // The real cadence is one batch per 100 ms flush, carrying the patches the
    // frames in it produced.
    const f2 = files();
    const writer = new CaptureWriter(f2, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
    const BATCH = 100;
    for (let start = 0; start < packets.length; start += BATCH) {
      const slice = packets.slice(start, start + BATCH);
      writer.append(slice);
      const lastId = slice[slice.length - 1].id;
      const firstId = slice[0].id;
      writer.applyPatches(
        patches.filter((pt) => {
          const at = (pt as InfoPatch & { _at: number })._at;
          return at >= firstId && at <= lastId;
        }),
      );
    }
    writer.finish();

    check(`${name}: the default horizon loses no patch`, writer.stats.patchesMissed, 0);
    check(`${name}: every frame was written`, writer.stats.framesWritten, packets.length);

    const back = readAll(f2);
    check(`${name}: the same number reads back`, back.length, packets.length);

    // Compared against the buffer AFTER its patches, which is the whole point:
    // the disk copy must equal what the in-RAM list holds once the frames that
    // learned something later have handed it back. Comparing against the raw
    // dissection would be comparing the disk to something less correct than
    // itself - the first run of this did exactly that and reported 5,590
    // "mismatches" that were the written rows being right.
    const expected = packets.map((pk) => ({ ...pk }));
    applyInfoPatchesInPlace(expected, patches);

    let mismatched = 0;
    let firstBad: { id: number; want: string; got: string } | null = null;
    for (let i = 0; i < back.length; i++) {
      if (back[i].id !== expected[i].id || back[i].info !== expected[i].info) {
        mismatched += 1;
        if (firstBad === null) {
          firstBad = { id: expected[i].id, want: expected[i].info, got: back[i].info };
        }
      }
    }
    check(`${name}: every id and Info survives the whole write path`, mismatched, 0);
    if (firstBad !== null) {
      console.log(`        first at frame ${firstBad.id}`);
      console.log(`        want ${JSON.stringify(firstBad.want)}`);
      console.log(`        got  ${JSON.stringify(firstBad.got)}`);
    }

    // The patched fields too, not only Info - dns.response_in is a field and
    // would slip past an Info-only comparison.
    let fieldMismatch = 0;
    for (let i = 0; i < back.length; i++) {
      const want = expected[i].fields?.['dns.response_in'];
      const got = back[i].fields?.['dns.response_in'];
      if (want !== got) fieldMismatch += 1;
    }
    check(`${name}: dns.response_in survives too`, fieldMismatch, 0);

    const total = f2.pfx.size() + f2.sum.size() + f2.byt.size() + f2.index.size();
    console.log(`      ${name}: ${(total / packets.length).toFixed(0)} B/frame on disk`
      + ` (${(f2.byt.size() / packets.length).toFixed(0)} frame`
      + ` + ${((f2.pfx.size() + f2.sum.size() + f2.index.size()) / packets.length).toFixed(1)} summary)`);
  }
}

async function main(): Promise<void> {
  await realCaptures();
  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All capture writer checks passed.');
  process.exit(0);
}

void main();
