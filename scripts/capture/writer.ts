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
import {
  CaptureWriter, dataFilesOf, type CaptureFiles, type DataFiles, type SegmentFiles,
  type PackedRowIn, type WriterOptions, type WriterStats, type RawFrame,
} from '../../src/services/capture/captureWriter';
import { MemoryBlockFile, readExact, type BlockFile } from '../../src/services/capture/blockFile';
import { CaptureIndex, recoverIndex } from '../../src/services/capture/captureIndex';
import { decodeChunk, encodeChunk, applyPrefixes, CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { packRows, unpackRows, type RowPack } from '../../src/services/pipeline/rowPack';
import { applyOverlay, type RowOverlay } from '../../src/services/pipeline/rowOverlay';
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
  const rec = new MemoryBlockFile();
  return { index, pfx, sum, byt, rec, all: [index, pfx, sum, byt, rec] };
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
    const data = dataFilesOf(f, r.segment) ?? f;
    const summary = inflateRawSync(readExact(data.sum, r.sumOffset, r.sumLength));
    const prefix = inflateRawSync(readExact(data.pfx, r.pfxOffset, r.pfxLength));
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

  // And the writer that picks the capture up afterwards. This is what a
  // reopen does, and getting it wrong is not a crash: the ordinals would
  // restart at zero and the second chunk of the resumed capture would claim
  // to be the first chunk of the whole thing.
  const { records: survived } = recoverIndex(f.index, f.pfx, f.sum, f.byt);
  const resumed = new CaptureWriter(f, {
    horizonUs: 0, resumeFrom: survived, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  check('a resumed writer counts what is already there',
    [resumed.stats.framesWritten, resumed.stats.chunksWritten],
    [CHUNK_FRAMES * 2, 2]);
  resumed.append(Array.from({ length: 10 }, (_, i) => frame(CHUNK_FRAMES * 3 + i + 1)));
  resumed.finish();
  const grown = readAll(f);
  check('...and continues the capture rather than restarting it',
    grown.length, CHUNK_FRAMES * 2 + 10);
  check('...with ordinals that follow on', (() => {
    const bytes = new Uint8Array(f.index.size());
    f.index.read(0, bytes);
    const index = CaptureIndex.parse(bytes);
    return index.record(index.chunkCount - 1).firstOrdinal;
  })(), CHUNK_FRAMES * 2);
  check('...and the new frames readable at the end',
    [grown[grown.length - 1].id, grown[CHUNK_FRAMES * 2].id],
    [CHUNK_FRAMES * 3 + 10, CHUNK_FRAMES * 3 + 1]);
}

console.log('\n--- bytes and rows are two arrivals ---\n');

/** One frame as the capture path hands it over: no dissector has looked at it. */
const raw = (id: number, size = 20) => ({
  id,
  tsUs: 1_000_000_000 + id * 1000,
  bytes: new Uint8Array(size).fill(id & 0xff),
});

{
  // The property the split exists to buy: the capture path writes bytes and
  // does not wait for a dissector. Bytes only - no row attached at all.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.appendBytes([raw(1), raw(2), raw(3)]);
  check('bytes reach disk with no row at all', f.byt.size(), 60);
  check('...and a slot is staged for each', writer.stagedCount, 3);
  writer.finish();
  const back = readAll(f);
  check('every frame is still there', back.map((p) => p.id), [1, 2, 3]);
  // The frame is not lost - its bytes are exact and complete on disk. What is
  // degraded is the derived row, and it SAYS so rather than inventing a
  // plausible one, which would be a confident wrong answer about a frame
  // nobody dissected.
  checkTrue('...with a row that admits it was not dissected',
    back.every((p) => p.info.includes('Not dissected')));
  check('...counted, so the cost is visible', writer.stats.framesSealedWithoutRow, 3);
  // Never to be read as frames lost. Asserted because the status bar adds drop
  // counters together and this is emphatically not one of them.
  check('...and no frame was dropped', writer.stats.framesWritten, 3);
}

{
  // Rows catching up. The ordinary case: bytes lead by a flush interval.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  const ids = [1, 2, 3, 4];
  writer.appendBytes(ids.map((id) => raw(id)));
  writer.attachRows(ids.map((id) => frame(id)));
  check('rows attach to the slots their bytes made', writer.stats.rowsAttached, 4);
  check('...and none was missed', writer.stats.rowsMissed, 0);
  writer.finish();
  check('no placeholder was needed', writer.stats.framesSealedWithoutRow, 0);
  check('and the dissected rows are what came back',
    readAll(f).map((p) => p.info), ['frame 1', 'frame 2', 'frame 3', 'frame 4']);
}

{
  // **A row that overtakes its own bytes.** Two channels into one process have
  // no ordering guarantee between them. In practice bytes lead; "in practice"
  // is not a guarantee, and the failure it would produce is a silently missing
  // row rather than an error - so an early row is held and later claimed.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.attachRows([frame(1), frame(2)]);
  check('an early row is held rather than dropped', writer.stats.rowsMissed, 0);
  check('...and is attached to nothing yet', writer.stats.rowsAttached, 0);
  writer.appendBytes([raw(1), raw(2)]);
  writer.finish();
  check('...and is claimed when its bytes arrive', writer.stats.framesSealedWithoutRow, 0);
  check('the early rows are what came back',
    readAll(f).map((p) => p.info), ['frame 1', 'frame 2']);
}

{
  // A slow dissector must not stall the write path. Bytes for two whole chunks
  // with no rows at all, at a horizon of zero: the chunks seal on the SLOT's
  // timestamp, which exists whether or not a row does. Before the split the
  // ageing test read `packet.tsUs`, so a chunk with no rows could never age out
  // and the capture path stalled behind the dissector - the coupling removed.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch = [];
  for (let id = 1; id <= CHUNK_FRAMES * 2; id++) batch.push(raw(id));
  writer.appendBytes(batch);
  check('chunks seal with no rows attached at all', writer.stats.chunksWritten, 2);
  check('...leaving nothing staged behind them', writer.stagedCount, 0);
}

{
  // A row arriving after its slot was sealed cannot be written - a sealed chunk
  // is deflated and appended, and rewriting it would undo the append-only
  // property recovery depends on. Counted, never silent.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch = [];
  for (let id = 1; id <= CHUNK_FRAMES; id++) batch.push(raw(id));
  writer.appendBytes(batch);
  check('the chunk sealed without its rows', writer.stats.chunksWritten, 1);
  writer.attachRows([frame(1)]);
  check('a row for a sealed slot is counted as missed', writer.stats.rowsMissed, 1);
  check('...and attaches to nothing', writer.stats.rowsAttached, 0);
}

{
  // Contiguity, which `sealChunk` checks rather than assumes. Bytes arriving
  // without rows must still produce a chunk whose byte extent equals the sum of
  // its frames' lengths - otherwise every byte read in it slices the wrong
  // frame, silently. Variable lengths, so a mismatch cannot cancel out.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  let expected = 0;
  const batch = [];
  for (let id = 1; id <= CHUNK_FRAMES; id++) {
    const size = 20 + (id % 37);
    expected += size;
    batch.push(raw(id, size));
  }
  writer.appendBytes(batch);
  writer.finish();
  const index = new CaptureIndex(recoverIndex(f.index, f.pfx, f.sum, f.byt).records);
  check('the sealed chunk covers exactly the bytes appended',
    index.record(0).bytLength, expected);
  check('...starting at the first frame', index.record(0).bytOffset, 0);
}

{
  // **A batch's bytes are one write, not one a frame.** A `writeSync` per frame
  // was a quarter of the store's thread at 60k frames a second (ADR 0053 phase
  // 6, `scripts/perf/store-boundary.ts`). The bytes, and where each frame says
  // its bytes are, must be exactly what writing them one at a time produced.
  class CountingFile extends MemoryBlockFile {
    writes = 0;
    override write(offset: number, from: Uint8Array): void {
      this.writes++;
      super.write(offset, from);
    }
  }
  const byt = new CountingFile();
  const f = { ...files(), byt };
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  const batch = [];
  for (let id = 1; id <= 50; id++) batch.push(raw(id, 20 + (id % 7)));
  writer.appendBytes(batch);
  check('a batch of frames is one write to frames.iwbyt', byt.writes, 1);
  let at = 0;
  const placed = batch.every((frame) => {
    const back = readExact(byt, at, frame.bytes.length);
    at += frame.bytes.length;
    return back.every((v, i) => v === frame.bytes[i]);
  });
  checkTrue('...holding every frame\'s bytes, in order, end to end', placed && at === byt.size());
  writer.appendBytes([raw(51), raw(52)]);
  check('...and the next batch appends after it', byt.size(), at + 40);
  writer.finish();
  const index = new CaptureIndex(recoverIndex(f.index, f.pfx, f.sum, f.byt).records);
  check('the chunk covers both batches', index.record(0).bytLength, at + 40);
}

{
  // `append` still does both in one call, because the import path has bytes and
  // rows at the same moment and has no reason to split them. It must stage and
  // attach BEFORE draining: draining first seals the whole batch as
  // placeholders at a short horizon, which is the bug this split shipped with
  // for one run.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES; i++) batch.push(frame(i));
  writer.append(batch);
  check('append seals its own rows, not placeholders', writer.stats.framesSealedWithoutRow, 0);
  check('...attaching every one', writer.stats.rowsAttached, CHUNK_FRAMES);
  check('...and the rows are what reached disk',
    readAll(f).find((p) => p.id === 7)?.info, 'frame 7');
}

{
  // **The writer decides whether bytes are already down, and that is what
  // keeps the app out of it.** A live capture sends bytes first from the
  // Worker; an import sends both at once; a build with no ingest port sends
  // only `append`. All three go through `append`, and writing a frame's bytes
  // twice would append a second copy nothing indexes - breaking the contiguity
  // check for every chunk after it.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.appendBytes([raw(1), raw(2)]);
  check('bytes are down once', f.byt.size(), 40);
  writer.append([frame(1), frame(2)]);
  check('...and append does not write them again', f.byt.size(), 40);
  check('...it attaches the rows instead', writer.stats.rowsAttached, 2);
  writer.finish();
  check('no placeholder was needed', writer.stats.framesSealedWithoutRow, 0);
  check('and the rows are the dissected ones',
    readAll(f).map((p) => p.info), ['frame 1', 'frame 2']);
}

{
  // A frame whose bytes were already SEALED must not be re-written either -
  // `stagedAt` no longer holds it, so only the high-water id can say.
  const f = files();
  const writer = new CaptureWriter(f, {
    horizonUs: 0, deflate: (b) => new Uint8Array(deflateRawSync(b)),
  });
  const batch = [];
  for (let id = 1; id <= CHUNK_FRAMES; id++) batch.push(raw(id));
  writer.appendBytes(batch);
  const sealedBytes = f.byt.size();
  writer.append([frame(1)]);
  check('a sealed frame does not get a second copy of its bytes',
    f.byt.size(), sealedBytes);
  check('...and its late row is counted as missed', writer.stats.rowsMissed, 1);
}

{
  // The degraded path: no ingest port at all, so `append` is the only message.
  // This is what a build with an older preload does, and it must behave exactly
  // as it did before the split.
  const f = files();
  const writer = new CaptureWriter(f, { deflate: (b) => new Uint8Array(deflateRawSync(b)) });
  writer.append([frame(1), frame(2), frame(3)]);
  check('with no bytes sent ahead, append writes them', f.byt.size(), 60);
  writer.finish();
  check('...with no placeholders', writer.stats.framesSealedWithoutRow, 0);
  check('...and the rows intact', readAll(f).map((p) => p.id), [1, 2, 3]);
}

console.log('\n--- shard rows staged as packed slots (ADR 0053 phase 6) ---\n');

/**
 * Structural equality, written out because the usual shortcuts both lie here:
 * `JSON.stringify` throws on a bigint and drops a key whose value is undefined,
 * and a key that is present but undefined is exactly the bug an overlay that
 * clears `expert` or `tsNanos` must not cause.
 */
function firstDifference(a: unknown, b: unknown, path = ''): string | null {
  if (typeof a === 'bigint' || typeof b === 'bigint') return a === b ? null : `${path}: bigint ${String(a)} vs ${String(b)}`;
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    if (!(a instanceof Uint8Array && b instanceof Uint8Array)) return `${path}: bytes vs not bytes`;
    if (a.length !== b.length) return `${path}: ${a.length} bytes vs ${b.length}`;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return `${path}[${i}]: byte differs`;
    return null;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return `${path}: array vs not an array`;
    if (a.length !== b.length) return `${path}: length ${a.length} vs ${b.length}`;
    for (let i = 0; i < a.length; i++) {
      const d = firstDifference(a[i], b[i], `${path}[${i}]`);
      if (d !== null) return d;
    }
    return null;
  }
  if (a !== null && b !== null && typeof a === 'object' && typeof b === 'object') {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    if (ka.join('\u0000') !== kb.join('\u0000')) {
      const only = ka.filter((k) => !kb.includes(k)).concat(kb.filter((k) => !ka.includes(k)));
      return `${path}: keys differ (${only.join(', ')})`;
    }
    for (const k of ka) {
      const d = firstDifference((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`);
      if (d !== null) return d;
    }
    return null;
  }
  return a === b || (Number.isNaN(a) && Number.isNaN(b)) ? null : `${path}: ${String(a)} vs ${String(b)}`;
}

{
  check('the comparison sees a key that is present but undefined', firstDifference({ a: undefined }, {}) !== null, true);
  check('...a bigint that differs', firstDifference({ a: 1n }, { a: 2n }) !== null, true);
  check('...a byte that differs', firstDifference(new Uint8Array([1]), new Uint8Array([2])) !== null, true);
  check('...and calls equal things equal',
    firstDifference({ a: [1n, 'x', new Uint8Array([3])] }, { a: [1n, 'x', new Uint8Array([3])] }), null);
}

const DEFLATE = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b));
const range = (from: number, to: number): number[] => Array.from({ length: to - from + 1 }, (_, i) => from + i);
const oddsTo = (n: number): number[] => range(1, n).filter((i) => i % 2 === 1);
const evensTo = (n: number): number[] => range(1, n).filter((i) => i % 2 === 0);
const bytesOf = (id: number): Uint8Array => new Uint8Array(20).fill(id & 0xff);

/** A row as a shard packs it, with a different shape for each residue so the codec's branches are on the path. */
function shardRow(id: number): Packet {
  return frame(id, {
    info: `Seq=${id} Len=${id % 5}`,
    ...(id % 5 === 0 ? { protocolLabel: 'TLSv1.3' } : {}),
    fields: { 'tcp.srcport': 40_000 + (id % 9), 'tcp.seq': id, ...(id % 4 === 0 ? { 'dns.id': id } : {}) },
    ...(id % 3 === 0 ? { expert: [{ message: 'Possible loss', category: 'Loss' as const }] } : {}),
    ...(id % 4 === 0 ? { tsNanos: BigInt(1_000_000_000 + id * 1000) * 1000n + BigInt(id % 1000), tsPrecision: 9 } : {}),
  });
}

/** What the merge wrote to a row afterwards, including the members that clear a key. */
function overlayFor(id: number): RowOverlay | null {
  if (id % 7 === 0) return { fields: { 'tls.stream': id } };
  if (id % 11 === 0) return { tsNanos: BigInt(id) * 1000n + 17n, tsPrecision: 9 };
  if (id % 13 === 0) return { expert: undefined, tsNanos: undefined };
  return null;
}

/**
 * The same frames two ways: as slots into packs, and as the plain rows an
 * independent decode of those packs gives. The second is the oracle - what the
 * object path is handed today.
 */
function buildWorld(groups: readonly (readonly number[])[]) {
  const placed = new Map<number, { pack: RowPack; index: number }>();
  const decoded = new Map<RowPack, Packet[]>();
  groups.forEach((ids, g) => {
    const rows = ids.map(shardRow);
    const pack = packRows(g + 1, rows, rows.map(() => 20));
    ids.forEach((id, index) => placed.set(id, { pack, index }));
  });
  return {
    packed(id: number, carry: boolean): Packet | PackedRowIn {
      const at = placed.get(id);
      if (at === undefined) return frame(id);
      return {
        pack: at.pack, index: at.index, overlay: overlayFor(id), id,
        ...(carry ? { rawBytes: bytesOf(id) } : {}),
      };
    },
    object(id: number, carry: boolean): Packet {
      const at = placed.get(id);
      if (at === undefined) return frame(id);
      let rows = decoded.get(at.pack);
      if (rows === undefined) { rows = unpackRows(at.pack); decoded.set(at.pack, rows); }
      const row = { ...rows[at.index] };
      const overlay = overlayFor(id);
      if (overlay !== null) {
        if (overlay.fields && row.fields) row.fields = { ...row.fields };
        applyOverlay(row, overlay);
        if ('expert' in overlay && row.expert === undefined) delete row.expert;
        if ('tsPrecision' in overlay && row.tsPrecision === undefined) delete row.tsPrecision;
        if ('tsNanos' in overlay && row.tsNanos === undefined) delete row.tsNanos;
      }
      if (carry) row.rawBytes = bytesOf(id);
      return row;
    },
  };
}

/** In-memory segment directories, for the cases that cut a chunk at a ring file. */
function memorySegments(): SegmentFiles {
  const open = new Map<number, DataFiles>();
  const make = (): DataFiles => ({
    pfx: new MemoryBlockFile(), sum: new MemoryBlockFile(), byt: new MemoryBlockFile(), rec: new MemoryBlockFile(),
  });
  return {
    open(n) {
      let d = open.get(n);
      if (d === undefined) { d = make(); open.set(n, d); }
      return d;
    },
    find: (n) => open.get(n) ?? null,
    remove(n) { open.delete(n); },
    list: () => [...open.keys()].sort((a, b) => a - b),
  };
}

interface Ctx {
  w: CaptureWriter;
  /** Frame `id` as a row the writer is handed: a pack slot, or its plain-row twin. */
  slot(id: number, carry?: boolean): Packet | PackedRowIn;
  raws(from: number, to: number, ring?: (id: number) => RawFrame['ring']): RawFrame[];
  /** Records what `stagedFrame` answers now. */
  observe(id: number): void;
  /** Records the counters and the staged count now. */
  snapshot(): void;
}

interface Scenario {
  name: string;
  /** Each is one shard pack's ids, ascending. Frames in none are plain rows. */
  groups: number[][];
  options?: WriterOptions;
  rings?: boolean;
  drive(ctx: Ctx): void;
  /** Checks on the pack-native run, against numbers worked out by hand. */
  expect?(native: Outcome): void;
}

interface Outcome {
  rows: Packet[];
  stats: WriterStats;
  missed: InfoPatch[];
  observed: unknown[];
  layout: Record<string, number>[];
  pfx: Uint8Array[];
  byt: Uint8Array[];
  sum: Uint8Array[];
  versions: number[];
}

type Variant = 'native' | 'decoded' | 'objects';

function allBytes(file: BlockFile): Uint8Array { return readExact(file, 0, file.size()); }

function run(sc: Scenario, variant: Variant): Outcome {
  const world = buildWorld(sc.groups);
  const f: CaptureFiles = { ...files(), ...(sc.rings ? { segments: memorySegments() } : {}) };
  const w = new CaptureWriter(f, { deflate: DEFLATE, ...sc.options, packNative: variant !== 'decoded' });
  const observed: unknown[] = [];
  sc.drive({
    w,
    slot: (id, carry = false) => (variant === 'objects' ? world.object(id, carry) : world.packed(id, carry)),
    raws: (from, to, ring) => range(from, to).map((id) => ({ ...raw(id), ...(ring ? { ring: ring(id) } : {}) })),
    // Without `rawBytes`: a plain row that carried its bytes still holds them,
    // and a packed one never does - the bytes are on disk, and `stagedFrame`
    // answers them as `bytes`.
    observe: (id) => {
      const packet = w.stagedFrame(id)?.packet;
      if (packet === undefined || packet === null) { observed.push(null); return; }
      const { rawBytes: _bytes, ...rest } = packet;
      observed.push(rest);
    },
    snapshot: () => { observed.push({ ...w.stats, staged: w.stagedCount }); },
  });
  w.finish();

  const indexBytes = new Uint8Array(f.index.size());
  f.index.read(0, indexBytes);
  const index = CaptureIndex.parse(indexBytes);
  const layout: Record<string, number>[] = [];
  const versions: number[] = [];
  const sum: Uint8Array[] = [];
  for (let c = 0; c < index.chunkCount; c++) {
    const r = index.record(c);
    const data = dataFilesOf(f, r.segment) ?? f;
    layout.push({
      firstId: r.firstId, lastId: r.lastId, frameCount: r.frameCount, firstOrdinal: r.firstOrdinal,
      pfxOffset: r.pfxOffset, pfxLength: r.pfxLength, bytOffset: r.bytOffset, bytLength: r.bytLength,
      firstTsUs: r.firstTsUs, segment: r.segment,
    });
    sum.push(readExact(data.sum, r.sumOffset, r.sumLength));
    const inflated = inflateRawSync(sum[c]);
    versions.push(inflated[4] | (inflated[5] << 8));
  }
  const datas: DataFiles[] = [f, ...(f.segments?.list() ?? []).map((n) => f.segments!.find(n)!)];
  return {
    rows: readAll(f), stats: { ...w.stats }, missed: [...w.missedPatches], observed, layout, sum, versions,
    pfx: datas.map((d) => allBytes(d.pfx)), byt: datas.map((d) => allBytes(d.byt)),
  };
}

function sameOutcome(name: string, a: Outcome, b: Outcome): void {
  const parts: [string, unknown, unknown][] = [
    ['rows', a.rows, b.rows], ['counters', a.stats, b.stats], ['missed patches', a.missed, b.missed],
    ['staged answers', a.observed, b.observed], ['index records', a.layout, b.layout],
    ['prefix files', a.pfx, b.pfx], ['byte files', a.byt, b.byt],
  ];
  let first: string | null = null;
  for (const [label, x, y] of parts) {
    first = firstDifference(x, y, label);
    if (first !== null) break;
  }
  check(name, first, null);
}

/** Runs a scenario three ways: pack-native, decoded at seal, and as plain rows. */
function scenario(sc: Scenario): Outcome {
  const native = run(sc, 'native');
  const decoded = run(sc, 'decoded');
  const objects = run(sc, 'objects');
  sameOutcome(`${sc.name}: pack-native chunks read back what plain rows wrote`, native, objects);
  sameOutcome(`${sc.name}: ...and so do rows decoded at seal (packNative off)`, decoded, objects);
  check(`${sc.name}: only the pack-native run wrote a version 3 chunk, and only for packed rows`,
    [native.versions.some((v) => v === 3), [...decoded.versions, ...objects.versions].every((v) => v === 2)],
    [sc.groups.length > 0, true]);
  sc.expect?.(native);
  return native;
}

const infoOf = (o: Outcome, id: number): string | undefined => o.rows.find((p) => p.id === id)?.info;
const pair = (o: Outcome): number[] => [o.stats.patchesApplied, o.stats.patchesMissed];

scenario({
  name: 'a patch before its row',
  groups: [oddsTo(40), evensTo(40)],
  drive({ w, slot, raws, observe }) {
    w.appendBytes(raws(1, 40));
    w.applyPatches([{ frameId: 5, suffix: ' [early]' }]);
    w.attachRows(range(1, 40).map((id) => slot(id)));
    w.applyPatches([{ frameId: 6, suffix: ' [late]' }, { frameId: 6, protocolLabel: 'TLSv1.2' }]);
    observe(5);
    observe(6);
  },
  expect(o) {
    check('  a patch for a slot with no row is missed', pair(o), [2, 1]);
    check('  ...and the row that arrives is not patched', infoOf(o, 5), 'Seq=5 Len=0');
    check('  a patch after the row lands in it', [infoOf(o, 6), o.rows[5].protocolLabel], ['Seq=6 Len=1 [late]', 'TLSv1.2']);
    check('  ...and the staged answer shows it before the seal', (o.observed[1] as Packet).info, 'Seq=6 Len=1 [late]');
  },
});

scenario({
  name: 'a patch, then a second attach',
  groups: [oddsTo(40), evensTo(40)],
  drive({ w, slot, raws, observe }) {
    w.appendBytes(raws(1, 40));
    w.attachRows(range(1, 40).map((id) => slot(id)));
    w.applyPatches([
      { frameId: 5, suffix: ' [a]' }, { frameId: 5, suffix: ' [b]' },
      { frameId: 9, responseInFrame: 12 }, { frameId: 10, protocolLabel: 'TLSv1.2' },
      { frameId: 11, links: { 'tcp.reassembled_in': 20 } },
    ]);
    observe(5);
    w.attachRows([slot(5)]);
    observe(5);
    w.applyPatches([{ frameId: 5, suffix: ' [c]' }]);
    observe(5);
    observe(7);
  },
  expect(o) {
    check('  every patch was applied', [pair(o), o.stats.rowsAttached], [[6, 0], 41]);
    check('  the staged row carries both patches', (o.observed[0] as Packet).info, 'Seq=5 Len=0 [a] [b]');
    check('  a second attach drops them', (o.observed[1] as Packet).info, 'Seq=5 Len=0');
    check('  ...and a patch after that lands on the new row', infoOf(o, 5), 'Seq=5 Len=0 [c]');
    check('  a response patch reaches the field', o.rows[8].fields?.['dns.response_in'], 12);
    check('  a label patch reaches the row', o.rows[9].protocolLabel, 'TLSv1.2');
    check('  a link patch reaches the field', o.rows[10].fields?.['tcp.reassembled_in'], 20);
    check('  an overlay shows in the staged row', (o.observed[3] as Packet).fields?.['tls.stream'], 7);
  },
});

scenario({
  name: 'a patch after the seal, and packed rows that carry their bytes',
  groups: [oddsTo(4106), evensTo(4106)],
  options: { horizonUs: 0 },
  drive({ w, slot, snapshot, observe }) {
    w.append(range(1, 4106).map((id) => slot(id, true)));
    snapshot();
    w.applyPatches([{ frameId: 5, suffix: ' [too late]' }, { frameId: 4100, suffix: ' [in time]' }]);
    observe(4100);
    observe(5);
  },
  expect(o) {
    check('  the full chunk sealed with its rows, ten are still staged',
      [(o.observed[0] as { chunksWritten: number }).chunksWritten, (o.observed[0] as { staged: number }).staged,
        (o.observed[0] as { framesSealedWithoutRow: number }).framesSealedWithoutRow], [1, 10, 0]);
    check('  a patch past the seal is missed, one inside the horizon applied', pair(o), [1, 1]);
    check('  ...and the missed one is kept in the sample', o.missed.map((p) => p.frameId), [5]);
    check('  the sealed row is unpatched', infoOf(o, 5), 'Seq=5 Len=0');
    check('  the staged one is patched', infoOf(o, 4100), 'Seq=4100 Len=0 [in time]');
    check('  a sealed frame has no staged answer', o.observed[2], null);
    check('  the bytes came from the carrying rows, once', [o.stats.bytesWritten, o.stats.rowsAttached], [4106 * 20, 4106]);
  },
});

scenario({
  name: 'a row before its bytes',
  groups: [oddsTo(40), evensTo(40), [999]],
  drive({ w, slot, raws, snapshot }) {
    w.attachRows([...range(1, 40), 999].map((id) => slot(id)));
    snapshot();
    w.applyPatches([{ frameId: 7, suffix: ' [orphan]' }]);
    w.appendBytes(raws(1, 40));
    snapshot();
  },
  expect(o) {
    check('  an early row is held, not counted', [(o.observed[0] as WriterStats).rowsMissed, (o.observed[0] as WriterStats).rowsAttached], [0, 0]);
    check('  a patch for it is missed', pair(o), [0, 1]);
    check('  its bytes claim it, so nothing is a placeholder', o.stats.framesSealedWithoutRow, 0);
    check('  the row whose bytes never came is counted at the end', o.stats.rowsMissed, 1);
    check('  the claimed rows are the dissected ones', [infoOf(o, 7), infoOf(o, 40)], ['Seq=7 Len=2', 'Seq=40 Len=0']);
  },
});

scenario({
  name: 'a placeholder at the seal',
  groups: [oddsTo(40), evensTo(40)],
  drive({ w, slot, raws }) {
    w.appendBytes(raws(1, 40));
    // The odd pack whole, five rows of the even one: the even pack's rows in this
    // chunk are too few to travel as a segment, and fifteen frames never got a row.
    w.attachRows([...oddsTo(40), 2, 4, 6, 8, 10].sort((a, b) => a - b).map((id) => slot(id)));
    w.applyPatches([{ frameId: 3, suffix: ' [x]' }, { frameId: 12, suffix: ' [no row]' }]);
  },
  expect(o) {
    check('  frames with no row are written as placeholders', o.stats.framesSealedWithoutRow, 15);
    check('  ...and say so', infoOf(o, 12), 'Not dissected - frame bytes are on disk');
    check('  ...with the captured length the writer recorded', o.rows[11].length, 20);
    check('  the patches follow the same rule', pair(o), [1, 1]);
    check('  the five even rows kept their own text', infoOf(o, 10), 'Seq=10 Len=0');
  },
});

scenario({
  name: 'horizon cuts through packs',
  // One pack of 4090 rows, one of 100 and one of 10: the chunk boundary at 4096
  // leaves six rows of the second pack in the first chunk (too few to travel as
  // a segment) and 94 in the second (enough).
  groups: [range(1, 4090), range(4091, 4190), range(4191, 4200)],
  options: { horizonUs: 60_000_000, horizonFrames: 1_000_000 },
  drive({ w, slot, raws, observe, snapshot }) {
    w.appendBytes(raws(1, 4200));
    snapshot();
    w.attachRows(range(1, 4200).map((id) => slot(id)));
    w.applyPatches([100, 4093, 4150, 4195].map((frameId) => ({ frameId, suffix: ' [p]' })));
    observe(4093);
    snapshot();
  },
  expect(o) {
    check('  nothing sealed before finish, then two chunks', [(o.observed[0] as WriterStats).chunksWritten, o.stats.chunksWritten], [0, 2]);
    check('  every patch applied', pair(o), [4, 0]);
    check('  the chunk boundaries are the chunk size', o.layout.map((r) => r.frameCount), [4096, 104]);
    check('  both chunks are pack-native', o.versions, [3, 3]);
    check('  patches land on both sides of the cut', [4093, 4150, 100, 4195].map((id) => infoOf(o, id)),
      ['Seq=4093 Len=3 [p]', 'Seq=4150 Len=0 [p]', 'Seq=100 Len=0 [p]', 'Seq=4195 Len=0 [p]']);
  },
});

{
  const ring = (id: number): RawFrame['ring'] => ({ epoch: 1, file: id <= 40 ? 1 : id <= 90 ? 2 : 3, seq: id });
  scenario({
    name: 'ring-segment cuts through packs',
    // Files of 40, 50 and 10 frames. Both packs have 20, 25 and 5 rows in them.
    groups: [oddsTo(100), evensTo(100)],
    rings: true,
    options: { horizonUs: 60_000_000, horizonFrames: 1_000_000 },
    drive({ w, slot, raws }) {
      w.appendBytes(raws(1, 100, ring));
      w.attachRows(range(1, 100).map((id) => slot(id)));
      w.applyPatches([{ frameId: 45, suffix: ' [mid]' }, { frameId: 95, suffix: ' [end]' }]);
    },
    expect(o) {
      check('  a chunk per ring file', o.layout.map((r) => [r.segment, r.frameCount]), [[1, 40], [2, 50], [3, 10]]);
      check('  all three are pack-native', o.versions, [3, 3, 3]);
      check('  patches reach rows in the later segments', [pair(o), infoOf(o, 45), infoOf(o, 95)],
        [[2, 0], 'Seq=45 Len=0 [mid]', 'Seq=95 Len=0 [end]']);
    },
  });
}

scenario({
  name: 'packs under sixteen rows, beside plain rows',
  groups: [range(1, 5), range(6, 10), [12]],
  drive({ w, slot, raws }) {
    w.appendBytes(raws(1, 20));
    w.attachRows(range(1, 20).map((id) => slot(id)));
    w.applyPatches([3, 11, 12, 18].map((frameId) => ({ frameId, suffix: ' [t]' })));
  },
  expect(o) {
    check('  patches reach packed and plain rows alike', [pair(o), [3, 11, 12, 18].map((id) => infoOf(o, id))],
      [[4, 0], ['Seq=3 Len=3 [t]', 'frame 11 [t]', 'Seq=12 Len=2 [t]', 'frame 18 [t]']]);
  },
});

{
  // With no packed slot nothing changes: packNative on writes the chunk packNative
  // off writes, which is the chunk `encodeChunk` made before packed slots existed.
  const sc: Scenario = {
    name: 'no packed slot',
    groups: [],
    drive({ w, slot }) {
      w.append(range(1, 50).map((id) => slot(id)));
      w.applyPatches([{ frameId: 7, suffix: ' [s]' }]);
    },
  };
  const native = scenario(sc);
  const direct = encodeChunk(range(1, 50).map((id) => frame(id, id === 7 ? { info: 'frame 7 [s]' } : {})), range(1, 50).map(() => 20));
  const off = run(sc, 'decoded');
  check('no packed slot: the chunk is version 2', native.versions, [2]);
  check('...byte for byte what packNative off writes', firstDifference(native.sum, off.sum), null);
  check('...and what encodeChunk makes of the same rows', firstDifference(native.sum[0], DEFLATE(direct.summary)), null);
}

for (const variant of ['native', 'decoded'] as const) {
  // A caller that changes what `stagedFrame` hands it must not change the row
  // that is written, nor what the next call answers: the answer is built on
  // request from a pack other slots share.
  const make = (mutate: boolean): Scenario => ({
    name: `staged answers (${variant})`,
    groups: [oddsTo(40), evensTo(40)],
    drive({ w, slot, raws, observe }) {
      w.appendBytes(raws(1, 40));
      w.attachRows(range(1, 40).map((id) => slot(id)));
      w.applyPatches([{ frameId: 5, suffix: ' [a]' }, { frameId: 7, suffix: ' [b]' }]);
      observe(5);
      observe(7);
      if (mutate) {
        for (const id of [5, 7]) {
          const staged = w.stagedFrame(id)!.packet!;
          staged.info = 'MUTATED';
          staged.fields!['tls.stream'] = 999;
          staged.fields!['injected'] = 1;
          staged.layers.push({ name: 'x', fields: [] } as unknown as Packet['layers'][number]);
        }
      }
      observe(5);
      observe(7);
    },
  });
  const clean = run(make(false), variant);
  const mutated = run(make(true), variant);
  sameOutcome(`staged answers (${variant}): changing one leaves the next answer and the written rows alone`, mutated, clean);
  check(`staged answers (${variant}): ...and the answer is the patched, overlaid row`,
    [(clean.observed[1] as Packet).info, (clean.observed[1] as Packet).fields?.['tls.stream']], ['Seq=7 Len=2 [b]', 7]);
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
