/**
 * The chunk directory, and what a reader does after a crash.
 *
 *   npx tsx scripts/capture/capture-index.ts
 *
 * Two things are held here and the second is the reason the `BlockFile` seam
 * exists at all.
 *
 * **The lookups**, which are easy to get subtly wrong: a frame's *ordinal* is
 * its gapless position in the capture and its *id* is `packetGenerator`'s
 * number, and ids have holes because a frame that fails to dissect burns one.
 * `scripts/session/frame-index.ts` already documents that trap for the in-RAM
 * buffer - "correct only while numbering is contiguous, which stops being true
 * the moment the buffer trims" - and a disk-backed capture has more places to
 * fall into it.
 *
 * **The recovery rule**, which cannot be tested any other way. OPFS does not
 * exist in Node and a browser cannot be crashed on demand, so the rule is
 * exercised against a `BlockFile` that is truncated at chosen offsets: data
 * written but never indexed, an index record whose flush did not land, a file
 * cut mid-record. What is lost must be exactly the torn tail and never a byte
 * more, because this is the one function in the capture store that decides a
 * user's frames are gone.
 */
import {
  CaptureIndex, planRecovery, recoverIndex, encodeChunkRecord, decodeChunkRecord,
  writeIndexHeader, recordsIn, INDEX_HEADER_BYTES, INDEX_RECORD_BYTES,
  type ChunkRecord,
} from '../../src/services/capture/captureIndex';
import { MemoryBlockFile, readExact, append } from '../../src/services/capture/blockFile';

let failures = 0;
/**
 * Canonical comparison: object keys sorted.
 *
 * Key INSERTION order is not part of the contract - `decodeChunkRecord` builds
 * a record in the order the bytes are laid out and a caller builds one in
 * whatever order reads well - and a test that fails on it sends whoever reads
 * it hunting for a data loss that is not there.
 */
function canon(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canon);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canon((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
const show = (v: unknown): string => JSON.stringify(canon(v));

function check(name: string, actual: unknown, expected: unknown): void {
  const pass = show(actual) === show(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${show(expected)}`);
    console.log(`        actual   ${show(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }
function checkThrows(name: string, fn: () => unknown): void {
  let threw = false;
  try { fn(); } catch { threw = true; }
  check(name, threw, true);
}

/** A chunk record whose extents follow on from the one before it. */
function chain(
  specs: { firstId: number; lastId: number; frameCount: number; firstTsUs?: number }[],
): ChunkRecord[] {
  let ordinal = 0, pfx = 0, sum = 0, byt = 0;
  return specs.map((s, i) => {
    const record: ChunkRecord = {
      firstId: s.firstId,
      lastId: s.lastId,
      frameCount: s.frameCount,
      firstOrdinal: ordinal,
      pfxOffset: pfx, pfxLength: s.frameCount * 72,
      sumOffset: sum, sumLength: s.frameCount * 40,
      bytOffset: byt, bytLength: s.frameCount * 1100,
      firstTsUs: s.firstTsUs ?? 1_000_000 + i * 1_000_000,
    };
    ordinal += s.frameCount;
    pfx += record.pfxLength;
    sum += record.sumLength;
    byt += record.bytLength;
    return record;
  });
}

console.log('--- the record ---\n');

{
  const record: ChunkRecord = {
    firstId: 40_001, lastId: 44_096, frameCount: 4096, firstOrdinal: 8_000_000,
    pfxOffset: 5_000_000_000, pfxLength: 294_912,
    sumOffset: 900_000_000, sumLength: 163_840,
    bytOffset: 40_000_000_000, bytLength: 4_505_600,
    firstTsUs: 1_788_477_971_653_284,
  };
  const buf = new Uint8Array(INDEX_RECORD_BYTES);
  encodeChunkRecord(record, buf, 0);
  check('a record round-trips', decodeChunkRecord(buf, 0), record);
  // The reason offsets are f64 and not u64: a 40 GB offset is nowhere near
  // 2^53, and a BigInt read on the lookup path would cost more than the search.
  checkTrue('an offset past 2^32 survives exactly',
    decodeChunkRecord(buf, 0).bytOffset === 40_000_000_000);
  check('the record is the stated width', INDEX_RECORD_BYTES, 64);
}

{
  const bytes = new Uint8Array(INDEX_HEADER_BYTES + 2 * INDEX_RECORD_BYTES);
  writeIndexHeader(bytes);
  const records = chain([
    { firstId: 1, lastId: 4096, frameCount: 4096 },
    { firstId: 4097, lastId: 6000, frameCount: 1904 },
  ]);
  encodeChunkRecord(records[0], bytes, INDEX_HEADER_BYTES);
  encodeChunkRecord(records[1], bytes, INDEX_HEADER_BYTES + INDEX_RECORD_BYTES);
  const index = CaptureIndex.parse(bytes);
  check('a parsed index knows its chunks and frames',
    [index.chunkCount, index.frameCount], [2, 6000]);
  check('recordsIn counts whole records only',
    [recordsIn(0), recordsIn(INDEX_HEADER_BYTES), recordsIn(INDEX_HEADER_BYTES + 63)], [0, 0, 0]);

  checkThrows('a header this build does not know is refused',
    () => { const bad = bytes.slice(); bad[4] = 99; return CaptureIndex.parse(bad); });
  checkThrows('a different record stride is refused rather than misread',
    () => { const bad = bytes.slice(); bad[6] = 32; return CaptureIndex.parse(bad); });
  check('an empty file parses to an empty index', CaptureIndex.parse(new Uint8Array(0)).chunkCount, 0);
}

console.log('\n--- ordinals, which are gapless ---\n');

{
  // A short chunk in the middle, which is what a capture that resumed after a
  // restore looks like. The arithmetic guess is wrong here and must fall back.
  const index = new CaptureIndex(chain([
    { firstId: 1, lastId: 4096, frameCount: 4096 },
    { firstId: 4097, lastId: 4196, frameCount: 100 },
    { firstId: 4197, lastId: 8292, frameCount: 4096 },
  ]));
  check('the first frame is in the first chunk', index.chunkForOrdinal(0), 0);
  check('the last frame of a chunk is still in it', index.chunkForOrdinal(4095), 0);
  check('the next one is in the next chunk', index.chunkForOrdinal(4096), 1);
  check('a short middle chunk does not break the search', index.chunkForOrdinal(4195), 1);
  check('...nor the chunk after it', index.chunkForOrdinal(4196), 2);
  check('the last frame in the capture', index.chunkForOrdinal(8291), 2);
  check('one past the end is not a chunk', index.chunkForOrdinal(8292), -1);
  check('a negative ordinal is not a chunk', index.chunkForOrdinal(-1), -1);
}

console.log('\n--- ids, which have holes ---\n');

{
  // Frames 4097..4200 failed to dissect and burned their ids, so the second
  // chunk starts at 4201. Nothing may compute a position from `firstId + n`.
  const index = new CaptureIndex(chain([
    { firstId: 1, lastId: 4096, frameCount: 4096 },
    { firstId: 4201, lastId: 8296, frameCount: 4096 },
  ]));
  check('an id inside the first chunk', index.chunkForId(1), 0);
  check('an id inside the second', index.chunkForId(5000), 1);
  check('the boundary ids', [index.chunkForId(4096), index.chunkForId(4201)], [0, 1]);
  // The important one. An id in the hole is not the neighbouring frame, and
  // answering with the neighbour would be a confidently wrong row.
  check('an id that fell in a hole is NOT the nearest frame', index.chunkForId(4150), -1);
  check('an id before the capture', index.chunkForId(0), -1);
  check('an id after it', index.chunkForId(9999), -1);

  check('idRange reports the ends, holes and all', index.idRange(), { first: 1, last: 8296 });
  check('an empty capture has no range, rather than a zero one',
    new CaptureIndex([]).idRange(), null);
}

console.log('\n--- time, which the record already carried ---\n');

{
  const index = new CaptureIndex(chain([
    { firstId: 1, lastId: 100, frameCount: 100, firstTsUs: 1_000_000 },
    { firstId: 101, lastId: 200, frameCount: 100, firstTsUs: 2_000_000 },
    { firstId: 201, lastId: 300, frameCount: 100, firstTsUs: 3_000_000 },
  ]));
  check('a time before the capture lands on the first chunk', index.chunkForTime(0), 0);
  check('a time inside a chunk lands on that chunk', index.chunkForTime(2_500_000), 1);
  check('a time exactly at a boundary lands on that chunk', index.chunkForTime(2_000_000), 1);
  check('a time past the end lands on the last chunk', index.chunkForTime(9_000_000), 2);
}

console.log('\n--- the recovery rule ---\n');

{
  const records = chain([
    { firstId: 1, lastId: 4096, frameCount: 4096 },
    { firstId: 4097, lastId: 8192, frameCount: 4096 },
    { firstId: 8193, lastId: 12_288, frameCount: 4096 },
  ]);
  const whole = records[2];
  const pfxAll = whole.pfxOffset + whole.pfxLength;
  const sumAll = whole.sumOffset + whole.sumLength;
  const bytAll = whole.bytOffset + whole.bytLength;

  const clean = planRecovery(records, pfxAll, sumAll, bytAll);
  check('a clean capture loses nothing', [clean.keepRecords, clean.framesLost], [3, 0]);
  check('...and truncates nothing', [clean.pfxLength, clean.sumLength, clean.bytLength],
    [pfxAll, sumAll, bytAll]);

  // The ordinary crash: the last chunk's bytes were written but its flush did
  // not land, so one data file is short. The whole chunk goes.
  const tornBytes = planRecovery(records, pfxAll, sumAll, bytAll - 1);
  check('one short data file discards exactly the chunk it belonged to',
    [tornBytes.keepRecords, tornBytes.framesLost], [2, 4096]);
  check('...and truncates the other files back to the same boundary',
    [tornBytes.pfxLength, tornBytes.sumLength, tornBytes.bytLength],
    [records[1].pfxOffset + records[1].pfxLength,
      records[1].sumOffset + records[1].sumLength,
      records[1].bytOffset + records[1].bytLength]);
  check('...and shortens the index to match',
    tornBytes.indexLength, INDEX_HEADER_BYTES + 2 * INDEX_RECORD_BYTES);

  // Data written past the last index record is the OTHER direction, and it is
  // the one the write order is designed to produce. It is discarded silently:
  // nothing can find it, and leaving it would put every later offset out.
  const extraData = planRecovery(records.slice(0, 2), pfxAll, sumAll, bytAll);
  check('data past the last index record is discarded, not adopted',
    [extraData.keepRecords, extraData.pfxLength],
    [2, records[1].pfxOffset + records[1].pfxLength]);

  const nothing = planRecovery(records, 0, 0, 0);
  check('a capture whose data never landed keeps no records',
    [nothing.keepRecords, nothing.framesLost, nothing.indexLength],
    [0, 12_288, INDEX_HEADER_BYTES]);

  // A middle chunk cannot be the torn one - the write order forbids it - but if
  // it ever were, recovery must stop there rather than keeping later chunks
  // whose offsets are then meaningless.
  const holed = planRecovery(records, records[0].pfxLength, sumAll, bytAll);
  check('recovery stops at the first bad record and does not skip past it',
    holed.keepRecords, 1);
}

console.log('\n--- against a real file, through the seam ---\n');

{
  // The reason `BlockFile` exists: this is the recovery rule driven over bytes
  // that were actually written and then actually truncated, which is as close
  // to a crash as a test can get and closer than a browser allows.
  const index = new MemoryBlockFile();
  const pfx = new MemoryBlockFile();
  const sum = new MemoryBlockFile();
  const byt = new MemoryBlockFile();

  const header = new Uint8Array(INDEX_HEADER_BYTES);
  writeIndexHeader(header);
  index.write(0, header);

  const written: ChunkRecord[] = [];
  for (let c = 0; c < 4; c++) {
    const frames = c === 3 ? 500 : 4096;
    const pfxBytes = new Uint8Array(frames * 72).fill(c + 1);
    const sumBytes = new Uint8Array(frames * 40).fill(c + 1);
    const bytBytes = new Uint8Array(frames * 100).fill(c + 1);
    const record: ChunkRecord = {
      firstId: c * 4096 + 1,
      lastId: c * 4096 + frames,
      frameCount: frames,
      firstOrdinal: written.reduce((n, r) => n + r.frameCount, 0),
      pfxOffset: append(pfx, pfxBytes), pfxLength: pfxBytes.length,
      sumOffset: append(sum, sumBytes), sumLength: sumBytes.length,
      bytOffset: append(byt, bytBytes), bytLength: bytBytes.length,
      firstTsUs: 1_000_000 * (c + 1),
    };
    // Data first, flush, THEN the index record. The whole recovery rule rests
    // on this order, so the test writes in it too.
    pfx.flush(); sum.flush(); byt.flush();
    const rec = new Uint8Array(INDEX_RECORD_BYTES);
    encodeChunkRecord(record, rec, 0);
    append(index, rec);
    written.push(record);
  }

  const healthy = recoverIndex(index, pfx, sum, byt);
  check('a cleanly written capture recovers whole',
    [healthy.records.length, healthy.plan.keepRecords, healthy.plan.framesLost], [4, 4, 0]);
  check('...and its frames are all there',
    new CaptureIndex(healthy.records.slice(0, healthy.plan.keepRecords)).frameCount, 12_788);

  // Now the crash: the last chunk's bytes are half there and its index record
  // landed anyway, which is the one inconsistency the write order permits.
  byt.truncate(byt.size() - 10);
  const torn = recoverIndex(index, pfx, sum, byt);
  check('a torn tail costs exactly the last chunk',
    [torn.plan.keepRecords, torn.plan.framesLost], [3, 500]);

  // And the reader that acts on the plan is left with something consistent.
  index.truncate(torn.plan.indexLength);
  pfx.truncate(torn.plan.pfxLength);
  sum.truncate(torn.plan.sumLength);
  byt.truncate(torn.plan.bytLength);
  const after = recoverIndex(index, pfx, sum, byt);
  check('recovery is idempotent - a second pass finds nothing wrong',
    [after.plan.keepRecords, after.plan.framesLost], [3, 0]);
  check('...and the surviving files end exactly where the index says they do',
    [pfx.size(), sum.size(), byt.size()],
    [after.records[2].pfxOffset + after.records[2].pfxLength,
      after.records[2].sumOffset + after.records[2].sumLength,
      after.records[2].bytOffset + after.records[2].bytLength]);

  // The surviving chunks must still read back as themselves, not merely as the
  // right number of bytes.
  const third = after.records[2];
  const bytes = readExact(pfx, third.pfxOffset, third.pfxLength);
  checkTrue('a surviving chunk reads back with its own contents',
    bytes[0] === 3 && bytes[bytes.length - 1] === 3);
  checkThrows('reading past the truncated end throws rather than returning short',
    () => readExact(byt, byt.size() - 5, 100));
}

console.log('\n--- the seam itself ---\n');

{
  const file = new MemoryBlockFile(8);
  file.write(0, new Uint8Array([1, 2, 3]));
  check('a write extends the file', file.size(), 3);
  // A hole must read as zeros, because the recovery scan reads past the last
  // good record and has to see something deterministic there.
  file.write(10, new Uint8Array([9]));
  const out = new Uint8Array(11);
  check('a write past the end leaves zeros, not whatever was in the buffer',
    [file.read(0, out), Array.from(out)], [11, [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 9]]);
  check('a read past the end is short rather than an error',
    file.read(9, new Uint8Array(10)), 2);
  file.truncate(2);
  check('truncate shortens', file.size(), 2);
  file.truncate(5);
  check('...and growing by truncate zero-fills',
    Array.from(file.snapshot()), [1, 2, 0, 0, 0]);
  checkThrows('a negative offset is refused', () => file.write(-1, new Uint8Array(1)));
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture index checks passed.');
process.exit(0);
