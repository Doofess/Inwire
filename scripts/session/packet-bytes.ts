/**
 * Assertion tests for the frame-bytes seam and the rule behind it.
 *
 *   npx tsx scripts/session/packet-bytes.ts
 *
 * A million-frame buffer cannot hold every frame's bytes (0013), and it does not
 * have to: they are already on disk, keyed by frame id. What makes dropping them
 * safe is knowing exactly which frames the store can still supply - a frame
 * whose bytes were dropped one moment too early has them nowhere.
 *
 * `CaptureIndex.idRange` is that rule, and it replaced `sessionStore`'s write
 * ledger. The two answer the same question with the same shape and the same
 * null-when-empty, which is why `packetBytes.ts` did not change - but they
 * answer it differently in one way that matters: the ledger's front was sliced
 * by a 512 MB budget that **evicted**, so its first id rose faster than the RAM
 * window's and pinned bytes in memory between the two. A capture index only
 * grows, so the cases below are the ends of a capture rather than the ends of
 * whatever a budget left.
 */
import { CaptureIndex, type ChunkRecord } from '../../src/services/capture/captureIndex';
import { evictOldBytes, hasBytes, NO_BYTES, packetsBytes } from '../../src/services/packetBytes';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** One sealed chunk, described the way the index holds it. */
function chunk(firstId: number, lastId: number, ordinal = 0): ChunkRecord {
  return {
    firstId, lastId, frameCount: lastId - firstId + 1, firstOrdinal: ordinal,
    pfxOffset: 0, pfxLength: 0, sumOffset: 0, sumLength: 0,
    bytOffset: 0, bytLength: 0, firstTsUs: 0, recOffset: 0, recLength: 0,
  };
}
const range = (...records: ChunkRecord[]) => new CaptureIndex(records).idRange();
function pkt(id: number, bytes: Uint8Array): Packet {
  return { id, rawBytes: bytes, info: '', layers: [], fields: {} } as unknown as Packet;
}

// --- What the store can still supply ------------------------------------------
{
  check('a capture with no sealed chunk can supply nothing', range(), null);
  check('one frame is a range of one', range(chunk(7, 7)), { first: 7, last: 7 });
  check('the ends are the ends',
    range(chunk(5, 8), chunk(9, 12, 4)), { first: 5, last: 12 });

  // A capture that resumed after a restore does not start at 1: the frames
  // before it are in an earlier capture directory, and this one begins where
  // the numbering had got to.
  check('a capture that resumed numbering starts where it starts',
    range(chunk(40_001, 44_096)), { first: 40_001, last: 44_096 });

  // Holes are allowed: a frame that failed to dissect burns an id, so the ids
  // skip. The range is still the ends, and a caller asking for a missing id
  // inside it simply gets nothing back.
  check('holes inside and between chunks do not move the ends',
    range(chunk(1, 2), chunk(4, 9, 2)), { first: 1, last: 9 });

  // The property the ledger did NOT have, and the reason for the change: an
  // index is append-only, so the floor never rises and a frame that was ever
  // readable stays readable for the life of the capture.
  const index = new CaptureIndex([chunk(1, 4096)]);
  const before = index.idRange();
  index.append(chunk(4097, 8192, 4096));
  check('appending a chunk never moves the first id',
    [before?.first, index.idRange()?.first], [1, 1]);
  check('...and extends the last', index.idRange()?.last, 8192);
}

// --- The seam is synchronous while packets still carry their bytes ------------
//
// The property that matters today: introducing this seam must not introduce a
// database read. Every packet still has its bytes, so nothing may reach the
// store - which is also what keeps a capture small enough to hold in memory
// doing no IO at all.
{
  const a = pkt(1, new Uint8Array([1, 2, 3]));
  const b = pkt(2, new Uint8Array([4, 5]));
  checkTrue('a packet carrying bytes reports so', hasBytes(a));
  checkTrue('...and an emptied one does not', !hasBytes(pkt(3, NO_BYTES)));

  // packetsBytes must not touch the store when nothing is missing. If it did,
  // this would reject or hang: there is no IndexedDB in Node.
  const got = await packetsBytes([a, b]);
  check('every frame is returned', [...got.keys()].sort(), [1, 2]);
  check('...with its own bytes', [...(got.get(1) ?? [])], [1, 2, 3]);
  checkTrue('...by reference, not copied', got.get(1) === a.rawBytes);
  check('...and the second frame too', [...(got.get(2) ?? [])], [4, 5]);

  const none = await packetsBytes([]);
  check('no frames, no work', none.size, 0);
}

// --- Eviction: the destructive half -------------------------------------------
//
// The rules that keep this from losing a capture. A frame whose bytes are
// dropped while the store cannot supply them again has lost them outright -
// there is no second copy anywhere - so the range is a precondition and not a
// hint.
{
  const buffer = Array.from({ length: 10 }, (_, i) => pkt(i + 1, new Uint8Array([i + 1])));
  const all = { first: 1, last: 10 };

  // Nothing is on disk: nothing may be dropped, however old.
  check('no stored range evicts nothing', evictOldBytes(buffer, 3, null), 0);
  checkTrue('...and every frame still has its bytes', buffer.every(hasBytes));

  // A window larger than the buffer leaves it alone.
  check('a buffer inside the resident window is untouched',
    evictOldBytes(buffer, 100, all), 0);
  checkTrue('...still all present', buffer.every(hasBytes));

  // The ordinary case: keep the newest 4, drop the older 6.
  const freed = evictOldBytes(buffer, 4, all);
  check('the frames outside the window are evicted', freed, 6);
  check('...leaving the newest four', buffer.map(hasBytes),
    [false, false, false, false, false, false, true, true, true, true]);

  // Idempotent, which matters because React runs a state updater twice under
  // StrictMode and this is called from one.
  check('a second pass evicts nothing more', evictOldBytes(buffer, 4, all), 0);
  check('...and changes nothing', buffer.map(hasBytes),
    [false, false, false, false, false, false, true, true, true, true]);
}

// --- A frame the store cannot supply is never dropped ---------------------------
//
// The storage budget slices the oldest frames off disk. Those frames are still
// in the buffer and still export; dropping their bytes would be the one way to
// actually lose data here.
{
  const buffer = Array.from({ length: 10 }, (_, i) => pkt(i + 1, new Uint8Array([i + 1])));
  // Only frames 5..10 are still on disk - 1..4 were evicted for budget.
  const freed = evictOldBytes(buffer, 2, { first: 5, last: 10 });
  check('only the recoverable frames are evicted', freed, 4);
  check('...frames the store no longer has keep their bytes in memory',
    buffer.map(hasBytes), [true, true, true, true, false, false, false, false, true, true]);
}

// --- Mutation, not replacement --------------------------------------------------
//
// The display filter's cache is a second array of references to these same
// frames. Replacing a slot in one array frees nothing while the other still
// points at the original, so eviction has to reach the object itself.
{
  const shared = pkt(1, new Uint8Array([1, 2, 3]));
  const buffer = [shared, pkt(2, new Uint8Array([4])), pkt(3, new Uint8Array([5]))];
  const filterCache = [shared];          // what filterIncrementally holds

  evictOldBytes(buffer, 2, { first: 1, last: 3 });
  checkTrue('the frame in the buffer lost its bytes', !hasBytes(buffer[0]));
  checkTrue('...and so did the one the filter cache holds, because it is the same object',
    !hasBytes(filterCache[0]));
  checkTrue('...identity is unchanged, so no memo is invalidated', buffer[0] === shared);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All packet-bytes checks passed.');
process.exit(0);
