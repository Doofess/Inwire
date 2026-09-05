/**
 * Assertion tests for the frame-bytes seam and the rule behind it.
 *
 *   npx tsx scripts/session/packet-bytes.ts
 *
 * A million-frame buffer cannot hold every frame's bytes (0013), and it does not
 * have to: they are already on disk, keyed by frame id. What makes dropping them
 * safe is knowing exactly which frames the store can still supply - because
 * `toStoredFrame` writes a byte-less packet as a `fallback` block, so a frame
 * whose bytes were dropped one moment too early loses them from both places at
 * once and there is no way back.
 *
 * `ledgerRange` is that rule. The write ledger holds one entry per frame the
 * store has confirmed written, oldest first; the buffer's trimming and the
 * storage budget both slice from its front. So the ledger is the answer to "what
 * could be read back", and these tests hold its ends to that.
 *
 * There is no IndexedDB in Node and no fake in this repo, so the IO itself is
 * kept small enough to read; what is tested here is the decision.
 */
import { ledgerRange } from '../../src/services/sessionStore';
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

const entry = (id: number) => ({ id, bytes: 100 });
function pkt(id: number, bytes: Uint8Array): Packet {
  return { id, rawBytes: bytes, info: '', layers: [], fields: {} } as unknown as Packet;
}

// --- What the store can still supply ------------------------------------------
{
  check('an empty ledger can supply nothing', ledgerRange([]), null);
  check('one frame is a range of one', ledgerRange([entry(7)]), { first: 7, last: 7 });
  check('the ends are the ends',
    ledgerRange([entry(5), entry(6), entry(7), entry(8)]), { first: 5, last: 8 });

  // The front is sliced by the buffer's own trimming and by the storage budget,
  // so the first id is not 1 and is not a count - it is whatever survived.
  check('a ledger trimmed from the front starts where it starts',
    ledgerRange([entry(40_001), entry(40_002)]), { first: 40_001, last: 40_002 });

  // Holes are allowed: a frame that failed to dissect burns an id, so the
  // ledger skips. The range is still the ends, and a caller asking for a
  // missing id inside it simply gets nothing back.
  check('a ledger with holes still reports its ends',
    ledgerRange([entry(1), entry(2), entry(4), entry(9)]), { first: 1, last: 9 });
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
// dropped while the store cannot supply them again has lost them outright:
// `toStoredFrame` writes a byte-less packet as a `fallback` block, so there is
// no second chance.
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
