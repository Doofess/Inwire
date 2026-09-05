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
import { hasBytes, NO_BYTES, packetsBytes } from '../../src/services/packetBytes';
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

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All packet-bytes checks passed.');
process.exit(0);
