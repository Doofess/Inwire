/**
 * Assertion tests for what a live buffer's raw bytes pin (D2, `slabLedger.ts`).
 *
 *   npx tsx scripts/session/slab-ledger.ts
 *
 * A live row's `rawBytes` is a view into its flush's slab, so the slab is held
 * in full while any row of it keeps its bytes. Evicting half a flush frees
 * nothing; evicting the rest frees the slab. The first version of the buffer's
 * accounting counted each row's own length, which reports memory freed that the
 * heap still holds.
 */
import { SlabLedger } from '../../src/services/slabLedger';
import { evictOldBytes } from '../../src/services/packetBytes';
import {
  commitBatch, dropBelowFloor, freshAccounting, prepareBatch, type BufferAccounting,
} from '../../src/services/packetBuffer';
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

let nextId = 1;
/** `count` frames of `size` bytes, each a view into one slab, as a flush's rows are. */
function flushOf(count: number, size: number): Packet[] {
  const slab = new Uint8Array(count * size);
  return Array.from({ length: count }, (_, i) => ({
    id: nextId++, info: '', layers: [], fields: {},
    rawBytes: slab.subarray(i * size, (i + 1) * size),
  }) as unknown as Packet);
}
const WHOLE = { first: 1, last: 1_000_000 };

// --- The ledger on its own ------------------------------------------------------
{
  const ledger = new SlabLedger();
  const rows = flushOf(8, 100);
  rows.forEach((row) => ledger.pin(row));
  check('a slab counts in full once, not per row', ledger.pinnedBytes, 800);
  check('a row leaving while others remain frees nothing', ledger.release(rows[0]), 0);
  check('...and the slab is still counted in full', ledger.pinnedBytes, 800);
  for (let i = 1; i < 7; i++) ledger.release(rows[i]);
  check('...down to its last row', ledger.pinnedBytes, 800);
  check('the last row frees the whole slab', ledger.release(rows[7]), 800);
  check('...and it is no longer counted', ledger.pinnedBytes, 0);
  check('a row released twice frees nothing the second time', ledger.release(rows[7]), 0);

  const own = { rawBytes: new Uint8Array(40) } as Packet;
  ledger.pin(own);
  check('a row with a buffer of its own is a slab of one', [ledger.pinnedBytes, ledger.release(own), ledger.pinnedBytes], [40, 40, 0]);
  check('a row that was never pinned frees nothing', ledger.release(flushOf(1, 10)[0]), 0);
  const empty = { rawBytes: new Uint8Array(0) } as Packet;
  ledger.pin(empty);
  check('a row with no bytes pins nothing', ledger.pinnedBytes, 0);
}

// --- A row released twice, or through a copy (React re-running an updater) --------------
//
// An updater React re-applies on a rebased state can trim a row it already trimmed, and
// a patched row is a copy that shares the original's `rawBytes`. Counting per buffer
// alone let one row's second release stand in for another row, so the slab left the
// ledger while rows still held it.
{
  const ledger = new SlabLedger();
  const rows = flushOf(4, 100);
  rows.forEach((row) => ledger.pin(row));
  ledger.release(rows[0]);
  check('a row released twice while others remain frees nothing the second time', ledger.release(rows[0]), 0);
  check('...and the slab is still counted while three rows hold it', ledger.pinnedBytes, 400);
  const copy = { ...rows[1] } as Packet;
  ledger.release(rows[1]);
  check('a patched copy of a released row frees nothing', ledger.release(copy), 0);
  ledger.pin(rows[2]);
  check('a row pinned twice counts once', [ledger.release(rows[2]), ledger.pinnedBytes], [0, 400]);
  check('the slab frees with its real last row', ledger.release(rows[3]), 400);
  check('...and is no longer counted', ledger.pinnedBytes, 0);
}

// --- Eviction, half a flush and then the rest -----------------------------------------
{
  const ledger = new SlabLedger();
  const buffer = flushOf(8, 100);
  buffer.forEach((row) => ledger.pin(row));
  // Keep the newest 4: the oldest 4 of the one slab go.
  const first = evictOldBytes(buffer, 4, WHOLE, ledger);
  check('half a flush evicted frees no memory', first, 0);
  check('...and resident bytes still include the whole slab', ledger.pinnedBytes, 800);
  const rest = evictOldBytes(buffer, 0, WHOLE, ledger);
  check('the rest of the flush frees the slab', rest, 800);
  check('...and resident bytes drop by the slab', ledger.pinnedBytes, 0);
  check('without a ledger the return is still the rows\' own lengths', evictOldBytes(flushOf(3, 5), 0, WHOLE), 15);
}

// --- Two flushes: only the evicted one is released -------------------------------------
{
  const ledger = new SlabLedger();
  const older = flushOf(4, 50);
  const newer = flushOf(4, 70);
  [...older, ...newer].forEach((row) => ledger.pin(row));
  check('both slabs are counted', ledger.pinnedBytes, 200 + 280);
  check('evicting exactly the older flush frees its slab', evictOldBytes([...older, ...newer], 4, WHOLE, ledger), 200);
  check('...the newer is still pinned', ledger.pinnedBytes, 280);
}

// --- Through the flush: prepare pins, commit evicts and trims ---------------------------
function drive(budgetBytes: number): { accounting: BufferAccounting; buffer: Packet[] } {
  const accounting = freshAccounting();
  const incoming = flushOf(8, 100);
  prepareBatch(incoming, accounting, { persist: () => {}, absorb: () => {} });
  const residentBytesAtEntry = accounting.residentBytes;
  let buffer: Packet[] = [];
  for (let i = 0; i < 2; i++) {   // the updater runs twice, as StrictMode does
    buffer = commitBatch([], incoming, [], [], accounting, {
      budgetBytes, capturing: false, residentFrames: 4, residentBytesAtEntry, freeDiskBytes: null,
    }, { storedIdRange: () => WHOLE, reportDropped: () => {}, autoPause: () => {} });
  }
  return { accounting, buffer };
}
{
  const { accounting } = drive(100 * 1024 * 1024);
  check('a flush pins its slab when it joins the buffer, and a half-evicted slab stays pinned',
    accounting.slabs.pinnedBytes, 800);
}
{
  // A budget so small the trim drops the oldest rows with the newest 4 still holding bytes.
  const { accounting, buffer } = drive(1);
  check('a trim keeps one frame at least', buffer.length >= 1, true);
  check('the survivor still pins its slab', accounting.slabs.pinnedBytes, 800);
  evictOldBytes(buffer, 0, WHOLE, accounting.slabs);
  check('rows trimmed with their bytes released them, so the slab leaves with its last row',
    accounting.slabs.pinnedBytes, 0);
}
{
  const accounting = freshAccounting();
  const incoming = flushOf(8, 100);
  prepareBatch(incoming, accounting, { persist: () => {}, absorb: () => {} });
  const kept = dropBelowFloor(incoming, incoming[4].id, accounting);
  check('rows dropped below the ring floor leave the slab pinned by the rest', [kept.length, accounting.slabs.pinnedBytes], [4, 800]);
  dropBelowFloor(kept, kept[kept.length - 1].id + 1, accounting);
  check('...and the last of them frees it', accounting.slabs.pinnedBytes, 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All slab-ledger checks passed.');
process.exit(0);
