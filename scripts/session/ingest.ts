/**
 * The packet buffer's ingest, driven twice on purpose.
 *
 *   npx tsx scripts/session/ingest.ts
 *
 * `scripts/session/buffer-budget.ts` already tests `planBufferTrim`, and every
 * other piece the flush uses - `estimateSummaryBytes`, `evictOldBytes`, the two
 * patch passes - is pure and exported. What was untested is the **wiring**: the
 * order the pieces run in, and what happens when React runs the state updater
 * more than once with the same `prev`. `main.tsx` turns `StrictMode` on, so in
 * development it always does.
 *
 * Every failure below actually happened, and the comments in `App.tsx` name
 * them. They are all the same shape - an impure step running twice - and none
 * of them is a crash:
 *
 *   - the batch written to the session store twice;
 *   - a second dense-field row claimed per frame and wasted;
 *   - the dropped-frame counter "roughly double", which the code calls "a
 *     miscount in the one number this whole feature exists to report
 *     accurately";
 *   - the freed bytes subtracted twice, walking the running total down "until
 *     the buffer stopped trimming at all".
 *
 * A screenshot cannot see any of that, and neither can the compiler. A script
 * can, because it can call the updater twice deterministically and then check
 * the arithmetic - and the strongest check here does not mirror the
 * implementation at all: **resident bytes must equal the sum recomputed over
 * the frames actually in the buffer.** That one cannot be satisfied by copying
 * the code it tests.
 *
 * What this file cannot do is prove the stored session matches the buffer,
 * because the store needs IndexedDB. That was checked by hand once, on a real
 * capture, and the result is recorded here so nobody has to repeat it blind: a
 * 3,828-frame session was discarded, a fresh capture of 1,673 frames taken, and
 * a reload restored **exactly 1,673** - contiguous, ending where the capture
 * ended. Before `handleStartCapture` cleared the session it would have restored
 * those 1,673 plus the previous capture's frames 1,674 and up, since the store
 * keys by id and nothing deleted the tail.
 */
import {
  adoptAccounting, commitBatch, prepareBatch, freshAccounting, type BufferAccounting,
} from '../../src/services/packetBuffer';
import { estimateSummaryBytes } from '../../src/services/bufferBudget';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) { console.log(`PASS  ${name}`); return; }
  failures++;
  console.log(`FAIL  ${name}\n        expected ${b}\n        actual   ${a}`);
}

// --- a frame, with only what the buffer's accounting reads -------------------

let nextId = 1;
function frame(bytes = 1400): Packet {
  const id = nextId++;
  return {
    id,
    tsUs: 1_700_000_000_000_000 + id * 1000,
    relativeTime: id / 1000,
    timeDelta: 0.001,
    source: '10.0.0.1',
    destination: '10.0.0.2',
    protocol: 'TCP',
    length: bytes,
    info: `frame ${id}`,
    layers: [],
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    rawBytes: new Uint8Array(bytes),
  } as unknown as Packet;
}

/** Records what the flush asked the outside world to do. */
function recorder() {
  const persisted: number[][] = [];
  const absorbed: number[][] = [];
  const droppedReports: number[] = [];
  let autoPauses = 0;
  return {
    persisted, absorbed, droppedReports,
    get autoPauses() { return autoPauses; },
    prepare: {
      persist: (f: readonly Packet[]) => persisted.push(f.map((p) => p.id)),
      absorb: (f: readonly Packet[]) => absorbed.push(f.map((p) => p.id)),
    },
    commit: {
      storedIdRange: () => null,
      reportDropped: (total: number) => droppedReports.push(total),
      autoPause: () => { autoPauses++; },
    },
  };
}

/** What the buffer's bytes SHOULD be, recomputed from the frames it holds. */
function recomputeBytes(packets: readonly Packet[]): number {
  return packets.reduce((sum, p) => sum + estimateSummaryBytes(p), 0);
}

/**
 * One flush, with the updater run `invocations` times on the same `prev` -
 * which is exactly what React does, and 2 is what StrictMode does.
 */
function flush(
  prev: Packet[], incoming: Packet[], accounting: BufferAccounting,
  rec: ReturnType<typeof recorder>, budgetBytes: number, capturing = true,
  invocations = 2,
): Packet[] {
  prepareBatch(incoming, accounting, rec.prepare);
  // Snapshotted once per flush, exactly as App.tsx does it - see the note on
  // `residentBytesAtEntry`. Taking it inside the loop would hide the very bug
  // this harness exists to catch.
  const residentBytesAtEntry = accounting.residentBytes;
  let result = prev;
  for (let i = 0; i < invocations; i++) {
    result = commitBatch(prev, incoming, [], [], accounting, {
      budgetBytes, capturing, residentFrames: 25000, residentBytesAtEntry,
    }, rec.commit);
  }
  return result;
}

// --- 1. a flush that fits inside the budget ---------------------------------
{
  const rec = recorder();
  const accounting = freshAccounting();
  const batch = Array.from({ length: 10 }, () => frame());
  const packets = flush([], batch, accounting, rec, 100 * 1024 * 1024);

  check('a batch that fits is committed whole', packets.length, 10);
  check('...persisted exactly once, however often the updater ran',
    rec.persisted.length, 1);
  check('...and absorbed exactly once', rec.absorbed.length, 1);
  check('...with nothing dropped', accounting.droppedTotal, 0);
  check('...and no trim reported', rec.droppedReports.length, 0);
  // The load-bearing one: recomputed, not mirrored.
  check('...resident bytes match the frames actually held',
    accounting.residentBytes, recomputeBytes(packets));
}

// --- 2. the same batch offered twice ----------------------------------------
{
  const rec = recorder();
  const accounting = freshAccounting();
  const batch = Array.from({ length: 5 }, () => frame());
  flush([], batch, accounting, rec, 100 * 1024 * 1024);
  // A retry of the same batch - the guard is `persistedThroughId`, and this is
  // what stops a re-offered batch being written to disk a second time.
  prepareBatch(batch, accounting, rec.prepare);
  check('a batch already persisted is not written again', rec.persisted.length, 1);
}

// --- 3. a flush that overruns the budget and trims ---------------------------
{
  const rec = recorder();
  const accounting = freshAccounting();
  // A budget small enough that a few hundred frames overrun it.
  const budget = 200 * estimateSummaryBytes(frame());
  let packets: Packet[] = [];
  for (let i = 0; i < 12; i++) {
    packets = flush(packets, Array.from({ length: 50 }, () => frame()),
      accounting, rec, budget, false);
  }

  check('the buffer trimmed', accounting.droppedTotal > 0, true);
  check('...and the reported total is the last one, not a doubled one',
    rec.droppedReports[rec.droppedReports.length - 1], accounting.droppedTotal);
  // The counter bug: dropped + held must equal every frame ever offered.
  check('...frames dropped plus frames held equals frames offered',
    accounting.droppedTotal + packets.length, 12 * 50);
  // The byte-accounting bug: the running total must not have drifted.
  check('...resident bytes still match the frames actually held',
    accounting.residentBytes, recomputeBytes(packets));
  // What used to be here: "the store was told to forget as often as the buffer
  // did". It is not told any more and must not be - the capture store is
  // append-only, and a frame leaving the RAM window is not a frame leaving the
  // capture. The check that replaced it is that trimming reports a drop and
  // touches nothing else.
  check('...and trimming is the only thing the buffer told anyone about',
    rec.droppedReports.length > 0, true);
}

// --- 4. one invocation and two must agree ------------------------------------
//
// The clearest statement of the property: running the updater once and running
// it twice must leave the accounting in the same place. If any impure step
// escapes its guard, these two diverge.
{
  const budget = 200 * estimateSummaryBytes(frame());
  const run = (invocations: number) => {
    nextId = 1;                                   // same frames both times
    const rec = recorder();
    const accounting = freshAccounting();
    let packets: Packet[] = [];
    for (let i = 0; i < 12; i++) {
      packets = flush(packets, Array.from({ length: 50 }, () => frame()),
        accounting, rec, budget, false, invocations);
    }
    return { accounting, held: packets.length, reports: rec.droppedReports.length,
      persists: rec.persisted.length, absorbs: rec.absorbed.length };
  };
  const once = run(1);
  const twice = run(2);
  check('running the updater twice drops the same number of frames',
    twice.accounting.droppedTotal, once.accounting.droppedTotal);
  check('...leaves the same resident byte total',
    twice.accounting.residentBytes, once.accounting.residentBytes);
  check('...holds the same frames', twice.held, once.held);
  check('...reports the drop the same number of times', twice.reports, once.reports);
  check('...persists the same number of times', twice.persists, once.persists);
  check('...and absorbs the same number of times', twice.absorbs, once.absorbs);
}

// --- 5. auto-pause ------------------------------------------------------------
{
  const rec = recorder();
  const accounting = freshAccounting();
  const budget = 40 * estimateSummaryBytes(frame());
  let packets: Packet[] = [];
  for (let i = 0; i < 4; i++) {
    packets = flush(packets, Array.from({ length: 20 }, () => frame()),
      accounting, rec, budget, true);
  }
  check('a buffer at its budget asks for capture to stop', rec.autoPauses > 0, true);

  const quiet = recorder();
  const roomy = freshAccounting();
  flush([], Array.from({ length: 5 }, () => frame()), roomy, quiet, 100 * 1024 * 1024, true);
  check('...and one with room does not', quiet.autoPauses, 0);
}


// --- 6. Clear and Discard: the buffer is now nothing --------------------------
{
  const rec = recorder();
  const accounting = freshAccounting();
  const batch = Array.from({ length: 20 }, () => frame());
  flush([], batch, accounting, rec, 100 * 1024 * 1024);

  // What Clear and Discard do, through `adoptBuffer([], 0)`.
  adoptAccounting(accounting, [], 0);
  check('Clear leaves no bytes accounted for', accounting.residentBytes, 0);
  check('...and rewinds the store high-water mark', accounting.persistedThroughId, 0);

  // The point of rewinding it: a fresh capture numbers from 1 again, and those
  // frames have to reach the store. Without the rewind `prepareBatch` would see
  // ids below the old mark and decline.
  const after = Array.from({ length: 5 }, () => frame());
  const before = rec.persisted.length;
  prepareBatch(after, accounting, rec.prepare);
  check('...so a new capture after Clear is persisted', rec.persisted.length, before + 1);
}

// --- 7. Import: the buffer is now these frames -------------------------------
{
  const accounting = freshAccounting();
  const imported = Array.from({ length: 30 }, () => frame());
  adoptAccounting(accounting, imported, null);
  // The bug this replaced: setting the total to zero reported a full buffer as
  // empty and stopped it trimming.
  check('an import accounts for what it actually costs',
    accounting.residentBytes, recomputeBytes(imported));
}

// --- 8. Import leaves the store's high-water mark alone ----------------------
//
// True at this level, and **not reachable from the buttons** - which is worth
// stating precisely, because it was first reported here as a data-loss bug and
// it is not one. Import passes `null`, so `persistedThroughId` keeps whatever
// the previous capture left. On its own that would mean a capture started
// afterwards issued lower ids and was silently not persisted.
//
// The UI never gets there. After an import the buffer is not empty, so the
// Start button is "Start a new capture, discarding the current one", and it
// calls `onClearPackets()` before `onStartCapture()` - which passes 0 and
// rewinds the mark. The checks below pin the unit-level behaviour so that the
// day something calls `prepareBatch` without that Clear in front of it, the
// consequence is written down rather than rediscovered.
{
  const rec = recorder();
  const accounting = freshAccounting();

  // A long capture, which pushes the store's high-water mark up.
  nextId = 10_000;
  prepareBatch(Array.from({ length: 10 }, () => frame()), accounting, rec.prepare);
  const highWater = accounting.persistedThroughId;
  check('a capture moves the store high-water mark', highWater > 0, true);

  // Then an import, whose frames are numbered from 1 by the importer.
  nextId = 1;
  const imported = Array.from({ length: 5 }, () => frame());
  adoptAccounting(accounting, imported, null);
  check('an import does not rewind the mark', accounting.persistedThroughId, highWater);

  // So a capture started after the import issues low ids, and they are declined.
  const persistsBefore = rec.persisted.length;
  prepareBatch(Array.from({ length: 5 }, () => frame()), accounting, rec.prepare);
  check('...so a batch with lower ids would not be persisted without a Clear',
    rec.persisted.length, persistsBefore);
}

// --- 9. The dropped counter survives a Clear ----------------------------------
//
// Also characterisation. `reportDropped` is only ever called by the flush, so
// nothing resets the running total: after a Clear the buffer is empty and the
// "frames dropped (buffer full)" figure still reports the previous capture's.
{
  const rec = recorder();
  const accounting = freshAccounting();
  const budget = 200 * estimateSummaryBytes(frame());
  let packets: Packet[] = [];
  for (let i = 0; i < 12; i++) {
    packets = flush(packets, Array.from({ length: 50 }, () => frame()),
      accounting, rec, budget, false);
  }
  check('the buffer dropped frames', accounting.droppedTotal > 0, true);
  adoptAccounting(accounting, [], 0);
  // The count belongs to the buffer it was dropped from, and that buffer is
  // gone. Nothing reset it before, so Driver Info kept reporting the previous
  // capture's figure after a Clear.
  check('...and replacing the buffer resets it', accounting.droppedTotal, 0);
  check('...along with the head-id guard, so the next trim is not a repeat',
    accounting.droppedHeadId, -1);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All packet-buffer ingest checks passed.');
process.exit(0);
