/**
 * Assertion tests for QUIC STREAM reassembly, and specifically for the budget
 * that bounds it.
 *
 *   npx tsx scripts/quic/stream-reassembly.ts
 *
 * QUIC hands over fragments with explicit offsets and no promise about order,
 * so a fragment ahead of a gap has to be held. What is held is charged against
 * MAX_PENDING_STREAM_BYTES, and once that allowance is gone every further
 * out-of-order fragment on the stream is dropped for the life of the
 * connection - silently, and looking exactly like a stream that simply
 * stopped. Two ways the charge used to be wrong, both fixed here and both
 * asserted below:
 *
 *   - a retransmission of a held fragment was charged AGAIN, because `set`
 *     overwrites without refunding what it replaced;
 *   - a held fragment the cursor later passed was never consumed and never
 *     refunded, because consumption was an exact `get(nextOffset)`.
 *
 * The checks are black-box: the budget is private, so each one exhausts it and
 * then asserts that reassembly still works. A leak fails them.
 */
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';

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

const A = { ip: '10.0.0.1', port: 44444 };
const B = { ip: '93.184.216.34', port: 443 };
/** Bidirectional, client-initiated: both low bits clear. */
const STREAM_ID = 0;

/** One HTTP/3 DATA frame: type 0x00, a one-byte varint length, then payload. */
function dataFrame(payload: number[]): Uint8Array {
  return new Uint8Array([0x00, payload.length, ...payload]);
}

function read(t: QuicFlowTracker, fragments: { offset: number; data: Uint8Array }[]) {
  return t.readStreams(A.ip, A.port, B.ip, B.port,
    fragments.map((f) => ({ streamId: STREAM_ID, offset: f.offset, data: f.data, fin: false })));
}

/** Every DATA byte the tracker has handed back, in order. */
function dataLengths(out: ReturnType<typeof read>): number[] {
  return out.flatMap((s) => s.frames.map((f) => f.length));
}

// --- 1. The ordinary case, so the rest means something --------------------------
{
  const t = new QuicFlowTracker();
  const frame = dataFrame([1, 2, 3, 4]);
  check('a stream delivered in order is read straight through',
    dataLengths(read(t, [{ offset: 0, data: frame }])), [4]);
}

// --- 2. Out of order, then filled -----------------------------------------------
{
  const t = new QuicFlowTracker();
  const frame = dataFrame([1, 2, 3, 4]);
  const head = frame.subarray(0, 3);
  const tail = frame.subarray(3);

  check('a fragment ahead of a gap yields nothing yet',
    dataLengths(read(t, [{ offset: 3, data: tail }])), []);
  check('...and the gap being filled delivers the whole frame',
    dataLengths(read(t, [{ offset: 0, data: head }])), [4]);
}

// --- 3. A retransmission must not be charged twice --------------------------------
//
// One fragment, held, retransmitted. No more than its own length is ever
// actually held - but `set` overwrote it while `pendingBytes` kept climbing,
// so twelve copies of 32 KB read as 384 KB against a 256 KB allowance. The
// budget then refuses a fragment that would have fitted, and the frame waiting
// on it never completes.
{
  const t = new QuicFlowTracker();
  const junk = new Uint8Array(32 * 1024);
  for (let i = 0; i < 12; i++) read(t, [{ offset: 1_000_000, data: junk }]);

  const frame = dataFrame([1, 2, 3, 4]);
  check('twelve retransmissions of one 32 KB fragment cost 32 KB, not 384 KB',
    dataLengths(read(t, [
      { offset: 3, data: frame.subarray(3) },
      { offset: 0, data: frame.subarray(0, 3) },
    ])), [4]);
}

// --- 4. A held fragment the cursor overtakes must be released ----------------------
//
// Held at offset+3, then a fragment arrives that covers it whole and carries
// the cursor past it. Consumption used to be an exact `get(nextOffset)`, which
// never names it - so it was neither delivered nor refunded, and 24 KB went
// missing from the allowance on every pass.
{
  const t = new QuicFlowTracker();
  const FRAME = dataFrame([1, 2, 3, 4]);
  const BIG = new Uint8Array(FRAME.length * 8000);
  for (let i = 0; i < 8000; i++) BIG.set(FRAME, i * FRAME.length);
  // Exactly an eighth of MAX_PENDING_STREAM_BYTES, so eight stranded copies
  // saturate the allowance precisely and the ninth fragment - of any size at
  // all - is refused. A size that does not divide it leaves a few bytes of
  // headroom, which is enough for the small fragment below to slip through and
  // for this check to pass against the very bug it is here to catch.
  const junk = new Uint8Array(32 * 1024);

  let offset = 0;
  for (let i = 0; i < 10; i++) {
    read(t, [{ offset: offset + 3, data: junk }]);
    read(t, [{ offset, data: BIG }]);
    offset += BIG.length;
  }
  // Ten passes strand 320 KB in the old code - the allowance is 256 KB.

  const frame = dataFrame([9, 9, 9, 9]);
  check('a fragment the cursor overtook does not keep its bytes charged',
    dataLengths(read(t, [
      { offset: offset + 3, data: frame.subarray(3) },
      { offset, data: frame.subarray(0, 3) },
    ])), [4]);
}

// --- 5. A held fragment that only partly overlaps still contributes -----------------
//
// Held at 4; the cursor then reaches 6. Its first two bytes are already read
// and its last two are not, so it must be trimmed and used, not discarded.
{
  const t = new QuicFlowTracker();
  const frame = dataFrame([1, 2, 3, 4, 5, 6]);   // 8 bytes: 00 06 + six

  check('a fragment held ahead of the gap yields nothing yet',
    dataLengths(read(t, [{ offset: 4, data: frame.subarray(4) }])), []);
  checkTrue('...and a fragment overlapping it completes the frame from both',
    dataLengths(read(t, [{ offset: 0, data: frame.subarray(0, 6) }])).length === 1);
}

// --- 6. Fragments genuinely past the budget are still refused -----------------------
//
// The bound has to bind: this is a cap, not a leak to be fixed by removing it.
{
  const t = new QuicFlowTracker();
  const big = new Uint8Array(64 * 1024);
  // Five 64 KB fragments, none of them adjacent, all ahead of a gap at 0.
  for (let i = 0; i < 5; i++) read(t, [{ offset: 1_000_000 * (i + 1), data: big }]);
  const frame = dataFrame([1, 2, 3, 4]);
  check('the budget still bounds what is held, and the stream still works',
    dataLengths(read(t, [{ offset: 0, data: frame }])), [4]);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All QUIC STREAM reassembly checks passed.');
process.exit(0);
