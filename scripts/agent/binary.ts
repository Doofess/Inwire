/**
 * Assertion tests for the binary packet frame's browser decoder.
 *
 *   npx tsx scripts/agent/binary.ts
 *
 * The vectors below are the same ones `local-agent/test_protocol.py` asserts
 * the Python encoder produces, byte for byte. That is the point of writing
 * them out longhand rather than round-tripping through an encoder written
 * here: a wire format with only one implementation of itself will agree with
 * itself no matter what it does, and the two ends of this one are in different
 * languages and different repositories' worth of test runs.
 *
 * The refusals matter as much as the successes. A truncated batch means the
 * socket delivered something this build does not understand, and dissecting
 * the prefix would put frames into the buffer with no way to tell they are the
 * survivors of a message that was wrong.
 */
import {
  BATCH_HEADER_BYTES, BATCH_RECORD_BYTES, BATCH_VERSION,
  decodePacketBatch, isPacketBatch, retain,
} from '../../src/services/agentBinary';

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
function checkThrows(name: string, fn: () => unknown) {
  let threw = false;
  try { fn(); } catch { threw = true; }
  check(name, threw, true);
}

/** The Python encoder, written out here so both ends are asserted, not shared. */
function record(seq: number, iface: number, tsUs: number, origLen: number, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(BATCH_RECORD_BYTES + data.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, seq, true);
  view.setUint16(4, iface, true);
  view.setUint16(6, 0, true);
  view.setFloat64(8, tsUs, true);
  view.setUint32(16, origLen, true);
  view.setUint32(20, data.length, true);
  out.set(data, BATCH_RECORD_BYTES);
  return out;
}

function batch(records: Uint8Array[]): ArrayBuffer {
  const size = BATCH_HEADER_BYTES + records.reduce((a, r) => a + r.length, 0);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  out.set([0x49, 0x57, 0x50, 0x31], 0); // 'IWP1'
  view.setUint8(4, BATCH_VERSION);
  view.setUint8(5, 0);
  view.setUint16(6, records.length, true);
  let at = BATCH_HEADER_BYTES;
  for (const r of records) { out.set(r, at); at += r.length; }
  return out.buffer;
}

const sixtyFour = new Uint8Array(64).map((_, i) => i);
const jumbo = new Uint8Array(9000).fill(0xff);

// --- the happy path ----------------------------------------------------------

{
  const buffer = batch([
    record(0, 0, 1788477971653284, 1514, sixtyFour),
    record(4294967295, 7, 1788477971653285.5, 60, new Uint8Array(0)),
    record(9, 1, 1, 9000, jumbo),
  ]);

  check('a batch is recognised before it is decoded', isPacketBatch(buffer), true);
  const frames = decodePacketBatch(buffer);
  check('every record comes back', frames.length, 3);
  check('the capture time survives to the microsecond', frames[0].tsUs, 1788477971653284);
  check('a sequence number at the u32 ceiling round-trips', frames[1].seq, 4294967295);
  check('the interface index is carried', frames[1].iface, 7);
  check('a zero-length capture is a frame, not an error', frames[1].bytes.length, 0);
  check('the wire length is carried apart from the captured length',
    [frames[2].origLen, frames[2].bytes.length], [9000, 9000]);
  check('the frame bytes are exact', Array.from(frames[0].bytes.slice(0, 5)), [0, 1, 2, 3, 4]);

  // The whole reason the bytes travel binary: nothing is copied between the
  // socket and the dissector.
  check('a frame is a view over the received buffer, not a copy',
    frames[0].bytes.buffer === buffer, true);
  check('...offset to where the record actually starts',
    frames[0].bytes.byteOffset, BATCH_HEADER_BYTES + BATCH_RECORD_BYTES);

  // ...which is also why anything that outlives the batch has to copy: one
  // 60-byte ARP frame would otherwise hold a quarter-megabyte batch alive.
  const kept = retain(frames[1]);
  check('a retained frame is detached from the batch', kept.buffer === buffer, false);
  check('...and is the same bytes', Array.from(kept), Array.from(frames[1].bytes));
}

// --- an empty batch ----------------------------------------------------------
// The agent never sends one (encode_batch refuses), but a decoder that threw on
// one would turn a harmless message into a dropped connection.
check('an empty batch decodes to no frames', decodePacketBatch(batch([])).length, 0);

// --- refusals -----------------------------------------------------------------

{
  const good = batch([record(1, 0, 1, 60, sixtyFour)]);
  const bytes = new Uint8Array(good);

  const notABatch = bytes.slice();
  notABatch.set([0x4e, 0x4f, 0x50, 0x45], 0); // 'NOPE'
  check('a message that is not a batch is not mistaken for one', isPacketBatch(notABatch.buffer), false);
  checkThrows('...and is refused rather than read', () => decodePacketBatch(notABatch.buffer));

  const futureVersion = bytes.slice();
  futureVersion[4] = BATCH_VERSION + 1;
  checkThrows('a version this build does not read is refused', () => decodePacketBatch(futureVersion.buffer));

  checkThrows('a batch truncated mid-payload is refused',
    () => decodePacketBatch(bytes.slice(0, bytes.length - 1).buffer));
  checkThrows('a batch truncated mid-record-header is refused',
    () => decodePacketBatch(bytes.slice(0, BATCH_HEADER_BYTES + 4).buffer));

  const trailing = new Uint8Array(bytes.length + 1);
  trailing.set(bytes);
  checkThrows('trailing bytes after the last record are refused',
    () => decodePacketBatch(trailing.buffer));

  // A count that overstates the records is the shape a partially-written frame
  // takes; it must not yield the records it does have.
  const overCount = bytes.slice();
  new DataView(overCount.buffer).setUint16(6, 2, true);
  checkThrows('a count larger than the records present is refused',
    () => decodePacketBatch(overCount.buffer));

  check('a message shorter than a header is not a batch',
    isPacketBatch(new Uint8Array([0x49, 0x57]).buffer), false);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All binary packet frame checks passed.');
process.exit(0);
