/**
 * Assertion tests for spotting a frame captured twice.
 *
 *   npx tsx scripts/dissect/duplicate-frames.ts
 *
 * Capturing on two adapters at once catches some frames twice - a bridge, a
 * VPN adapter and its underlying NIC, a virtual switch and its uplink. Neither
 * copy is wrong, but a reader counting frames, or looking at what appears to
 * be a retransmission, is being misled by an arrangement rather than by the
 * network.
 *
 * What this holds is mostly the refusals, because a false positive here is
 * worse than a miss: it labels a real retransmission - which is a genuine
 * network event somebody may be investigating - as an artefact of their own
 * capture setup, and invites them to ignore it.
 *
 *   - Two identical frames on ONE interface are not duplicates. That is a
 *     retransmission, or a beacon, and it is the thing this must never eat.
 *   - Identical bytes far apart in time are not duplicates either.
 *   - The whole frame is hashed, not a prefix: two frames on one TCP stream
 *     share their headers and differ only in the part a prefix would skip.
 */
import {
  DuplicateFinder, DUPLICATE_WINDOW_US, duplicateSuffix,
} from '../../src/services/duplicateFrames';
import { isDuplicate, directionOf, packDirection, Direction, DirectionSignal }
  from '../../src/services/direction';
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

const BODY = new Uint8Array(Array.from({ length: 200 }, (_, i) => i & 0xff));

function frame(id: number, iface: string, tsUs: number, bytes = BODY,
  direction?: number): Packet {
  return {
    id, interfaceName: iface, tsUs, length: bytes.length,
    rawBytes: bytes, direction,
  } as unknown as Packet;
}

// --- The same frame on two adapters --------------------------------------------
{
  const finder = new DuplicateFinder();
  const first = frame(1, 'eth0', 1000);
  const second = frame(2, 'wlan0', 1200);
  const marks = finder.scan([first, second]);
  check('the later copy is marked', marks.map((m) => m.frameId), [2]);
  check('...against the earlier frame', marks[0].ofFrameId, 1);
  check('...naming the interface that saw it first', marks[0].onInterface, 'eth0');
  checkTrue('...and the frame itself reads as a duplicate', isDuplicate(second.direction));
  checkTrue('the first copy is left alone', !isDuplicate(first.direction));
  check('the Info suffix says which frame and where',
    duplicateSuffix(marks[0]), ' [Duplicate of frame 1 on eth0]');
}

// --- What must NOT be called a duplicate -----------------------------------------
{
  // The important one. A retransmission is identical bytes on the SAME
  // interface, and labelling it an artefact of the capture setup would invite
  // somebody to ignore a real network event.
  const finder = new DuplicateFinder();
  check('identical frames on one interface are not duplicates',
    finder.scan([frame(1, 'eth0', 1000), frame(2, 'eth0', 1200)]).length, 0);
}
{
  const finder = new DuplicateFinder();
  check('identical bytes outside the window are not duplicates',
    finder.scan([
      frame(1, 'eth0', 1000),
      frame(2, 'wlan0', 1000 + DUPLICATE_WINDOW_US + 1),
    ]).length, 0);
}
{
  const finder = new DuplicateFinder();
  const other = new Uint8Array(BODY);
  // One byte different, deep in the payload - where a header prefix would not
  // have looked. Two frames on one TCP stream differ in exactly this way.
  other[180] ^= 0xff;
  check('frames differing only in their payload are not duplicates',
    finder.scan([frame(1, 'eth0', 1000), frame(2, 'wlan0', 1100, other)]).length, 0);
}
{
  const finder = new DuplicateFinder();
  // Nothing to compare. A frame whose bytes the buffer has evicted, or one
  // that never had any, is skipped rather than guessed at.
  check('a frame with no bytes is skipped',
    finder.scan([
      frame(1, 'eth0', 1000, new Uint8Array(0)),
      frame(2, 'wlan0', 1100, new Uint8Array(0)),
    ]).length, 0);
}

// --- Three adapters give two marks against the first, not a chain ------------------
{
  const finder = new DuplicateFinder();
  const marks = finder.scan([
    frame(1, 'eth0', 1000), frame(2, 'wlan0', 1100), frame(3, 'tun0', 1200),
  ]);
  check('every later copy is marked', marks.map((m) => m.frameId), [2, 3]);
  check('...all against the first, rather than in a chain',
    marks.map((m) => m.ofFrameId), [1, 1]);
}

// --- Marking preserves what the frame already decided --------------------------------
{
  const finder = new DuplicateFinder();
  const slot = packDirection(Direction.Out, DirectionSignal.InterfaceMac);
  const second = frame(2, 'wlan0', 1100, BODY, slot);
  finder.scan([frame(1, 'eth0', 1000, BODY, slot), second]);
  checkTrue('a marked frame is still a duplicate', isDuplicate(second.direction));
  check('...and still knows which way it went', directionOf(second.direction), Direction.Out);
}

// --- It works flush by flush, as a live capture feeds it -------------------------------
{
  const finder = new DuplicateFinder();
  check('the first flush finds nothing on its own',
    finder.scan([frame(1, 'eth0', 1000)]).length, 0);
  const second = finder.scan([frame(2, 'wlan0', 1100)]);
  check('the next flush matches against it', second.map((m) => m.ofFrameId), [1]);

  // And forgets, once the window has passed. Otherwise a long capture would
  // hold every frame it ever saw.
  const later = finder.scan([frame(3, 'wlan0', 1000 + DUPLICATE_WINDOW_US * 3)]);
  check('an old frame is no longer a candidate', later.length, 0);
}

// --- A reset forgets everything ----------------------------------------------------------
{
  const finder = new DuplicateFinder();
  finder.scan([frame(1, 'eth0', 1000)]);
  finder.reset();
  check('after a reset the earlier frame is gone',
    finder.scan([frame(2, 'wlan0', 1100)]).length, 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All duplicate-frame checks passed.');
process.exit(0);
