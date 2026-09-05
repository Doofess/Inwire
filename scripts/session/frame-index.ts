/**
 * Assertion tests for finding a frame by id, and for the two patch passes
 * built on it.
 *
 *   npx tsx scripts/session/frame-index.ts
 *
 * Both passes used to walk the whole buffer to touch one or two frames - 14.1 ms
 * each at a million frames, ten times a second (`scripts/perf/buffer-cost.ts`).
 * They now reach for the frame directly, which is only safe because ids are
 * handed out in order and only ever leave from the head.
 *
 * That is *nearly* true, and the nearly is the whole risk here: the Worker takes
 * an id before it dissects, so a frame that fails to dissect burns an id and
 * leaves a hole. The arithmetic guess is therefore checked, and a miss falls
 * back to a binary search. These tests are mostly about the holes.
 */
import { applyInfoPatchesInPlace, indexOfFrame, type InfoPatch } from '../../src/services/pcapParser';
import { applyIcmpRepliesInPlace } from '../../src/services/sessionRestore';
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

/** Just enough of a Packet for these functions. */
function pkt(id: number, info = 'i'): Packet {
  return { id, info, layers: [], fields: {} } as unknown as Packet;
}
const buffer = (ids: number[]) => ids.map((id) => pkt(id));

// --- 1. Contiguous, from any base -------------------------------------------------
{
  const b = buffer([1, 2, 3, 4, 5]);
  check('the first frame', indexOfFrame(b, 1), 0);
  check('the last frame', indexOfFrame(b, 5), 4);
  check('one in the middle', indexOfFrame(b, 3), 2);
  check('an id below the head is absent', indexOfFrame(b, 0), -1);
  check('an id above the tail is absent', indexOfFrame(b, 6), -1);

  // A trimmed buffer does not start at 1, which is the ordinary live case.
  const trimmed = buffer([40001, 40002, 40003]);
  check('a trimmed buffer indexes from its own head', indexOfFrame(trimmed, 40002), 1);
  check('...and an id it no longer holds is absent', indexOfFrame(trimmed, 40000), -1);

  check('an empty buffer finds nothing', indexOfFrame([], 1), -1);
}

// --- 2. Holes, which is what the arithmetic guess gets wrong -----------------------
//
// A frame that fails to dissect consumes an id and produces no packet, so the
// buffer skips one. The guess lands on the wrong frame and must be rejected.
{
  const b = buffer([1, 2, 4, 5, 6]);          // 3 never arrived
  check('a frame after a hole is still found', indexOfFrame(b, 5), 3);
  check('...and so is the last one', indexOfFrame(b, 6), 4);
  check('the missing id itself is absent', indexOfFrame(b, 3), -1);
  check('a frame before the hole is unaffected', indexOfFrame(b, 2), 1);

  const many = buffer([10, 20, 30, 40, 50, 60, 70]);
  for (const id of [10, 20, 30, 40, 50, 60, 70]) {
    checkTrue(`a badly-holed buffer still finds ${id}`, many[indexOfFrame(many, id)].id === id);
  }
  check('...and reports a gap id as absent', indexOfFrame(many, 35), -1);
}

// --- 3. The ICMP reply pass -------------------------------------------------------
{
  const b = buffer([1, 2, 3]);
  const before = b[1];
  const changed = applyIcmpRepliesInPlace(b, [{ requestFrameId: 2, replyId: 9 }]);
  check('a reply is applied', changed, true);
  check('...to the frame it names', b[1].info, 'i (reply in 9)');
  check('...and to no other', [b[0].info, b[2].info], ['i', 'i']);
  // The packets are replaced, not mutated: a selection or a filtered array
  // holding the old object must still see what it saw.
  checkTrue('...replacing the packet rather than mutating it', b[1] !== before);
  check('...leaving the original object untouched', before.info, 'i');

  const none = buffer([1, 2, 3]);
  check('a reply naming a frame that is gone changes nothing',
    applyIcmpRepliesInPlace(none, [{ requestFrameId: 99, replyId: 1 }]), false);
  check('...and no reply at all is not a change',
    applyIcmpRepliesInPlace(none, []), false);
}

// --- 4. The info-patch pass -------------------------------------------------------
{
  const b = buffer([5, 6, 7]);
  const patches: InfoPatch[] = [{ frameId: 6, suffix: ' [reassembled]' } as InfoPatch];
  check('a patch is applied', applyInfoPatchesInPlace(b, patches), true);
  check('...to the frame it names', b[1].info, 'i [reassembled]');

  // Two patches for one frame both land, in order - a frame can carry more
  // than one reassembly note.
  const two = buffer([1]);
  applyInfoPatchesInPlace(two, [
    { frameId: 1, suffix: ' a' } as InfoPatch,
    { frameId: 1, suffix: ' b' } as InfoPatch,
  ]);
  check('two patches for one frame both land, in order', two[0].info, 'i a b');

  check('a patch for a frame that is gone changes nothing',
    applyInfoPatchesInPlace(buffer([1, 2]), [{ frameId: 50, suffix: 'x' } as InfoPatch]), false);
}

// --- 5. The property the flush depends on -----------------------------------------
//
// The flush concatenates, then patches the result in place. A patch may target a
// frame in the batch just appended - a record that began and ended inside one
// flush - which is exactly what the restore path used to drop by patching
// before it concatenated.
{
  const prev = buffer([1, 2, 3]);
  const batch = buffer([4, 5]);
  const next = prev.concat(batch);
  applyInfoPatchesInPlace(next, [{ frameId: 5, suffix: ' [in this batch]' } as InfoPatch]);
  check('a patch targeting the newly appended batch lands', next[4].info, 'i [in this batch]');
  check('...and the frames already in the buffer are untouched',
    next.slice(0, 3).map((p) => p.info), ['i', 'i', 'i']);
  check('...and the previous array is not disturbed',
    prev.map((p) => p.info), ['i', 'i', 'i']);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All frame-index checks passed.');
process.exit(0);
