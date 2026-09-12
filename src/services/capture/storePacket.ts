/**
 * A frame, flattened so it survives the trip to the capture store.
 *
 * ## The bug this exists to prevent, which shipped
 *
 * The buffer keeps the 33 commonest fields in typed columns rather than in the
 * bag (ADRs 0017 and 0018), so a buffered `Packet` carries `cols` - a
 * `FieldBlock` **class instance** - and a `row` index into it. Everything that
 * reads a field goes through `fieldAccess.ts`, which knows to look in both
 * places.
 *
 * A structured clone does not carry a prototype. The Maps and typed arrays
 * inside the block arrive intact; the methods do not. So the moment the store
 * became a `utilityProcess` instead of a Worker in the same JavaScript context,
 * every `encodeChunk` threw `block.read is not a function` - once per chunk,
 * caught, reported as a non-fatal `failure`, and retried on the next append
 * for the life of the capture.
 *
 * The visible result was a capture directory with **raw frame bytes and no
 * rows**: `frames.iwbyt` grew, `index.iwidx` stayed empty, `chunkCount` stayed
 * 0. Everything built on stored rows - the restore, scrolling below the RAM
 * window, and the whole-capture filter - was silently inert, and the symptom
 * was `ordinalOf` answering -1 for every frame, which reads as "not
 * addressable yet" rather than as a failure.
 *
 * ## Flattened rather than rehydrated
 *
 * The block survives the clone as data, so `Object.setPrototypeOf` in the
 * store would work. It is the wrong trade: a block holds 4,096 rows and an
 * append batch is ~300 frames, so the same half-megabyte block would cross
 * fourteen times as it fills - about 1.7 kB a frame, roughly doubling what
 * `scripts/perf/store-boundary.ts` measures the crossing to cost.
 *
 * The store does not want the layout, it wants the values, and it interns
 * every string as it encodes - so flattening costs nothing on disk and less on
 * the wire.
 *
 * A frame with no block is passed through untouched: an imported capture, or
 * one restored from disk, already carries everything in the bag.
 */
import { fieldEntries } from '../dissect/fieldAccess';
import type { Packet } from '../../types/packet';

/**
 * The same frame with its dense columns folded back into `fields`.
 *
 * ## Always a copy, and that is the second half of the bug
 *
 * The obvious shortcut - return the packet itself when `cols` is undefined,
 * so the common case allocates nothing - is wrong here, and wrong in a way
 * that looks fine in every test.
 *
 * `prepareBatch` calls `persist` **before** `absorb`: the store is handed the
 * frames, and only then does the buffer's field writer claim a row and set
 * `cols` on those very objects. And `CaptureClient.send` awaits the port, so
 * the `postMessage` happens a microtask later. Hand back the same object and
 * the message serialises a packet that grew a `FieldBlock` in between - which
 * is exactly the failure this module exists to prevent, arriving by a
 * completely different route.
 *
 * More generally: a message is a snapshot. `applyInfoPatchesInPlace` mutates
 * buffer packets after the fact too, and a store that received the patched
 * Info early would be quietly inconsistent with the row the reader saw.
 *
 * A shallow copy per frame at flush time is a few thousand small objects a
 * second at the rates that matter, against a clone that already costs 5.26 µs
 * a frame (`scripts/perf/store-boundary.ts`).
 */
export function plainForStore(packet: Packet): Packet {
  if (packet.cols === undefined) return { ...packet };
  const fields: Record<string, string | number> = {};
  for (const [key, value] of fieldEntries(packet)) fields[key] = value;
  // `cols` and `row` are dropped rather than nulled: they describe a buffer
  // this frame is about to leave, and a row index into a block that is not
  // travelling is worse than no index at all.
  const { cols: _cols, row: _row, ...rest } = packet;
  return { ...rest, fields };
}
