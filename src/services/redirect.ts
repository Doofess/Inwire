/**
 * Re-deciding the direction of frames that are already in the buffer.
 *
 * Two things make this necessary. An imported capture is dissected before
 * anything knows whose machine it came from - the host is inferred from the
 * frames themselves, which cannot happen until there are frames - so every one
 * of them is dissected with no identity and has to be revisited once there is
 * one. And a user who overrides the host is asking for exactly that revisit.
 *
 * It is cheap because the two values it needs are **dense columns**:
 * `eth.src` and `eth.dst` are declared in `dissect/denseFields.ts`, so reading
 * them back is an index into a typed array rather than a property lookup on a
 * dictionary-mode object, and no frame has to be re-dissected. Direction is a
 * plain property on `Packet`, so writing it back is an assignment - which is
 * the whole reason it is not a dense column itself (`services/direction.ts`).
 *
 * **Chunked, and not as a precaution.** A synchronous pass over a full buffer
 * is precisely the failure `docs/decisions/0015` recorded: repainting every
 * frame in one go stalled the main thread for 202 ms at the old 100k cap and
 * 1,985 ms at a million, and the buffer is larger now that it is bounded by
 * memory rather than by a frame count. So the work is sliced between animation
 * frames, the same shape the minimap's colour fill ended up with.
 */
import type { Packet } from '../types/packet';
import { fieldValue } from './dissect/fieldAccess';
import {
  Direction, directionFromAddresses, directionFromMacs, directionOf,
  isDuplicate, withDuplicate, type HostIdentity,
} from './direction';

/**
 * Frames per slice.
 *
 * Sized from the measurement in ADR 0015 rather than picked: a warm pass over
 * a million frames costs ~23 ms there, so ~20,000 frames is on the order of a
 * millisecond of work - comfortably inside a frame's budget even on a slow
 * machine, and few enough slices that a 700,000-frame buffer finishes in about
 * thirty five of them.
 */
const CHUNK = 20_000;

function decide(packet: Packet, host: HostIdentity): number {
  const srcMac = fieldValue(packet, 'eth.src');
  const dstMac = fieldValue(packet, 'eth.dst');
  let slot = directionFromMacs(
    typeof srcMac === 'string' ? srcMac : undefined,
    typeof dstMac === 'string' ? dstMac : undefined,
    host,
  );
  if (slot === 0) {
    slot = directionFromAddresses(packet.source, packet.destination, host);
  }
  // The duplicate bit belongs to a different question and is preserved: a
  // frame that duplicates one on another adapter still does, whoever the host
  // turns out to be.
  return isDuplicate(packet.direction) && slot !== 0 ? withDuplicate(slot) : slot;
}

/**
 * Re-decides every frame in place, in slices.
 *
 * **In place, and that is deliberate** - the frames are mutated rather than
 * copied. Copying would break identity for every cache in the app that is
 * keyed on it (`packetsExtend`, the display-filter cache, each
 * `useIncrementalAggregate`), turning a re-derive into a full refold of the
 * dashboard. `onDone` is what tells React to re-read; it is called once, at
 * the end, rather than per slice, so the list repaints once.
 *
 * Returns a cancel function. A second import, or a second override, must not
 * leave a half-finished pass writing an identity that is no longer current.
 */
export function rederiveDirections(
  packets: readonly Packet[],
  host: HostIdentity,
  onDone: (changed: number) => void,
  /**
   * Called for each frame as it is passed, before its direction is decided.
   *
   * This is how an **imported** capture gets its network facts. The collector
   * lives in the Worker for a live capture, and an import never goes near the
   * Worker - it is dissected on the main thread, which is what makes live and
   * imported frames identical. Without this the Network panel's "observed"
   * column would be empty for every file, which is exactly the case it is
   * most useful in: somebody else's capture, on a network you cannot ask.
   *
   * It rides on this pass rather than taking one of its own because the two
   * want the same thing - every frame, once, without blocking - and a second
   * chunked sweep would double the cost to save nothing.
   */
  onFrame?: (packet: Packet, host: HostIdentity) => void,
): () => void {
  let index = 0;
  let changed = 0;
  let handle: number | null = null;
  let cancelled = false;

  const step = () => {
    if (cancelled) return;
    const end = Math.min(index + CHUNK, packets.length);
    for (; index < end; index++) {
      const packet = packets[index];
      // Before the decision, so a collector that reads `direction` sees the
      // value this frame had rather than the one it is about to get. Nothing
      // does today; getting the order right costs nothing and removes a
      // question somebody would otherwise have to answer later.
      onFrame?.(packet, host);
      const slot = decide(packet, host);
      const next = slot === 0 ? undefined : slot;
      if (next !== packet.direction) {
        packet.direction = next;
        changed++;
      }
    }
    if (index < packets.length) {
      handle = requestAnimationFrame(step);
      return;
    }
    handle = null;
    onDone(changed);
  };

  // The first slice runs on the next frame rather than now: the caller is
  // usually mid-render (an import that has just set state), and doing work
  // before that render commits delays the thing the user is waiting to see.
  handle = requestAnimationFrame(step);

  return () => {
    cancelled = true;
    if (handle !== null) cancelAnimationFrame(handle);
  };
}

/** How many frames of each direction a buffer holds, for a summary line. */
export function countDirections(packets: readonly Packet[]): Record<Direction, number> {
  const counts = {
    [Direction.Unknown]: 0, [Direction.Out]: 0,
    [Direction.In]: 0, [Direction.Transit]: 0,
  };
  for (const packet of packets) counts[directionOf(packet.direction)]++;
  return counts;
}
