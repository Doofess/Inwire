/**
 * The same frame captured twice, on two adapters at once.
 *
 * Capturing on more than one interface is the only way to see a machine's
 * whole traffic when it is multi-homed, and it comes with an artefact: a frame
 * that crosses a bridge, a VPN adapter and its underlying NIC, or a virtual
 * switch and its uplink, is captured once on each. Nothing about either copy is
 * wrong - both really were on both interfaces - but a reader counting frames,
 * or looking at a retransmission that is not one, is being misled by an
 * arrangement rather than by the network.
 *
 * So the later copy is **marked, never dropped**. Removing it would be a
 * stronger claim than the evidence supports: this cannot tell a duplicated
 * frame from a genuinely retransmitted identical one, and a capture that
 * quietly discarded frames would be lying about what was on the wire. Marking
 * says "this looks like the frame you already saw", and leaves the decision.
 *
 * **Only when more than one interface is being captured.** In single-interface
 * mode this is skipped entirely rather than merely finding nothing: a hash per
 * frame is real work on the hot path, and in the common case there is by
 * construction nothing for it to find.
 */
import type { Packet } from '../types/packet';
import { withDuplicate } from './direction';

/**
 * How far apart two copies of one frame may be.
 *
 * Five milliseconds. The two captures are of the same instant, so the gap is
 * scheduling jitter between two capture threads rather than anything on the
 * network - microseconds in practice. The window is generous against that and
 * still far tighter than any real retransmission, which waits for a timeout
 * measured in hundreds of milliseconds at the very least.
 */
export const DUPLICATE_WINDOW_US = 5_000;

/**
 * A cheap content hash of a frame.
 *
 * FNV-1a over the bytes. Not cryptographic and it does not need to be: a
 * collision here marks one frame as a duplicate of another, which is a wrong
 * annotation on one row rather than anything unsafe - and the length and the
 * timestamp window have to agree as well.
 *
 * The whole frame, not a prefix. A prefix is what makes two different frames
 * on one TCP stream look identical - they share their headers and differ only
 * in the payload, which is exactly the part a prefix would skip.
 */
function hashFrame(bytes: Uint8Array): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

interface Seen {
  frameId: number;
  interfaceName: string;
  tsUs: number;
  length: number;
}

export interface DuplicateMark {
  frameId: number;
  /** The earlier frame this one repeats. */
  ofFrameId: number;
  /** The interface that earlier frame arrived on. */
  onInterface: string;
}

/**
 * Finds frames that repeat an earlier one from another adapter.
 *
 * Stateful across calls so a live capture can be fed flush by flush, and
 * bounded: entries older than the window are dropped as they are passed, so a
 * capture of any length holds only the few milliseconds it is still comparing
 * against.
 */
export class DuplicateFinder {
  private byHash = new Map<number, Seen[]>();
  /** Most recent timestamp seen, for expiring entries as time moves forward. */
  private nowUs = 0;

  reset(): void {
    this.byHash.clear();
    this.nowUs = 0;
  }

  /**
   * Marks duplicates within a batch, returning what it marked.
   *
   * The frames are mutated - the duplicate bit is set on `Packet.direction` -
   * because the alternative is a parallel structure keyed on frame id that
   * everything downstream would have to consult. The returned list is what the
   * caller turns into Info suffixes and expert entries.
   */
  scan(packets: readonly Packet[]): DuplicateMark[] {
    const marks: DuplicateMark[] = [];
    for (const packet of packets) {
      const bytes = packet.rawBytes;
      // A frame whose bytes have been evicted cannot be compared, and a frame
      // with none never had any. Both are skipped rather than guessed at.
      if (!bytes || bytes.length === 0) continue;
      if (packet.tsUs > this.nowUs) this.nowUs = packet.tsUs;

      const hash = hashFrame(bytes);
      let bucket = this.byHash.get(hash);
      if (bucket === undefined) {
        bucket = [];
        this.byHash.set(hash, bucket);
      } else {
        // Expire as we pass, which is what keeps this bounded without a
        // sweep: a bucket is only ever touched when a frame hashes into it.
        let live = 0;
        for (const seen of bucket) {
          if (packet.tsUs - seen.tsUs <= DUPLICATE_WINDOW_US) bucket[live++] = seen;
        }
        bucket.length = live;
      }

      const earlier = bucket.find(
        (seen) => seen.interfaceName !== packet.interfaceName
          && seen.length === packet.length,
      );
      if (earlier !== undefined) {
        packet.direction = withDuplicate(packet.direction);
        marks.push({
          frameId: packet.id,
          ofFrameId: earlier.frameId,
          onInterface: earlier.interfaceName,
        });
        // Not recorded as a candidate itself. Three adapters carrying one
        // frame should give two frames each marked against the first, rather
        // than a chain where the third points at the second.
        continue;
      }

      bucket.push({
        frameId: packet.id, interfaceName: packet.interfaceName,
        tsUs: packet.tsUs, length: packet.length,
      });
      // A bucket that grows without bound is a hash collision on a frame that
      // repeats constantly - a keepalive, a beacon. The window bounds it in
      // time; this bounds it against a pathological case within the window.
      if (bucket.length > 64) bucket.splice(0, bucket.length - 64);
    }
    if (this.byHash.size > 50_000) this.byHash.clear();
    return marks;
  }
}

/** The Info suffix a marked frame carries, in the same shape as the others. */
export function duplicateSuffix(mark: DuplicateMark): string {
  return ` [Duplicate of frame ${mark.ofFrameId} on ${mark.onInterface}]`;
}
