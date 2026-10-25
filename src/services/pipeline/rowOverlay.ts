/**
 * What the coordinator's merge writes to a shard's row, carried beside the row
 * rather than in it (ADR 0053 phase 6).
 *
 * A shard packs its rows into one buffer (`rowPack.ts`) that the coordinator
 * forwards to the window and the store without re-encoding. The merge still
 * writes to each row after the shard is done with it - `tls.stream` numbered in
 * capture order, the process, a live gap, a fingerprint match, the clock's
 * precision - and those writes travel here, applied by the receiver over the
 * row it unpacks.
 *
 * **What is covered is a list, not a diff.** Diffing the whole row would cost a
 * copy of it per frame, which is the cost packing removes. The merge's writers
 * are few and known: `settleField` (`tls.stream`), `writeProcessFields` and
 * `learnOrLabelFingerprint` (`inwire.process.*`), `markLiveGap`
 * (`inwire.live.skipped` and an `expert` entry), and `emitMerged`'s clock.
 * `scripts/pipeline/row-overlay.ts` runs every one of them and fails on a write
 * this list does not carry - which is the only thing that would notice, since
 * a lost write renders as an absence.
 */
import type { Packet } from '../../types/packet';

export interface RowOverlay {
  fields?: Record<string, string | number>;
  expert?: Packet['expert'];
  tsPrecision?: number;
  tsNanos?: bigint;
}

/** The covered keys' values before the merge, to compare against after it. */
export interface OverlayMark {
  fields: Map<string, string | number>;
  expert: Packet['expert'];
  expertLength: number;
  tsPrecision: number | undefined;
  tsNanos: bigint | undefined;
}

function covered(abbrev: string): boolean {
  return abbrev === 'tls.stream' || abbrev.startsWith('inwire.');
}

export function overlayMark(packet: Packet): OverlayMark {
  const fields = new Map<string, string | number>();
  if (packet.fields) {
    for (const key in packet.fields) if (covered(key)) fields.set(key, packet.fields[key]);
  }
  return {
    fields,
    expert: packet.expert,
    expertLength: packet.expert?.length ?? 0,
    tsPrecision: packet.tsPrecision,
    tsNanos: packet.tsNanos,
  };
}

/** What the merge wrote since `mark`, or null when it wrote nothing covered. */
export function overlayOf(packet: Packet, mark: OverlayMark): RowOverlay | null {
  let overlay: RowOverlay | null = null;
  if (packet.fields) {
    for (const key in packet.fields) {
      if (!covered(key)) continue;
      const value = packet.fields[key];
      if (mark.fields.get(key) === value && mark.fields.has(key)) continue;
      ((overlay ??= {}).fields ??= {})[key] = value;
    }
  }
  const expert = packet.expert;
  if (expert !== mark.expert || (expert?.length ?? 0) !== mark.expertLength) {
    (overlay ??= {}).expert = expert === undefined ? undefined : expert.slice();
  }
  if (packet.tsPrecision !== mark.tsPrecision) (overlay ??= {}).tsPrecision = packet.tsPrecision;
  if (packet.tsNanos !== mark.tsNanos) (overlay ??= {}).tsNanos = packet.tsNanos;
  return overlay;
}

/**
 * The overlay over its row. A row the window split as it decoded already has
 * its dense keys in a FieldBlock, and `tls.stream` is one of them: a value put
 * in the bag instead would be shadowed by the shard's provisional one, because
 * readers ask the block first. So a key the block has a column for goes there.
 */
export function applyOverlay(packet: Packet, overlay: RowOverlay): void {
  if (overlay.fields) {
    const block = packet.cols;
    const row = packet.row;
    for (const key in overlay.fields) {
      const value = overlay.fields[key];
      if (block === undefined || row === undefined || !block.tryWrite(row, key, value)) (packet.fields ??= {})[key] = value;
    }
  }
  if ('expert' in overlay) packet.expert = overlay.expert;
  if ('tsPrecision' in overlay) packet.tsPrecision = overlay.tsPrecision;
  if ('tsNanos' in overlay) packet.tsNanos = overlay.tsNanos;
}
