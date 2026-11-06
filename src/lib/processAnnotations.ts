import type { Packet } from '../types/packet';
import type { FlowAnnotationStore } from '../services/flowAnnotations';
import { fieldValue } from '../services/dissect/fieldAccess';
import { processForPacket, writeProcessFields } from '../services/dissect/processFields';
import { adoptInSlices } from './adoptSlices';

/**
 * Names the process behind each frame of the buffer that does not have one yet,
 * from a socket table that arrived after the frame (`App.applySocketTable`).
 * Frames older than `horizonUs` are left alone. Returns `prev` itself when
 * nothing changed, so React keeps the buffer.
 */
export function annotateProcesses(prev: Packet[], horizonUs: number, store: FlowAnnotationStore): Packet[] {
  let changed = false;
  const next = prev.map((packet) => {
    if (packet.tsUs < horizonUs) return packet;
    if (fieldValue(packet, 'inwire.process.name') !== undefined) return packet;
    const process = processForPacket(packet, store);
    if (!process) return packet;
    changed = true;
    // A copy, because a packet already handed to React is not ours to
    // mutate - a row that changed in place would not re-render.
    //
    // The spread carries `cols` and `row` across, which is what we
    // want: the copy shares the original's block and its row, and a row
    // is written only before the frame joins the buffer (as its pack
    // decodes and its overlay applies, or in `absorb`) and never after,
    // so two packets reading it see the same values. What is written
    // HERE goes to the bag, because the process fields are declared
    // post-dissection and so are never dense (`dissect/denseFields.ts`,
    // asserted in `scripts/dissect/dense-fields.ts`).
    const copy: Packet = { ...packet, fields: { ...packet.fields } };
    writeProcessFields(copy, process);
    return copy;
  });
  return changed ? next : prev;
}

/**
 * How far back the socket tables applied during an import's adoption reached:
 * the lowest horizon of any of them, or null when none arrived. The slices of an
 * adoption replace the buffer with prefixes of the imported rows, which have none
 * of what a table added between two slices.
 */
export class AnnotationReach {
  private lowest = Infinity;

  /** An adoption begins: what was applied before it belongs to a buffer that is gone. */
  begin(): void {
    this.lowest = Infinity;
  }

  /** A socket table was applied to the buffer with this horizon. */
  note(horizonUs: number): void {
    if (horizonUs < this.lowest) this.lowest = horizonUs;
  }

  /** The lowest horizon noted since `begin`, or null. */
  reach(): number | null {
    return this.lowest === Infinity ? null : this.lowest;
  }
}

export interface AdoptionHooks {
  /** False once a newer adoption owns the buffer: the slices stop. */
  current(): boolean;
  /** The first slice: the adoption itself. */
  adoptFirst(prefix: Packet[]): void;
  /** A later slice replaces the buffer with a longer prefix. */
  showPrefix(prefix: Packet[]): void;
  /** How far back socket tables applied since the adoption began (`AnnotationReach.reach`). */
  annotatedReach(): number | null;
  /** Re-runs the process annotator over the buffer as it stands. */
  reannotate(horizonUs: number): void;
}

/**
 * `adoptInSlices` for an import, which re-runs the process annotator once after
 * the last slice when a socket table landed between slices: each later slice sets
 * the buffer to a prefix of the imported rows, and the copies the annotator made
 * of the earlier slice's rows go with it.
 */
export function adoptImportedRows(
  rows: Packet[],
  sliceRows: number,
  hooks: AdoptionHooks,
  nextTask: () => Promise<void>,
): Promise<boolean> {
  return adoptInSlices(rows, sliceRows, (prefix, first) => {
    if (!hooks.current()) return false;
    if (first) {
      hooks.adoptFirst(prefix);
      return true;
    }
    hooks.showPrefix(prefix);
    if (prefix === rows) {
      // After the buffer is set, so the annotator runs over the rows that stay.
      const reach = hooks.annotatedReach();
      if (reach !== null) hooks.reannotate(reach);
    }
    return true;
  }, nextTask);
}
