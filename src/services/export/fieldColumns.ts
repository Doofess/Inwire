/**
 * Every dissected field, as columns.
 *
 * CSV and Excel are one row per frame, so "every field" has to become a fixed
 * set of columns before the first row is written - and a whole-capture export
 * never holds the capture, so that set cannot be read off an array. It comes
 * from a **survey**: one pass over the rows (no bytes), folding the union of
 * every frame's field keys. The export then writes against that set, and a
 * frame that lacks a field leaves its cell empty.
 *
 * Wide rather than long - one column per field, not one row per (frame,
 * field) - because a row is still a frame: the importer reads the same file
 * back, and a spreadsheet user filters a column rather than pivoting a table.
 *
 * ## Order
 *
 * By `LAYERS`, outermost first, then by position in the registry - the order a
 * reader meets the fields in Wireshark's tree, so `eth.*` sits before `ip.*`
 * before `tcp.*` before `tls.*`. A key the registry does not know (none today;
 * `scripts/dissect/registry.ts` fails a dissector that writes one) goes last,
 * in plain code-unit order, so the order never depends on what the survey
 * happened to see first.
 *
 * ## Headers are abbreviations
 *
 * Exactly `ip.src`, `tcp.flags.syn` - the Wireshark filter name, which is what
 * the registry promises a field is called everywhere. A friendlier label would
 * be a second vocabulary, and the abbreviation is the one a reader can paste
 * into the filter bar. It is also why the importer ignores dotted headers when
 * it looks for its own columns (`exportSchema.matchHeaders`): `frame.len`
 * normalises to a spelling of Length.
 */
import type { Packet } from '../../types/packet';
import { fieldEntries } from '../dissect/fieldAccess';
import { FIELDS, LAYERS, fieldDef, type FieldType } from '../dissect/fieldRegistry';

export interface FieldColumn {
  /** The key in `Packet.fields`, which is also the header. */
  abbrev: string;
  /** The registry's type, when the registry knows the field. */
  type: FieldType | undefined;
  /** Frames that carry the field, in what was surveyed. */
  frames: number;
}

const LAYER_INDEX = new Map<string, number>(LAYERS.map((token, index) => [token, index]));
const FIELD_INDEX = new Map<string, number>(FIELDS.map((def, index) => [def.abbrev, index]));
const UNREGISTERED = Number.MAX_SAFE_INTEGER;

/**
 * Sort keys, memoised: JSON sorts every frame's fields, so the same few
 * hundred abbreviations are ranked millions of times on a large capture.
 */
const RANKS = new Map<string, readonly [number, number]>();

/** Sort key for one abbreviation: layer, then registry position. */
function rankOf(abbrev: string): readonly [number, number] {
  let rank = RANKS.get(abbrev);
  if (rank === undefined) {
    const def = fieldDef(abbrev);
    rank = def
      ? [LAYER_INDEX.get(def.layer) ?? UNREGISTERED - 1, FIELD_INDEX.get(abbrev) ?? UNREGISTERED]
      : [UNREGISTERED, UNREGISTERED];
    RANKS.set(abbrev, rank);
  }
  return rank;
}

/**
 * Compares two abbreviations in export order. Total: two different keys never
 * compare equal, so any collection of them sorts to one answer.
 */
export function compareAbbrevs(a: string, b: string): number {
  if (a === b) return 0;
  const [la, fa] = rankOf(a);
  const [lb, fb] = rankOf(b);
  return la - lb || fa - fb || (a < b ? -1 : 1);
}

/**
 * The fold. `add` each frame the export will write - the same frames, in any
 * order and in any pages - then `columns()`.
 */
export class FieldSurvey {
  private readonly counts = new Map<string, number>();
  private cellCount = 0;
  private frameCount = 0;

  add(packet: Packet): void {
    this.frameCount += 1;
    for (const [abbrev] of fieldEntries(packet)) {
      this.counts.set(abbrev, (this.counts.get(abbrev) ?? 0) + 1);
      this.cellCount += 1;
    }
  }

  addPage(page: readonly Packet[]): void {
    for (const packet of page) this.add(packet);
  }

  /** The columns, in export order. */
  columns(): FieldColumn[] {
    return [...this.counts.keys()]
      .sort(compareAbbrevs)
      .map((abbrev) => ({ abbrev, type: fieldDef(abbrev)?.type, frames: this.counts.get(abbrev)! }));
  }

  /**
   * Non-empty field cells the export will write: the sum over frames of the
   * fields each carries. What the Excel budget is measured in - a sparse
   * column costs exceljs nothing where it is empty.
   */
  get cells(): number {
    return this.cellCount;
  }

  get frames(): number {
    return this.frameCount;
  }
}

/** One pass over an array, for a caller that has one. */
export function surveyFields(packets: readonly Packet[]): FieldColumn[] {
  const survey = new FieldSurvey();
  survey.addPage(packets);
  return survey.columns();
}

/**
 * One frame's fields, in export order, for a writer that writes them per frame
 * (JSON) rather than as columns. Needs no survey.
 */
export function orderedFieldEntries(packet: Packet): [string, string | number][] {
  return fieldEntries(packet).sort((a, b) => compareAbbrevs(a[0], b[0]));
}

/**
 * A reader of one frame's fields by column position.
 *
 * `fieldEntries` once per frame into a map, rather than `fieldValue` per
 * column: with ~170 surveyed columns and ~27 fields a frame, asking each
 * column is six times the work of asking the frame once.
 */
export function fieldRow(packet: Packet, columns: readonly FieldColumn[]): (string | number | undefined)[] {
  const out: (string | number | undefined)[] = new Array(columns.length);
  if (columns.length === 0) return out;
  const values = new Map(fieldEntries(packet));
  for (let i = 0; i < columns.length; i++) out[i] = values.get(columns[i].abbrev);
  return out;
}
