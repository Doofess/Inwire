/**
 * What the three row formats - CSV, JSON, Excel - share: their options, and
 * the per-frame work of turning a frame into its standard values.
 */
import type { ColorRule, Packet } from '../../../types/packet';
import { guardFormula, standardValues, type ColumnKind, type StandardValue } from '../../exportSchema';
import { isoMicros } from '../captureMeta';
import type { CaptureMeta } from '../captureMeta';
import type { FieldColumn } from '../fieldColumns';
import { RuleMatcher } from '../ruleMatcher';
import type { Anonymiser } from '../../anonymise';
import { AdapterNumbering, redactFilter } from '../../report/redact';

export interface TabularOptions {
  /** Append each frame's bytes, base64. */
  includeRawBytes: boolean;
  /**
   * The field columns, from the survey (`FieldSurvey`). Absent or empty, no
   * field columns are written. JSON needs none: it writes each frame's own.
   */
  fields?: readonly FieldColumn[];
  /** Printed at the top of the file. Absent, the file carries none. */
  meta?: CaptureMeta;
  /** The colour chain frames are matched against; the shipped one when absent. */
  colorRules?: readonly ColorRule[];
  /**
   * The job's anonymiser, when `meta` says the export is anonymised - the one
   * that rewrote the frames and `redactMeta`, so an adapter label here is the
   * label the metadata prints. See `AdapterLabels`.
   */
  anonymiser?: Anonymiser;
  /**
   * The capture's adapters by their REAL labels, in the order `meta.source`
   * listed them before redaction - what numbers `adapter N` the way
   * `redactMeta` numbers it.
   */
  adapters?: readonly string[];
}

/**
 * The Interface column, and pcapng's `if_name`, for an export that may be
 * anonymised.
 *
 * The anonymiser rewrites a frame's addresses and leaves `interfaceName`
 * alone, and an adapter's name - "Ethernet (Intel(R) Ethernet Controller (3)
 * I225-V)", or a device path `\Device\NPF_{GUID}` - identifies this machine.
 * So an anonymised export labels every adapter the way `report/redact.ts`'s
 * `redactMeta` does: `adapter N`, where N is the adapter's place in `adapters`
 * - the list `redactMeta` numbered - and, for one not in it (an import names
 * its own), the order adapters first appear after those.
 */
export class AdapterLabels {
  private readonly numbering: AdapterNumbering;

  constructor(private readonly options: Pick<TabularOptions, 'meta' | 'anonymiser' | 'adapters'>) {
    this.numbering = new AdapterNumbering(options.adapters ?? []);
  }

  get anonymised(): boolean {
    return this.options.meta?.flags.anonymised === true;
  }

  label(name: string): string {
    if (!this.anonymised || name === '') return name;
    return this.numbering.label(name);
  }

  /** A colour rule's filter, as the Capture sheet may print it. */
  filter(filter: string): string {
    if (!this.anonymised) return filter;
    return this.options.anonymiser ? redactFilter(this.options.anonymiser, filter) : '(withheld)';
  }
}

/**
 * Whether dissected fields are written at all.
 *
 * Not when the export is anonymised, whatever the caller passed: the
 * anonymiser drops each frame's field bag because every address, port and
 * name in it is the thing being removed (`anonymise.ts`), so columns for them
 * would be empty at best - and a caller that surveyed the real frames before
 * anonymising would otherwise publish their names as headers.
 */
export function writesFields(options: Pick<TabularOptions, 'meta'>): boolean {
  return options.meta?.flags.anonymised !== true;
}

/** Field columns to write, after the anonymisation rule. */
export function fieldColumnsFor(options: TabularOptions): readonly FieldColumn[] {
  return writesFields(options) ? options.fields ?? [] : [];
}

/**
 * Each frame's colour rule - the caller's answer when it has one (matched
 * before anonymising), else this writer's own match.
 */
export class RuleSource {
  private readonly matcher: RuleMatcher;

  constructor(rules: readonly ColorRule[] | undefined) {
    this.matcher = new RuleMatcher(rules);
  }

  ruleAt(page: readonly Packet[], index: number, given: readonly (ColorRule | null)[] | undefined): ColorRule | null {
    if (given !== undefined && index < given.length) return given[index];
    return this.matcher.match(page[index]);
  }

  enabledRules(): ColorRule[] {
    return this.matcher.enabledRules();
  }
}

/** A frame's standard values, split from its raw bytes (which sit after the field columns). */
export function splitValues(
  packet: Packet,
  rule: ColorRule | null,
  includeRawBytes: boolean,
  standardCount: number,
  labels?: AdapterLabels,
): { standard: StandardValue[]; raw: StandardValue | undefined } {
  const source = labels?.anonymised ? { ...packet, interfaceName: labels.label(packet.interfaceName) } : packet;
  const values = standardValues(source, rule, includeRawBytes);
  return includeRawBytes
    ? { standard: values.slice(0, standardCount), raw: values[standardCount] }
    : { standard: values, raw: undefined };
}

// --- one standard value as text ----------------------------------------------------
//
// Here rather than beside the schema: only the writers spell values, and
// `exportSchema.ts` is in the entry chunk (the importer reads it), so
// everything in it is paid for at launch.

/**
 * Epoch milliseconds to the microsecond, always with three decimals.
 *
 * `String(ms)` is the shortest string that reads back as the same double, and
 * so it drops trailing zeros: a frame at .120 ms printed `…989.12` and one at
 * .000 printed `…989`, and a column of them read as three precisions. Built
 * from the integer microseconds rather than with `toFixed(3)`, which formats
 * the double and can print one digit off: `ms * 1000` is within a fraction of
 * a microsecond of the integer the capture stored (an epoch is ~2^40 ms, and a
 * double's spacing there is 2^-12 ms), so rounding recovers it exactly.
 */
export function epochMsText(ms: number): string {
  const us = Math.round(ms * 1000);
  const abs = Math.abs(us);
  const whole = Math.floor(abs / 1000);
  return `${us < 0 ? '-' : ''}${whole}.${String(abs - whole * 1000).padStart(3, '0')}`;
}

/**
 * A standard value as text, the one spelling CSV writes and the importer reads.
 *
 * Time keeps its six places, as it always has; epoch milliseconds keep their
 * three (`epochMsText`); a date is ISO-8601 in UTC with all six digits. Text
 * is formula-guarded - base64 included, which can begin with `+`.
 */
export function standardText(kind: ColumnKind, value: StandardValue): string {
  if (value === null) return '';
  if (typeof value === 'string') return guardFormula(value);
  switch (kind) {
    case 'seconds': return value.toFixed(6);
    case 'epochMs': return epochMsText(value);
    case 'datetime': return isoMicros(value);
    default: return String(value);
  }
}
