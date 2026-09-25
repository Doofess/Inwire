/**
 * What the three row formats - CSV, JSON, Excel - share: their options, and
 * the per-frame work of turning a frame into its standard values.
 */
import type { ColorRule, Packet } from '../../../types/packet';
import { standardValues, type StandardValue } from '../../exportSchema';
import type { CaptureMeta } from '../captureMeta';
import type { FieldColumn } from '../fieldColumns';
import { RuleMatcher } from '../ruleMatcher';
import type { Anonymiser } from '../../anonymise';
import { adapterLabel, redactFilter } from '../../report/redact';

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
 * alone, and a device path - `\Device\NPF_{GUID}` - identifies this machine's
 * install as surely as a MAC does. So an anonymised export labels adapters the
 * way `report/redact.ts`'s `redactMeta` does, through the same `adapterLabel`:
 * a friendly name stays with any address in it mapped, a GUID or device path
 * becomes `adapter N`. N is the adapter's place in `adapters` - the list
 * `redactMeta` numbered - and, for one not in it (an import names its own),
 * the order adapters first appear after those.
 *
 * With no anonymiser to map through, every adapter becomes `adapter N`:
 * withholding a friendly name costs a reader little, and publishing a device
 * path is the one mistake this exists to prevent.
 */
export class AdapterLabels {
  private readonly order: string[];
  private readonly labels = new Map<string, string>();

  constructor(private readonly options: Pick<TabularOptions, 'meta' | 'anonymiser' | 'adapters'>) {
    this.order = [...(options.adapters ?? [])];
  }

  get anonymised(): boolean {
    return this.options.meta?.flags.anonymised === true;
  }

  label(name: string): string {
    if (!this.anonymised || name === '') return name;
    let label = this.labels.get(name);
    if (label === undefined) {
      let index = this.order.indexOf(name);
      if (index < 0) index = this.order.push(name) - 1;
      label = this.options.anonymiser ? adapterLabel(this.options.anonymiser, name, index) : `adapter ${index + 1}`;
      this.labels.set(name, label);
    }
    return label;
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
