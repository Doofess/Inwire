/**
 * What an export says about the capture it came from.
 *
 * One record, and one formatter, for every format: the pcapng section comment,
 * the CSV preamble, the JSON `meta`, the Excel Capture sheet and the PDF's
 * cover all print `metaEntries`. Five formatters would disagree about the
 * first thing a reader checks - how many frames, from where, and what was lost.
 *
 * ## A missing count is not a zero
 *
 * Drop counters come from the agent, and an agent that could not ask the
 * driver has no number to give. `null` stays `null` here and prints as "not
 * available", never as 0: a zero says the capture is complete, which is the
 * one claim nobody measured. Exporting a null `droppedKernel` as 0 is the bug
 * this rule exists to end.
 *
 * ## Fixed formatting
 *
 * `en-US` numbers and UTC ISO-8601 times, never the viewer's locale or zone.
 * An export is a file that leaves this machine, and a date that means the 3rd
 * of April here and the 4th of March elsewhere is worse than one that looks
 * foreign everywhere. It also makes the output deterministic, which is what
 * lets a test compare it.
 */

export type CaptureSource =
  /**
   * Captured here, from these adapters (their display names), with the
   * capture filter and snaplen the driver applied (`captureOptions.ts`) -
   * null when the capture asked for none. Undefined for a capture that
   * predates them, which is "not recorded" rather than "none".
   */
  | { kind: 'live'; adapters: string[]; filter?: string | null; snaplen?: number | null }
  /** Opened from a file. */
  | { kind: 'import'; fileName: string }
  /** Restored from a stored session, whose origin is no longer known. */
  | { kind: 'session' };

/** What the capture lost, by where it was lost. `null` is "not reported". */
export interface DropCounts {
  /** The driver's kernel buffer overflowed. */
  kernel: number | null;
  /** The agent's own queue overflowed. */
  agent: number | null;
  /** The pipe to the app backed up. */
  pipe: number | null;
}

/** Which frames the export holds. */
export type ExportScope = 'capture' | 'filtered';

export interface CaptureMeta {
  app: string;
  version: string;
  /** The OS the export was made on, as the caller describes it; null if unknown. */
  os: string | null;
  /** When the export was made, epoch milliseconds. */
  generatedAt: number;
  source: CaptureSource;
  /** First and last frame's capture time, epoch microseconds; null when empty. */
  firstUs: number | null;
  lastUs: number | null;
  frames: {
    /** Frames written into this export. */
    exported: number;
    /** Frames the capture holds, whatever the scope. */
    inCapture: number;
    /** Frames that could not be read back (a torn chunk) and are absent. */
    unreadable: number;
    /**
     * Frames written without their bytes, because the store could not supply
     * them. Known only once the frames are written, so present only where the
     * metadata is printed after them (Excel's Capture sheet); absent means it
     * was not measured, never zero.
     */
    withoutBytes?: number;
  };
  drops: DropCounts;
  scope: ExportScope;
  /** The display filter, when the scope is `filtered`; '' otherwise. */
  filter: string;
  flags: {
    anonymised: boolean;
    /** Frame bytes are included. */
    rawBytes: boolean;
    /** Every dissected field is included. */
    fields: boolean;
    /** Decryption secrets are included. */
    secrets: boolean;
  };
}

export type MetaEntry = readonly [key: string, value: string];

const NOT_AVAILABLE = 'not available';
const NUMBER = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const SECONDS = new Intl.NumberFormat('en-US', { minimumFractionDigits: 6, maximumFractionDigits: 6 });

function count(n: number | null): string {
  return n === null || !Number.isFinite(n) ? NOT_AVAILABLE : NUMBER.format(n);
}

/**
 * Epoch microseconds as UTC ISO-8601 with all six digits.
 *
 * `toISOString` stops at milliseconds, and a capture's timestamps are exact to
 * the microsecond - the last three digits are appended rather than dropped.
 *
 * Total: a timestamp no `Date` can hold - a corrupt record, a file whose
 * clock field is garbage - is printed as the raw count rather than throwing
 * `RangeError` out of the export. The metadata is the last place an export
 * should fail, and a raw number still says what the file claimed.
 */
export function isoMicros(us: number): string {
  const ms = Math.floor(us / 1000);
  const date = new Date(ms);
  if (!Number.isFinite(us) || Number.isNaN(date.getTime())) return `${us} µs since 1970 (out of range)`;
  const micros = String(Math.floor(us - ms * 1000)).padStart(3, '0');
  return date.toISOString().replace('Z', `${micros}Z`);
}

function yesNo(b: boolean): string {
  return b ? 'yes' : 'no';
}

function sourceText(source: CaptureSource): string {
  switch (source.kind) {
    case 'live':
      return source.adapters.length > 0
        ? `live capture on ${source.adapters.join(', ')}`
        : 'live capture';
    case 'import':
      return `imported from ${source.fileName}`;
    case 'session':
      return 'restored session';
  }
}

/** The metadata as ordered key/value text, the one form every format prints. */
export function metaEntries(meta: CaptureMeta): MetaEntry[] {
  const entries: MetaEntry[] = [
    ['Application', `${meta.app} ${meta.version}`],
    ['Operating system', meta.os ?? NOT_AVAILABLE],
    ['Generated', new Date(meta.generatedAt).toISOString()],
    ['Source', sourceText(meta.source)],
    // How the capture was narrowed before a frame was kept. A filter decides
    // which frames exist in the file at all and a snaplen how much of each,
    // so a reader who does not know them will misread both the counts and
    // the frames.
    ...(meta.source.kind === 'live'
      ? [
        ['Capture filter', meta.source.filter === undefined ? NOT_AVAILABLE : (meta.source.filter ?? 'none')] as MetaEntry,
        ['Snapshot length', meta.source.snaplen === undefined
          ? NOT_AVAILABLE
          : meta.source.snaplen === null ? 'whole frames' : `${meta.source.snaplen} bytes`] as MetaEntry,
      ]
      : []),
    ['First frame', meta.firstUs === null ? NOT_AVAILABLE : isoMicros(meta.firstUs)],
    ['Last frame', meta.lastUs === null ? NOT_AVAILABLE : isoMicros(meta.lastUs)],
    ['Duration', meta.firstUs === null || meta.lastUs === null
      ? NOT_AVAILABLE
      : `${SECONDS.format((meta.lastUs - meta.firstUs) / 1e6)} s`],
    ['Scope', meta.scope === 'filtered' ? 'frames matching the display filter' : 'the whole capture'],
  ];
  if (meta.scope === 'filtered') entries.push(['Display filter', meta.filter]);
  entries.push(
    ['Frames exported', count(meta.frames.exported)],
    ['Frames in capture', count(meta.frames.inCapture)],
    ['Frames unreadable', count(meta.frames.unreadable)],
    ...(meta.frames.withoutBytes === undefined
      ? []
      : [['Frames without bytes', count(meta.frames.withoutBytes)] as MetaEntry]),
    ['Dropped by the driver', count(meta.drops.kernel)],
    ['Dropped by the agent', count(meta.drops.agent)],
    ['Dropped on the pipe', count(meta.drops.pipe)],
    ['Anonymised', yesNo(meta.flags.anonymised)],
    ['Frame bytes included', yesNo(meta.flags.rawBytes)],
    ['Dissected fields included', yesNo(meta.flags.fields)],
    ['Decryption secrets included', yesNo(meta.flags.secrets)],
  );
  return entries;
}
