/**
 * The words the Monitoring sheet and its panel section say, and the small
 * decisions behind them, kept out of the components so the same state always
 * reads the same way in both places.
 *
 * Plain functions of `MonitoringState`, with no React: nothing here re-renders
 * anything, and the panel line and the sheet's header line are one answer.
 */
import { MAX_STORAGE_BYTES, readSourceConfig } from '../../services/monitoring/config';
import type { IntakeStopReason } from '../../services/monitoring/control';
import { nothingArriving, type MonitoringState } from '../../services/monitoring/state';
import { DEFAULT_RETENTION, validateRetentionPolicy, type RetentionPolicy } from '../../services/monitoring/retention';
import type { SamplingStatus, SequenceStatus } from '../../services/monitoring/exporterState';
import { parseSourceKey } from '../../services/monitoring/sourceKeys';
import { LIMITS, type ClockStatus, type ExpiryCause, type RangeSampling, type SourceConfig } from '../../services/monitoring/types';

export type Tone = 'neutral' | 'progress' | 'good' | 'warn' | 'bad';

export interface Summary { text: string; tone: Tone }

/**
 * Where the history lives: `monitoring` under the app's data folder, which main
 * moves out of Roaming (`app.setPath('userData', ...)` in `electron/main.ts`).
 * The renderer cannot ask, so it is named the way the capture folder is.
 */
export const MONITORING_FOLDER = '%LOCALAPPDATA%\\Inwire\\monitoring';

/** The stop-reason copy, verbatim from the brief. */
export function stopReasonText(reason: IntakeStopReason | null, error: string | null): string | null {
  switch (reason) {
    case 'user': return 'Stopped.';
    case 'quit': return 'Stopped when Inwire last quit.';
    case 'suspend': return 'Stopped while the computer slept — press Start.';
    case 'socket-error': return `Stopped: the socket failed — ${error ?? 'no reason was given'}.`;
    case 'storage-limit': return 'Stopped: the history reached its storage limit.';
    case 'storage-failed': return `Stopped: the history could not be written — ${error ?? 'no reason was given'}. Nothing after this was recorded.`;
    default: return null;
  }
}

/**
 * One line for where monitoring is: the panel section shows it under its title,
 * the sheet beside its own. Main sends no status until the sheet has connected,
 * so before that the only honest answer is "Not started".
 */
export function monitoringSummary(state: MonitoringState, nowMs: number): Summary {
  const { intake } = state;
  if (state.runtime === 'unavailable') return { text: state.problem ?? 'Monitoring is not available.', tone: 'bad' };
  if (intake?.listener === 'failed') {
    return { text: `Could not listen: ${intake.listenerError ?? 'no reason was given'}`, tone: 'bad' };
  }
  if (state.runtime === 'connecting') return { text: 'Opening history…', tone: 'progress' };
  if (state.runtime === 'idle' || intake === null) return { text: 'Not started', tone: 'neutral' };
  if (intake.listener === 'starting') return { text: 'Starting…', tone: 'progress' };
  if (intake.listener === 'listening') {
    if (state.health?.freshness === 'stale') return { text: 'No recent export', tone: 'warn' };
    if (state.health?.freshness === 'fresh' || intake.received > 0) return { text: 'Receiving', tone: 'good' };
    if (nothingArriving(state, nowMs)) return { text: 'Listening, nothing received yet', tone: 'warn' };
    return { text: 'Listening, nothing received yet', tone: 'progress' };
  }
  const reason = stopReasonText(intake.stopReason, intake.listenerError ?? intake.storageError);
  const bad = intake.stopReason === 'socket-error' || intake.stopReason === 'storage-failed'
    || intake.stopReason === 'storage-limit';
  // A collector that was never started has no reason to give: it is not stopped, it is not started.
  return { text: reason ?? 'Not started', tone: bad ? 'bad' : 'neutral' };
}

// --- the source form ---------------------------------------------------------------------------------

export interface SourceDraft {
  exporterIPv4: string;
  bindIPv4: string;
  port: string;
  /** In `unit`s, as typed. */
  limit: string;
  unit: 'MiB' | 'GiB';
}

export type FieldErrors = Partial<Record<'exporterIPv4' | 'bindIPv4' | 'port' | 'limit', string>>;

const MiB = 1024 * 1024;
const UNIT_BYTES = { MiB, GiB: 1024 * MiB } as const;

/** A field is judged by the service's own rule, holding every other field at a value it accepts. */
const PROBE: SourceConfig = {
  exporterIPv4: '192.0.2.1', bindIPv4: '127.0.0.1', port: 2055, storageLimitBytes: LIMITS.minStorageBytes,
};
const accepts = (patch: Partial<SourceConfig>): boolean => readSourceConfig({ ...PROBE, ...patch }) !== null;
const DOTTED = /^\d{1,3}(\.\d{1,3}){3}$/;

export function draftFromConfig(config: SourceConfig | null): SourceDraft {
  const bytes = config?.storageLimitBytes ?? LIMITS.defaultStorageBytes;
  const unit = bytes % UNIT_BYTES.GiB === 0 || bytes >= UNIT_BYTES.GiB ? 'GiB' : 'MiB';
  const amount = bytes / UNIT_BYTES[unit];
  return {
    exporterIPv4: config?.exporterIPv4 ?? '',
    bindIPv4: config?.bindIPv4 ?? '',
    port: String(config?.port ?? 2055),
    limit: Number.isInteger(amount) ? String(amount) : amount.toFixed(2),
    unit,
  };
}

/** The draft as a config the service accepts, or the reason for each field it would not. */
export function readDraft(draft: SourceDraft): { config: SourceConfig | null; errors: FieldErrors } {
  const errors: FieldErrors = {};
  const exporter = draft.exporterIPv4.trim();
  const bind = draft.bindIPv4.trim();
  if (exporter === '') errors.exporterIPv4 = 'Enter the exporter’s IPv4 address.';
  else if (!accepts({ exporterIPv4: exporter })) {
    errors.exporterIPv4 = DOTTED.test(exporter)
      ? 'That address names no one in particular. Enter the exporter’s own address.'
      : 'Enter four numbers from 0 to 255 separated by dots, such as 192.168.1.1.';
  }
  if (bind === '') errors.bindIPv4 = 'Enter the address of this PC that the exporter sends to.';
  else if (bind === '0.0.0.0') {
    errors.bindIPv4 = '0.0.0.0 would listen on every network adapter. Name the address of this PC the exporter sends to.';
  } else if (!accepts({ bindIPv4: bind })) {
    errors.bindIPv4 = 'Enter four numbers from 0 to 255 separated by dots, such as 192.168.1.20.';
  }
  const port = Number(draft.port.trim());
  if (draft.port.trim() === '' || !accepts({ port })) errors.port = 'A port is a whole number from 1 to 65535.';
  const amount = Number(draft.limit.trim());
  const bytes = Math.round(amount * UNIT_BYTES[draft.unit]);
  if (draft.limit.trim() === '' || !Number.isFinite(amount) || !accepts({ storageLimitBytes: bytes })) {
    // `readSourceConfig` refuses both ends and says neither, so which one it was is read from the number.
    errors.limit = draft.limit.trim() !== '' && Number.isFinite(amount) && bytes > MAX_STORAGE_BYTES
      ? 'The history can be at most 64 TiB.'
      : 'The history needs at least 16 MiB.';
  }
  if (Object.keys(errors).length > 0) return { config: null, errors };
  return { config: readSourceConfig({ exporterIPv4: exporter, bindIPv4: bind, port, storageLimitBytes: bytes }), errors };
}

export const sameConfig = (a: SourceConfig | null, b: SourceConfig | null): boolean =>
  a !== null && b !== null && a.exporterIPv4 === b.exporterIPv4 && a.bindIPv4 === b.bindIPv4
  && a.port === b.port && a.storageLimitBytes === b.storageLimitBytes;

// --- storage: retention and expiry ---------------------------------------------------------------

export interface RetentionDraft {
  /** Whether raw evidence expires by age at all. */
  keep: boolean;
  /** Whole days, as typed. */
  days: string;
  atLimit: RetentionPolicy['atLimit'];
}

export function retentionDraftFrom(policy: RetentionPolicy): RetentionDraft {
  return { keep: policy.keepRawDays !== null, days: String(policy.keepRawDays ?? 30), atLimit: policy.atLimit };
}

export const DEFAULT_RETENTION_DRAFT: RetentionDraft = retentionDraftFrom(DEFAULT_RETENTION);

/** The draft as a policy the service accepts, or the reason it would not. */
export function readRetentionDraft(draft: RetentionDraft): { policy: RetentionPolicy | null; error?: string } {
  const days = draft.keep ? Number(draft.days.trim()) : null;
  const policy = validateRetentionPolicy({ keepRawDays: days, atLimit: draft.atLimit });
  return policy === null ? { policy: null, error: 'Days is a whole number from 1 to 36500.' } : { policy };
}

export const sameRetention = (a: RetentionPolicy, b: RetentionPolicy): boolean =>
  a.keepRawDays === b.keepRawDays && a.atLimit === b.atLimit;

export const EVIDENCE_EXPIRED_LEGEND = 'Evidence expired';
export const INCOMPLETE_EXPIRED_MINUTE = 'Not available: this minute exceeded the key budget, and its evidence has expired.';
export const RETENTION_OFF_NOTE = 'Nothing expires unless you turn this on';

export const expiryDate = (ms: number): string =>
  new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Why a range has totals and no detail, said by what removed the detail. */
export function evidenceExpiredText(expiry: ExpiryCause | null, expiredMs: number): string {
  const tail = 'Totals come from retained minute rollups.';
  if (expiry?.kind === 'retention') {
    return `Detailed evidence for this range expired on ${expiryDate(expiry.atMs)} under the retention policy. ${tail}`;
  }
  if (expiry?.kind === 'discard') {
    return `Detailed evidence for this range was discarded before ${expiryDate(expiry.atMs)}. ${tail}`;
  }
  return `Detailed evidence for this range expired before ${expiryDate(expiredMs + 1)}. ${tail}`;
}

// --- numbers and times -------------------------------------------------------------------------------

const GROUPED = new Intl.NumberFormat(undefined);

/** A counter as a person reads it, grouped; bigint counters stay exact. */
export const count = (n: number | bigint): string => GROUPED.format(n);

export function localTime(ms: number, withDate = false): string {
  const d = new Date(ms);
  return withDate
    ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function localRange(fromMs: number, toMs: number): string {
  const sameDay = new Date(fromMs).toDateString() === new Date(toMs).toDateString();
  const short = (ms: number) => new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  return sameDay ? `${short(fromMs)}–${short(toMs)}` : `${localTime(fromMs, true)} – ${localTime(toMs, true)}`;
}

/** A source key as the selector labels it: a v5 engine, or what a v9 or IPFIX source calls itself. */
export function engineLabel(key: string): string {
  const parsed = parseSourceKey(key);
  if (parsed?.protocol === 'v9') return `NetFlow v9, source ID ${parsed.a}`;
  if (parsed?.protocol === 'ipfix') return `IPFIX, domain ${parsed.a}`;
  const parts = key.split('/');
  return parts.length === 3 ? `engine ${parts[1]}/${parts[2]}` : key;
}

// --- v9 and IPFIX: templates, sampling, clock, sequence (ADRs 0064-0066) -------------------------------

/** Every element a template carries that Inwire does not read, as the spec words it; null when there is none. */
export function notInterpretedText(elements: { pen: number | null; ie: number }[]): string | null {
  if (elements.length === 0) return null;
  return `not interpreted: ${elements.map((e) => (e.pen === null ? `IE ${e.ie}` : `PEN ${e.pen} / IE ${e.ie}`)).join(', ')}`;
}

/** The word an estimate carries wherever it is shown, so it is never read as a reported figure. */
export const ESTIMATE_LABEL = 'estimate';

/**
 * A source's sampling as it is stated now (`SamplingStatus`), or a range's (`RangeSampling`), which adds
 * `mixed`. Absent is never read as 1:1: counters stay as reported either way.
 */
export function samplingText(s: SamplingStatus | RangeSampling | { kind: 'unsupported'; reason?: string }): Summary {
  switch (s.kind) {
    case 'known':
      return { text: `Sampled 1 in ${count(s.interval)}${'sinceEntryId' in s ? ` since entry ${count(s.sinceEntryId)}` : ''}`, tone: 'neutral' };
    case 'absent':
      return { text: 'Sampling not stated by the exporter: counters are as reported, never assumed 1:1', tone: 'neutral' };
    case 'unsupported':
      return { text: `Sampling unsupported${'reason' in s && s.reason ? `: ${s.reason}` : ''}; counters are as reported`, tone: 'warn' };
    case 'mixed':
      return { text: 'Sampling changed within this range: no one rate applies, so there is no estimate', tone: 'warn' };
  }
}

/**
 * Reported counts scaled by the rate, only when the range's rate is known and the same throughout and every
 * matching record has one (`samplingKnown`: a range whose interval folds to one rate may still hold records of
 * unknown rate, which the interval would wrongly scale). Kept
 * apart from the reported totals, and labelled `ESTIMATE_LABEL` wherever it shows. 1 in 1 is no sampling.
 */
export function samplingEstimate(s: RangeSampling, samplingKnown: boolean, octets: bigint, packets: bigint): { interval: number; octets: bigint; packets: bigint } | null {
  if (!samplingKnown || s.kind !== 'known' || s.interval <= 1) return null;
  const n = BigInt(s.interval);
  return { interval: s.interval, octets: octets * n, packets: packets * n };
}

function skewWords(ms: number): string {
  const abs = Math.abs(ms);
  const amount = abs >= 60_000 ? `${(abs / 60_000).toFixed(1)} min` : abs >= 10_000 ? `${Math.round(abs / 1000)} s` : `${(abs / 1000).toFixed(1)} s`;
  return abs < 100 ? 'level with receipt' : `${amount} ${ms > 0 ? 'ahead' : 'behind'}`;
}

/** The export clock against receipt time: export minus receipt, so ahead is positive. Flagged past `LIMITS.clockFlagMs`. */
export function clockText(c: ClockStatus): Summary {
  if (c.latestSkewMs === null) return { text: 'No export time received yet', tone: 'neutral' };
  let text = `Export clock ${skewWords(c.latestSkewMs)}`;
  if (c.minSkewMs !== null && c.maxSkewMs !== null && c.minSkewMs !== c.maxSkewMs) {
    text += ` (between ${skewWords(c.minSkewMs)} and ${skewWords(c.maxSkewMs)})`;
  }
  if (c.flagged) text += `, past the ${Math.round(LIMITS.clockFlagMs / 1000)} s threshold`;
  return { text, tone: c.flagged ? 'warn' : 'good' };
}

/** How the source's sequence numbers are read, and what they suggest: an export gap is evidence, not loss. */
export function sequenceText(s: SequenceStatus): string {
  const mode = {
    learning: 'Learning how this exporter numbers its exports',
    rfc: 'Numbered as the RFC says',
    'own-records': 'Numbered by its own records',
    unrecognized: 'Numbering not recognized: gaps are not counted',
  }[s.mode];
  if (s.mode === 'learning' || s.mode === 'unrecognized') return mode;
  const gaps = s.suspectedGap === 0 ? 'no suspected export gaps' : `${count(s.suspectedGap)} skipped in its numbering (a suspected export gap, not network loss)`;
  const reordered = s.reordered === 0 ? '' : `, ${count(s.reordered)} out of order`;
  return `${mode}; ${gaps}${reordered}`;
}

export const PROTOCOLS: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP' };
