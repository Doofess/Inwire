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
import { LIMITS, type SourceConfig } from '../../services/monitoring/types';

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

/** An engine-form source key, `exporter/type/id`, as the selector labels it. */
export function engineLabel(key: string): string {
  const parts = key.split('/');
  return parts.length === 3 ? `engine ${parts[1]}/${parts[2]}` : key;
}

export const PROTOCOLS: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP' };
