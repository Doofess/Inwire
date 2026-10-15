/**
 * The speed test's history: this machine's results, kept here and nowhere else.
 *
 * Nothing is uploaded - the reason the engine is a port of Cloudflare's method
 * rather than their library, which posts every result to `/__results`. A
 * preference like any other, so it survives a restart and is normalised on the
 * way in: a damaged entry is dropped, never shown as a zero.
 */
import { createPreferenceStore } from '../preferenceStore';
import { WARMUP_MS } from './method';
import type { SpeedResult } from './protocol';

/** One remembered test: the four numbers and where it ran. */
export interface SpeedHistoryEntry {
  at: number;
  downMbps: number;
  upMbps: number;
  pingMs: number;
  jitterMs: number;
  grade: string;
  server: string | null;
  isp: string | null;
  /** The data centre and where it is, for the globe; absent on a test that was not placed. */
  colo?: string | null;
  lat?: number | null;
  lon?: number | null;
  /** Responsiveness and the loaded medians; absent on an entry older than them, shown as a dash. */
  rpm?: number | null;
  loadedDownMs?: number | null;
  loadedUpMs?: number | null;
}

/** The most kept; the oldest goes first. */
export const HISTORY_LIMIT = 50;

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const strOrNull = (v: unknown): string | null => (typeof v === 'string' && v.length <= 200 ? v : null);

export function normalizeHistory(raw: unknown): SpeedHistoryEntry[] | null {
  if (!Array.isArray(raw)) return null;
  const out: SpeedHistoryEntry[] = [];
  for (const e of raw) {
    if (typeof e !== 'object' || e === null) continue;
    const v = e as Record<string, unknown>;
    if (!isNum(v.at) || !isNum(v.downMbps) || !isNum(v.upMbps) || !isNum(v.pingMs)) continue;
    out.push({
      at: v.at, downMbps: v.downMbps, upMbps: v.upMbps, pingMs: v.pingMs,
      jitterMs: isNum(v.jitterMs) ? v.jitterMs : 0,
      grade: typeof v.grade === 'string' && /^(A\+|[A-DF])$/.test(v.grade) ? v.grade : '?',
      server: strOrNull(v.server),
      isp: strOrNull(v.isp),
      colo: typeof v.colo === 'string' && /^[A-Za-z]{3}$/.test(v.colo) ? v.colo : null,
      lat: typeof v.lat === 'number' && Math.abs(v.lat) <= 90 ? v.lat : null,
      lon: typeof v.lon === 'number' && Math.abs(v.lon) <= 180 ? v.lon : null,
      rpm: isNum(v.rpm) ? v.rpm : null,
      loadedDownMs: isNum(v.loadedDownMs) ? v.loadedDownMs : null,
      loadedUpMs: isNum(v.loadedUpMs) ? v.loadedUpMs : null,
    });
  }
  // Newest first, and no more than the limit, however it was stored.
  return out.sort((a, b) => b.at - a.at).slice(0, HISTORY_LIMIT);
}

export const speedHistoryStore = createPreferenceStore<SpeedHistoryEntry[]>(
  'inwire.speedTestHistory',
  normalizeHistory,
  [],
);

/** A finished test as history keeps it. */
export function historyEntry(result: SpeedResult): SpeedHistoryEntry {
  return {
    at: result.at,
    downMbps: result.download.mbps,
    upMbps: result.upload.mbps,
    pingMs: result.latency.idleMs,
    jitterMs: result.latency.jitterMs,
    grade: result.grade,
    server: result.server.coloCity ?? result.server.colo ?? null,
    isp: result.server.isp,
    colo: result.server.colo,
    lat: result.server.coloLat,
    lon: result.server.coloLon,
    rpm: result.summary.rpm,
    loadedDownMs: result.download.loadedLatencyMs,
    loadedUpMs: result.upload.loadedLatencyMs,
  };
}

/**
 * The last run's traces, for the next run's ghost. A key of its own rather
 * than a field of every history entry: one run's slices, not fifty.
 */
export interface LastTrace { at: number; download: number[]; upload: number[]; warmupMs: number }

/** Two transfers' slices with room to spare; past it the value is not one this build wrote. */
const LAST_TRACE_POINTS = 400;

const isTrace = (v: unknown): v is number[] =>
  Array.isArray(v) && v.length <= LAST_TRACE_POINTS && v.every(isNum);

export function normalizeLastTrace(raw: unknown): LastTrace | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  if (!isNum(v.at) || !isNum(v.warmupMs) || !isTrace(v.download) || !isTrace(v.upload)) return null;
  return { at: v.at, download: [...v.download], upload: [...v.upload], warmupMs: v.warmupMs };
}

export const lastTraceStore = createPreferenceStore<LastTrace | null>(
  'inwire.speedTestLastTrace.v1',
  normalizeLastTrace,
  null,
);

/**
 * Keeps a finished test: its entry, and its traces as the next run's ghost.
 * The sheet has already read the previous ghost - it takes it when a run
 * starts - so overwriting it here never draws a run against itself.
 */
export function recordResult(result: SpeedResult): void {
  speedHistoryStore.set([historyEntry(result), ...speedHistoryStore.get()].slice(0, HISTORY_LIMIT));
  lastTraceStore.set({
    at: result.at,
    download: result.download.trace.slice(-LAST_TRACE_POINTS / 2),
    upload: result.upload.trace.slice(-LAST_TRACE_POINTS / 2),
    warmupMs: WARMUP_MS,
  });
}

/**
 * An ISP's name as a glance reads it - "Bezeq- THE ISRAEL TELECOMMUNICATION
 * CORP. LTD." is "Bezeq" - with the whole name kept for a title. Cloudflare's
 * own AS organisation for the client, never a lookup; null stays null, and
 * nothing is shown rather than "Unknown".
 */
export function shortIsp(isp: string | null | undefined): string | null {
  if (!isp) return null;
  const head = isp.split(/[-,(]/)[0].trim();
  return head.length >= 2 ? head : isp;
}

/** When a test ran, as a glance reads it: "just now", "5 min ago", "3 h ago", then the date. */
export function whenText(at: number, now: number): string {
  const s = Math.max(0, (now - at) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * How a figure compares with the same figure last time, as a signed percentage
 * and nothing more - "+4%", "-12%", "same". No "better" or "worse": a lower ping
 * and a higher download are both the good direction, and a word would have to
 * know which one it was describing.
 */
export function changeText(now: number, before: number): string {
  if (!(before > 0)) return '';
  const pct = Math.round(((now - before) / before) * 100);
  if (pct === 0) return 'same';
  return `${pct > 0 ? '+' : '−'}${Math.abs(pct)}%`;
}
