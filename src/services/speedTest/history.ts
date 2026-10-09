/**
 * The speed test's history: this machine's results, kept here and nowhere else.
 *
 * Nothing is uploaded - the reason the engine is a port of Cloudflare's method
 * rather than their library, which posts every result to `/__results`. A
 * preference like any other, so it survives a restart and is normalised on the
 * way in: a damaged entry is dropped, never shown as a zero.
 */
import { createPreferenceStore } from '../preferenceStore';
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
  };
}

export function recordResult(result: SpeedResult): void {
  speedHistoryStore.set([historyEntry(result), ...speedHistoryStore.get()].slice(0, HISTORY_LIMIT));
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
