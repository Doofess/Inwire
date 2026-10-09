/**
 * The speed test's server on the Routing Map (ADR 0054): where it is, what it
 * says, and the request to fly there.
 *
 * **An overlay, not traffic.** It is built from the speed test's history -
 * the latest test only - and never from the capture, so it cannot join the
 * map's routes, its pins, its location counter or anything exported: those are
 * all derived from `packets`, and this is derived from a preference. Where the
 * server is comes from the test itself - Cloudflare's `/meta`, or its colo
 * code and the bundled table the engine resolves it against - never from a
 * lookup; a test whose server could not be placed has no overlay, and the
 * results say "location unknown".
 *
 * Pure, so `scripts/speed-test/map-overlay.ts` holds it.
 */
import type { LngLat } from '../../lib/greatCircle';
import { formatMbps } from './method';
import type { SpeedHistoryEntry } from './history';

export interface SpeedOverlay {
  lngLat: LngLat;
  /** "Speed test · Cloudflare Tel Aviv" - the chip's own words. */
  label: string;
  /** "↓ 940 · ↑ 41.9 Mb/s · 3 ms" - the hover's. */
  summary: string;
  at: number;
}

const placed = (n: number | null | undefined): n is number => typeof n === 'number' && Number.isFinite(n);

/** The overlay for the latest test, or null when there is none or it was not placed. */
export function speedTestOverlay(latest: SpeedHistoryEntry | null): SpeedOverlay | null {
  if (!latest || !placed(latest.lat) || !placed(latest.lon)) return null;
  if (Math.abs(latest.lat) > 90 || Math.abs(latest.lon) > 180) return null;
  return {
    lngLat: [latest.lon, latest.lat],
    label: `Speed test · Cloudflare${latest.server ? ` ${latest.server}` : ''}`,
    summary: `↓ ${formatMbps(latest.downMbps)} · ↑ ${formatMbps(latest.upMbps)} Mb/s · ${latest.pingMs < 10 ? latest.pingMs.toFixed(1) : Math.round(latest.pingMs)} ms`,
    at: latest.at,
  };
}

/** The arc's two ends: this machine's network to the server, or null without a home. */
export function overlayArcEnds(
  overlay: SpeedOverlay | null,
  home: { latitude: number; longitude: number } | null,
): { from: LngLat; to: LngLat } | null {
  if (!overlay || !home || !placed(home.latitude) || !placed(home.longitude)) return null;
  return { from: [home.longitude, home.latitude], to: overlay.lngLat };
}

// --- "Show on map" -------------------------------------------------------------
//
// The sheet asks, the map answers when it is next on screen and ready. A store
// rather than a prop, because the map is a view App mounts and unmounts while
// the sheet is a different surface entirely - the request has to wait for
// whichever comes second.

let pending: LngLat | null = null;
const listeners = new Set<() => void>();

export function requestMapFocus(lngLat: LngLat): void {
  pending = lngLat;
  for (const listener of listeners) listener();
}

/** The waiting request, consumed: a second call returns null. */
export function takeMapFocus(): LngLat | null {
  const out = pending;
  pending = null;
  return out;
}

export function onMapFocusRequest(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
