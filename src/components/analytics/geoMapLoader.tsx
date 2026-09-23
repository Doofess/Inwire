/**
 * The map's code arrives after the first paint rather than before it.
 *
 * `GeoMap.tsx` reaches maplibre-gl and `three`, which together are the largest
 * thing in the renderer's eager chunk, and exactly one branch of `App.tsx`
 * mounts it - behind a rail button most launches never press. Every launch
 * parsed all of it first.
 *
 * ## Why this is not a plain `React.lazy`
 *
 * The audit that first proposed one refuted it, and the reason is two lines of
 * module scope in `GeoMap.tsx`: `setWorkerUrl` followed by `setRTLTextPlugin`.
 * The second acquires MapLibre's worker pool - up to three Workers, each
 * parsing the 487 kB shared chunk - which is why that ordering is commented
 * there at length. Under a bare `React.lazy` that spawn moves to the click that
 * opens the map, landing *in front of* the 2-4 serial HTTPS round trips to
 * openfreemap the first basemap pixel already waits on. A launch cost that is
 * mostly paid would have been traded for an open cost that is entirely serial.
 *
 * So the chunk is lazy and the load is **warmed**: `warmGeoMap()` runs once
 * from an idle callback after the app has painted. The parse and the pool spawn
 * happen where nothing is waiting on them, the eager chunk stops carrying them,
 * and the rail button finds the module already in the registry - `React.lazy`
 * resolves from its own cache, one microtask, no fetch.
 *
 * The fallback below is therefore what a warmed load shows for a single commit,
 * not a loading state anybody reads. It is the window's own ground so that the
 * one frame it does occupy is not a flash of a different colour - the same
 * argument `electron/window.ts` makes about `backgroundColor`.
 *
 * Measured at ~32 ms per 413 kB of eager chunk on this machine (ADR 0041);
 * `test/perf/ceilings.json` records what came off.
 */
import React from 'react';
import type { GeoMapProps } from './GeoMap';

/**
 * One loader for both callers, so the warm and the mount share a promise.
 *
 * `import()` is idempotent per specifier - the second call returns the module
 * registry's existing entry - which is what makes `warmGeoMap` a warm rather
 * than a second parse.
 */
const load = (): Promise<{ default: React.ComponentType<GeoMapProps> }> =>
  import('./GeoMap').then((module) => ({ default: module.GeoMap }));

export const GeoMap = React.lazy(load);

let warmed = false;

/**
 * Starts the map's chunk downloading and parsing, once, when the app is idle.
 *
 * Called from `App`'s mount effect. `requestIdleCallback` rather than a bare
 * `setTimeout` because the point is to take the parse and three worker spawns
 * off whatever the main thread is doing immediately after first paint; the
 * timeout is the ceiling for a main thread that never goes idle, which during a
 * live capture it may not.
 */
export function warmGeoMap(): void {
  if (warmed) return;
  warmed = true;

  const start = (): void => {
    void load().catch(() => {
      // Deliberately swallowed, and this is not a measurement behind a silent
      // catch (ADR 0041): nothing reads a result here. A chunk that fails to
      // load fails again at mount, where `React.lazy` reports it to the nearest
      // boundary - which is the only place a person can be told. Rejecting here
      // as well would be an unhandled rejection at startup for a load nobody
      // asked for yet.
    });
  };

  if (typeof requestIdleCallback === 'function') requestIdleCallback(start, { timeout: 3000 });
  else setTimeout(start, 300);
}
