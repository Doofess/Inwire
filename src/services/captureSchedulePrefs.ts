/**
 * Where the capture schedule and its presets are kept.
 *
 * Split from `captureSchedule.ts` so that module stays free of storage: it is
 * pure, `scripts/schedule/decisions.ts` drives it directly, and a pure module
 * that reaches for `localStorage` is only pure until somebody adds one line.
 */
import { createPreferenceStore } from './preferenceStore';
import {
  DEFAULT_SCHEDULE_PRESETS, EMPTY_SCHEDULE, normalizePresets, normalizeSchedule,
  type CaptureSchedule, type SchedulePreset,
} from './captureSchedule';

/**
 * The pending schedule.
 *
 * `Date.now()` is read here rather than inside `normalizeSchedule`, and the
 * moment it is read is the point: a store is loaded once, at module scope, so
 * this is exactly when a `startAt` from a previous session is judged stale and
 * dropped. Reopening the tab in the morning must not begin a capture that was
 * scheduled for the previous evening.
 */
export const captureScheduleStore = createPreferenceStore<CaptureSchedule>(
  'inwire.captureSchedule',
  (raw) => normalizeSchedule(raw, Date.now()),
  EMPTY_SCHEDULE,
);

/**
 * The preset library, seeded on first run the way the filter presets are.
 *
 * Seeded rather than fixed: an empty library is a real state - somebody deleted
 * them all - and `normalizePresets` returns `[]` for it rather than null, so the
 * defaults do not grow back on the next load and look like a bug.
 */
export const capturePresetStore = createPreferenceStore<SchedulePreset[]>(
  'inwire.capturePresets',
  normalizePresets,
  DEFAULT_SCHEDULE_PRESETS,
);
