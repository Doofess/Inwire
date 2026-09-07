/**
 * Where the schedule presets are kept.
 *
 * The presets persist and the SCHEDULE does not - see the note in `App.tsx`. A
 * preset is a habit worth keeping; a schedule is a decision about the next few
 * minutes, and an app opened tomorrow should not still be armed with one.
 *
 * Split from `captureSchedule.ts` so that module stays free of storage: it is
 * pure, `scripts/schedule/decisions.ts` drives it directly, and a pure module
 * that reaches for `localStorage` is only pure until somebody adds one line.
 */
import { createPreferenceStore } from './preferenceStore';
import {
  DEFAULT_SCHEDULE_PRESETS, normalizePresets, type SchedulePreset,
} from './captureSchedule';

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
