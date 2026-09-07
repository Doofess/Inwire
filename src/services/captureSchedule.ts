/**
 * Scheduling a capture: when it starts, when it stops, and the presets that
 * fill both in.
 *
 * Pure, and deliberately so - `now` is always a parameter rather than a call to
 * `Date.now()` inside. Everything interesting here is a decision about time,
 * and a decision about time that reads the clock itself can only be tested by
 * waiting. `scripts/schedule/decisions.ts` drives all of it with an injected
 * clock instead.
 *
 * ## A preset is a duration, not a stop time
 *
 * "Capture for 5 mins" means the capture lasts five minutes. It would be
 * simpler to write `now + 5min` into the stop field when the preset is clicked,
 * and it would be wrong: click it, get distracted for six minutes, and the
 * schedule you armed is already in the past - so the capture either stops the
 * instant it starts or never runs at all. `stopAfterMinutes` is resolved
 * against the moment capture actually begins, which is what the preset's own
 * name promises.
 *
 * The two stop forms are mutually exclusive. Setting one clears the other, so
 * the dropdown never shows two different answers to "when does this end".
 */

/** What the schedule wants done, checked once a second. */
export type ScheduleAction = 'start' | 'stop' | 'idle';

export interface CaptureSchedule {
  /** Epoch ms, or null for "start when the user presses Start". */
  startAt: number | null;
  /** Epoch ms. An absolute stop, from the date/time field. */
  stopAt: number | null;
  /** Minutes. From a preset, resolved against the real start time. */
  stopAfterMinutes: number | null;
}

export interface SchedulePreset {
  id: string;
  name: string;
  /**
   * Presets only ever carry a duration. A saved absolute time would be stale
   * the day after it was saved, which is not a preset at all.
   */
  stopAfterMinutes: number;
}

export const EMPTY_SCHEDULE: CaptureSchedule = {
  startAt: null,
  stopAt: null,
  stopAfterMinutes: null,
};

/**
 * Seeds a first run, and what "Restore defaults" restores.
 *
 * Seeded rather than fixed, the way `DEFAULT_FILTER_PRESET_LIBRARY` is: five
 * reasonable durations, not a closed set. The user can rename, delete and add.
 */
export const DEFAULT_SCHEDULE_PRESETS: SchedulePreset[] = [
  { id: 'preset-5m', name: 'Capture for 5 mins', stopAfterMinutes: 5 },
  { id: 'preset-15m', name: 'Capture for 15 mins', stopAfterMinutes: 15 },
  { id: 'preset-30m', name: 'Capture for 30 mins', stopAfterMinutes: 30 },
  { id: 'preset-1h', name: 'Capture for 1 hour', stopAfterMinutes: 60 },
  { id: 'preset-2h', name: 'Capture for 2 hours', stopAfterMinutes: 120 },
];

// --- editing ------------------------------------------------------------------

/** True when nothing is scheduled at either end. */
export function isScheduleEmpty(schedule: CaptureSchedule): boolean {
  return schedule.startAt === null
    && schedule.stopAt === null
    && schedule.stopAfterMinutes === null;
}

/** Sets the absolute stop, clearing any duration. */
export function withStopAt(schedule: CaptureSchedule, stopAt: number | null): CaptureSchedule {
  return { ...schedule, stopAt, stopAfterMinutes: null };
}

/** Sets the duration, clearing any absolute stop. */
export function withStopAfter(schedule: CaptureSchedule, minutes: number | null): CaptureSchedule {
  return { ...schedule, stopAfterMinutes: minutes, stopAt: null };
}

export function withStartAt(schedule: CaptureSchedule, startAt: number | null): CaptureSchedule {
  return { ...schedule, startAt };
}

/** Applying a preset replaces the stop and leaves the start alone. */
export function applyPreset(schedule: CaptureSchedule, preset: SchedulePreset): CaptureSchedule {
  return withStopAfter(schedule, preset.stopAfterMinutes);
}

// --- deciding -----------------------------------------------------------------

/**
 * When a capture that began at `startedAt` should stop, or null if never.
 *
 * The duration is measured from the real start, which is the whole reason it is
 * stored as a duration rather than resolved when the preset was clicked.
 */
export function resolveStopTime(schedule: CaptureSchedule, startedAt: number): number | null {
  if (schedule.stopAt !== null) return schedule.stopAt;
  if (schedule.stopAfterMinutes !== null) return startedAt + schedule.stopAfterMinutes * 60_000;
  return null;
}

/**
 * What the schedule wants to happen right now.
 *
 * `startedAt` is when the running capture began, and is only read while
 * capturing - a duration has nothing to measure from before then.
 *
 * A start only fires for an explicit `startAt`. An empty one means the user
 * presses Start themselves, which is the documented case for a schedule that
 * sets only a stop.
 */
export function scheduleDecision(
  schedule: CaptureSchedule,
  now: number,
  isCapturing: boolean,
  startedAt: number | null,
): ScheduleAction {
  if (isCapturing) {
    if (startedAt === null) return 'idle';
    const stopAt = resolveStopTime(schedule, startedAt);
    return stopAt !== null && now >= stopAt ? 'stop' : 'idle';
  }
  return schedule.startAt !== null && now >= schedule.startAt ? 'start' : 'idle';
}

/** Milliseconds until the running capture stops, or null when nothing will. */
export function millisUntilStop(
  schedule: CaptureSchedule, now: number, startedAt: number | null,
): number | null {
  if (startedAt === null) return null;
  const stopAt = resolveStopTime(schedule, startedAt);
  return stopAt === null ? null : Math.max(0, stopAt - now);
}

// --- describing ---------------------------------------------------------------

function hhmmss(millis: number): string {
  const total = Math.floor(millis / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const mm = String(minutes).padStart(2, '0');
  const ss = String(seconds).padStart(2, '0');
  return hours > 0 ? `${hours}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** A duration as the presets name it - "5 mins", "1 hour", "1h 30m". */
export function describeDuration(minutes: number): string {
  if (minutes < 60) return `${minutes} min${minutes === 1 ? '' : 's'}`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  const whole = `${hours} hour${hours === 1 ? '' : 's'}`;
  return rest === 0 ? whole : `${hours}h ${rest}m`;
}

/**
 * The one line the trigger button carries.
 *
 * A running capture counts DOWN, because that is the number somebody watching a
 * timed capture actually wants. An armed one names the wall-clock time it will
 * act at, because that is what they set.
 */
export function describeSchedule(
  schedule: CaptureSchedule,
  now: number,
  isCapturing: boolean,
  startedAt: number | null,
  formatTime: (epochMs: number) => string,
): string {
  if (isScheduleEmpty(schedule)) return 'Schedule capture';
  if (isCapturing) {
    const left = millisUntilStop(schedule, now, startedAt);
    return left === null ? 'Schedule capture' : `Stops in ${hhmmss(left)}`;
  }
  if (schedule.startAt !== null) return `Starts ${formatTime(schedule.startAt)}`;
  if (schedule.stopAt !== null) return `Stops ${formatTime(schedule.stopAt)}`;
  if (schedule.stopAfterMinutes !== null) return `Runs ${describeDuration(schedule.stopAfterMinutes)}`;
  return 'Schedule capture';
}

// --- the stored round trip ------------------------------------------------------

const isFiniteNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

/**
 * Reads a stored schedule, dropping a `startAt` that has already passed.
 *
 * Dropped rather than fired: reopening the tab in the morning must not begin a
 * capture that was scheduled for the previous evening. The stop halves survive
 * - a stale absolute stop is harmless, because `scheduleDecision` reads it only
 * while capturing, and a capture starting now cannot already be past it.
 */
export function normalizeSchedule(raw: unknown, now: number): CaptureSchedule | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  const startAt = isFiniteNumber(v.startAt) && v.startAt > now ? v.startAt : null;
  const stopAt = isFiniteNumber(v.stopAt) ? v.stopAt : null;
  const stopAfterMinutes = isFiniteNumber(v.stopAfterMinutes) && v.stopAfterMinutes > 0
    ? v.stopAfterMinutes
    : null;
  // Exclusivity is enforced on the way in as well as on the way out, so a
  // hand-edited or older blob cannot produce a schedule with two stops.
  return stopAt !== null
    ? { startAt, stopAt, stopAfterMinutes: null }
    : { startAt, stopAt: null, stopAfterMinutes };
}

export function normalizePresets(raw: unknown): SchedulePreset[] | null {
  if (!Array.isArray(raw)) return null;
  const out: SchedulePreset[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null) continue;
    const v = entry as Record<string, unknown>;
    if (typeof v.id !== 'string' || typeof v.name !== 'string') continue;
    if (!isFiniteNumber(v.stopAfterMinutes) || v.stopAfterMinutes <= 0) continue;
    out.push({ id: v.id, name: v.name, stopAfterMinutes: v.stopAfterMinutes });
  }
  // An empty array is a real state - the user deleted every preset - and has to
  // survive, or the defaults would grow back on the next load.
  return out;
}
