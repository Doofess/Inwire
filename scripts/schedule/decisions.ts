/**
 * The capture schedule's decisions, driven with an injected clock.
 *
 *   npx tsx scripts/schedule/decisions.ts
 *
 * There is no UI harness in this repo, so the way to test a feature whose whole
 * substance is "what happens at 14:00" is to keep that substance out of the
 * component and hand it the time. `services/captureSchedule.ts` takes `now` as
 * a parameter everywhere for exactly this reason; nothing in it reads the clock.
 *
 * The property worth the most here is the one that decided the data model. A
 * preset is a **duration**, resolved when capture starts - not a stop time
 * written when the preset was clicked. The difference only shows up when the
 * two moments are far apart, which is precisely the case a person testing by
 * hand would never wait for.
 */
import {
  DEFAULT_SCHEDULE_PRESETS, EMPTY_SCHEDULE, applyPreset, describeDuration,
  describeSchedule, isScheduleEmpty, millisUntilStop, normalizePresets,
  normalizeSchedule, resolveStopTime, scheduleDecision, withStartAt, withStopAfter,
  withStopAt, type CaptureSchedule,
} from '../../src/services/captureSchedule';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) { console.log(`PASS  ${name}`); return; }
  failures++;
  console.log(`FAIL  ${name}\n        expected ${b}\n        actual   ${a}`);
}

const MIN = 60_000;
/** An arbitrary fixed "now", so every expectation below is arithmetic. */
const T0 = 1_800_000_000_000;

// --- 1. a preset is a duration, resolved at start ------------------------------
{
  const armed = applyPreset(EMPTY_SCHEDULE, DEFAULT_SCHEDULE_PRESETS[0]);   // 5 mins
  check('a preset stores minutes, not a moment', armed.stopAfterMinutes, 5);
  check('...and no absolute stop', armed.stopAt, null);

  // Clicked at T0, started twenty minutes later. The capture must still run for
  // five minutes - an absolute stop written at click time would have expired
  // fifteen minutes before it began.
  const startedAt = T0 + 20 * MIN;
  check('...and resolves against the real start, not the click',
    resolveStopTime(armed, startedAt), startedAt + 5 * MIN);
  check('...so a start twenty minutes late still gets its full five',
    scheduleDecision(armed, startedAt + 4 * MIN, true, startedAt), 'idle');
  check('...and stops on time from there',
    scheduleDecision(armed, startedAt + 5 * MIN, true, startedAt), 'stop');
}

// --- 2. the two stop forms are mutually exclusive -------------------------------
{
  const byTime = withStopAt(EMPTY_SCHEDULE, T0 + 10 * MIN);
  check('setting an absolute stop clears a duration',
    withStopAfter(byTime, 15).stopAt, null);
  const byDuration = withStopAfter(EMPTY_SCHEDULE, 15);
  check('...and setting a duration clears an absolute stop',
    withStopAt(byDuration, T0 + 10 * MIN).stopAfterMinutes, null);
}

// --- 3. an empty start means the user presses Start ------------------------------
//
// The case the feature was asked for by name: fill in only a stop, and the
// capture begins by hand and ends by itself.
{
  const stopOnly = withStopAt(EMPTY_SCHEDULE, T0 + 10 * MIN);
  check('a stop-only schedule never starts on its own',
    scheduleDecision(stopOnly, T0 + 100 * MIN, false, null), 'idle');
  check('...but stops the capture the user started',
    scheduleDecision(stopOnly, T0 + 10 * MIN, true, T0), 'stop');
  check('...and not before', scheduleDecision(stopOnly, T0 + 9 * MIN, true, T0), 'idle');
}

// --- 4. a start time fires once, and only while not capturing --------------------
{
  const timed = withStartAt(EMPTY_SCHEDULE, T0 + 5 * MIN);
  check('a start is idle before its time', scheduleDecision(timed, T0, false, null), 'idle');
  check('...fires at it', scheduleDecision(timed, T0 + 5 * MIN, false, null), 'start');
  check('...fires after it too, since a throttled tab may look late',
    scheduleDecision(timed, T0 + 40 * MIN, false, null), 'start');
  // Guards the obvious bug: a schedule that keeps "starting" a capture already
  // running would discard the buffer every second.
  check('...and never fires while already capturing',
    scheduleDecision(timed, T0 + 40 * MIN, true, T0 + 5 * MIN), 'idle');
}

// --- 5. a window whose end has passed stops rather than restarting ---------------
{
  const window: CaptureSchedule = { startAt: T0, stopAt: T0 + 5 * MIN, stopAfterMinutes: null };
  check('a capture past its own window stops',
    scheduleDecision(window, T0 + 6 * MIN, true, T0), 'stop');
}

// --- 6. a duration cannot be measured before the capture begins -------------------
{
  const armed = withStopAfter(EMPTY_SCHEDULE, 5);
  check('a duration with no start time is idle, not an immediate stop',
    scheduleDecision(armed, T0, true, null), 'idle');
  check('...and reports no countdown', millisUntilStop(armed, T0, null), null);
}

// --- 7. what the button says ------------------------------------------------------
{
  const at = (epoch: number) => new Date(epoch).toISOString().slice(11, 16);
  check('an empty schedule names itself',
    describeSchedule(EMPTY_SCHEDULE, T0, false, null, at), 'Schedule capture');
  check('a running capture counts down',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 5), T0 + 2 * MIN, true, T0, at), 'Stops in 03:00');
  // Past an hour the countdown grows a field rather than showing 90 minutes.
  check('...with an hours field once there is one',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 90), T0, true, T0, at), 'Stops in 1:30:00');
  check('an armed duration names the duration',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 120), T0, false, null, at), 'Runs 2 hours');
  check('...and a mixed one reads naturally', describeDuration(90), '1h 30m');
  check('...and one minute is singular', describeDuration(1), '1 min');
  check('an armed start names the start',
    describeSchedule(withStartAt(EMPTY_SCHEDULE, T0), T0, false, null, at).startsWith('Starts'), true);
}

// --- 8. the stored round trip ------------------------------------------------------
{
  // The one that matters: a start time from yesterday must not fire on load.
  const stale = normalizeSchedule({ startAt: T0 - 60 * MIN, stopAfterMinutes: 5 }, T0);
  check('a start already past is dropped on load, not fired', stale?.startAt, null);
  check('...while its stop survives', stale?.stopAfterMinutes, 5);

  const future = normalizeSchedule({ startAt: T0 + 60 * MIN, stopAt: T0 + 90 * MIN }, T0);
  check('a start still ahead is kept', future?.startAt, T0 + 60 * MIN);

  // A hand-edited blob carrying both stops must not survive as both.
  const both = normalizeSchedule({ stopAt: T0, stopAfterMinutes: 5 }, T0);
  check('a stored blob with two stops keeps only one', both?.stopAfterMinutes, null);

  check('garbage falls back', normalizeSchedule('nonsense', T0), null);
  check('...as does a null', normalizeSchedule(null, T0), null);
  check('a schedule of nothing is empty', isScheduleEmpty(normalizeSchedule({}, T0)!), true);
}

// --- 9. presets survive the round trip, including having none ----------------------
{
  check('the defaults round-trip', normalizePresets(DEFAULT_SCHEDULE_PRESETS), DEFAULT_SCHEDULE_PRESETS);
  // Deleting every preset is a real state and has to persist, or the defaults
  // would grow back on the next load and look like a bug.
  check('an empty library survives rather than reseeding', normalizePresets([]), []);
  check('a preset with no duration is dropped',
    normalizePresets([{ id: 'a', name: 'A' }]), []);
  check('...as is one with a nonsense duration',
    normalizePresets([{ id: 'a', name: 'A', stopAfterMinutes: -5 }]), []);
  check('a non-array falls back', normalizePresets({}), null);
  check('the five defaults are the ones asked for',
    DEFAULT_SCHEDULE_PRESETS.map((p) => p.stopAfterMinutes), [5, 15, 30, 60, 120]);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-schedule checks passed.');
process.exit(0);
