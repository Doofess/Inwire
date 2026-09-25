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
  describeSchedule, millisUntilStop, normalizePresets,
  resolveStopTime, scheduleDecision, withStartAt, withStopAfter,
  withStopAt, isStartMissed, START_GRACE_MS, type CaptureSchedule,
  afterScheduledStop, atTime, defaultStartAt, defaultStopAt, describeDay, describePlan,
  isStopBeforeStart, isStopPassed, onDay, scheduleProblem,
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
  // Late is expected: a background tab's timers are throttled to about once a
  // minute, so the tick that notices is usually not the one it was due on.
  check('...fires a little late too, since a throttled tab looks late',
    scheduleDecision(timed, T0 + 5 * MIN + 45_000, false, null), 'start');
  // Guards the obvious bug: a schedule that keeps "starting" a capture already
  // running would discard the buffer every second.
  check('...and never fires while already capturing',
    scheduleDecision(timed, T0 + 40 * MIN, true, T0 + 5 * MIN), 'idle');
}

// --- 4b. a start too far in the past does NOT fire ------------------------------
//
// The bug this was written for. The native date picker commits a value as you
// move around it, and its "Today" button sets today with whatever time is
// already in the field - usually one that has passed. Unbounded, the very next
// tick saw a due start and ran a capture nobody asked for. Reported as "I
// clicked Today and it started capturing", which is precisely what happened.
{
  const timed = withStartAt(EMPTY_SCHEDULE, T0);
  check('a start at the edge of the grace window still fires',
    scheduleDecision(timed, T0 + START_GRACE_MS, false, null), 'start');
  check('...and one past it does not',
    scheduleDecision(timed, T0 + START_GRACE_MS + 1, false, null), 'idle');
  // The case from the report: a time earlier today.
  check('...so picking a time from this morning starts nothing',
    scheduleDecision(withStartAt(EMPTY_SCHEDULE, T0 - 6 * 60 * MIN), T0, false, null), 'idle');
  // And the case the old rule got wrong in the other direction: a capture set
  // for 2am must not begin at 9am because that is when the laptop was opened.
  check('...nor does last night reaching this morning',
    scheduleDecision(withStartAt(EMPTY_SCHEDULE, T0 - 7 * 60 * MIN), T0, false, null), 'idle');

  // A start that can never fire has to SAY so, or it reads as a broken feature.
  check('a missed start is reported as missed', isStartMissed(timed, T0 + 10 * MIN), true);
  check('...and one still in its window is not', isStartMissed(timed, T0 + 30_000), false);
  check('...and no start at all is never missed', isStartMissed(EMPTY_SCHEDULE, T0), false);
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
  check('an empty schedule names itself',
    describeSchedule(EMPTY_SCHEDULE, T0, false, null), 'Schedule capture');
  check('a running capture counts down',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 5), T0 + 2 * MIN, true, T0), 'Stops in 03:00');
  // Past an hour the countdown grows a field rather than showing 90 minutes.
  check('...with an hours field once there is one',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 90), T0, true, T0), 'Stops in 1:30:00');
  check('an armed duration names the duration',
    describeSchedule(withStopAfter(EMPTY_SCHEDULE, 120), T0, false, null), 'Runs 2 hours');
  check('...and a mixed one reads naturally', describeDuration(90), '1h 30m');
  check('...and one minute is singular', describeDuration(1), '1 min');
  // The trigger and the panel have to agree: the panel says it will never
  // start, so the button must not still promise that it will.
  check('a missed start says so rather than promising a time',
    describeSchedule(withStartAt(EMPTY_SCHEDULE, T0), T0 + 10 * MIN, false, null),
    'Start time passed');
  check('an armed start names the start',
    describeSchedule(withStartAt(EMPTY_SCHEDULE, T0), T0, false, null).startsWith('Starts'), true);
}

// --- 8. presets survive the round trip, including having none ----------------------
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

// --- the redesign's rules --------------------------------------------------------
//
// Two checks the panel never made, a reset nothing performed, and the plan line
// that replaced "Manually" / "Not Set".
{
  const NOW = new Date(2026, 8, 25, 13, 58).getTime();   // Fri 25 Sep 2026, 13:58
  const at = (h: number, m: number, dayOffset = 0) => new Date(2026, 8, 25 + dayOffset, h, m).getTime();

  check('a stop before the start is caught',
    isStopBeforeStart({ startAt: at(14, 0), stopAt: at(13, 30), stopAfterMinutes: null }), true);
  check('...and a stop equal to it too - a capture of zero length',
    isStopBeforeStart({ startAt: at(14, 0), stopAt: at(14, 0), stopAfterMinutes: null }), true);
  check('...but not a stop after it', isStopBeforeStart({ startAt: at(14, 0), stopAt: at(14, 30), stopAfterMinutes: null }), false);
  check('...nor a duration, which cannot be before anything',
    isStopBeforeStart({ startAt: at(14, 0), stopAt: null, stopAfterMinutes: 30 }), false);
  check('a stop already past is caught', isStopPassed({ startAt: null, stopAt: at(13, 0), stopAfterMinutes: null }, NOW), true);
  check('...and one ahead is not', isStopPassed({ startAt: null, stopAt: at(15, 0), stopAfterMinutes: null }, NOW), false);

  // The two bugs, as the schedule the timer leaves behind. Put the old
  // behaviour back (a stop that clears nothing) and the second and third fail.
  const ran: CaptureSchedule = { startAt: at(14, 0), stopAt: at(14, 30), stopAfterMinutes: null };
  const after = afterScheduledStop(ran);
  check('a scheduled stop spends both absolute times', [after.startAt, after.stopAt], [null, null]);
  check('...so two minutes later nothing says the start "has passed"', isStartMissed(after, at(14, 33)), false);
  check('...and a capture started by hand later is not stopped by the old stop',
    scheduleDecision(after, at(16, 0), true, at(15, 59)), 'idle');
  check('...while a duration survives it - it is a habit, not a moment',
    afterScheduledStop({ startAt: at(14, 0), stopAt: null, stopAfterMinutes: 30 }).stopAfterMinutes, 30);

  // "At a time" must never land in its own error.
  const start = defaultStartAt(NOW);
  check('a new start is on a five-minute boundary', new Date(start).getMinutes() % 5, 0);
  check('...at least a minute ahead, so it is not already missed', start - NOW >= 60_000, true);
  check('a new stop is half an hour after the start',
    defaultStopAt({ startAt: at(14, 0), stopAt: null, stopAfterMinutes: null }, NOW), at(14, 30));

  check('moving to another day keeps the time of day', onDay(at(14, 5), new Date(2026, 8, 27)), at(14, 5, 2));
  check('setting a time keeps the day', atTime(at(14, 5, 2), 9, 30), at(9, 30, 2));

  check('today is "today"', describeDay(at(18, 0), NOW), 'today');
  check('tomorrow is "tomorrow"', describeDay(at(0, 30, 1), NOW), 'tomorrow');

  // The plan line, in every shape a schedule takes. Clock text is the
  // machine's locale, so the checks read around it rather than pinning "14:00".
  const plan = (s: CaptureSchedule) => describePlan(s, NOW, false, null);
  check('nothing scheduled says so',
    plan(EMPTY_SCHEDULE), 'Nothing scheduled. Capture starts and stops when you press the button.');
  check('a start and a duration name both ends',
    /^Starts today at .+ · stops .+ \(after 30 mins\)\.$/.test(plan({ startAt: at(14, 0), stopAt: null, stopAfterMinutes: 30 })), true);
  check('a start and no stop says it runs until stopped',
    /^Starts today at .+ · runs until you stop it\.$/.test(plan({ startAt: at(14, 0), stopAt: null, stopAfterMinutes: null })), true);
  check('two ends on one day say the day once',
    /^Starts today at [^·]+ · stops [^a-z]+\.$/.test(plan({ startAt: at(14, 0), stopAt: at(15, 0), stopAfterMinutes: null })), true);
  check('...and on two days say both',
    /· stops tomorrow at /.test(plan({ startAt: at(23, 0), stopAt: at(1, 0, 1), stopAfterMinutes: null })), true);
  check('a duration alone is measured from pressing Start',
    plan({ startAt: null, stopAt: null, stopAfterMinutes: 90 }), 'Stops 1h 30m after you press Start.');
  check('a stop alone applies however the capture began',
    /^Stops tomorrow at .+, however it was started\.$/.test(plan({ startAt: null, stopAt: at(9, 0, 1), stopAfterMinutes: null })), true);
  // No countdown: the plan line is a live region, and a ticking one was read
  // aloud every second. Two ticks a second apart must read the same.
  const running: CaptureSchedule = { startAt: null, stopAt: null, stopAfterMinutes: 30 };
  check('a running capture names its stop time',
    /^Capturing\. Stops today at .+\.$/.test(describePlan(running, at(14, 1), true, at(14, 0))), true);
  check('...and does not change from one second to the next',
    describePlan(running, at(14, 1), true, at(14, 0)), describePlan(running, at(14, 1) + 1000, true, at(14, 0)));
  check('...or says it has no stop',
    describePlan(EMPTY_SCHEDULE, NOW, true, at(13, 0)), 'Capturing. No stop set - it runs until you stop it.');
}

// --- the critic's blocker: a schedule the panel flags must not run --------------
//
// A stop before its start was shown in red in the panel, and armed everywhere
// else: the plan sentence, the trigger's summary and the rail's dot all read
// it as fine, and `scheduleDecision` started the capture - for the next tick to
// stop it. Put the `isStopBeforeStart` guard back out of `scheduleDecision` and
// the first check fails.
{
  const at = (h: number, m: number) => new Date(2026, 8, 25, h, m).getTime();
  const backwards: CaptureSchedule = { startAt: at(16, 20), stopAt: at(15, 50), stopAfterMinutes: null };
  check('a stop before its start does not start', scheduleDecision(backwards, at(16, 20), false, null), 'idle');
  check('...is reported as the problem it is', scheduleProblem(backwards, at(16, 0)), 'stop-before-start');
  check('...the plan says it is not armed', describePlan(backwards, at(16, 0), false, null),
    'Not armed: the stop is before the start.');
  check('...and so does the trigger', describeSchedule(backwards, at(16, 0), false, null), 'Schedule not armed');

  // The manual-start form of the same bug: a stop already past when Start is
  // pressed stopped the capture on its first tick.
  const stale: CaptureSchedule = { startAt: null, stopAt: at(15, 0), stopAfterMinutes: null };
  check('a stop that predates the capture does not stop it',
    scheduleDecision(stale, at(16, 0) + 1000, true, at(16, 0)), 'idle');
  check('...and reports no countdown', millisUntilStop(stale, at(16, 0) + 1000, at(16, 0)), null);
  check('...while idle, it is flagged', scheduleProblem(stale, at(16, 0)), 'stop-passed');
  check('a good schedule has no problem',
    scheduleProblem({ startAt: at(16, 20), stopAt: at(16, 50), stopAfterMinutes: null }, at(16, 0)), null);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-schedule checks passed.');
process.exit(0);
