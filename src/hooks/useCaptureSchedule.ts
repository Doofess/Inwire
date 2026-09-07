import { useEffect, useRef, useState, type RefObject } from 'react';

import { scheduleDecision, type CaptureSchedule } from '../services/captureSchedule';

/** How often the schedule is compared against the clock. */
const TICK_MS = 1000;

/**
 * Acts on the capture schedule, and drives the countdown the trigger shows.
 *
 * ## An interval over a timestamp, never a long `setTimeout`
 *
 * The obvious implementation is `setTimeout(stop, millisUntilStop)`. It does not
 * survive a background tab: browsers clamp timers there to roughly once a
 * minute and can freeze them outright, and this repo has already measured the
 * consequence in a neighbouring API - `requestAnimationFrame` fired **zero**
 * times over 3.8 s in a background tab (`services/redirect.ts`), which is why
 * the direction re-derivation runs on a MessageChannel instead.
 *
 * So this compares `Date.now()` against an absolute target once a second. A
 * throttled tab ticks late rather than never, and a late tick still sees
 * `now >= stopAt` and acts - so the failure mode is a capture that runs forty
 * seconds long, not one that never stops. A `setTimeout` armed for two hours
 * has no such recovery.
 *
 * ## Why the callbacks are refs
 *
 * The same reason `useKeyboardNavigation` and `useAgentConnection` hold theirs
 * that way: the effect owns an interval, and re-registering it whenever the
 * capture state or a handler identity changed would restart the tick on every
 * flush. The effect depends on nothing and reads everything live.
 */
export interface CaptureScheduleOptions {
  schedule: CaptureSchedule;
  isCapturingRef: RefObject<boolean>;
  /**
   * When the running capture began, epoch ms, or null when none is running.
   * A duration has nothing to measure from before this exists.
   */
  captureStartedAtRef: RefObject<number | null>;
  /**
   * Begins a scheduled capture. Returns false when it could not - no adapter,
   * or no agent - so the hook can say so rather than failing silently.
   */
  onScheduledStart: () => boolean;
  onScheduledStop: () => void;
}

export interface CaptureScheduleState {
  /**
   * A clock that advances once a second while something is scheduled.
   *
   * Returned so the trigger's countdown re-renders without every consumer
   * owning an interval of its own, and held at 0 when nothing is armed so an
   * idle app is not re-rendering once a second for a label that never changes.
   */
  now: number;
}

export function useCaptureSchedule({
  schedule, isCapturingRef, captureStartedAtRef, onScheduledStart, onScheduledStop,
}: CaptureScheduleOptions): CaptureScheduleState {
  const [now, setNow] = useState(() => Date.now());

  const scheduleRef = useRef(schedule);
  scheduleRef.current = schedule;
  const startRef = useRef(onScheduledStart);
  startRef.current = onScheduledStart;
  const stopRef = useRef(onScheduledStop);
  stopRef.current = onScheduledStop;

  /**
   * The `startAt` this hook has already acted on.
   *
   * A start fires for any `now >= startAt`, deliberately - a throttled tab may
   * only look after the moment has passed, and a schedule that fired only on
   * the exact second would be a schedule that usually did nothing. The cost of
   * that is that the condition stays true afterwards, so without this the hook
   * would keep starting a capture it had already started, discarding the buffer
   * once a second. Cleared whenever the schedule changes.
   */
  const firedStartRef = useRef<number | null>(null);
  useEffect(() => {
    firedStartRef.current = null;
  }, [schedule.startAt]);

  useEffect(() => {
    const tick = () => {
      const current = Date.now();
      setNow(current);
      const active = scheduleRef.current;
      const action = scheduleDecision(
        active, current, isCapturingRef.current ?? false, captureStartedAtRef.current ?? null,
      );
      if (action === 'stop') {
        stopRef.current();
        return;
      }
      if (action !== 'start') return;
      if (firedStartRef.current === active.startAt) return;
      // Marked before the attempt, not after: a start that is refused - no
      // adapter chosen, agent not connected - must not be retried once a second
      // for the rest of the session, each retry raising the same notice.
      firedStartRef.current = active.startAt;
      startRef.current();
    };
    const timer = window.setInterval(tick, TICK_MS);
    return () => window.clearInterval(timer);
  }, [isCapturingRef, captureStartedAtRef]);

  return { now };
}
