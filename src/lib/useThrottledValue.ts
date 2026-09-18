import { useEffect, useRef, useState } from 'react';

/**
 * The latest `value`, but changing at most once per `intervalMs`.
 *
 * Exists to decouple how often the packet buffer changes from how often the
 * things that summarize it recompute. App.tsx commits captured packets to
 * state every 100ms, and each analytics panel does at least one full pass over
 * the whole buffer when that array's identity changes - so their cost is
 * (buffer size x flush rate) even though nothing they display is legible at
 * 10Hz. Measured at a 21,903-packet buffer, those passes cost 16.6ms per
 * flush, or 166ms of every second, rising to roughly 380ms/s at the 50,000
 * packet cap.
 *
 * Leading edge: the first change is passed through immediately, so a panel
 * fills in the moment a capture starts rather than after a blank interval.
 * Subsequent changes inside the window are coalesced and the newest one lands
 * when the window closes - the trailing edge matters as much as the leading
 * one here, because a capture that stops mid-window must still leave the
 * panels showing the final buffer rather than a stale snapshot.
 *
 * Not for anything that has to be exact at the instant it is read (an export,
 * a stream reconstruction) - those keep reading the live value.
 *
 * **`useDebouncedValue` sits beside this, and the contrast is the reason
 * they are two hooks rather than one with a flag.** Throttling publishes at a
 * steady rate and suits a stream of updates nobody initiated - captured
 * packets arriving. Debouncing publishes when the input settles, which is what
 * typing is: every intermediate value of a filter expression is a prefix
 * nobody meant to ask for, and the ones that parse each cost a full pass over
 * the buffer.
 *
 * That hook was deleted with quick-find (`FindPacketPopover`,
 * `packetSearchText`, `inwire.packetSearch`) and this paragraph kept its two
 * rules against the day something needed them again. It did: the Graphs tab's
 * overlay filter compiles a display filter on every keystroke into a reset
 * dependency of `useIncrementalAggregate`. The rules held both times - never
 * debounce the FIELD, only the WORK, or the box drops characters; and do not
 * put the settled value in the effect's deps, or the timer restarts when the
 * value lands and schedules one more publish of what was just published.
 */
export function useThrottledValue<T>(value: T, intervalMs: number): T {
  const [throttled, setThrottled] = useState(value);
  // The newest value seen, so the trailing-edge timer publishes what is
  // current when it fires rather than what was current when it was scheduled.
  const latestRef = useRef(value);
  const lastPublishedAtRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  latestRef.current = value;

  useEffect(() => {
    const sincePublish = Date.now() - lastPublishedAtRef.current;

    if (sincePublish >= intervalMs) {
      lastPublishedAtRef.current = Date.now();
      setThrottled(value);
      return;
    }

    // Already inside the window: one trailing timer is enough, and rescheduling
    // it on every change would starve it under a sustained stream of updates.
    if (timerRef.current !== null) return;
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      lastPublishedAtRef.current = Date.now();
      setThrottled(latestRef.current);
    }, intervalMs - sincePublish);
  }, [value, intervalMs]);

  // Only on unmount. Clearing on every run would cancel the trailing timer
  // the effect above had just scheduled - the exact failure that broke
  // GeoMap's connection sync once already (see its comment).
  //
  // The ref must be nulled as well as cleared, not just cleared: under
  // StrictMode this cleanup fires between the two mount passes, and a guard
  // left pointing at an already-cancelled timer would make the branch above
  // return early forever, so no value would ever be published again.
  useEffect(() => () => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  return throttled;
}
