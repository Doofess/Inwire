import { useEffect, useState } from 'react';

/**
 * The latest `value`, but only once it has stopped changing for `delayMs`.
 *
 * The counterpart to `useThrottledValue`, and deliberately a different shape.
 * Throttling publishes at a steady rate and suits a stream of updates nobody
 * initiated - captured packets arriving. Debouncing publishes when the input
 * settles, which is what typing is: every intermediate value of
 * `tcp.port == 443` is a prefix nobody meant to ask for, and the ones that
 * happen to compile each cost a full pass over the buffer.
 *
 * **This hook was deleted and is back, which is the useful part of its
 * history.** Its first consumer was quick-find, and it went when quick-find
 * did; `useThrottledValue`'s header kept the two rules that had made it work,
 * against the day something needed them again. That day was the Graphs tab's
 * overlay filter, which is the same shape of problem wearing different
 * clothes: a display filter typed a character at a time, compiled on every
 * keystroke, feeding a reset dependency of an aggregate that re-folds the
 * whole buffer from zero. Measured at a 21,903-frame buffer one such fold is
 * 16.6ms, and it runs synchronously during render while a capture flushes at
 * 10Hz.
 *
 * Both of the rules the old header recorded are load-bearing here:
 *
 * - **The caller keeps rendering the raw value in the input itself.** What is
 *   debounced is the WORK, never the field, or the box drops characters.
 * - **`settled` is deliberately absent from the effect's deps.** Including it
 *   restarts the timer when the value lands and schedules one more publish of
 *   what was just published. The guard reads it without depending on it.
 */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);

  useEffect(() => {
    if (Object.is(value, settled)) return;
    const timer = window.setTimeout(() => setSettled(value), delayMs);
    return () => window.clearTimeout(timer);
    // `settled` is deliberately absent: see the second rule above.
  }, [value, delayMs]); // eslint-disable-line react-hooks/exhaustive-deps

  return settled;
}
