import { useEffect, useState } from 'react';

/**
 * The latest `value`, but only once it has stopped changing for `delayMs`.
 *
 * The counterpart to `useThrottledValue`, and deliberately a different shape.
 * Throttling publishes at a steady rate and suits a stream of updates nobody
 * initiated - captured packets arriving. Debouncing publishes when the input
 * settles, which is what typing is: every intermediate value of "1.2.3.4" is a
 * prefix nobody meant to search for, and each one costs a full pass over the
 * buffer.
 *
 * At a 50,000-frame buffer the quick-find scan lowercases four strings per
 * frame per keystroke. That is survivable; at the buffer sizes this work is
 * aimed at it is a keystroke that visibly janks, and the cost is paid for
 * results that are replaced before they can be read.
 *
 * The caller keeps rendering the raw value in the input itself - what is
 * debounced is the WORK, never the field, or the box would drop characters.
 */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);

  useEffect(() => {
    if (Object.is(value, settled)) return;
    const timer = window.setTimeout(() => setSettled(value), delayMs);
    return () => window.clearTimeout(timer);
    // `settled` is deliberately absent: including it would restart the timer
    // when the value lands, scheduling one more publish of what was just
    // published. The guard above reads it without depending on it.
  }, [value, delayMs]); // eslint-disable-line react-hooks/exhaustive-deps

  return settled;
}
