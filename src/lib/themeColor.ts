import { useEffect, useRef, useState } from 'react';

/**
 * Reads a theme token's resolved value at runtime.
 *
 * Most of the app colours itself with Tailwind classes, which follow the
 * active theme for free. D3 and MapLibre do not: they want a concrete colour
 * string handed to them, so anything drawn by those libraries had the accent
 * baked in as a literal `#06b6d4` and stayed cyan no matter which theme was
 * selected. This closes that gap by reading the same CSS custom property the
 * Tailwind utilities resolve against.
 *
 * Callers must also re-run their draw when the theme changes - a value read
 * once at mount is just a slower way of hardcoding it. Components that draw
 * imperatively take a `themeKey` prop for exactly that reason.
 */

/** The raw read, or null when the token cannot be resolved right now. */
function readToken(token: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    const value = getComputedStyle(document.documentElement).getPropertyValue(token).trim();
    return value || null;
  } catch {
    return null;
  }
}

export function themeColor(token: string, fallback: string): string {
  return readToken(token) ?? fallback;
}

/**
 * A theme token as React state, which never regresses to the fallback once a
 * real value has been seen.
 *
 * `themeColor()` alone is not enough for anything drawn imperatively, and the
 * reason is a bug this fixes rather than a hypothetical. `getPropertyValue`
 * returns an empty string whenever the stylesheet is not applied at that
 * instant - a dev-server CSS swap, a draw that happens before styles land -
 * and the fallback it then substitutes is a hardcoded dark-theme cyan, which
 * is wrong in the light and mono themes. Worse, nothing redrew afterwards: the
 * traffic timeline would paint its line cyan on a mono theme whose accent is
 * white, and stay that way until something unrelated forced a redraw, which is
 * why clicking the chart "fixed" it.
 *
 * So this hook:
 *
 *   - only ever adopts a value it could actually read, so one unlucky moment
 *     cannot replace a known-good colour with a guess;
 *   - keeps retrying while the token is unresolvable, so the first successful
 *     read lands on its own instead of waiting for a user gesture;
 *   - re-reads when the theme class on <html> changes, which is the ground
 *     truth for a theme switch regardless of what React state thinks.
 *
 * Because the result is state, a component that draws from it redraws when it
 * changes, with no extra wiring.
 */
export function useThemeToken(token: string, fallback: string): string {
  const [value, setValue] = useState(() => readToken(token) ?? fallback);
  // Whether the current value came from a real read rather than the fallback.
  const resolvedRef = useRef(readToken(token) !== null);

  useEffect(() => {
    let cancelled = false;
    let frame = 0;
    let attempts = 0;

    const apply = (): boolean => {
      const next = readToken(token);
      if (next === null) return false;
      resolvedRef.current = true;
      if (!cancelled) setValue(prev => (prev === next ? prev : next));
      return true;
    };

    // A theme switch swaps the class on <html> and an accent switch its
    // data-accent-color; those are the authoritative signals, and they do not
    // depend on any React state having caught up.
    const observer = new MutationObserver(() => apply());
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'style', 'data-accent-color'],
    });

    // Until the token reads for the first time, keep trying. Bounded, because
    // a token that genuinely does not exist should not spin forever - after
    // that the fallback is the honest answer.
    const retry = () => {
      if (cancelled || apply() || attempts++ > 120) return;
      frame = requestAnimationFrame(retry);
    };

    if (!apply()) frame = requestAnimationFrame(retry);

    return () => {
      cancelled = true;
      observer.disconnect();
      if (frame) cancelAnimationFrame(frame);
    };
  }, [token]);

  return value;
}
