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
export function themeColor(token: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(token)
    .trim();
  return value || fallback;
}
