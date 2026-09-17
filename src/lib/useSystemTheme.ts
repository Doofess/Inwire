import { useEffect, useRef } from 'react';
import { useTheme } from 'next-themes';
import { useMediaQuery } from './useMediaQuery';
import { SYSTEM_THEME_PAIR } from './themeOptions';
import { followSystemThemeStore } from '../services/themePrefs';
import { usePreferenceValue } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';

/**
 * "System" as a third choice in the picker, without it being a third theme.
 *
 * next-themes has an `enableSystem` mode of its own, and it is deliberately not
 * used. It resolves the OS preference to whichever themes are literally named
 * `light` and `dark`, which is a naming coincidence rather than a decision -
 * it was the wrong answer outright when the `dark` id belonged to a warm theme
 * called Graphite, and it would be the wrong answer again the moment a third
 * theme arrives. Which pair System chooses between is a product decision, so it
 * is made in `SYSTEM_THEME_PAIR` and read here.
 *
 * Kept out of THEME_OPTIONS for the same reason. Everything downstream of that
 * list - the CSS class blocks, `isDarkTheme`, the palettes, the assertion
 * scripts - assumes every entry names a real set of colours, and `system` names
 * a rule for choosing between two. It is a MODE over the pair, stored as its
 * own boolean, and what next-themes holds is always a concrete theme.
 */
export function useSystemThemePreference(): void {
  const [follows] = usePreferenceValue(followSystemThemeStore);
  usePreferenceSync(
    followSystemThemeStore.key,
    followSystemThemeStore.normalize,
    followSystemThemeStore.accept,
  );

  const prefersDark = useMediaQuery('(prefers-color-scheme: dark)');
  const { setTheme } = useTheme();

  /**
   * The value this hook last chose, so it can tell its own writes from the
   * user's.
   *
   * Deliberately NOT keyed on the current theme. An effect that reads `theme`
   * re-runs whenever the theme changes - including when the user picks one by
   * name - and then has to decide whether to overwrite it. That decision is
   * unwinnable: turning following off and setting the theme are two state
   * updates from one click, and any ordering assumption between them is a race
   * (it lost, reliably, when leaving System for a named theme).
   *
   * Keyed on the two things that should actually drive it - whether following
   * is on, and what the OS says - it simply never runs on a user pick.
   */
  const lastApplied = useRef<string | null>(null);

  useEffect(() => {
    if (!follows) {
      // Following off: forget what we chose, so switching back on re-applies.
      lastApplied.current = null;
      return;
    }
    const wanted = prefersDark ? SYSTEM_THEME_PAIR.dark : SYSTEM_THEME_PAIR.light;
    if (lastApplied.current === wanted) return;
    lastApplied.current = wanted;
    setTheme(wanted);
  }, [follows, prefersDark, setTheme]);
}
