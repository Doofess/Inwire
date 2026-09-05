import { useEffect } from 'react';
import { colorfulChromeStore } from '../services/themePrefs';
import { usePreferenceValue } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';

/**
 * Applies the Colourful setting to the document.
 *
 * The third of these - `motion.ts` writes `data-motion`, `font.ts` writes
 * `--font-sans`, this writes `data-chrome` - and the same shape as both: read
 * the store, resolve, write onto `<html>`.
 *
 * An attribute rather than the tokens themselves, unlike the font. The plain
 * chrome is four different pairs of colours, one per theme, and writing them
 * from here would mean reading each theme's `--card` out of the computed style
 * and setting it back - JavaScript doing what the cascade already does, and
 * getting it wrong for one frame every time the theme changes. The attribute
 * lets index.css hold both sets and pick between them; see the
 * `[data-chrome="plain"]` block there.
 */
export function useChromePreference(): void {
  const [colorful] = usePreferenceValue(colorfulChromeStore);
  // Cross-tab: the `storage` event fires only in the tabs that did NOT write.
  usePreferenceSync(
    colorfulChromeStore.key,
    colorfulChromeStore.normalize,
    colorfulChromeStore.accept,
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-chrome', colorful ? 'colorful' : 'plain');
  }, [colorful]);
}

/**
 * The same write, before React exists.
 *
 * Called at module scope from `main.tsx` for the reason `applyStoredFont` is:
 * an effect runs after the first paint, so without this someone who turned the
 * accent bar off would watch a coloured header appear and then go plain on
 * every single load. A whole-bar colour change is a far more visible flash than
 * a font swap.
 *
 * Reads storage directly rather than through the store, so this cannot be the
 * thing that forces that module to evaluate.
 */
export function applyStoredChrome(): void {
  try {
    const raw = localStorage.getItem(colorfulChromeStore.key);
    const colorful = raw === null ? true : JSON.parse(raw) !== false;
    document.documentElement.setAttribute('data-chrome', colorful ? 'colorful' : 'plain');
  } catch {
    // Blocked, absent or corrupt storage. The default is colourful, which is
    // what the theme blocks already say, so there is nothing to write.
  }
}
