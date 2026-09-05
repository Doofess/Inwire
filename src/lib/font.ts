import { useEffect } from 'react';
import { fontStore } from '../services/accessibilityPrefs';
import { usePreferenceValue } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';
import { DEFAULT_FONT_ID, fontStackFor, isFontId } from './fontOptions';

/**
 * Applies the chosen typeface to the document.
 *
 * The same shape as `useMotionPreference` in `motion.ts`: read the store,
 * resolve, write onto `<html>`. Here the written thing is `--font-sans`
 * itself, which every `font-sans` utility and the `body` default already read -
 * so one property reaches the whole app and no component needs to know a
 * setting exists.
 *
 * This beats the value in `index.css` because that token is declared in a plain
 * `@theme` block rather than `@theme inline`, so Tailwind emits it as a real
 * custom property on `:root` and an inline style on the same element wins.
 *
 * `--font-mono` is deliberately untouched. See `fontOptions.ts`.
 */
export function useFontPreference(): void {
  const [font] = usePreferenceValue(fontStore);
  // Cross-tab: the `storage` event fires only in the tabs that did NOT write,
  // so without this a second window keeps the old face until it reloads.
  usePreferenceSync(fontStore.key, fontStore.normalize, fontStore.accept);

  useEffect(() => {
    document.documentElement.style.setProperty('--font-sans', fontStackFor(font));
  }, [font]);
}

/**
 * The same write, before React exists.
 *
 * Called at module scope from `main.tsx`, next to `migrateStoredTheme`, and for
 * the same class of reason: an effect runs AFTER the first paint, so leaving
 * this to `useFontPreference` alone would paint the app once in the default
 * face and reflow into the chosen one a frame later. Text reflowing on load is
 * a poor first impression generally, and a worse one for the reader who
 * changed this setting because the default was hard for them to read.
 *
 * Reads storage directly rather than through the store: the store's own module
 * may not have been evaluated yet, and this must not be the thing that forces
 * it to be.
 */
export function applyStoredFont(): void {
  try {
    const raw = localStorage.getItem(fontStore.key);
    const parsed = raw === null ? null : (JSON.parse(raw) as unknown);
    const id = isFontId(parsed) ? parsed : DEFAULT_FONT_ID;
    document.documentElement.style.setProperty('--font-sans', fontStackFor(id));
  } catch {
    // Blocked, absent or corrupt storage. The CSS default is already Geist, so
    // there is nothing to fall back to and nothing to report.
  }
}
