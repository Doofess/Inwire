import { DEFAULT_FONT_ID, type FontId, isFontId } from '../lib/fontOptions';
import { createPreferenceStore } from './preferenceStore';

/**
 * Settings that exist to make the app usable, rather than to make it look a
 * particular way.
 *
 * Separate from `interfacePrefs.ts` on purpose, and the reason is the same one
 * written above `motionStore` there: a corrupt sibling must never be able to
 * reset one of these. For someone who set Hyperlegible because they cannot
 * comfortably read the default, silently reverting to it is not a cosmetic
 * regression, and folding this in with the layout values would make a bad
 * `inwire.layout` blob able to cause exactly that.
 *
 * It is also why this is deliberately NOT in `INTERFACE_STORES`, whose reset
 * button clears everything it lists.
 */

/** A bare string on its own key - nothing to parse, nothing to partially fail. */
export function normalizeFont(raw: unknown): FontId | null {
  return isFontId(raw) ? raw : null;
}

export const fontStore = createPreferenceStore(
  'inwire.font',
  normalizeFont,
  DEFAULT_FONT_ID,
);
