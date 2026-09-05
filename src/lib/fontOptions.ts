/**
 * The faces the app's chrome can be set in.
 *
 * Declared once, here, the way `themeOptions.ts` declares the four themes -
 * the Accessibility tab's picker, the stored preference and the assertion
 * script all read this array, so a face cannot be offered in the UI without
 * also being imported and installed.
 *
 * **Only the sans is a choice.** `--font-mono` is not on this list and is not
 * settable: the packet list, hex dump and protocol tree are column-aligned and
 * stop being readable the moment the advance width varies. The header wordmark
 * is set in `font-mono` too, which is why it keeps its own face through every
 * option below without needing to be excluded by hand.
 *
 * No React and no DOM, so `scripts/accessibility/fonts.ts` can import it.
 */

export type FontId = 'geist' | 'hyperlegible' | 'nunito';

export interface FontOption {
  id: FontId;
  /** Shown in the picker. */
  label: string;
  /** The line under the picker when this one is selected. */
  hint: string;
  /**
   * The full stack, written exactly as it goes into `--font-sans`.
   *
   * Every one ends in a generic family. A stack that does not is a stack that
   * falls back to the browser's default serif when the woff2 fails to load -
   * which on an air-gapped machine with a cold cache is not hypothetical.
   */
  stack: string;
  /** The `@fontsource` package `index.css` imports for this face. */
  packageName: string;
}

const FALLBACK = 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

export const FONT_OPTIONS: FontOption[] = [
  {
    id: 'geist',
    label: 'Geist',
    hint: 'Sharp and geometric. Neutral enough to stay behind the data.',
    stack: `"Geist Variable", "Geist", ${FALLBACK}`,
    packageName: '@fontsource-variable/geist',
  },
  {
    id: 'hyperlegible',
    label: 'Hyperlegible',
    // The reason this picker belongs in Accessibility rather than Appearance.
    // Atkinson Hyperlegible was drawn by the Braille Institute specifically to
    // separate the characters low-vision readers confuse - I/l/1, O/0, b/d -
    // which is a different job from looking good, and one no other face here
    // is trying to do.
    hint: 'Drawn to pull apart letterforms that are easy to confuse - I/l/1, O/0.',
    stack: `"Atkinson Hyperlegible", ${FALLBACK}`,
    packageName: '@fontsource/atkinson-hyperlegible',
  },
  {
    id: 'nunito',
    label: 'Nunito',
    hint: 'Rounded and softer, if a geometric face is hard going.',
    stack: `"Nunito Variable", "Nunito", ${FALLBACK}`,
    packageName: '@fontsource-variable/nunito',
  },
];

export const DEFAULT_FONT_ID: FontId = 'geist';

export function fontStackFor(id: FontId): string {
  return (FONT_OPTIONS.find((f) => f.id === id) ?? FONT_OPTIONS[0]).stack;
}

export function isFontId(raw: unknown): raw is FontId {
  return typeof raw === 'string' && FONT_OPTIONS.some((f) => f.id === raw);
}
