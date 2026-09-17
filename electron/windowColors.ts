/**
 * The colour a window is painted before the renderer has drawn anything.
 *
 * This was `titleBarColors.ts`, and it existed because Windows drew the
 * caption buttons and had to be told two colours for them. The window is
 * frameless now and those buttons are ours, drawn in CSS by
 * `WindowControls.tsx`, which follows the cascade like everything else in the
 * app. So the whole `symbolColor` half of this module - the focused/unfocused
 * axis, `mixHex`, the pre-composited 60% dim - went with it: an unfocused
 * window dims its controls with `opacity`, the way any other element does.
 *
 * What is left is the one thing CSS still cannot do, because it happens before
 * there is a document: **the colour of the window itself, at the instant it is
 * created.**
 *
 * ## Why that is not just a constant
 *
 * It used to be - a `WINDOW_BACKGROUND` constant in `window.ts`, `#09090b`, a
 * near-black picked to match `index.html`'s own class; it is deleted, and the
 * note there says why it must not come back. That was survivable while the
 * flash was a plain window with a native caption above it. It is not
 * survivable now: a frameless
 * window IS the app's surface, so opening one in near-black and repainting it
 * to Day's `#f6f7f9` a beat later is a full-window flash rather than a dark
 * rectangle that happens to be the right colour already.
 *
 * So main caches the resolved theme's ground in `window-state.json` and opens
 * the next window in it. The theme still lives in `localStorage`; this is a
 * cache of what it resolved to, written by the renderer, never the source of
 * truth - exactly the argument `windowState.ts` makes for window bounds, which
 * is why it is the same file.
 *
 * ## Why this is a table and not a read of the cascade
 *
 * `src/lib/chrome.ts` settled that argument once: resolving theme colours in
 * JavaScript means reading a token out of the computed style and setting it
 * back, which is JavaScript doing what the cascade already does and getting it
 * wrong for one frame every time the theme changes. Here it is worse, because
 * the consumer is in another process and runs before the page exists at all.
 *
 * The hex comes from `PALETTE_BY_THEME`, which already duplicates index.css's
 * surfaces as concrete hex for canvas, MapLibre and the assertion scripts, and
 * which `scripts/themes/packet-themes.ts` holds to index.css so the copies
 * cannot drift. One more consumer of an existing, asserted duplicate is much
 * cheaper than a third copy of four colours.
 */
import { PALETTE_BY_THEME } from '../src/services/themePalettes';

/**
 * The theme a window opens with when nothing is stored.
 *
 * `normalizeThemeName` in `src/lib/themeOptions.ts` also defaults to `dark`,
 * and for the same reason: guessing light and being wrong is a white flash,
 * guessing dark and being wrong is a dark one, and the second is the one people
 * do not report as a bug.
 */
export const DEFAULT_WINDOW_THEME = 'dark';

/**
 * The window ground for a resolved theme name.
 *
 * Takes `resolvedTheme`, never `theme` - the picker carries System alongside the
 * two real themes, and System is a rule for choosing between them rather than a
 * theme, so the unresolved value can be the literal string `system` and has no
 * palette. Stated without an ordinal on purpose: it was "the fifth entry" while
 * Paper and Graphite existed, and outlived them by two cuts.
 *
 * An unknown name falls back to the default rather than throwing: this runs
 * while a window is being created, and a stored name from a build that had a
 * theme this one retired must not stop the app opening.
 */
export function resolveWindowBackground(resolvedTheme: string | undefined): string {
  const palette = PALETTE_BY_THEME[resolvedTheme ?? '']
    ?? PALETTE_BY_THEME[DEFAULT_WINDOW_THEME];
  return palette.surface.background;
}

/**
 * Whether that ground is a dark one.
 *
 * Derived from the colour rather than from a second table of theme names. The
 * app already declares each theme's mode in `src/lib/themeOptions.ts`, but that
 * module imports React and `lucide-react`, and main is not dragging a component
 * library in to answer a yes/no question. A duplicated list here would be the
 * other option, and it would be one more thing to forget when a theme is added
 * or retired - which has happened twice.
 *
 * Luminance cannot drift out of agreement with the palette, because it IS the
 * palette. The two grounds are nowhere near the threshold: Day's `#f6f7f9`
 * reads 0.93 and Night's `#161616` reads 0.008, so a 0.5 cut is not a close
 * call for any theme this app could plausibly ship.
 *
 * Its one consumer is `nativeTheme.themeSource` around the quit confirm - see
 * `guardClose` in `main.ts` for why that is set for the dialog and put back
 * immediately afterwards.
 */
export function resolveWindowIsDark(resolvedTheme: string | undefined): boolean {
  const hex = resolveWindowBackground(resolvedTheme);
  const channel = (pair: string): number => {
    const c = Number.parseInt(pair, 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const luminance = 0.2126 * channel(hex.slice(1, 3))
    + 0.7152 * channel(hex.slice(3, 5))
    + 0.0722 * channel(hex.slice(5, 7));
  return luminance < 0.5;
}

/**
 * Whether a value off the disk is a colour this can hand to Electron.
 *
 * Validated rather than trusted for the reason the bounds are: this value is
 * handed straight to `backgroundColor`, and a malformed one is rejected by
 * Electron at construction - which would be a window that does not open,
 * caused by a file the user can edit.
 */
export function isHexColor(value: unknown): value is string {
  return typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value);
}
