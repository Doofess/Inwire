/**
 * What colour the native window buttons are painted, per theme.
 *
 * Windows draws the minimise/maximise/close buttons itself, inside the area
 * `titleBarOverlay` reserves. It is told two colours - the ground behind them
 * and the glyph colour - and it draws the glyphs at a weight we do not control.
 * So these two values are the whole of the app's influence over whether the
 * native buttons look like they belong to the window they are in.
 *
 * ## Why this is a table and not a read of the cascade
 *
 * `src/lib/chrome.ts` already settled this argument for the app's own chrome:
 * resolving theme colours in JavaScript means "reading each theme's `--card`
 * out of the computed style and setting it back - JavaScript doing what the
 * cascade already does, and getting it wrong for one frame every time the theme
 * changes". The same is true here and worse, because the consumer is in another
 * process: by the time a computed style could be read, the window has already
 * painted. A table resolves before the first paint and cannot be one frame
 * behind.
 *
 * The hex comes from `PALETTE_BY_THEME`, which already duplicates index.css's
 * surfaces as concrete hex for canvas, MapLibre and the assertion scripts, and
 * which `scripts/themes/packet-themes.ts` holds to index.css so the copies
 * cannot drift. One more consumer of an existing, asserted duplicate is much
 * cheaper than a third copy of four colours.
 *
 * ## Why the colourful preference is not an input
 *
 * The app has a Colourful setting that paints its chrome with a saturated
 * accent (`--chrome`) instead of the card surface. The title row deliberately
 * does **not** follow it: every app this one is measured against - VS Code,
 * Windows Terminal, Figma - keeps its title bar within a few percent of the
 * window background, and a saturated band with native Windows buttons sitting
 * in it is the one choice that reads as a web page wearing a frame. It is also
 * the worst case for glyphs drawn at a fixed weight.
 *
 * So the pair here is always the *plain* one, `--card` / `--card-foreground`,
 * which index.css itself describes as "already a designed, contrast-checked
 * pair". The Colourful setting keeps a real consumer in the command palette's
 * drawer (`AppMenu.tsx`), so nothing is dead - this is a scope decision, not a
 * retirement, and a future session should not "restore" the missing axis.
 *
 * One dependency worth naming: `surface.foreground` mirrors index.css's
 * `--foreground`, and this uses it as `--card-foreground`. Those are the same
 * value in all four themes today. `scripts/electron/title-bar.ts` asserts that
 * against index.css directly, so the day a theme separates them this fails
 * rather than quietly painting the wrong glyph colour.
 */
import { PALETTE_BY_THEME } from '../src/services/themePalettes';

/** Exactly the two fields `titleBarOverlay` takes, beside its height. */
export interface TitleBarColors {
  color: string;
  symbolColor: string;
}

/**
 * The theme a window opens with when nothing is stored.
 *
 * `normalizeThemeName` in `src/lib/themeOptions.ts` also defaults to `dark`,
 * and `isDarkTheme` defaults to dark for an unresolved name, both for the same
 * reason: guessing light and being wrong is a visible flash to white, and
 * guessing dark and being wrong is not.
 */
export const DEFAULT_TITLE_BAR_THEME = 'dark';

/**
 * How far the title row's foreground fades when the window loses focus.
 *
 * The app's own chrome can express this as an alpha, because it is drawing on
 * itself. `titleBarOverlay` cannot: it takes an **opaque** colour, so the dim
 * has to be composited against the title row's own ground here and handed over
 * as a flat hex. That is the whole reason `focused` is a parameter rather than
 * a CSS class.
 */
export const UNFOCUSED_SYMBOL_MIX = 0.6;

function parseHex(hex: string): [number, number, number] | null {
  const match = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  if (match === null) return null;
  const value = parseInt(match[1], 16);
  return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

function toHex(channels: [number, number, number]): string {
  return `#${channels.map((c) => Math.round(c).toString(16).padStart(2, '0')).join('')}`;
}

/**
 * `weight` of `a` over `b`, per channel, in sRGB.
 *
 * sRGB rather than a perceptual space on purpose: this has to match what the
 * renderer's own `opacity`/`color-mix` produces for the app's title row, and
 * the browser composites alpha in sRGB. A perceptually-even fade here would be
 * a *different* grey from the one beside it, which is the only way this can
 * visibly fail.
 */
export function mixHex(a: string, b: string, weight: number): string | null {
  const first = parseHex(a);
  const second = parseHex(b);
  if (first === null || second === null) return null;
  return toHex([0, 1, 2].map((i) => first[i] * weight + second[i] * (1 - weight)) as
    [number, number, number]);
}

/**
 * The overlay pair for a resolved theme name.
 *
 * Takes `resolvedTheme`, never `theme` - the picker has a fifth entry, System,
 * which is a rule for choosing between two themes rather than a theme, so the
 * unresolved value can be the literal string `system` and has no palette.
 *
 * An unknown name falls back to the default theme rather than throwing: this
 * runs while a window is being created, and a stored name from a build that had
 * a theme this one retired must not stop the app opening.
 */
export function resolveTitleBarColors(
  resolvedTheme: string | undefined, focused: boolean,
): TitleBarColors {
  const palette = PALETTE_BY_THEME[resolvedTheme ?? '']
    ?? PALETTE_BY_THEME[DEFAULT_TITLE_BAR_THEME];
  const color = palette.surface.card;
  const symbolColor = focused
    ? palette.surface.foreground
    : mixHex(palette.surface.foreground, color, UNFOCUSED_SYMBOL_MIX) ?? palette.surface.foreground;
  return { color, symbolColor };
}

/** Whether a value off the disk is a pair this can hand to Electron. */
export function isTitleBarColors(value: unknown): value is TitleBarColors {
  if (typeof value !== 'object' || value === null) return false;
  const pair = value as Record<string, unknown>;
  return typeof pair.color === 'string' && parseHex(pair.color) !== null
    && typeof pair.symbolColor === 'string' && parseHex(pair.symbolColor) !== null;
}
