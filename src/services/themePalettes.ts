/**
 * The colours each app theme paints *data* with.
 *
 * The app's CSS custom properties describe its chrome - surfaces, borders, one
 * accent. They cannot describe data, because data needs a set of hues that are
 * distinguishable from each other, and chrome only ever needs one. So the
 * packet list, the geo map and the protocol chart all used to invent their own:
 * hardcoded emerald markers, a hardcoded sky-blue line, six packet palettes
 * unrelated to any app theme, and a donut that gave up and painted everything
 * the accent.
 *
 * This is the missing layer. Each theme declares **nine hues of its own**, and
 * everything that colours data derives from them. That is what makes a Midnight
 * packet row and a Midnight map line obviously the same family: they are
 * literally the same nine colours.
 *
 * The hues are authored per theme rather than shared and retinted, because a
 * hue that reads as "green" on a warm near-white ground is not the same hex as
 * one that reads as green on a cool near-black. What IS shared is the shape:
 * every theme spaces its nine so that the packet list's distinguishability
 * floors hold, and `scripts/themes/packet-themes.ts` is what enforces that.
 *
 * Two small maps assign meaning on top (see `packetThemes.ts` for rule roles
 * and `protocolColors.ts` for protocols), so a theme never has to know what a
 * "TCP retransmission" is - it only says what its blue is.
 */

/**
 * A hue name, not a meaning. Deliberately: published palettes are indexed by
 * colour, so a theme is authored as a set of colours rather than as a set of
 * meanings, and the interpretation lives in one shared place instead of being
 * re-decided per theme.
 */
export type Hue =
  | 'red'
  | 'orange'
  | 'yellow'
  | 'green'
  | 'cyan'
  | 'blue'
  | 'violet'
  | 'magenta'
  | 'neutral';

export const HUES: Hue[] = [
  'red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'violet', 'magenta', 'neutral',
];

export interface ThemePalette {
  hues: Record<Hue, string>;
  /**
   * The ground data is drawn on. Mirrors the theme's own `--background`,
   * `--card`, `--foreground` and `--border` from index.css.
   *
   * Duplicated here as concrete hex rather than read through the cascade
   * because canvas, MapLibre and the assertion scripts all need a value
   * without a live document. `scripts/themes/packet-themes.ts` asserts the two
   * copies agree, so the duplication cannot drift silently.
   *
   * `card` is here and not merely `background` because the two grounds serve
   * different things: the packet list paints its rows on `background`, while
   * every panel header that has to NAME a packet - the inspection pane, the hex
   * pane, the detail window - sits on `card`. A colour legible on one is not
   * automatically legible on the other, and on the light themes `card` is the
   * lighter of the two, so it is the stricter test.
   */
  surface: { background: string; card: string; foreground: string; border: string };
}

const PALETTES: Record<string, ThemePalette> = {
  /**
   * Day - the default light theme.
   *
   * Tailwind 600-700s. Dark enough to stay legible once tinted into a
   * near-white ground, and spaced so the four frequent packet families (TCP,
   * UDP, ICMP, broadcast) land far apart on BOTH the hue and the lightness
   * axis - see LIGHTNESS_BY_HUE in packetThemes.ts, which is what lets the
   * fills be this quiet without becoming the same colour.
   */
  light: {
    hues: {
      red: '#c62828', orange: '#c2410c', yellow: '#a16207', green: '#15803d',
      cyan: '#0e7490', blue: '#1d4ed8', violet: '#6d28d9', magenta: '#a21caf',
      neutral: '#5b6470',
    },
    surface: { background: '#f6f7f9', card: '#ffffff', foreground: '#1b1f24', border: '#e1e5ea' },
  },

  /**
   * Paper - a warm, low-glare light theme.
   *
   * Not a sepia filter over Day: the hues are individually pulled toward the
   * warm side and darkened, because a cool hue tinted into a warm ground reads
   * as dirty rather than as itself. The ground is warm enough to be obviously
   * a different theme (5.8 deltaE from Day across background and card, against
   * the registry's floor of 5) while staying a working surface for eight hours
   * rather than a novelty.
   */
  paper: {
    hues: {
      red: '#b3261e', orange: '#a3540d', yellow: '#8a6d09', green: '#3f6b1f',
      cyan: '#116b6b', blue: '#1f4f9c', violet: '#5c3f9e', magenta: '#95306e',
      neutral: '#6b6154',
    },
    surface: { background: '#f4efe4', card: '#fdfaf3', foreground: '#2b2620', border: '#e4dbc9' },
  },

  /**
   * Graphite - the default dark theme.
   *
   * Orange on a warm grey. The ground is Tailwind's `stone` scale rather than
   * `slate`, and that is the half that does the work: slate is a blue grey,
   * and every blue-grey pixel behind an orange accent pushes the accent toward
   * its complement and makes it read as a warning rather than as the app's own
   * colour.
   *
   * The nine hues stay a full spread, because they are the PACKET LIST's
   * colours - categorical data, not chrome - and narrowing them to the accent's
   * family would cost the thing they exist for. Only `neutral` sits on the
   * ground's own grey, so unmatched rows belong to the theme rather than beside
   * it.
   */
  dark: {
    hues: {
      red: '#f87171', orange: '#fb923c', yellow: '#fbbf24', green: '#4ade80',
      cyan: '#2dd4bf', blue: '#60a5fa', violet: '#a78bfa', magenta: '#f472b6',
      neutral: '#a8a29e',
    },
    surface: { background: '#0c0a09', card: '#1c1917', foreground: '#e7e5e4', border: '#292524' },
  },

  /**
   * Midnight - a cool, deep dark theme for long sessions.
   *
   * The counterweight to Graphite, and the reason both exist: one warm dark and
   * one cool dark is a real choice, where four darks that differ by a few
   * percent of saturation were not.
   *
   * `red` and `magenta` are further apart here than the obvious rose/pink pair
   * would put them. The first draft used `#fb7185` and `#f472b6`, whose fills
   * came out 6.7 deltaE apart - under the 7 the frequent-pair check demands,
   * because ICMP errors and ICMP are both frequent and both matter. Widening
   * the pair to red and fuchsia takes it to 10.5.
   */
  midnight: {
    hues: {
      red: '#f87171', orange: '#fb923c', yellow: '#fde047', green: '#34d399',
      cyan: '#22d3ee', blue: '#818cf8', violet: '#c084fc', magenta: '#e879f9',
      neutral: '#a1a1a1',
    },
    surface: { background: '#1e1e1e', card: '#222222', foreground: '#e4e4e4', border: '#3c3c3c' },
  },
};

export const PALETTE_BY_THEME: Readonly<Record<string, ThemePalette>> = PALETTES;

/**
 * The palette for a resolved theme name.
 *
 * Falls back to the dark palette for an unknown or absent name, for the same
 * reason `isDarkTheme` defaults to dark: next-themes leaves `resolvedTheme`
 * undefined for one tick on mount, and resolving that to a light palette
 * produced a visible flash of the wrong ground on every load.
 */
export function themePalette(resolvedTheme: string | undefined): ThemePalette {
  return (resolvedTheme && PALETTES[resolvedTheme]) || PALETTES.dark;
}
