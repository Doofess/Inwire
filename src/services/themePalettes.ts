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
 * everything that colours data derives from them. That is what makes a Night
 * packet row and a Night map line obviously the same family: they are
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
  /**
   * A marked packet row's fill and ink (ADR 0067): inverted against the ground,
   * so a mark reads over any colouring rule. Mirrors `--marked` and
   * `--marked-foreground` for the canvas minimap, which has no cascade to read
   * them from; `scripts/themes/registry.ts` asserts the two copies agree.
   */
  marked: { background: string; foreground: string };
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
    marked: { background: '#2a2f37', foreground: '#f4f6f8' },
  },

  /**
   * Dark - the near-black dark theme.
   *
   * This was `midnight`, the cool counterweight to a warm dark called Graphite.
   * Graphite is gone and this took its id: next-themes writes `color-scheme`
   * only for the literal strings "light" and "dark", so the id is what keeps
   * native scrollbars and form controls on the right side of the divide.
   *
   * `red` and `magenta` are further apart here than the obvious rose/pink pair
   * would put them. The first draft used `#fb7185` and `#f472b6`, whose fills
   * came out 6.7 deltaE apart - under the 7 the frequent-pair check demands,
   * because ICMP errors and ICMP are both frequent and both matter. Widening
   * the pair to red and fuchsia takes it to 10.5.
   */
  dark: {
    hues: {
      red: '#f87171', orange: '#fb923c', yellow: '#fde047', green: '#34d399',
      cyan: '#22d3ee', blue: '#818cf8', violet: '#c084fc', magenta: '#e879f9',
      neutral: '#a1a1a1',
    },
    surface: { background: '#101112', card: '#141516', foreground: '#e4e4e4', border: '#2e2f30' },
    marked: { background: '#dcdfe4', foreground: '#101112' },
  },

  /**
   * Dim - a grey ground for long sessions, beside Dark's near-black one.
   *
   * Dark's nine to start with: the ground is lighter, but not so much that a
   * hue legible on near-black stops being legible here, and
   * `scripts/themes/packet-themes.ts` is what decides that rather than taste.
   */
  dim: {
    hues: {
      red: '#f87171', orange: '#fb923c', yellow: '#fde047', green: '#34d399',
      cyan: '#22d3ee', blue: '#818cf8', violet: '#c084fc', magenta: '#e879f9',
      neutral: '#9aa4b0',
    },
    surface: { background: '#1c2026', card: '#20252b', foreground: '#d1d7e0', border: '#353c46' },
    marked: { background: '#cfd6df', foreground: '#1c2026' },
  },

  /**
   * High Contrast - the accessibility theme.
   *
   * Tailwind 300s, lighter than Dark's 400s, so every hue clears 7:1 on the
   * black ground as text and not only as a tint.
   */
  contrast: {
    hues: {
      red: '#fca5a5', orange: '#fdba74', yellow: '#fde047', green: '#86efac',
      cyan: '#67e8f9', blue: '#a5b4fc', violet: '#d8b4fe', magenta: '#f0abfc',
      neutral: '#c4c7cc',
    },
    surface: { background: '#000000', card: '#050505', foreground: '#ffffff', border: '#8a8f98' },
    marked: { background: '#ffffff', foreground: '#000000' },
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
