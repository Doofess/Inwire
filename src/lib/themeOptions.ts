import { Sun, Moon, Monitor } from 'lucide-react';

/**
 * Every app theme, and whether it is a light or a dark one.
 *
 * Shared by every surface that offers a theme, so they all list the same
 * next-themes values with the same icon/label pairing.
 *
 * `mode` is the important part. Most of the app follows the theme for free
 * through Tailwind's `dark:` variant and the CSS custom properties in
 * index.css, but a handful of components draw with a library that wants a
 * concrete decision - MapLibre picks a whole tile style, D3 picks axis colors -
 * and those need to know which ground they are drawing on. That used to be
 * derived as `resolvedTheme !== 'light'`, which was true for exactly as long as
 * `light` was the only light theme: the moment a second one existed it was
 * classified as dark and those components rendered for the wrong ground.
 * Lightness is a property of a theme, so it is declared here rather than
 * inferred from a name.
 *
 * NOTE: adding a theme means adding a matching class block to index.css with
 * ALL of its custom properties, and listing dark ones in the `dark` custom
 * variant. A block that omits a property silently inherits the light `:root`
 * value instead of failing. scripts/themes/registry.ts enforces both.
 */
export interface ThemeOption {
  value: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  /**
   * Required. It was optional only because `system` was once an entry in this
   * array and had no mode of its own. It is out of the array now - still very
   * much in the picker, as `SYSTEM_THEME_OPTION` below - so every entry here
   * names a real palette and nothing in this list resolves to another at
   * runtime.
   */
  mode: 'light' | 'dark';
}

export const THEME_OPTIONS: ThemeOption[] = [
  { value: 'light', label: 'Day', icon: Sun, mode: 'light' },
  { value: 'dark', label: 'Night', icon: Moon, mode: 'dark' },
];

/**
 * Two themes and a rule, where there were four and a rule.
 *
 * Paper and Graphite are gone. Paper was the warm light one and Graphite the
 * warm dark one, and each existed as a counterweight to the other survivor -
 * "one warm and one cool is a real choice" was the argument, and it was a good
 * argument for four. It is not an argument for keeping a second of each when
 * what is wanted is Day, Night and System.
 *
 * **Night took the `dark` id from Graphite, and that is the part worth
 * knowing.** next-themes writes `color-scheme` onto the document only for the
 * literal strings `"light"` and `"dark"`, which is what keeps native
 * scrollbars, text selection and form controls on the right side of the
 * light/dark divide. While the neutral dark theme was stored as `midnight` it
 * did not get that - the id belonged to Graphite. Deleting Graphite freed it,
 * so the cut fixed something rather than only removing two entries, and every
 * stored `midnight` lands on it through `RETIRED_THEMES`.
 */

/**
 * Themes that no longer exist, and where their users land.
 *
 * This is not tidiness. next-themes does NOT validate the stored value against
 * the `themes` array: its pre-hydration script does `classList.add(stored)`
 * unconditionally, and its cleanup only removes classes it currently knows
 * about. A stored `dracula` therefore puts `class="dracula"` on <html> with no
 * `.dracula` block behind it - so the chrome falls back to the `:root` light
 * baseline while `themePalette()` falls back to the dark palette, Tailwind's
 * `dark:` utilities do not apply, and the settings picker shows nothing
 * selected. Mixed and broken, which is worse than either extreme.
 *
 * Each retired theme goes to the survivor closest to it, not to a default -
 * which with two survivors means every light one lands on Day and every dark
 * one on Night.
 *
 * `paper` and `midnight` are in here as ids this build once shipped, and they
 * are the two that matter most: `midnight` is where most people's dark theme
 * is currently stored, and it must land on `dark` rather than on the fallback
 * for the same reason as everything else here - a stored name with no class
 * block behind it puts `class="midnight"` on <html> against the light `:root`
 * baseline while `themePalette()` returns the dark palette. Mixed and broken,
 * which is worse than either extreme.
 */
export const RETIRED_THEMES: Record<string, string> = {
  'paper': 'light',
  'solarized-light': 'light',
  'gruvbox-light': 'light',
  'colorblind-safe': 'light',
  'midnight': 'dark',
  'solarized-dark': 'dark',
  'dracula': 'dark',
  'mono': 'dark',
};

/**
 * The theme a stored value should resolve to.
 *
 * Pure, and exported, so `scripts/themes/registry.ts` can assert that every
 * retired id lands somewhere real rather than trusting the table above to stay
 * consistent with THEME_OPTIONS by inspection.
 */
export function normalizeThemeName(stored: string | null | undefined): string {
  if (stored && THEME_NAMES.includes(stored)) return stored;
  if (stored && RETIRED_THEMES[stored]) return RETIRED_THEMES[stored];
  return 'dark';
}

/**
 * The picker's third entry, which is not a theme.
 *
 * Deliberately outside THEME_OPTIONS: everything downstream of that list - the
 * CSS class blocks, `isDarkTheme`, the palettes, the assertion scripts -
 * assumes each entry names a real set of colours, and `system` names a rule for
 * choosing between the two. next-themes is never handed this value; see
 * useSystemThemePreference.
 */
export const SYSTEM_THEME_OPTION = {
  value: 'system',
  label: 'System',
  icon: Monitor,
} as const;

/**
 * Which two themes "System" chooses between.
 *
 * Now that there are exactly two, this pair is every theme there is - but it
 * stays a declared pair rather than being inferred from THEME_OPTIONS, and
 * next-themes' own `enableSystem` stays unused. Both for the same reason: which
 * theme someone who asked for "whatever the OS says" should land on is a
 * product decision, and a third theme would otherwise silently make it by
 * position in a list.
 */
export const SYSTEM_THEME_PAIR = { light: 'light', dark: 'dark' } as const;

/** Every theme next-themes is allowed to resolve to. */
export const THEME_NAMES: string[] = THEME_OPTIONS.map((t) => t.value);

const MODE_BY_VALUE = new Map(THEME_OPTIONS.map((t) => [t.value, t.mode] as const));

/**
 * Whether a resolved theme name is a dark one.
 *
 * Takes `resolvedTheme` (never `theme`, which can be the unresolved literal
 * "system"). Defaults to dark for an unknown or absent name: next-themes leaves
 * resolvedTheme undefined for one tick before its mount effect runs, and
 * guessing light there caused a visible flash-to-light on every load.
 */
export function isDarkTheme(resolvedTheme: string | undefined): boolean {
  if (!resolvedTheme) return true;
  return (MODE_BY_VALUE.get(resolvedTheme) ?? 'dark') === 'dark';
}
