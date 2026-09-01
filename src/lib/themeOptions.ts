import { TbSun, TbBook, TbMoon, TbMoonStars, TbDeviceDesktop } from 'react-icons/tb';

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
   * Required. It was optional only because `system` had no mode of its own,
   * and `system` is gone - every theme now names a real palette, so nothing
   * has to resolve to one at runtime.
   */
  mode: 'light' | 'dark';
}

export const THEME_OPTIONS: ThemeOption[] = [
  { value: 'light', label: 'Day', icon: TbSun, mode: 'light' },
  { value: 'paper', label: 'Paper', icon: TbBook, mode: 'light' },
  { value: 'dark', label: 'Graphite', icon: TbMoon, mode: 'dark' },
  { value: 'midnight', label: 'Midnight', icon: TbMoonStars, mode: 'dark' },
];

/**
 * The ids are `light` and `dark` while the labels are Day and Graphite, and
 * that is on purpose.
 *
 * next-themes only writes `color-scheme` onto the document when the stored
 * value is literally `"light"` or `"dark"` - which is what keeps native
 * scrollbars, text selection and form controls on the right side of the
 * light/dark divide. Renaming the two defaults would cost that for the two
 * themes most people use, to gain nothing a label cannot express.
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
 * Each retired theme goes to the survivor closest to it, not to a default:
 * the two warm lights become Paper, the three cool/low-contrast darks become
 * Midnight, and Colorblind Safe - which was a light theme - becomes Day.
 */
export const RETIRED_THEMES: Record<string, string> = {
  'solarized-light': 'paper',
  'gruvbox-light': 'paper',
  'colorblind-safe': 'light',
  'solarized-dark': 'midnight',
  'dracula': 'midnight',
  'mono': 'midnight',
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
 * The picker's fifth entry, which is not a theme.
 *
 * Deliberately outside THEME_OPTIONS: everything downstream of that list - the
 * CSS class blocks, `isDarkTheme`, the palettes, the assertion scripts -
 * assumes each entry names a real set of colours, and `system` names a rule for
 * choosing between two of them. next-themes is never handed this value; see
 * useSystemThemePreference.
 */
export const SYSTEM_THEME_OPTION = {
  value: 'system',
  label: 'System',
  icon: TbDeviceDesktop,
} as const;

/**
 * Which two themes "System" chooses between.
 *
 * Midnight rather than Graphite for the dark half, which is why next-themes'
 * own `enableSystem` is not used: it would resolve to the theme literally named
 * `dark`. Which dark theme suits someone who has asked for "whatever the OS
 * says" is a product decision, and this is where it is made.
 */
export const SYSTEM_THEME_PAIR = { light: 'light', dark: 'midnight' } as const;

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
