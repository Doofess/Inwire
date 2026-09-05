import { createPreferenceStore } from './preferenceStore';
import { packetColorSet, type PacketColorSet } from './packetThemes';

/**
 * Whether the app theme follows the operating system.
 *
 * Its own key rather than a fifth value in next-themes' `theme`, because the
 * two answer different questions: next-themes must always hold a concrete
 * theme (it is what puts a class on <html> before first paint), while this
 * records that the concrete theme was CHOSEN FOR the user and should keep being
 * re-chosen. Collapsing them would mean "System" could not stay selected in the
 * picker - the moment it resolved, the stored value would say Day or Midnight.
 *
 * See useSystemThemePreference, which owns the resolving.
 */
export const followSystemThemeStore = createPreferenceStore<boolean>(
  'inwire.themeFollowsSystem',
  (raw) => (typeof raw === 'boolean' ? raw : null),
  false,
);

/**
 * Which colour set the packet list is painted in.
 *
 * A second axis over the app theme rather than part of it, and stored
 * separately for the same reason `followSystemThemeStore` is: next-themes owns
 * one string, the concrete theme, and it has to keep owning exactly that.
 *
 * Deliberately NOT the packet list's own theme picker that this app used to
 * have and deleted. That one chose a whole palette - ground, text and fills -
 * independently of the app, which is how a light app theme shipped a dark
 * packet list. This chooses only how the nine data hues are derived; the ground
 * and the text still come from the app theme, so every combination is coherent
 * by construction. See services/packetThemes.
 */
export const packetColorSetStore = createPreferenceStore<PacketColorSet>(
  'inwire.packetColorSet',
  // Normalised through the same function the assertion script checks, so an
  // id retired later degrades to Default rather than to an empty list.
  (raw) => (typeof raw === 'string' ? packetColorSet(raw) : null),
  'default',
);

/**
 * Whether the header bar and the drawer are painted in the accent.
 *
 * On - the default, and what the app has always done - they take `--chrome`,
 * which is each theme's accent as that ground can carry it. Off, they fall back
 * to `--card`, the same surface as the panels beside them, and the app reads as
 * one continuous window with a border across the top instead of a coloured
 * band.
 *
 * Not part of the theme. It is a second axis over all four, for the same reason
 * the packet colour set is: the theme owns the palette, and this owns how much
 * of it the chrome is allowed to spend. Collapsing them would mean eight themes
 * where there are four.
 *
 * The switching itself is CSS - see the `[data-chrome="plain"]` block in
 * index.css and `lib/chrome.ts`, which writes the attribute.
 */
export const colorfulChromeStore = createPreferenceStore<boolean>(
  'inwire.colorfulChrome',
  (raw) => (typeof raw === 'boolean' ? raw : null),
  true,
);
