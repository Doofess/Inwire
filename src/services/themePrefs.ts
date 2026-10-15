import { createPreferenceStore } from './preferenceStore';
import { packetColorSet, type PacketColorSet } from './packetThemes';
import { DEFAULT_ACCENT, normalizeAccent, type AccentId } from '../lib/accents';

/**
 * Whether the app theme follows the operating system.
 *
 * Its own key rather than a fifth value in next-themes' `theme`, because the
 * two answer different questions: next-themes must always hold a concrete
 * theme (it is what puts a class on <html> before first paint), while this
 * records that the concrete theme was CHOSEN FOR the user and should keep being
 * re-chosen. Collapsing them would mean "System" could not stay selected in the
 * picker - the moment it resolved, the stored value would say Day or Night.
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
 * Which accent swatch the app is painted in (ADR 0056, `lib/accents.ts`).
 *
 * A third axis over the theme, stored on its own key for the reason the two
 * above are. A stored swatch that has since been removed loads as Blue.
 */
export const accentColorStore = createPreferenceStore<AccentId>(
  'inwire.accentColor',
  normalizeAccent,
  DEFAULT_ACCENT,
);

