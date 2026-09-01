import { createPreferenceStore } from './preferenceStore';

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
  'netview.themeFollowsSystem',
  (raw) => (typeof raw === 'boolean' ? raw : null),
  false,
);
