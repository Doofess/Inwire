import { createPreferenceStore } from './preferenceStore';

/**
 * Whether the first-run tour is done with.
 *
 * The requirement it exists to meet is "it must not happen again after a user
 * succeeds", so the interesting decision is what counts as succeeding.
 *
 * **Finishing retires it, and so does Skip.** Someone who dismisses a tutorial
 * has told you they do not want it; showing it again at the next launch is
 * precisely the nagging that requirement is written against, and it is the
 * behaviour people remember an app for. Retiring on Skip is only defensible
 * because the Accessibility tab keeps a Replay button - without a way back, a
 * mis-click would cost the tour permanently.
 *
 * **Closing the tab mid-tour does not retire it.** Nothing was read and nothing
 * was dismissed; an interrupted first run gets another go.
 *
 * Its own key rather than a field on an existing one, for the same reason
 * `motionStore` is: a corrupt `inwire.layout` must not be able to make the tour
 * reappear for someone who finished it a year ago.
 */
export interface TourPrefs {
  /** Set by reaching the last step, and by Skip. Cleared by Replay. */
  completed: boolean;
}

export const TOUR_DEFAULTS: TourPrefs = { completed: false };

export function normalizeTour(raw: unknown): TourPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    completed: typeof v.completed === 'boolean' ? v.completed : TOUR_DEFAULTS.completed,
  };
}

export const tourStore = createPreferenceStore('inwire.tour', normalizeTour, TOUR_DEFAULTS);
