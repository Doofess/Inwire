import { createPreferenceStore } from './preferenceStore';

/**
 * Whether Inwire may ask the update feed on its own.
 *
 * **Off by default, and it stays off until somebody says otherwise.** An
 * update check is an outbound request, and CLAUDE.md's standing direction is
 * "no outbound connection the user did not ask for" - which is a sharper rule
 * here than in most apps, because this one is a packet analyzer: a request
 * Inwire makes without being asked shows up in the user's own capture, on the
 * screen they are already staring at, and the first thing they will do is
 * wonder what else it is sending.
 *
 * So the default is not a conservative guess at a preference. It is the
 * product invariant, and the toggle is the consent.
 *
 * `asked` is separate from `automatic` because "no" and "not yet asked" are
 * different states and collapsing them is how a one-time prompt becomes a
 * recurring one. Somebody who declines gets `asked: true, automatic: false`
 * and is never asked again; the switch in Settings is the way back.
 *
 * Its own key rather than a field on an existing one, for the same reason
 * `tourStore` has its own: a corrupt `inwire.layout` must not be able to start
 * making network requests for somebody who turned them off.
 */
export interface UpdatePrefs {
  /** Check the feed once, shortly after launch. */
  automatic: boolean;
  /** Whether the one-time prompt has been answered, either way. */
  asked: boolean;
}

export const UPDATE_DEFAULTS: UpdatePrefs = { automatic: false, asked: false };

export function normalizeUpdatePrefs(raw: unknown): UpdatePrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  // Field by field, the house rule for a preference: one bad field must not
  // discard its siblings. Note which way each defaults - a value that cannot
  // be read must never come back as "yes, keep making requests".
  return {
    automatic: typeof v.automatic === 'boolean' ? v.automatic : UPDATE_DEFAULTS.automatic,
    asked: typeof v.asked === 'boolean' ? v.asked : UPDATE_DEFAULTS.asked,
  };
}

export const updateStore = createPreferenceStore(
  'inwire.updates', normalizeUpdatePrefs, UPDATE_DEFAULTS,
);

/**
 * Whether to ask, right now.
 *
 * A function rather than a condition in the panel, because there are two
 * callers - the panel renders the prompt, and the launch check has to know not
 * to run while it is unanswered - and two copies of this would eventually
 * disagree about whether silence means yes.
 */
export function shouldPrompt(prefs: UpdatePrefs): boolean {
  return !prefs.asked;
}

/** Whether to check on launch. Unanswered is not consent. */
export function shouldCheckOnLaunch(prefs: UpdatePrefs): boolean {
  return prefs.asked && prefs.automatic;
}
