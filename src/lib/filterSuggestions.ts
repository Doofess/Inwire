/**
 * Whether the filter field's completion list is on screen.
 *
 * Lifted out of `FilterBar` so a script can hold it: the list used to be a pure
 * function of the word being typed, so once a word had completions nothing put
 * them away - Enter applied the filter and left the list over the results, and
 * neither Escape nor a click elsewhere closed it. A dismissal records the word
 * it was made for, so typing on brings completions back without a second state
 * to reset.
 */
export interface SuggestionsInput {
  suggestions: readonly string[];
  /** The word under the caret. */
  token: string;
  /** Who opened the presets list; the chevron's request beats completions. */
  presetsSource: 'field' | 'chevron' | null;
  /** The word the list was last dismissed for, or null. */
  dismissedFor: string | null;
}

export function suggestionsVisible(input: SuggestionsInput): boolean {
  const { suggestions, token, presetsSource, dismissedFor } = input;
  if (suggestions.length === 0) return false;
  if (suggestions.length === 1 && suggestions[0] === token) return false;
  if (presetsSource === 'chevron') return false;
  return dismissedFor !== token;
}
