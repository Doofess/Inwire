import { createPreferenceStore } from './preferenceStore';

/**
 * The display filters most recently applied, newest first (ADR 0057).
 *
 * The filter field offers them on focus and the palette offers them by name,
 * so one list serves both. Only an APPLIED filter is remembered - typing is
 * not choosing, and a list of half-typed expressions is noise.
 */
export const RECENT_FILTERS_KEY = 'inwire.recentFilters';
export const RECENT_FILTERS_MAX = 8;

/** Strings only, trimmed, non-empty, distinct, capped; `null` for anything not a list. */
export function normalizeRecentFilters(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    const expression = entry.trim();
    if (expression === '' || out.includes(expression)) continue;
    out.push(expression);
    if (out.length === RECENT_FILTERS_MAX) break;
  }
  return out;
}

/** The list with `expression` first. An empty expression leaves it as it was. */
export function pushRecentFilter(list: readonly string[], expression: string): string[] {
  const trimmed = expression.trim();
  if (trimmed === '') return list as string[];
  return [trimmed, ...list.filter((e) => e !== trimmed)].slice(0, RECENT_FILTERS_MAX);
}

export const recentFiltersStore = createPreferenceStore<string[]>(
  RECENT_FILTERS_KEY, normalizeRecentFilters, [],
);
