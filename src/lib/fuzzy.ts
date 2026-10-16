/**
 * The palette's matcher: a subsequence, scored for where its letters land.
 *
 * Local rather than a dependency (ADR 0057). The lists it ranks are tens of
 * entries - commands, settings, a handful of filters - so the whole question
 * is ordering, and the ordering every palette converges on is this one: a
 * letter at the start of a word is worth more than one inside it, and a run
 * of letters is worth more than the same letters scattered.
 */

export interface FuzzyMatch {
  score: number;
  /** Indices into the text of each matched letter, for highlighting. */
  hits: number[];
}

const WORD_BREAK = new Set([' ', '/', '-', '(', '.', ':']);

/** Null when any letter of the query is missing from the text, in order. */
export function fuzzyScore(query: string, text: string): FuzzyMatch | null {
  const q = query.trim().toLowerCase();
  if (q === '') return { score: 0, hits: [] };
  const t = text.toLowerCase();
  const hits: number[] = [];
  let from = 0;
  for (const ch of q) {
    if (ch === ' ') continue;
    const at = t.indexOf(ch, from);
    if (at < 0) return null;
    hits.push(at);
    from = at + 1;
  }
  let score = 0;
  hits.forEach((at, i) => {
    score += 1;
    if (at === 0 || WORD_BREAK.has(t[at - 1])) score += 3;
    if (i > 0 && hits[i - 1] === at - 1) score += 2;
  });
  score -= 0.01 * (hits[0] ?? 0);
  return { score, hits };
}

/**
 * Every item that matches, best first. Ties keep the input's order - which for
 * the registry is its curated order - and an empty query returns everything,
 * unscored, in that order.
 */
export function rankByFuzzy<T>(
  query: string,
  items: readonly T[],
  textOf: (item: T) => string,
): { item: T; score: number; hits: number[] }[] {
  if (query.trim() === '') return items.map((item) => ({ item, score: 0, hits: [] }));
  const ranked: { item: T; score: number; hits: number[]; at: number }[] = [];
  items.forEach((item, at) => {
    const match = fuzzyScore(query, textOf(item));
    if (match) ranked.push({ item, ...match, at });
  });
  ranked.sort((a, b) => b.score - a.score || a.at - b.at);
  return ranked.map(({ item, score, hits }) => ({ item, score, hits }));
}
