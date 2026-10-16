/**
 * When the filter field's completion list is on screen.
 *
 *   npx tsx scripts/filter/suggestions-visible.ts
 *
 * The list used to be a pure function of the word being typed, so once a word
 * had completions nothing could put it away: Enter applied the filter and left
 * the list over the results, and neither Escape nor a click elsewhere closed
 * it. Dismissing now records the word it was dismissed for, and typing a
 * different word brings completions back.
 */
import { dismissalAfter, suggestionsVisible } from '../../src/lib/filterSuggestions';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const base = { suggestions: ['dns', 'dns.a', 'dns.qry.name'], token: 'dn', presetsSource: null, dismissedFor: null } as const;

check('a half-typed word with completions shows them', suggestionsVisible({ ...base }), true);
check('no completions, no list', suggestionsVisible({ ...base, suggestions: [] }), false);
check('the one completion that IS the word is not offered', suggestionsVisible({ ...base, suggestions: ['dns'], token: 'dns' }), false);
check('the chevron asking for presets hides completions', suggestionsVisible({ ...base, presetsSource: 'chevron' }), false);
check('dismissed for this word: hidden', suggestionsVisible({ ...base, token: 'dns', dismissedFor: 'dns' }), false);
check('dismissed for an earlier word: a new word shows again', suggestionsVisible({ ...base, token: 'dns.q', dismissedFor: 'dns' }), true);
check('a dismissal holds while the word is unchanged', dismissalAfter('dns', 'dns'), 'dns');
check('a dismissal lapses once the word changes', dismissalAfter('dns', 'dns '), null);
// Apply `dns`, dismiss, clear the field, type `dns` again: the list must come back.
let d: string | null = 'dns';
for (const t of ['dn', 'd', '', 'd', 'dn', 'dns']) d = dismissalAfter(d, t);
check('retyping a dismissed word later shows completions again', suggestionsVisible({ ...base, token: 'dns', dismissedFor: d }), true);

if (failures > 0) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
