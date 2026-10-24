/**
 * Settings copy: one plain line per setting (UX audit group 4).
 *
 *   npx tsx scripts/settings/settings-copy.ts
 *
 * The descriptions had grown into engineering notes - two and three sentences
 * about redraw budgets and why a default is what it is. A description says what
 * the setting does for the person, in one short sentence; a trade-off they need
 * to choose ("costs CPU while capturing") stays, history and reasons go.
 *
 * The rules are mechanical so they hold after this pass: a length ceiling, one
 * sentence, and none of the implementation nouns that crept in. Both copies are
 * read - the panels' `<SettingRow description="...">` and the search index's
 * mirror - because `settings-index.ts` only holds them equal, not short.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SETTINGS_INDEX } from '../../src/lib/settingsIndex';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** About one line in the sheet at its narrowest; the measured long tail was 230. */
const MAX_CHARS = 90;
/** Words that describe how the app is built rather than what it does for you. */
const JARGON = [/\bworker\b/i, /\bchunks?\b/i, /\bredraws?\b/i, /\btokens?\b/i, /\bwe\b/i];

let failures = 0;
function fail(where: string, text: string, why: string) {
  failures++;
  console.log(`FAIL  ${where}: ${why}`);
  console.log(`        "${text}"`);
}

function judge(where: string, text: string) {
  if (text.length > MAX_CHARS) fail(where, text, `${text.length} characters, over ${MAX_CHARS}`);
  if (/[.!?]\s+[A-Z]/.test(text) || /;\s/.test(text)) fail(where, text, 'more than one sentence');
  for (const word of JARGON) {
    if (word.test(text)) fail(where, text, `uses "${word.source.replace(/\\b/g, '')}"`);
  }
}

const panelDir = join(root, 'src', 'components', 'common');
let seen = 0;
for (const file of readdirSync(panelDir).filter((f) => /Panel\.tsx$/.test(f))) {
  const src = readFileSync(join(panelDir, file), 'utf8');
  for (const m of src.matchAll(/<SettingRow\s+label="([^"]+)"[^>]*?\sdescription="([^"]*)"/g)) {
    seen++;
    judge(`${file} "${m[1]}"`, m[2]);
  }
  // A description passed as an expression would slip past the walk above.
  for (const m of src.matchAll(/<SettingRow\s+label="([^"]+)"[^>]*?\sdescription=\{/g)) {
    fail(`${file} "${m[1]}"`, '{…}', 'description is an expression; write it as a string literal');
  }
}
for (const entry of SETTINGS_INDEX) {
  if (entry.description === undefined) continue;
  seen++;
  judge(`settingsIndex "${entry.label}"`, entry.description);
}

console.log(`${failures === 0 ? 'PASS' : 'FAIL'}  ${seen} descriptions read`);
if (seen < 30) {
  failures++;
  console.log('FAIL  fewer descriptions than expected: did the walk break?');
}

if (failures > 0) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log('\nAll settings-copy checks passed.');
