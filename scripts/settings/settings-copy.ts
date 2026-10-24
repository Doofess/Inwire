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

// The privacy row is a disclosure, and shortening it must not make it wrong:
// the capture's addresses go to get.geojs.io only, ipapi.co hears about this
// connection only (the Network panel's Public identity), and the map is what
// the switch is for - the fact a person turns it on for.
const locate = [
  ...[...readFileSync(join(panelDir, 'InterfaceSettingsPanel.tsx'), 'utf8')
    .matchAll(/<SettingRow\s+label="Locate addresses"[^>]*?\sdescription="([^"]*)"/g)].map((m) => m[1]),
  ...SETTINGS_INDEX.filter((e) => e.label === 'Locate addresses').map((e) => e.description ?? ''),
];
if (locate.length !== 2) fail('Locate addresses', String(locate.length), 'expected the panel row and its index mirror');
for (const text of locate) {
  if (!/addresses to get\.geojs\.io/.test(text)) fail('Locate addresses', text, 'does not say the addresses go to get.geojs.io');
  if (!/this connection to ipapi\.co/.test(text)) fail('Locate addresses', text, 'does not keep ipapi.co to this connection');
  if (/addresses[^.]*and ipapi\.co/.test(text)) fail('Locate addresses', text, 'says the addresses go to ipapi.co too');
  if (!/\bmap\b/.test(text)) fail('Locate addresses', text, 'does not say the map needs it');
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
