/**
 * Assertion tests for the accent swatches (ADR 0056).
 *
 *   npx tsx scripts/themes/accents.ts
 *
 * The swatches are a table in `src/lib/accents.ts`, and index.css carries the
 * same values as CSS because they have to be right before first paint. That is
 * a second copy, so this is the drift test `status.ts` is for the status
 * colours: `scripts/themes/accent-css.ts` prints the block, and the block
 * between the markers must be exactly what it prints.
 *
 * Contrast per theme and swatch is `registry.ts`'s job; this file holds the
 * table, the setting and the stylesheet to each other.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ACCENTS, DEFAULT_ACCENT, normalizeAccent } from '../../src/lib/accents';
import { accentColorStore } from '../../src/services/themePrefs';
import { loadPreference } from '../../src/services/preferences';
import { THEME_NAMES } from '../../src/lib/themeOptions';
import { accentCss } from './accent-css';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const root = process.cwd();
const css = fs.readFileSync(path.join(root, 'src/index.css'), 'utf8');

// --- the stylesheet is the generator's output --------------------------------

const BEGIN = '/* accent-css:begin */';
const END = '/* accent-css:end */';
const begin = css.indexOf(BEGIN);
const end = css.indexOf(END);
checkTrue('index.css carries the accent-css markers, in order', begin !== -1 && end > begin);
const pasted = begin !== -1 && end > begin ? css.slice(begin + BEGIN.length, end).trim() : '';
check('the block between the markers is accentCss(), byte for byte', pasted, accentCss().trim());

// --- the table ----------------------------------------------------------------

check('seven swatches, Blue first',
  ACCENTS.map((a) => a.id), ['blue', 'teal', 'green', 'violet', 'rose', 'amber', 'graphite']);
check('Blue is the default', DEFAULT_ACCENT, 'blue');
for (const a of ACCENTS) {
  for (const field of ['primary', 'primaryForeground', 'ring'] as const) {
    check(`${a.id}: ${field} has a value for every theme`,
      THEME_NAMES.filter((t) => !/^#[0-9a-f]{6}$/.test(a[field][t] ?? '')), []);
  }
}

// --- normalising a stored value -----------------------------------------------

for (const raw of ['magenta', null, 3, {}, undefined, 'Blue']) {
  check(`normalizeAccent(${JSON.stringify(raw)}) is null`, normalizeAccent(raw), null);
}
for (const a of ACCENTS) check(`normalizeAccent('${a.id}') is '${a.id}'`, normalizeAccent(a.id), a.id);

const storageHolding = (value: string) => ({
  getItem: () => value,
  setItem: () => {},
  removeItem: () => {},
});
check('the setting lives under inwire.accentColor', accentColorStore.key, 'inwire.accentColor');
check('a stored accent that is no longer a swatch loads as Blue',
  loadPreference(accentColorStore.key, accentColorStore.normalize, accentColorStore.defaults,
    storageHolding(JSON.stringify('magenta'))), 'blue');
check('a stored real swatch loads as itself',
  loadPreference(accentColorStore.key, accentColorStore.normalize, accentColorStore.defaults,
    storageHolding(JSON.stringify('rose'))), 'rose');

// --- Blue is today's accent, so the default needs no rule -----------------------

function themeBlock(theme: string): string {
  const selector = theme === 'light' ? '.light, :root' : `.${theme}`;
  const start = css.indexOf(`\n${selector} {`);
  return start === -1 ? '' : css.slice(start, css.indexOf('\n}', start + 1));
}
const tokenIn = (theme: string, token: string) =>
  new RegExp(`\\n\\s*${token}:\\s*(#[0-9a-fA-F]{6})`).exec(themeBlock(theme))?.[1]?.toLowerCase();

const blue = ACCENTS.find((a) => a.id === 'blue')!;
for (const theme of THEME_NAMES) {
  check(`${theme}: Blue is the block's own --primary`, blue.primary[theme], tokenIn(theme, '--primary'));
  check(`${theme}: Blue is the block's own --primary-foreground`,
    blue.primaryForeground[theme], tokenIn(theme, '--primary-foreground'));
  check(`${theme}: Blue is the block's own --ring`, blue.ring[theme], tokenIn(theme, '--ring'));
}
checkTrue('the generated block has no rule for Blue', !/data-accent-color="?blue/.test(accentCss()));

// --- an accent overrides four things and nothing else ---------------------------

const allowed = new Set(['--primary', '--primary-foreground', '--ring', '--speed-download']);
const strays: string[] = [];
for (const rule of accentCss().matchAll(/([^{}]+)\{([^}]*)\}/g)) {
  const selector = rule[1].trim();
  for (const decl of rule[2].matchAll(/(--[a-z-]+)\s*:/g)) {
    const prop = decl[1];
    const ok = allowed.has(prop) || (prop === '--speed-upload' && /violet/.test(selector));
    if (!ok) strays.push(`${selector.split('\n').pop()}: ${prop}`);
  }
}
check('every accent rule sets only --primary, --primary-foreground, --ring and --speed-download '
  + '(and --speed-upload for Violet)', strays, []);
checkTrue('no accent rule touches --accent, which is the hover fill', !/--accent\s*:/.test(accentCss()));

// --- the stamp ---------------------------------------------------------------

const main = fs.readFileSync(path.join(root, 'src/main.tsx'), 'utf8');
checkTrue('main.tsx stamps the accent on <html> at module scope, before render',
  /^stampAccentColor\(\);/m.test(main)
  && /dataset\.accentColor\s*=\s*accentColorStore\.get\(\)/.test(main)
  && main.indexOf('stampAccentColor();') < main.indexOf('createRoot('));
checkTrue('...and re-stamps when the setting changes',
  /accentColorStore\.subscribe\(stampAccentColor\)/.test(main));

// --- the picker ----------------------------------------------------------------

const panel = fs.readFileSync(path.join(root, 'src/components/common/AppearanceSettingsPanel.tsx'), 'utf8');
checkTrue('Appearance renders a swatch per ACCENTS entry', /ACCENTS\.map\(/.test(panel));
checkTrue('...inside a radiogroup named "Accent colour"',
  /role="radiogroup"/.test(panel) && /aria-label="Accent colour"/.test(panel));
checkTrue('...each swatch a radio carrying aria-checked and its label',
  /role="radio"/.test(panel) && /aria-checked=\{/.test(panel) && /aria-label=\{\s*(a|accent|swatch)\.label\s*\}/.test(panel));
checkTrue('...whose value is the accent setting', /usePreferenceValue\(accentColorStore\)/.test(panel));
checkTrue('...and the theme tiles draw the chosen accent', /data-accent-color=\{/.test(panel));

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All accent checks passed.');
