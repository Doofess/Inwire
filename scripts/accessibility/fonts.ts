/**
 * Assertion tests for the typeface options.
 *
 *   npx tsx scripts/accessibility/fonts.ts
 *
 * The picker in the Accessibility tab, the `@fontsource` imports in
 * `index.css` and the dependencies in `package.json` are three lists that have
 * to agree, and only one of them is visible while you are editing any of the
 * others.
 *
 * The failure this exists to catch is silent in the worst way: add a face to
 * `FONT_OPTIONS` and forget the import, and the option appears in Settings,
 * selects cleanly, persists across reloads - and changes nothing on screen,
 * because the font it names was never loaded. No error, no warning, and the
 * person most likely to hit it is the one who went looking for a more legible
 * face because the default was not working for them.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_FONT_ID, FONT_OPTIONS } from '../../src/lib/fontOptions';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const text = (p: string) => readFileSync(join(root, p), 'utf8');

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

const css = text('src/index.css');
const pkg = JSON.parse(text('package.json')) as { dependencies?: Record<string, string> };
const deps = pkg.dependencies ?? {};

// --- Every offered face is actually loaded ----------------------------------

check('every typeface option is imported by index.css',
  FONT_OPTIONS.filter((f) => !css.includes(`@import "${f.packageName}"`)).map((f) => f.id), []);

check('...and installed',
  FONT_OPTIONS.filter((f) => !(f.packageName in deps)).map((f) => f.id), []);

// --- The stacks themselves ---------------------------------------------------

const GENERIC = ['sans-serif', 'serif', 'monospace', 'system-ui', 'ui-sans-serif'];
check('every stack ends in a generic family, so a failed load degrades',
  FONT_OPTIONS.filter((f) => !GENERIC.some((g) => f.stack.trim().endsWith(g))).map((f) => f.id),
  []);

// A stack naming only the variable file falls back to nothing when the static
// build is what is installed, and vice versa - both names, or neither works.
check('no stack is a single family with no fallback at all',
  FONT_OPTIONS.filter((f) => f.stack.split(',').length < 2).map((f) => f.id), []);

check('the default is one of the options',
  FONT_OPTIONS.some((f) => f.id === DEFAULT_FONT_ID), true);

check('ids are unique',
  FONT_OPTIONS.length, new Set(FONT_OPTIONS.map((f) => f.id)).size);

// --- What the setting is allowed to touch ------------------------------------

// The packet list, hex dump and protocol tree only line up because every glyph
// is the same width, and the header wordmark rides on the same token. A
// typeface option that reached --font-mono would break all four at once, so the
// setting must never name it.
check('no option offers to change the monospace token',
  FONT_OPTIONS.filter((f) => /mono/i.test(f.stack)).map((f) => f.id), []);

const fontModule = text('src/lib/font.ts');
check('the applier writes --font-sans and nothing else',
  [...fontModule.matchAll(/setProperty\(\s*'(--[a-z-]+)'/g)].map((m) => m[1]),
  ['--font-sans', '--font-sans']);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All typeface checks passed.');
process.exit(0);
