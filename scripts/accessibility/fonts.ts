/**
 * Assertion tests for the typography.
 *
 *   npx tsx scripts/accessibility/fonts.ts
 *
 * The app is set in one type family, IBM Plex, in two cuts: Plex Sans on
 * `--font-sans` for the chrome, Plex Mono on `--font-mono` for the data. That
 * is the whole of the typography, and every rule here exists to keep it the
 * whole of it.
 *
 * This script used to police a typeface picker - three faces on the
 * Accessibility tab, rewriting `--font-sans` on <html> at runtime - and its
 * rules were about keeping the picker's three lists in sync. The picker is
 * deleted, and with it the one thing that could set the sans and the mono from
 * different families. Atkinson Hyperlegible went with it; that is a real
 * low-vision accommodation lost and is recorded in CLAUDE.md rather than
 * glossed. What replaces the old rules is their inverse: nothing offers a
 * face, nothing writes a token, and no component names a family of its own.
 *
 * Each failure this catches is silent. A stray `font-family` in a component
 * renders in whatever it names and looks fine on its own - the seam only shows
 * beside its neighbours. A runtime write to `--font-sans` is the picker coming
 * back one setting at a time. A retired package left in `dependencies` ships
 * a megabyte of woff2 nothing loads.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

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

/** Every source file under src/, as a posix-separated path relative to root. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(root, dir))) {
    const rel = `${dir}/${entry}`;
    if (statSync(join(root, rel)).isDirectory()) out.push(...walk(rel));
    else if (/\.(ts|tsx|css)$/.test(entry)) out.push(rel.split(sep).join('/'));
  }
  return out;
}
const sources = walk('src');

// --- The two packages ----------------------------------------------------------

const WANTED = ['@fontsource-variable/ibm-plex-sans', '@fontsource/ibm-plex-mono'];
const RETIRED = [
  '@fontsource-variable/geist',
  '@fontsource-variable/jetbrains-mono',
  '@fontsource/atkinson-hyperlegible',
  '@fontsource-variable/nunito',
];

check('both Plex packages are imported by index.css',
  WANTED.filter((p) => !css.includes(`@import "${p}`)), []);

check('both Plex packages are installed',
  WANTED.filter((p) => !(p in deps)), []);

check('no retired face is still imported by index.css',
  RETIRED.filter((p) => css.includes(`@import "${p}`)), []);

check('no retired face is still installed',
  RETIRED.filter((p) => p in deps), []);

// --- The two tokens ------------------------------------------------------------

/**
 * The value of one `--token:` declaration in index.css, whitespace collapsed.
 * Anchored to a line start so a comment quoting a stack (`--font-sans: Geist, …;`)
 * is never mistaken for the declaration.
 */
function tokenValue(name: string): string {
  const m = css.match(new RegExp(`^\\s*${name}:\\s*([^;]+);`, 'm'));
  return m ? m[1].replace(/\s+/g, ' ').trim() : '';
}
const sans = tokenValue('--font-sans');
const mono = tokenValue('--font-mono');

check('--font-sans is IBM Plex Sans', sans.startsWith('"IBM Plex Sans Variable", "IBM Plex Sans"'), true);
check('--font-mono is IBM Plex Mono', mono.startsWith('"IBM Plex Mono"'), true);

// A stack that does not end in a generic family falls back to the browser's
// default serif when the woff2 fails to load - which on an air-gapped machine
// with a cold cache is not hypothetical.
check('--font-sans ends in a generic family', sans.endsWith('sans-serif'), true);
check('--font-mono ends in a generic family', mono.endsWith('monospace'), true);

/**
 * The source with its comments blanked. Block comments become spaces so line
 * numbers survive; a `//` comment is dropped from the first `//` that follows
 * whitespace or starts the line, which leaves `https://…` inside a string
 * alone. Prose that names a token or a package is not a declaration or an
 * import, and this suite's comments are dense enough that scanning them was
 * a recurring false positive.
 */
function withoutComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|\s)\/\/.*$/gm, '$1');
}

// --- Nothing else names a family -----------------------------------------------

// A font family may be declared outside index.css only as a token. That means
// a CSS `font-family:`, a JSX `fontFamily=`, a style-object `fontFamily:` or a
// d3 `.style('font-family', ...)` must carry `var(--font-sans)` or
// `var(--font-mono)` on the same line. The two d3 axis calls in
// TrafficTimelineChart.tsx are the legitimate case. READING a computed family
// is not a declaration and is not checked - PacketList.tsx reads
// `style.fontFamily` to size a canvas for text measurement, and a canvas font
// string cannot hold a var() anyway.
const DECLARES_A_FAMILY = /(?:font-family|fontFamily)\s*[:=](?!=)|['"]font-family['"]\s*,/;
const namesAFamily: string[] = [];
for (const file of sources) {
  if (file === 'src/index.css') continue;
  const lines = withoutComments(text(file)).split('\n');
  lines.forEach((line, i) => {
    if (!DECLARES_A_FAMILY.test(line)) return;
    if (/var\(--font-(sans|mono)\)/.test(line)) return;
    namesAFamily.push(`${file}:${i + 1}`);
  });
}
check('every font-family declared outside index.css is a token, not a family name', namesAFamily, []);

// --- Nothing writes the tokens -------------------------------------------------

// The picker wrote `--font-sans` onto <html> with setProperty. Reading a token
// (`var(--font-sans)`) is fine anywhere; naming one as a bare string in a .ts
// or .tsx file is only ever done to write it.
const writesAToken: string[] = [];
for (const file of sources) {
  if (!/\.tsx?$/.test(file)) continue;
  const stripped = withoutComments(text(file)).replace(/var\(--font-(sans|mono)\)/g, '');
  if (/--font-(sans|mono)/.test(stripped)) writesAToken.push(file);
}
check('no source file names --font-sans or --font-mono outside a var()', writesAToken, []);

// --- The picker is gone ----------------------------------------------------------

const deleted = ['src/lib/fontOptions.ts', 'src/lib/font.ts', 'src/services/accessibilityPrefs.ts'];
check('the picker\'s three modules are deleted',
  deleted.filter((p) => sources.includes(p)), []);

const prefs = text('src/services/preferences.ts');
check('inwire.font is a retired preference key',
  /RETIRED_PREFERENCE_KEYS[\s\S]*?'inwire\.font'[\s\S]*?\];/.test(prefs), true);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All typography checks passed.');
process.exit(0);
