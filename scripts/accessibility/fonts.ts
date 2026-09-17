/**
 * Assertion tests for the typography.
 *
 *   npx tsx scripts/accessibility/fonts.ts
 *
 * The app is set in the two faces Windows ships: Segoe UI Variable on
 * `--font-sans` for the chrome, Cascadia Mono on `--font-mono` for the data.
 * No webfont is imported. That is the whole of the typography, and every rule
 * here exists to keep it the whole of it.
 *
 * Two things sat on these tokens before, and each left a rule behind. Geist
 * with JetBrains Mono, chosen independently, was a seam under every table
 * header - hence "one family, two cuts", and the rule that nothing outside
 * index.css names a family. IBM Plex closed the seam for one day and was
 * retired on taste, and taking a webfont out is what showed how much of the
 * old script was about webfonts: which packages, which weights, which
 * imports. None of that survives. The system faces bring three traps of their
 * own, each measured against Chromium's DirectWrite path and each recorded
 * on the tokens in index.css: `"Segoe UI Variable"` is not a family name
 * Chromium resolves (the optical-size cuts are), weight 500 snaps UP to
 * Semibold, and Segoe's figures are proportional until `tnum` says otherwise.
 * The checks below are those three facts, plus the inverse of the picker
 * this script used to police: nothing offers a face, nothing writes a token.
 *
 * Each failure this catches is silent. A stray `font-family` in a component
 * renders in whatever it names and looks fine on its own - the seam only shows
 * beside its neighbours. A lost `--font-weight-medium` override makes 45
 * labels Semibold and nothing throws. A webfont imported back in ships bytes
 * and a cold-start swap that the tokens' comment says are gone.
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
const pkg = JSON.parse(text('package.json')) as {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};
const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };

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

// --- No webfont ----------------------------------------------------------------

// The faces are the ones Windows ships, so there is nothing to install and
// nothing to import. Any @fontsource package - not a list of retired ones,
// any - is a webfont coming back; so is an @font-face anywhere under src/,
// which is the other way to self-host one.
check('no @fontsource package is installed',
  Object.keys(deps).filter((d) => d.startsWith('@fontsource')), []);

check('index.css imports no font package',
  withoutComments(css).split('\n').filter((l) => /@import\s+["']@fontsource/.test(l)), []);

check('no @font-face is declared anywhere under src/',
  sources.filter((f) => /@font-face/.test(withoutComments(text(f)))), []);

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

// The optical-size cut is the family name, because `"Segoe UI Variable"` on
// its own resolves to nothing in Chromium - measured, not read: DirectWrite
// exposes the file as Display / Text / Small and no axis. Small is the cut for
// 12px and under. `"Segoe UI"` behind it is Windows 10's face and the one
// `system-ui` resolves to anyway.
check('--font-sans leads with Segoe UI Variable Small, then Segoe UI',
  sans.startsWith('"Segoe UI Variable Small", "Segoe UI"'), true);

// MONO, not Code: Cascadia Code ligates `->`, `==` and `!=`, and an Info
// column that draws an arrow is drawing something that is not in the bytes.
check('--font-mono leads with Cascadia Mono, then Consolas',
  mono.startsWith('"Cascadia Mono", Consolas'), true);
check('--font-mono never names Cascadia Code', /Cascadia Code/.test(mono), false);

// A stack that does not end in a generic family falls back to the browser's
// default serif on a machine missing every named face.
check('--font-sans ends in a generic family', sans.endsWith('sans-serif'), true);
check('--font-mono ends in a generic family', mono.endsWith('monospace'), true);

// --- The two traps the system faces bring --------------------------------------

// Neither face has a 500, and Chromium resolves 500 to Semibold, not Regular -
// measured: the ink at 500 equals the ink at 600 in every cut. Left alone,
// `font-medium` and `font-semibold` are one weight, and the heavier one.
// Fluent's own ramp is Regular and Semibold with no step between, so medium
// is mapped to Regular in @theme. Deleting the line fails nothing but this.
check('--font-weight-medium is remapped to 400', tokenValue('--font-weight-medium'), '400');

// Segoe UI Variable's figures are proportional by default - a 1 is narrower
// than a 0 - and only `tnum` lines a column of them up. Static Segoe UI was
// tabular by default, so the day the stack falls through to it this stops
// mattering, which is exactly the kind of thing that lets the feature get
// deleted and not missed until the machine changes.
const bodyRule = css.match(/^\s*body\s*\{[\s\S]*?^\s*\}/m)?.[0] ?? '';
check('body asks for tabular figures', /font-feature-settings:[^;]*"tnum"\s*1/.test(bodyRule), true);

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
