/**
 * Assertion tests for the icon set.
 *
 *   npx tsx scripts/themes/icon-set.ts
 *
 * Every icon in the app comes from one set, lucide-react, imported where it is
 * used. It lives in themes/ because that is where the checks on visual
 * consistency already are - registry.ts beside it reads ActivityRail.tsx for
 * the same reason.
 *
 * The failure this exists to catch is the two-set end state: a file left on
 * react-icons by a rebase, or a new component written from muscle memory
 * against the set that was here for two years. Nothing at runtime complains -
 * both sets render - so the only symptom is a glyph whose corners and
 * terminals do not quite match its neighbours, and nobody notices until a
 * screenshot.
 *
 * The alias rule is here for a quieter reason. Two Lucide names, `Map` and
 * `Image`, are also globals. Importing either bare shadows the global for the
 * whole module, `new Map()` becomes a React component, and tsc says nothing
 * because both are valid values. So both are always imported `as MapIcon` and
 * `as ImageIcon`, in every file, whether or not that file uses the global.
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

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(root, dir))) {
    const rel = `${dir}/${entry}`;
    if (statSync(join(root, rel)).isDirectory()) out.push(...walk(rel));
    else if (/\.tsx?$/.test(entry)) out.push(rel.split(sep).join('/'));
  }
  return out;
}
const sources = walk('src');

const pkg = JSON.parse(text('package.json')) as { dependencies?: Record<string, string> };
const deps = pkg.dependencies ?? {};

// --- One set, installed ----------------------------------------------------------

check('lucide-react is a dependency', 'lucide-react' in deps, true);
check('react-icons is not', 'react-icons' in deps, false);
check('@heroicons/react is not', '@heroicons/react' in deps, false);

// --- One set, imported -------------------------------------------------------------

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

/** `from 'pkg'`, `from 'pkg/sub'`, `import 'pkg'`, `import('pkg')` and `require('pkg')`. */
const importsFrom = (src: string, pkgName: string) =>
  new RegExp(
    `(?:\\bfrom\\s*|\\bimport\\s*\\(?\\s*|\\brequire\\s*\\(\\s*)["']${pkgName.replace('/', '\\/')}(?:\\/[^"']*)?["']`,
  ).test(src);

const onReactIcons = sources.filter((f) => importsFrom(withoutComments(text(f)), 'react-icons'));
const onHeroicons = sources.filter((f) => importsFrom(withoutComments(text(f)), '@heroicons/react'));
const onLucide = sources.filter((f) => importsFrom(withoutComments(text(f)), 'lucide-react'));

check('no source file imports from react-icons', onReactIcons, []);
check('no source file imports from @heroicons/react', onHeroicons, []);
// A sanity floor rather than a count to maintain: if this ever reads 0 the
// walk is looking at the wrong tree, and every rule above passed vacuously.
check('at least twenty files import from lucide-react', onLucide.length >= 20, true);

// --- The two globals are aliased -------------------------------------------------

const bareGlobals: string[] = [];
for (const f of onLucide) {
  for (const m of withoutComments(text(f)).matchAll(/import\s*\{([^}]*)\}\s*from\s*["']lucide-react["']/g)) {
    const specifiers = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    for (const spec of specifiers) {
      if (spec === 'Map' || spec === 'Image') bareGlobals.push(`${f}: ${spec}`);
    }
  }
}
check('Map and Image are never imported bare from lucide-react', bareGlobals, []);

// --- One stroke weight, set in CSS --------------------------------------------------

// index.css gives every `svg.lucide` a fixed 1.5px stroke, and that rule beats
// the attribute a `strokeWidth` prop writes - so the prop compiles, renders, and
// does nothing. A glyph that needs its own weight says `style={{ strokeWidth }}`.
const css = text('src/index.css');
check('index.css fixes the Lucide stroke at 1.5px', /svg\.lucide\s*\{\s*stroke-width:\s*1\.5px;/.test(css), true);
check('...in screen pixels, not the icon box', /svg\.lucide \*\s*\{\s*vector-effect:\s*non-scaling-stroke;/.test(css), true);

const strokeProps: string[] = [];
for (const f of onLucide) {
  const src = withoutComments(text(f));
  const names: string[] = [];
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*["']lucide-react["']/g)) {
    for (const spec of m[1].split(',').map((s) => s.trim()).filter(Boolean)) {
      names.push(spec.split(/\s+as\s+/).pop()!.replace(/^type\s+/, ''));
    }
  }
  for (const name of names) {
    if (new RegExp(`<${name}\\b[^<>]*\\bstrokeWidth=`).test(src)) strokeProps.push(`${f}: <${name} strokeWidth>`);
  }
}
check('no Lucide component takes a strokeWidth prop the CSS would ignore', strokeProps, []);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All icon-set checks passed.');
process.exit(0);
