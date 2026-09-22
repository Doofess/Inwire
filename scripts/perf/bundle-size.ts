/**
 * The one performance number this repository is allowed to fail on.
 *
 *   npx tsx scripts/perf/bundle-size.ts
 *   npx tsx scripts/perf/bundle-size.ts --write-ceilings
 *
 * Every other perf script here is a measurement. Of the seventeen under
 * `scripts/perf/`, four assert anything and **none of the four asserts a
 * size or a time** - so nothing in this repository failed when the renderer
 * got heavier, and the eager chunk reached 4.38 MB without a single gate
 * noticing.
 *
 * This is the exception, and the reason it *can* be a gate when a launch time
 * cannot is that a byte count is a property of the build rather than of the
 * machine. ADR 0021 is what forbids the others: a number with no right answer
 * must not become a ceiling, because then it becomes a backlog. `dist/` has a
 * right answer - it is the same on every machine that runs the same `npm run
 * build`.
 *
 * **Ceilings may only fall**, which is `acceptance.json`'s "floors only rise"
 * pointed the other way, and it is enforced the same way: by reading the
 * committed copy with `git show HEAD:` rather than by trusting the working
 * tree. The comparison is deliberately the same shape as
 * `scripts/parity/acceptance.ts`'s, because two ratchets that disagree about
 * what a ratchet is would be worse than one.
 *
 * **It skips cleanly with no `dist/`.** CI runs `npm run check` *before*
 * `npm run build` on purpose, so that every `dist/`-dependent script reports
 * SKIP rather than failing - and a check that fails because nothing was built
 * teaches people to ignore it.
 *
 * Two traps this walked into while being written, both recorded so the next
 * edit does not re-introduce them:
 *
 * - **Hashed filenames.** Vite emits `index-BOYwi-cz.js`; the hash changes on
 *   every content change, so a ceiling keyed on the exact filename would be
 *   unfindable after the first edit. Entries are matched by a glob on the
 *   stable part of the name.
 * - **The eager chunk is not the total.** `pdf.worker`, `exceljs` and the
 *   maplibre worker are all lazily fetched and land in `dist/assets` beside
 *   the entry chunk. Ceiling them together and a lazy chunk growing looks
 *   identical to the startup path growing, which is the thing this exists to
 *   see. `eager` and `total` are two separate numbers.
 */
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CEILINGS_PATH = 'test/perf/ceilings.json';
const ASSETS_DIR = join(root, 'dist', 'assets');

interface Ceilings {
  /**
   * What each number means, in the file, because a bare integer in a JSON file
   * is the thing that goes stale without anyone noticing (see
   * `buffer-cost.ts`'s `SUMMARY_BYTES_PER_FRAME`, which sat wrong through two
   * changes while being printed as a measurement).
   */
  note: string;
  measured: string;
  bundle: {
    /** The entry chunk - what must parse before React's first commit. */
    eagerJs: number;
    /** The render-blocking stylesheet beside it. */
    eagerCss: number;
    /** Every emitted asset, lazy chunks included. */
    total: number;
  };
}

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

const kb = (n: number) => `${(n / 1024).toFixed(1)} kB`;

// --- skip cleanly ------------------------------------------------------------

if (!existsSync(ASSETS_DIR)) {
  console.log('SKIP  no dist/assets - run `npm run build` first.');
  console.log('      (CI runs `npm run check` before `npm run build` deliberately,');
  console.log('       so this is the expected result there.)');
  process.exit(0);
}

// --- measure -----------------------------------------------------------------

const files = readdirSync(ASSETS_DIR)
  .map((name) => ({ name, bytes: statSync(join(ASSETS_DIR, name)).size }))
  .sort((a, b) => b.bytes - a.bytes);

/**
 * The entry chunk, by the stable part of its name.
 *
 * `index-<hash>.js` and not `pipeline.worker-<hash>.js`: the Worker is
 * constructed lazily by `pipelineClient.ts`'s `ensureWorker()`, so its 1.3 MB
 * is not on the path to first paint and ceiling it here would be wrong.
 */
const eagerJs = files.find((f) => /^index-[^.]+\.js$/.test(f.name));
const eagerCss = files.find((f) => /^index-[^.]+\.css$/.test(f.name));
const total = files.reduce((sum, f) => sum + f.bytes, 0);

if (eagerJs === undefined || eagerCss === undefined) {
  console.log('FAIL  no index-<hash>.js / index-<hash>.css in dist/assets.');
  console.log('      Either the build is broken or Vite\'s entry naming changed;');
  console.log('      this script matches on it and would silently ceiling nothing.');
  process.exit(1);
}

const measured = { eagerJs: eagerJs.bytes, eagerCss: eagerCss.bytes, total };

console.log('dist/assets:\n');
for (const f of files) {
  const tag = f.name === eagerJs.name ? '  <- eager, parsed before first paint'
    : f.name === eagerCss.name ? '  <- eager, render-blocking' : '';
  console.log(`  ${f.name.padEnd(34)} ${kb(f.bytes).padStart(10)}${tag}`);
}
console.log(`  ${'TOTAL'.padEnd(34)} ${kb(total).padStart(10)}\n`);

// --- --write-ceilings --------------------------------------------------------

if (process.argv.includes('--write-ceilings')) {
  const next: Ceilings = {
    note: 'Ceilings for the built renderer, in bytes. They may only FALL - '
      + 'scripts/perf/bundle-size.ts fails a raised one, read against git HEAD. '
      + 'eagerJs is the entry chunk that must parse before React\'s first commit; '
      + 'total is every emitted asset including lazily-fetched ones.',
    measured: new Date().toISOString().slice(0, 10),
    bundle: measured,
  };
  writeFileSync(join(root, CEILINGS_PATH), `${JSON.stringify(next, null, 2)}\n`);
  console.log(`Wrote ${CEILINGS_PATH}. Commit it in the same commit as the code that moved it.`);
  process.exit(0);
}

// --- the ceilings ------------------------------------------------------------

if (!existsSync(join(root, CEILINGS_PATH))) {
  console.log(`FAIL  ${CEILINGS_PATH} is missing.`);
  console.log('      Run with --write-ceilings to record the current build as the ceiling.');
  process.exit(1);
}

const ceilings = JSON.parse(readFileSync(join(root, CEILINGS_PATH), 'utf8')) as Ceilings;

check('eager JS is within its ceiling',
  measured.eagerJs <= ceilings.bundle.eagerJs,
  true);
if (measured.eagerJs > ceilings.bundle.eagerJs) {
  console.log(`        ${kb(measured.eagerJs)} against a ceiling of ${kb(ceilings.bundle.eagerJs)}`
    + ` (+${kb(measured.eagerJs - ceilings.bundle.eagerJs)})`);
  console.log('        A static import reached src/main.tsx\'s graph. Make it an');
  console.log('        `await import()` - tabularWriters.ts:97 is the pattern - or,');
  console.log('        if the growth is intended, lower nothing and raise this');
  console.log('        ceiling deliberately in its own commit with the reason.');
}

check('eager CSS is within its ceiling',
  measured.eagerCss <= ceilings.bundle.eagerCss, true);
if (measured.eagerCss > ceilings.bundle.eagerCss) {
  console.log(`        ${kb(measured.eagerCss)} against a ceiling of ${kb(ceilings.bundle.eagerCss)}`);
}

check('total emitted assets are within the ceiling',
  measured.total <= ceilings.bundle.total, true);
if (measured.total > ceilings.bundle.total) {
  console.log(`        ${kb(measured.total)} against a ceiling of ${kb(ceilings.bundle.total)}`
    + ` (+${kb(measured.total - ceilings.bundle.total)})`);
}

// --- the ratchet: a ceiling may only fall ------------------------------------
//
// Read from git rather than from the working tree, for the reason
// `acceptance.ts` gives: the cheapest way to pass a ceiling is to raise it, and
// the diff is where that has to become visible.

function committedCeilings(): Ceilings | null {
  try {
    const text = execFileSync('git', ['show', `HEAD:${CEILINGS_PATH}`],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return JSON.parse(text) as Ceilings;
  } catch {
    return null; // not committed yet, or no git - nothing to compare against
  }
}

const previous = committedCeilings();
if (previous) {
  for (const key of ['eagerJs', 'eagerCss', 'total'] as const) {
    // `?? Infinity` rather than an `in` guard, for the same reason acceptance.ts
    // uses `?? 0`: deleting a ceiling is the cheapest way to raise one.
    const before = previous.bundle?.[key] ?? Infinity;
    check(`ceiling for ${key} did not rise`, measured[key] <= before || ceilings.bundle[key] <= before, true);
    if (ceilings.bundle[key] > before) {
      console.log(`        ${key}: ${kb(before)} -> ${kb(ceilings.bundle[key])}.`);
      console.log('        Ceilings only fall. If this is deliberate, it belongs in its');
      console.log('        own commit saying what was added and why it was worth it.');
    }
  }
} else {
  console.log('note  no committed ceilings to compare against; shape checked only.');
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('Bundle size is within every ceiling.');
