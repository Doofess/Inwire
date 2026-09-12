/**
 * Every path CLAUDE.md names must exist.
 *
 *   npx tsx scripts/docs/claude-md-refs.ts
 *
 * CLAUDE.md is the first thing every session reads, and it is the one document
 * whose staleness is actively harmful rather than merely untidy: a path that
 * moved sends the next session to a file that is not there. That happened
 * repeatedly during the Electron migration - the document described
 * `server.ts`, the pairing token and a browser build for several commits after
 * each was deleted, and `local-agent/CLAUDE.md` still pointed at a directory
 * that had been removed when this check was written, which is how it was
 * found.
 *
 * This does NOT check that the prose is true; nothing can. It checks the half
 * that is mechanically checkable, which is the half that rots silently.
 *
 * ## How a reference is resolved
 *
 * The prose writes a path relative to whatever it is discussing.
 * `services/direction.ts` in a paragraph about the renderer means
 * `src/services/direction.ts`; `csp.ts` in a list of modules beside `main.ts`
 * means `electron/csp.ts`. Insisting on repository-root paths everywhere would
 * make the document worse to read, so this resolves the way a reader does - by
 * looking in the obvious places, and by basename for a bare filename.
 *
 * Resolving by basename is loose on purpose. It still catches the case that
 * matters, which is a file DELETED or RENAMED, and it lets the prose stay
 * readable.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

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

const DOCS = ['CLAUDE.md', 'local-agent/CLAUDE.md'];

/** Extensions that make a backticked token a path even without a slash. */
const EXTENSIONS = /\.(ts|tsx|py|md|json|css|cjs|mjs|iss|spec|sh|yml|html|ico)$/;

/** Looks like a path and is not one. */
const NOT_PATHS = new Set([
  'app://', 'app://inwire', 'node:fs', 'node:os', 'text/javascript',
  'ws://localhost:8999', 'tcp_analyze_sequence_number', '/^https?:/',
  'AUTO_PAUSE_AT', 'BUDGET_SLACK',
]);

/**
 * Paths the documents name **because they do not exist**.
 *
 * Listed one by one, so each is a decision. Asserted the other way round: if
 * one of these comes back, this check fails - which is correct, because
 * `server.ts` returning would mean the browser build had, and the banner at
 * the top of CLAUDE.md says it must not.
 */
const DELIBERATELY_ABSENT = new Map<string, string>([
  ['server.ts', 'deleted with the browser build; named under "what it is not"'],
]);

/**
 * Named, and produced by a build rather than committed.
 *
 * Separate from DELIBERATELY_ABSENT because the assertion is different: these
 * SHOULD exist after the right command has run, and a check that demanded them
 * would fail on a clean clone. Reported so they stay visible; not asserted
 * either way.
 */
const GENERATED = new Map<string, string>([
  ['maplibre-gl-worker.mjs', 'emitted into dist/assets by the vite plugin'],
  ['release-artifacts/', 'written by scripts/agent/package-unix.ts --build'],
]);

/** Where the prose's relative paths are rooted. */
const ROOTS = ['', 'src/', 'src/services/', 'electron/', 'local-agent/'];
/** Trees searched when resolving a bare filename. */
const TREES = ['src', 'electron', 'scripts', 'local-agent', 'docs'];

let basenames: Set<string> | null = null;
function indexBasenames(): Set<string> {
  if (basenames) return basenames;
  const found = new Set<string>();
  const walk = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '__pycache__') {
        continue;
      }
      if (entry.isDirectory()) walk(path.join(dir, entry.name));
      else found.add(entry.name);
    }
  };
  for (const tree of TREES) walk(tree);
  basenames = found;
  return found;
}

function looksLikePath(token: string): boolean {
  if (NOT_PATHS.has(token)) return false;
  if (/^[a-z]+:\/\//.test(token)) return false;
  if (token.startsWith('%') || token.startsWith('~') || token.startsWith('\\')) return false;
  if (token.includes(' ') || token.includes('*') || token.includes('|')) return false;
  if (token.startsWith('.') && !token.includes('/')) return false;
  if (!token.includes('/')) return EXTENSIONS.test(token);
  return EXTENSIONS.test(token) || token.endsWith('/');
}

function resolves(token: string, base: string): boolean {
  const clean = token.replace(/\/+$/, '');
  for (const root of [...ROOTS, `${base}/`]) {
    if (existsSync(path.join(root, clean))) return true;
  }
  if (!clean.includes('/')) return indexBasenames().has(clean);
  return false;
}

console.log('--- paths named in the guidance documents ---\n');

const missing: string[] = [];
const skipped = new Set<string>();
const absent: string[] = [];
const generated = new Set<string>();
let referenced = 0;

for (const doc of DOCS) {
  if (!existsSync(doc)) {
    check(`${doc} exists`, false, true);
    continue;
  }
  const text = readFileSync(doc, 'utf8');
  const base = path.dirname(doc);

  for (const match of text.matchAll(/`([^`\n]+)`/g)) {
    const token = match[1].trim();
    if (!looksLikePath(token)) {
      if (token.includes('/') || EXTENSIONS.test(token)) skipped.add(token);
      continue;
    }
    if (GENERATED.has(token)) {
      generated.add(`${token} — ${GENERATED.get(token)}`);
      continue;
    }
    if (DELIBERATELY_ABSENT.has(token)) {
      absent.push(`${token} — ${DELIBERATELY_ABSENT.get(token)}`);
      if (resolves(token, base)) {
        missing.push(`${doc}: ${token} EXISTS but is documented as absent`);
      }
      continue;
    }
    referenced++;
    if (resolves(token, base)) continue;
    missing.push(`${doc}: ${token}`);
  }
}

console.log(`      ${referenced} path references across ${DOCS.length} documents`);
check('every path the guidance names exists', missing, []);

if (absent.length > 0) {
  console.log(`\n      named as deliberately absent (${absent.length}):`);
  for (const entry of absent) console.log(`        ${entry}`);
}
if (generated.size > 0) {
  console.log(`\n      build output, named but not committed (${generated.size}):`);
  for (const entry of [...generated].sort()) console.log(`        ${entry}`);
}
if (skipped.size > 0) {
  console.log(`\n      not treated as paths (${skipped.size}):`);
  for (const token of [...skipped].sort()) console.log(`        ${token}`);
}

console.log('\n--- what the document promises about itself ---\n');

const root = readFileSync('CLAUDE.md', 'utf8');

// The banner is load-bearing: it is the first thing a session reads and the
// only place that says which deletions were decisions rather than tidying.
check('the must-not-come-back banner is present', root.includes('Must not come back'), true);
for (const item of ['pairing token', 'origin allowlist', 'nodeIntegration']) {
  check(`...and still names the ${item}`, root.includes(item), true);
}

const scripts = Object.keys(
  (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts,
);
const named = [...root.matchAll(/`npm run ([a-z:]+)`/g)].map((m) => m[1]);
check('every `npm run` the document names is a real script',
  [...new Set(named)].filter((s) => !scripts.includes(s)), []);

// The reverse, which is how a new script goes undocumented.
const EXEMPT = new Set(['dev:web', 'build:electron', 'clean']);
check('every script worth naming is named',
  scripts.filter((s) => !EXEMPT.has(s) && !named.includes(s)), []);

console.log(failures === 0
  ? '\nAll CLAUDE.md reference checks passed.'
  : `\n${failures} CLAUDE.md reference check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
