/**
 * Every path the guidance documents and the README name must exist.
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
 * README.md is in here for the same reason pointed outwards. It is the public
 * face on GitHub, and it described the browser app for the whole of phases 3-5
 * after the browser app was deleted - a pairing token to paste, a port to
 * dial, an Express server to start, none of which existed. So beyond the path
 * check it gets two of its own: the terms that went with the browser must not
 * come back (`README_BANNED` below), and the CI badge must name the repository
 * this clone actually points at.
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
import { execFileSync } from 'node:child_process';
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

const DOCS = ['CLAUDE.md', 'local-agent/CLAUDE.md', 'README.md'];

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
  ['security_spec.md', 'deleted; what was worth keeping is docs/ideas/sharing-threat-model.md'],
  // Replaced by ActivityRail + TitleRow + FilterRow. Asserted the other way
  // round like `server.ts`: a Header.tsx coming back would mean the 64px
  // accent bar had, and the shell section says it must not.
  ['Header.tsx', 'deleted with the 64px header bar; split into the rail and two rows'],
  // The hamburger drawer. Three of its seven entries duplicated rail buttons,
  // two became rail buttons, and two went to Settings -> Interface. Named the
  // same way round for the same reason: an AppMenu.tsx coming back would mean a
  // second navigation surface beside the rail had.
  ['AppMenu.tsx', 'deleted with the hamburger menu; its entries are rail buttons and Settings rows'],
]);

/**
 * Named, and written by something rather than committed.
 *
 * Separate from DELIBERATELY_ABSENT because the assertion is different: these
 * SHOULD exist once the right thing has run, and a check that demanded them
 * would fail on a clean clone. Two kinds live here - build outputs, and files
 * written into the user's profile at runtime, which are never in the repository
 * at all. Reported so they stay visible; not asserted either way.
 */
const GENERATED = new Map<string, string>([
  ['maplibre-gl-worker.mjs', 'emitted into dist/assets by the vite plugin'],
  ['release-artifacts/', 'written by scripts/agent/package-unix.ts --build'],
  // Asserting this one would fail on a clean clone, and `npm run check` runs
  // before `npm run build` in CI - so it exists on a developer's machine and
  // not on the runner, which is the worst shape an assertion can have.
  ['dist-electron/', 'written by electron/build.cjs during `npm run build`'],
  ['window-state.json', 'runtime, in userData: bounds and the title bar colour cache'],
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

console.log('\n--- what the README promises about itself ---\n');

const readme = readFileSync('README.md', 'utf8');

/**
 * Terms that went with the browser build and must not come back.
 *
 * Each named a real thing and every one of them is now a wrong answer: the
 * port is not opened, the token and the allowlist were deleted because the
 * pipe's ACL replaced them (ADR 0029), the session lives in files rather than
 * in a browser database, and there is no server to start.
 *
 * README-only. CLAUDE.md must keep saying these words, because its banner is
 * the only place recording that the deletions were decisions - the check above
 * asserts exactly that.
 */
const README_BANNED = [
  'ws://', 'token', 'allowlist', 'IndexedDB', 'Express', '8999', 'config.json',
];
check('the README says nothing the browser build left behind',
  README_BANNED.filter((term) => readme.toLowerCase().includes(term.toLowerCase())), []);

// `npm run start` served the built bundle over Express and is gone. The README
// lists its commands inside fences rather than in backticks, so this reads the
// plain lines; `npm run start:app` is a different, real script.
const readmeScripts = [...readme.matchAll(/\bnpm run ([a-z][a-z:]*)/g)].map((m) => m[1]);
check('every `npm run` the README names is a real script',
  [...new Set(readmeScripts)].filter((s) => !scripts.includes(s)), []);

// Commands the README tells a person to type. A path inside a fence is not
// backticked, so the walk above never sees it - and these are the lines most
// likely to be copied verbatim.
const FENCE = /```[^\n]*\n([\s\S]*?)```/g;
const fenced = [...readme.matchAll(FENCE)].map((m) => m[1]).join('\n');
const commandPaths = new Set(
  [...fenced.matchAll(/[\w.\-/]+\.(?:ts|tsx|py|spec|iss|txt|json|cjs|mjs|md)\b/g)]
    .map((m) => m[0])
    .filter((token) => token.includes('/')),
);
check('every path in a README command exists',
  [...commandPaths].filter((p) => !existsSync(p)).sort(), []);

/**
 * The CI badge has to name the repository this clone points at.
 *
 * The repository is still called `NetView` on GitHub while the product is
 * called Inwire, so the badge's owner/repo is exactly the kind of detail that
 * gets "corrected" to the product name and then serves a 404 image. Read from
 * the remote rather than from `package.json`, whose `repository.url` says
 * `Inwire` and works only because GitHub redirects a rename.
 *
 * Reported rather than asserted when there is no remote to ask: a clone with no
 * origin is a legitimate state and this check has nothing to say about it.
 */
const badge = readme.match(/!\[CI\]\(https:\/\/github\.com\/([^/]+\/[^/]+)\/actions\/workflows\/([^/]+)\/badge\.svg\)/);
if (badge === null) {
  check('the README carries a CI badge this check can read', false, true);
} else {
  check('the badge names a workflow that exists', existsSync(`.github/workflows/${badge[2]}`), true);
  let remote: string | null = null;
  try {
    remote = execFileSync('git', ['remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
  } catch {
    remote = null;
  }
  if (remote === null) {
    console.log('      no git remote to compare the badge against; not asserted');
  } else {
    const slug = remote.replace(/^.*github\.com[:/]/, '').replace(/\.git$/, '');
    check("the badge's owner/repo matches the origin remote", badge[1], slug);
  }
}

console.log(failures === 0
  ? '\nAll documentation reference checks passed.'
  : `\n${failures} documentation reference check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
