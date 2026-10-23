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
import { LAYERS } from '../../src/services/dissect/fieldRegistry';

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

/**
 * The public documents, each of which must exist. SECURITY.md and SCOPE.md
 * joined when the root CLAUDE.md started pointing at them for detail it no
 * longer carries itself - a pointer into a document nothing checks is the same
 * rot one hop further away.
 */
const PUBLIC_DOCS = ['README.md', 'SECURITY.md', 'SCOPE.md', 'CONTRIBUTING.md'];

/** Where the root CLAUDE.md sends a session for the detail it moved out. */
const REFERENCE_DOCS = ['docs/architecture.md', 'docs/testing.md'];

/**
 * Every CLAUDE.md in the tree, found by walking rather than listed, for the
 * reason `check.ts` discovers scripts: a list is the thing that silently stops
 * including the newest file, and a path-scoped CLAUDE.md is exactly the file a
 * session reads without anyone having checked it.
 */
function findClaudeMds(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      found.push(...findClaudeMds(path.join(dir, entry.name)));
    } else if (entry.name === 'CLAUDE.md') {
      found.push(path.join(dir, entry.name).split(path.sep).join('/'));
    }
  }
  return found;
}
const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'dist-electron', 'release', 'release-artifacts', 'target', '__pycache__', 'test',
]);

/**
 * The repo's Claude Code setup: the skills, the agents and their README. The
 * walk above skips dot-directories, so these are named by exact glob - and
 * never by walking `.claude/`, whose worktrees hold whole checkouts with their
 * own copies of every document here.
 */
function claudeSetupDocs(): string[] {
  const docs = existsSync('.claude/README.md') ? ['.claude/README.md'] : [];
  if (existsSync('.claude/agents')) {
    docs.push(...readdirSync('.claude/agents').filter((n) => n.endsWith('.md')).map((n) => `.claude/agents/${n}`));
  }
  if (existsSync('.claude/skills')) {
    for (const entry of readdirSync('.claude/skills', { withFileTypes: true })) {
      const skill = `.claude/skills/${entry.name}/SKILL.md`;
      if (entry.isDirectory() && existsSync(skill)) docs.push(skill);
    }
  }
  return docs.sort();
}

const DOCS = [
  ...findClaudeMds('.').map((p) => p.replace(/^\.\//, '')).sort(), ...REFERENCE_DOCS, ...PUBLIC_DOCS,
  ...claudeSetupDocs(),
];

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
  // The dock and its whole apparatus. Named the same way round as the three
  // above and for the strongest version of the same reason: any of these coming
  // back would mean a widget column had, and the shell section says what each of
  // the six widgets became instead.
  //
  // `dashboardPrefs.ts` was left off this list while nothing named it, and the
  // rail section names it again - it is where `DASHBOARD_RAIL_WIDTH` went, which
  // is the other half of a sentence about why the rail is 56 and not 48. Listed
  // rather than unnamed, because the entry is worth more as a guard than the
  // mention is worth removing.
  ['components/dock/', 'deleted with the dock; its widgets are a view and a Statistics tab'],
  ['dockPrefs.ts', 'deleted with the dock; the pane shares live in interfacePrefs.ts'],
  ['dashboardPrefs.ts', 'deleted with the dock; it held DASHBOARD_RAIL_WIDTH and the widget config'],
  ['dashboardWidgets.tsx', 'deleted with the dock; there is no widget registry'],
  // Custom Dissectors, which was a settings tab wired to nothing: no dissection
  // path ever asked the engine about a frame, so the panel edited, validated
  // and stored rules that were applied to none. Named here for the same reason
  // as the dock's files - either one coming back would mean the surface had.
  ['customDissectorEngine.ts', 'deleted with the Custom Dissectors tab; no dissection path ever consulted it'],
  ['CustomDissectorsPanel.tsx', 'deleted with the Custom Dissectors tab; it stored rules nothing applied'],
  // **The application's bottom bar was named here and the entry is retired**,
  // because the thing it asserted is no longer the thing that matters.
  //
  // It read: a StatusBar.tsx coming back would mean the whole apparatus had -
  // the readout's inset, the two-block row, `--details-pane-size` read from
  // outside the panes, and a hovered byte derived in `App` from a range the
  // protocol tree also publishes. That was true of the bar that was deleted,
  // and it is the wrong test for the one that replaced it: the bar is back at
  // `components/status/StatusBar.tsx` and carries none of that apparatus.
  //
  // Naming a FILE was always a proxy for naming the apparatus, and the proxy
  // stopped tracking the moment the file could come back without it.
  // `scripts/session/status-bar.ts` asserts the real invariants instead - no
  // layout custom property in the bar, no inline width, one publisher for the
  // hovered byte - which is what this entry was reaching for.
  // The pairing token's config file. `--init-config` minted a token and wrote
  // this so the installer could read it back; the branch is deleted and the
  // token is the FIRST item in the root banner. Named the same way round as the
  // five above: a `config.json` coming back would mean the token had.
  //
  // This entry is the cheapest kind of proof there is - the guard note that
  // names the file is what made this check fail, which is the check working. A
  // note recording a deletion has to name the thing it deleted, so every such
  // note lands here by construction.
  ['config.json', 'deleted with the pairing token; unix mints its own inline (ADR 0029)'],  ['scripts/session/dock.ts', 'deleted with the dock; scripts/session/view.ts covers the rail'],
  // The row, the 44px strip and the agent banner, all one deletion. The filter
  // is in the title row's centre and the banner's fault is named once, in the
  // status bar. Named in the guidance because a deletion note has to say what
  // it deleted, which is how every entry in this table gets here.
  ['FilterRow.tsx', 'deleted with the filter row; the filter is the title row centre slot'],
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
  // The four directories that line above describes and does not cover. They
  // were missing from this table for as long as it has existed, and the check
  // passed anyway on every machine it had ever run on - because every one of
  // those machines had built at least once, so `dist/` and `release/` were
  // there to be found. The first run on a runner with a clean checkout failed,
  // naming all five references.
  //
  // Worth keeping as a lesson rather than just a fix: a check that reads the
  // working tree is answering a question about THIS CLONE, and a developer's
  // clone is the one place the answer is always yes. Nothing here was wrong
  // about the documentation - `dist/` is exactly where Vite writes - so the
  // report is the right outcome and the assertion was the wrong one.
  ['dist/', "Vite's renderer build output, written by `npm run build`"],
  ['release/', 'electron-builder output, written by `npm run pack`'],
  ['release/win-unpacked/', 'the unpacked app inside it, which `npm run pack` produces'],
  ['local-agent/dist/', "PyInstaller's output directory for the agent"],
  ['local-agent/dist/inwire-agent-windows/',
    'the --onedir tree inside it; a directory rather than one file (local-agent/CLAUDE.md)'],
]);

/**
 * Named, and in somebody else's repository.
 *
 * A third list because the assertion is different again: these are not absent
 * from here deliberately and they are not written by a build - they were never
 * ours. The guidance cites them because a decision here was copied from a
 * decision there, and naming the file is what lets the next session check the
 * copy rather than re-derive it.
 *
 * Reported rather than asserted. Nothing here can look at another repository,
 * and a check that tried would be a network call in a suite whose whole promise
 * is plain `tsx` with no I/O outside this tree. The value of the list is that a
 * foreign path has to be ADDED to it deliberately, which is the moment somebody
 * decides the citation is worth carrying.
 */
const ELSEWHERE = new Map<string, string>([
  ['src/vs/workbench/browser/media/floatingPanels.css',
    'microsoft/vscode: the Modern UI card cluster the rail and the workspace copy'],
  // The same file by its bare name, because the prose cites it once in full and
  // then refers back to it - spelling the whole path every time would be
  // unreadable in a paragraph that mentions it three times.
  ['floatingPanels.css',
    'microsoft/vscode: the same file, short-named after the full path above'],
  ['sidebarPart.ts',
    'microsoft/vscode: where `minimumWidth = 170` is, which MIN_SIDE_BAR_PX cites'],
]);

/** Where the prose's relative paths are rooted. */
const ROOTS = ['', 'src/', 'src/services/', 'electron/', 'local-agent/'];
/** Trees searched when resolving a bare filename. */
const TREES = ['src', 'electron', 'scripts', 'local-agent', 'docs', '.out-of-scope'];

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
  // A key chord, such as `Ctrl+/`, ends in a slash and is not a directory.
  if (/^(Ctrl|Alt|Shift)\+/.test(token)) return false;
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
const elsewhere = new Set<string>();
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
    if (ELSEWHERE.has(token)) {
      elsewhere.add(`${token} — ${ELSEWHERE.get(token)}`);
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
if (elsewhere.size > 0) {
  console.log(`\n      cited from another repository (${elsewhere.size}):`);
  for (const entry of [...elsewhere].sort()) console.log(`        ${entry}`);
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
// Every document, not only the root: a lean root sends a reader to the scoped
// files for the commands, so a stale script name there is just as wrong.
const named = DOCS.filter((doc) => existsSync(doc))
  .flatMap((doc) => [...readFileSync(doc, 'utf8').matchAll(/`npm run ([a-z:]+)`/g)].map((m) => m[1]));
check('every `npm run` the documents name is a real script',
  [...new Set(named)].filter((s) => !scripts.includes(s)), []);

// The reverse, which is how a new script goes undocumented.
//
// `dev:web` used to be exempted here and is deleted: a bare Vite server on
// port 3000 was the browser build's entry point, and the renderer cannot run
// under one any more - `window.inwire` is the preload bridge and only exists
// under Electron, so the page it served would have been broken from the first
// render. It was the last thing in the visible tree that contradicted the
// README's "It is not a web app".
const EXEMPT = new Set(['build:electron', 'clean']);
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

/**
 * Features the README advertised after they were deleted.
 *
 * A separate list from the one above because the failure is a different one.
 * Those terms describe an ARCHITECTURE that was replaced, and a visitor who
 * reads them is merely misinformed about how the thing is built. These are
 * things the README told a visitor the application would DO, which it will
 * not - the worst sentence a public README can contain, because the only way
 * to discover it is to install the app and go looking for the feature.
 *
 * Both of these were found by reading the README against CLAUDE.md's
 * must-not-come-back banner on the way to publishing it, not by any check:
 *
 * - **Custom dissectors.** An editor that compiled a user's dissector at
 *   runtime. Deleted in `56925bd`; `packetGenerator.ts` carries the only
 *   surviving mention, as a note about what its constructor used to take.
 * - **A reorderable colour chain.** There was a Settings tab for one revision.
 *   The chain is shipped now, and `services/colorRules.ts` explains at length
 *   why - the parity harness compares the matched rule name against tshark's,
 *   so a chain the user can rewrite is one the harness cannot check.
 *
 * Matched case-insensitively as substrings, so the phrasing has to change
 * rather than the capitalisation. Describing the deletion is still allowed:
 * "the chain is shipped rather than configurable" contains neither phrase.
 */
const README_DELETED_FEATURES = ['custom dissector', 'reorderable'];
check('the README promises no feature that was deleted',
  README_DELETED_FEATURES.filter((t) => readme.toLowerCase().includes(t)), []);

/**
 * The README's layer count, held to the list it cites.
 *
 * It said "57 dissected layers" while `LAYERS` held 60: the three X.509 tokens
 * were appended and the prose was not. Nothing here could see it - a number is
 * not a path, so the reference walk above never looked at it - and it is the
 * most quotable figure in the document, which is the worst place for a stale
 * one.
 *
 * Checkable only because the sentence names its own source. That is the
 * general form: a figure in prose that cites where it comes from can be held
 * to it, and one that does not cannot be held to anything.
 */
const layerClaim = readme.match(/\*\*(\d+) dissected layers\*\*/);
check('the README states a layer count', layerClaim !== null, true);
if (layerClaim !== null) {
  check("...and it is the registry's own", Number(layerClaim[1]), LAYERS.length);
}

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
