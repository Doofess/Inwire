/**
 * What a sandboxed preload is allowed to import.
 *
 *   npx tsx scripts/electron/preload-sandbox.ts
 *
 * This exists because the failure is **completely silent**, and it has already
 * happened once. `electron/preload.ts` imported `node:os` for one string.
 * `tsc` was happy, esbuild bundled it without a word, and the packaged app
 * started normally - except that the preload threw while loading, so
 * `contextBridge.exposeInMainWorld` never ran and `window.inwire` was
 * `undefined`. No capture store, no agent link, no save dialog, and nothing in
 * any console explaining it. The renderer simply behaved as though it were a
 * web page again, which is exactly the state every check in `shell.ts` assumes
 * is impossible.
 *
 * `sandbox: true` gives a preload `electron` plus a small polyfill set and
 * nothing else. Anything further has to come through `process` (which Electron
 * shims), through an IPC call, or from main by another route.
 *
 * A build-output check rather than a source one, because what matters is what
 * the bundler emitted: a source import esbuild inlines is harmless, and one it
 * leaves as a runtime `require` is fatal.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/**
 * What Electron's sandboxed preload can actually resolve.
 *
 * `electron` is the bridge itself. The rest is the documented polyfill set -
 * these are provided by Electron's own loader, not by Node, which is why the
 * list is short and why adding to it is not a decision this repo can make.
 */
const ALLOWED = new Set(['electron', 'events', 'timers', 'url', 'buffer']);

const BUNDLE = path.join('dist-electron', 'preload.cjs');

if (!existsSync(BUNDLE)) {
  // Building here rather than skipping: a check that quietly does nothing when
  // the build output is missing is a check that passes in CI and never runs.
  console.log(`      ${BUNDLE} is missing - building it`);
  execFileSync('node', [path.join('electron', 'build.cjs')], { stdio: 'inherit' });
}

const bundle = readFileSync(BUNDLE, 'utf8');

console.log('--- what the bundled preload requires at runtime ---\n');

// esbuild emits `require("x")` for anything it did not inline. Node builtins
// are never inlined, so this finds exactly the set that must be resolvable
// inside the sandbox.
const required = [...bundle.matchAll(/require\(["']([^"']+)["']\)/g)]
  .map((m) => m[1])
  // A relative path was bundled and is not a runtime resolution.
  .filter((name) => !name.startsWith('.'));
const unique = [...new Set(required)].sort();

console.log(`      requires: ${unique.length ? unique.join(', ') : '(none)'}`);

const forbidden = unique.filter((name) => !ALLOWED.has(name.replace(/^node:/, '')));
check('the preload requires nothing the sandbox cannot resolve', forbidden, []);

// The specific one that bit. `node:os` is the natural way to ask what OS this
// is, it type-checks, it bundles, and it takes the whole bridge down.
checkTrue('...`node:os` in particular is absent',
  !unique.some((name) => name === 'os' || name === 'node:os'));
checkTrue('...and so is `fs`',
  !unique.some((name) => name === 'fs' || name === 'node:fs'));
checkTrue('...and `child_process`',
  !unique.some((name) => name.replace(/^node:/, '') === 'child_process'));

console.log('\n--- and that it still exposes the bridge ---\n');

// If the preload throws before this line runs, everything above can pass and
// the app still has no `window.inwire`. Cheap to assert that the call is in
// the emitted bundle at all.
checkTrue('the bundle calls exposeInMainWorld', bundle.includes('exposeInMainWorld'));
checkTrue("...under the name the renderer looks for", /['"]inwire['"]/.test(bundle));

// CommonJS, because `sandbox: true` forbids an ES-module preload and the repo
// root declares `"type": "module"`. An `import` statement surviving into the
// output would fail to load for a different reason and with equally little
// explanation.
checkTrue('the output is CommonJS, not ESM',
  !/^\s*import\s.+\sfrom\s/m.test(bundle) && !/^\s*export\s/m.test(bundle));

console.log(failures === 0
  ? '\nAll preload sandbox checks passed.'
  : `\n${failures} preload sandbox check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
