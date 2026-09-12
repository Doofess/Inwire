/**
 * Nothing the renderer loads may reach Node or Electron.
 *
 *   npx tsx scripts/capture/node-safe.ts
 *
 * ## Three rules, one of which is not a grep
 *
 * `CLAUDE.md` has named these as invariants and said "unenforced" beside them
 * since the migration started. This is the enforcement.
 *
 *  1. **Nothing under `src/` imports `electron`.** The renderer is sandboxed
 *     with `nodeIntegration: false`; an `electron` import there resolves to
 *     nothing at runtime and takes the module down with it.
 *  2. **`src/services/` and `src/lib/` import no `node:*`**, with one
 *     deliberate exception. This is what keeps the assertion suite runnable
 *     under plain `tsx` on any machine - a hundred-odd scripts reach into
 *     `src/services/` and none of them has a browser.
 *  3. **`nodeBlockFile.ts` is not reachable from `src/main.tsx`.** That one
 *     cannot be answered by looking at files, only by walking the import graph
 *     from the renderer's entry point, because the hazard is transitive: the
 *     module is *supposed* to exist and is *supposed* to import `node:fs`, and
 *     what must never happen is a chain from the React app to it.
 *
 * ## Why the third rule is worth a graph walk
 *
 * The near miss is documented in `captureClient.ts`'s own header: the store's
 * client is reached from `packetBytes.ts`, which is reached from two assertion
 * scripts, and it sits one import away from the module that owns the real
 * files. Vite would happily follow that edge into the renderer bundle, where
 * `node:fs` is not a thing. The symptom is a build that succeeds and a window
 * that is blank.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 400));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 400));
  }
}

/**
 * The one module allowed to import `node:*`, and why.
 *
 * `nodeBlockFile.ts` is the real-file implementation of `BlockFile`, which
 * exists so the capture format can be driven against a `MemoryBlockFile` in a
 * test and against a disk in the store. It is imported by
 * `electron/store/volume.ts` and by scripts, never by the app - which rule 3
 * is what proves.
 */
const MAY_IMPORT_NODE = new Map<string, string>([
  ['src/services/capture/nodeBlockFile.ts',
    'the real-file BlockFile; loaded by the store process and by scripts, never by the renderer'],
]);

/**
 * Modules the renderer's entry point must not be able to reach.
 *
 * `nodeBlockFile.ts` because it imports `node:fs`. `captureHost.ts` because it
 * is the store's whole routing layer and pulls `fflate` and the filter
 * compiler in with it - reachable from the app would mean shipping the store
 * inside the renderer bundle, which is not a crash but is not intended either.
 */
const STORE_ONLY = [
  'src/services/capture/nodeBlockFile.ts',
  'src/services/capture/captureHost.ts',
];

const posix = (p: string) => p.split(path.sep).join('/');

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry)) out.push(posix(full));
  }
  return out;
}

/**
 * Every module specifier a file imports.
 *
 * Regex rather than the TypeScript compiler API, deliberately: this has to run
 * under plain `tsx` in a second, and a specifier is the one part of an import
 * that is trivially unambiguous. It matches static imports, `export ... from`,
 * and dynamic `import(...)` - `type` imports included, because a type-only
 * import of a Node module is still a claim about where this file can live.
 */
function specifiersOf(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  const out: string[] = [];
  const patterns = [
    /\bimport\s+[^;'"]*?\bfrom\s*['"]([^'"]+)['"]/g,
    /\bexport\s+[^;'"]*?\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) out.push(match[1]);
  }
  return out;
}

/** A relative specifier resolved to a file, or null when it leaves the tree. */
function resolveRelative(from: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null;
  const base = posix(path.join(path.dirname(from), specifier));
  for (const candidate of [
    base, `${base}.ts`, `${base}.tsx`, `${base}/index.ts`, `${base}/index.tsx`,
  ]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return posix(candidate);
  }
  return null;
}

console.log('--- nothing under src/ imports electron ---\n');

{
  const offenders = walk('src')
    .filter((file) => specifiersOf(file).some((s) => s === 'electron' || s.startsWith('electron/')))
    .map(posix);
  check('no renderer module imports electron', offenders, []);
}

console.log('\n--- services and lib import no node: builtins ---\n');

{
  const offenders: string[] = [];
  const exempt: string[] = [];
  for (const file of [...walk(path.join('src', 'services')), ...walk(path.join('src', 'lib'))]) {
    const builtins = specifiersOf(file).filter((s) => s.startsWith('node:'));
    if (builtins.length === 0) continue;
    if (MAY_IMPORT_NODE.has(file)) { exempt.push(`${file} (${builtins.join(', ')})`); continue; }
    offenders.push(`${file}: ${builtins.join(', ')}`);
  }
  check('only the exempt module imports node:*', offenders, []);

  // Asserted the other way round too: an exemption for a module that no longer
  // needs one is a hole nobody would notice closing.
  const unused = [...MAY_IMPORT_NODE.keys()].filter(
    (file) => !exempt.some((e) => e.startsWith(file)));
  check('...and every exemption is still being used', unused, []);
  for (const entry of exempt) {
    console.log(`      exempt: ${entry}`);
    console.log(`              ${MAY_IMPORT_NODE.get(entry.split(' ')[0])}`);
  }
}

console.log('\n--- what the renderer can actually reach ---\n');

{
  const ENTRY = 'src/main.tsx';
  check(`${ENTRY} exists`, existsSync(ENTRY), true);

  /** Every file reachable from the entry point, and how it was reached. */
  const cameFrom = new Map<string, string | null>([[ENTRY, null]]);
  const queue = [ENTRY];
  while (queue.length > 0) {
    const file = queue.shift()!;
    for (const specifier of specifiersOf(file)) {
      const target = resolveRelative(file, specifier);
      // A bare specifier is a dependency, and a dependency's own graph is not
      // this rule's business - `fflate` and `react` are bundled for the
      // renderer on purpose.
      if (target === null || cameFrom.has(target)) continue;
      cameFrom.set(target, file);
      queue.push(target);
    }
  }
  console.log(`      ${cameFrom.size} modules reachable from ${ENTRY}`);

  /** The chain that reaches a module, for a failure that names the edge. */
  const chainTo = (file: string): string => {
    const chain: string[] = [];
    for (let at: string | null | undefined = file; at != null; at = cameFrom.get(at)) {
      chain.unshift(at.replace(/^src\//, ''));
    }
    return chain.join(' -> ');
  };

  const reached = STORE_ONLY.filter((file) => cameFrom.has(file)).map(chainTo);
  check('no store-only module is reachable from the renderer entry', reached, []);

  // The walk has to be able to find things, or the check above passes by
  // reaching nothing at all. `captureClient.ts` is the near miss the header
  // describes - one import from `nodeBlockFile.ts` - so its presence is what
  // says the graph was actually followed that far.
  check('...and the walk got as far as the store client',
    cameFrom.has('src/services/capture/captureClient.ts'), true);
  check('...and as far as the dissector',
    cameFrom.has('src/services/pcapParser.ts'), true);
}

console.log(failures === 0
  ? '\nAll node-safety checks passed.'
  : `\n${failures} node-safety check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
