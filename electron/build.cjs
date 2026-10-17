/**
 * Bundles the main process and the preload.
 *
 * ## Why a bundler and not just `tsc`
 *
 * **A sandboxed preload cannot `require` a relative module.** Electron runs it
 * through a restricted `preloadRequire` that resolves `electron` and a handful
 * of Node builtins and nothing else, so a preload emitted as one file per
 * module fails at load with `module not found: ./channels` - and the failure is
 * quiet in the sense that matters: the window still opens, the app still
 * renders, and `window.inwire` is simply `undefined`. Measured, not guessed.
 *
 * So the preload has to be a single self-contained file, and once it is being
 * bundled the main process may as well be too.
 *
 * ## Why `.cjs` rather than `.js` plus a `package.json`
 *
 * The repository root declares `"type": "module"`, so a `.js` file here would
 * be treated as an ES module and Node would refuse the CommonJS these outputs
 * have to be (`sandbox: true` forbids an ESM preload). Emitting `.cjs` says the
 * same thing in the filename and needs no second file to carry the claim.
 *
 * Type-checking is `tsc -p tsconfig.electron.json --noEmit`, run by
 * `npm run lint`. esbuild does not type-check and is not asked to.
 */
const esbuild = require('esbuild');
const path = require('node:path');

const root = path.join(__dirname, '..');

async function main() {
  await esbuild.build({
    entryPoints: {
      main: path.join(root, 'electron/main.ts'),
      preload: path.join(root, 'electron/preload.ts'),
      // The capture store's utilityProcess entry. Bundled like the others so
      // it carries its `src/services/capture` imports with it.
      'store/store': path.join(root, 'electron/store/entry.ts'),
      // The speed test's utilityProcess (ADR 0054), forked for one test.
      'speedTest/speedTest': path.join(root, 'electron/speedTest/entry.ts'),
      // The NetFlow collector's utilityProcess (ADR 0058): the UDP socket, the
      // journal and the rollup sidecar, and nothing that decodes them.
      'monitoring/monitoring': path.join(root, 'electron/monitoring/entry.ts'),
    },
    outdir: path.join(root, 'dist-electron'),
    outExtension: { '.js': '.cjs' },
    bundle: true,
    platform: 'node',
    // Electron 44 ships Node 22; nothing here needs to be older.
    target: 'node20',
    format: 'cjs',
    // Provided by the runtime, and `electron` must never be inlined.
    external: ['electron'],
    sourcemap: false,
    // Minified, and the reason is the store rather than the disk. `store.cjs`
    // is parsed by a `utilityProcess` on its cold start, which is on the path
    // between the window appearing and a capture being able to begin. The asar
    // saving is a rounding error next to a 246 MB Electron binary.
    //
    // Safe without a sourcemap because nothing here is symbolicated after the
    // fact: a main-process throw goes to `docs/verification.md`'s stderr and to
    // the store's `log()` pipe with its own message, and the fuses forbid
    // attaching an inspector to a packaged build anyway.
    minify: true,
    logLevel: 'warning',
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
