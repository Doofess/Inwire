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
    minify: false,
    logLevel: 'warning',
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
