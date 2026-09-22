/**
 * What happens to the packed output after electron-builder has written it:
 * the Electron fuses are flipped, and the locale packs the app cannot use are
 * dropped.
 *
 * ## The fuses, and why they are here rather than anywhere else
 *
 * A fuse is a byte in the Electron binary that turns a capability off for
 * good. Until this hook flipped them, `Inwire.exe` shipped with Node's own
 * entry points open - demonstrated rather than assumed, on the build this
 * replaced:
 *
 *     ELECTRON_RUN_AS_NODE=1 Inwire.exe -e "console.log(process.version)"
 *     v24.20.0
 *
 * That is arbitrary code, executing as the user, out of the application's own
 * signed executable. Every signature check passes, because the file is
 * unmodified - the capability is the file's.
 *
 * Four fuses, which is the set the root `CLAUDE.md` names:
 *
 *   - **RunAsNode** - the above.
 *   - **EnableNodeCliInspectArguments** - `--inspect` on the same binary,
 *     which opens a debugger port into the main process.
 *   - **EnableNodeOptionsEnvironmentVariable** - `NODE_OPTIONS=--require ...`,
 *     which injects a module into the app without touching the app.
 *   - **OnlyLoadAppFromAsar** - refuses `app/` and `app.asar.unpacked` beside
 *     the asar, so dropping a directory next to the executable cannot replace
 *     the application. Safe here because `resources/app.asar` is what
 *     electron-builder produces; on a build that stopped producing one this
 *     fuse would refuse to start rather than fail quietly.
 *
 * **Flipping mutates the executable, so it must happen before signing** - the
 * ordering `CLAUDE.md` calls out, and the reason this cannot be a step bolted
 * on after a release is built.
 *
 * Deliberately NOT flipped: `EnableEmbeddedAsarIntegrityValidation`.
 * electron-builder already stamps the integrity resource (it logs
 * `updating asar integrity executable resource` during a pack), but turning
 * the *validation* on is a separate decision with a failure mode this has no
 * way to rehearse - a mismatch is an app that will not start, on machines
 * where nobody can read the reason. It is the obvious next one, and it wants
 * its own commit.
 *
 * ## Dropping the Chromium locale packs
 *
 * ## Why not `electronLanguages`
 *
 * That is the documented option and it does not work here: electron-builder
 * applies `electronLanguages` on **macOS only**, where locales are `.lproj`
 * bundles it can prune. On Windows they are `locales/*.pak` files inside the
 * Electron distribution, which no `files` pattern reaches - `files` filters the
 * app's own tree, and this is the runtime's.
 *
 * ## What it is worth
 *
 * Measured on this build: `locales/` is **49 MB** of a 378 MB unpacked app,
 * 54 files. Everything the app displays is a hardcoded English string; there is
 * no i18n layer and no plan for one, so every pack but `en-US` is bytes nobody
 * can ever see.
 *
 * It matters more than a one-off install size, because updates are hand-rolled
 * and ship the whole installer: 48 MB is paid again by every user on every
 * update.
 *
 * ## What it costs
 *
 * `app.getLocale()` still answers correctly - that is the OS's locale, not
 * Chromium's UI language. What changes is the language of Chromium's OWN
 * strings: the default context menu, `<input type="file">` buttons, the PDF
 * viewer's chrome. This app supplies its own menu (`electron/menu.ts`), its own
 * save dialogs through the native `dialog` API (which uses the OS's language,
 * not Chromium's), and does not use the PDF viewer. So the visible surface is
 * close to nothing - but it is not zero, and the day this app grows a second
 * language, `KEEP` is the list to add to.
 */
const { readdirSync, rmSync, statSync } = require('node:fs');
const path = require('node:path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

/** Locales to keep. The app is English-only; see the header. */
const KEEP = new Set(['en-US.pak']);

exports.default = async function afterPack(context) {
  // **Before the platform gate below.** The locale prune is Windows-shaped;
  // a fuse is a property of the Electron binary on every platform, and
  // gating it behind `win32` would mean a macOS build silently shipping with
  // Node's entry points open the day one exists.
  const exe = context.electronPlatformName === 'win32'
    ? `${context.packager.appInfo.productFilename}.exe`
    : context.packager.appInfo.productFilename;
  const binary = path.join(context.appOutDir, exe);
  await flipFuses(binary, {
    version: FuseVersion.V1,
    // `resetAdHocDarwinSignature` is deliberately absent: it is a macOS
    // concern, and this app has no macOS build to have an opinion about.
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  });
  console.log('  • fuses flipped   runAsNode=off inspect=off nodeOptions=off onlyLoadAppFromAsar=on');

  // macOS prunes through `electronLanguages`, and its layout is different
  // enough that doing it here would be a second implementation of one idea.
  if (context.electronPlatformName !== 'win32') return;

  const dir = path.join(context.appOutDir, 'locales');
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    // No `locales/` at all would mean Electron changed its layout. Loud
    // rather than silent: a pruning step that quietly prunes nothing is how
    // 48 MB comes back without anyone noticing.
    throw new Error(`afterPack: expected a locales directory at ${dir}`);
  }

  let removed = 0;
  let freed = 0;
  for (const entry of entries) {
    if (!entry.endsWith('.pak') || KEEP.has(entry)) continue;
    const file = path.join(dir, entry);
    freed += statSync(file).size;
    rmSync(file);
    removed++;
  }

  // The one that must survive. Chromium falls back to `en-US` when its
  // requested locale is missing, so removing it is the difference between a
  // trimmed app and one that fails to start.
  if (!readdirSync(dir).includes('en-US.pak')) {
    throw new Error('afterPack: en-US.pak is missing - Chromium has no fallback left');
  }

  console.log(`  • locales pruned  removed=${removed} freed=${(freed / 1e6).toFixed(1)}MB`);
};
