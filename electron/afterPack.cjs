/**
 * Drops the Chromium locale packs the app cannot use.
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

/** Locales to keep. The app is English-only; see the header. */
const KEEP = new Set(['en-US.pak']);

exports.default = async function afterPack(context) {
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
