/**
 * electron-builder's Windows signing hook - which signs nothing itself.
 *
 * Every file electron-builder wants signed (`Inwire.exe`, and the DLLs that
 * `signExts` in electron-builder.yml adds) is handed to
 * `scripts/sign/sign.ps1`, the one place in this repository that signs. The
 * Inno installer goes through the same script, so a real certificate replaces
 * the self-signed one by changing a thumbprint, and neither build changes.
 *
 * This file therefore carries no certificate, no thumbprint and no signing
 * logic: which certificate, which digest, which timestamp server, what to skip
 * and when a missing certificate is an error are all sign.ps1's decisions, and
 * `scripts/sign/signing.ts` holds this file to calling nothing else.
 *
 * ## When it runs
 *
 * After `afterPack` - which is where `electron/afterPack.cjs` flips the fuses -
 * because app-builder-lib 26 runs the user's afterPack hook, then its own
 * sanity check, then `doSignAfterPack`. Flipping a fuse rewrites bytes in the
 * executable, so it must precede the signature; this ordering is electron-
 * builder's, not something this hook can get wrong.
 *
 * Called once per file per entry in `signingHashAlgorithms`, which the config
 * pins to sha256 alone. The `hash` electron-builder passes is ignored: sign.ps1
 * always signs SHA-256, and a second call would find the file already signed
 * and skip it.
 */
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'sign', 'sign.ps1');

/**
 * Windows PowerShell 5.1, by absolute path: it is on every supported Windows,
 * unlike pwsh, and a PATH lookup is one more thing a build machine can get
 * wrong. sign.ps1 runs under either edition.
 */
function powershell() {
  const root = process.env.SystemRoot || process.env.windir;
  return root
    ? path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    : 'powershell.exe';
}

exports.default = async function sign(configuration) {
  const file = configuration.path;

  if (process.platform !== 'win32') {
    // Authenticode through Set-AuthenticodeSignature is Windows-only. Same
    // rule as sign.ps1 with no certificate: unsigned with a warning, unless
    // signing was required.
    if (process.env.INWIRE_REQUIRE_SIGNING === '1') {
      throw new Error(`sign.cjs: signing is required and ${process.platform} cannot run sign.ps1 (${file})`);
    }
    console.warn(`  • not signed (sign.ps1 needs Windows)  file=${file}`);
    return;
  }

  const result = spawnSync(powershell(), [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', SCRIPT,
    '-Path', file,
  ], { stdio: 'inherit', windowsHide: true });

  if (result.error) throw result.error;
  if (result.status !== 0) {
    // Thrown, not logged: electron-builder's signing queue rejects the pack
    // on a throw, and a pack that "succeeded" with an unsigned exe is the
    // failure worth preventing.
    throw new Error(`sign.ps1 exited ${result.status} for ${file}`);
  }
};
