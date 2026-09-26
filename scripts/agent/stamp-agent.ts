/**
 * Turns cargo's output into the agent the installer ships.
 *
 *   npx tsx scripts/agent/stamp-agent.ts
 *
 * Reads `agent-rs/target/release/inwire-agent.exe`, writes
 * `agent-rs/dist/inwire-agent-windows.exe`. Run by `npm run build:agent`
 * (`scripts/agent/build-rust.ps1`) straight after `cargo build`; it is in
 * `check.ts`'s NOT_TESTS because it writes a file.
 *
 * ## What it adds, and why each is there
 *
 * Cargo's GNU build carries **no resources at all** - no VERSIONINFO, no icon,
 * no manifest. `local-agent/CLAUDE.md` says what that costs: no company, no
 * product, no version is also what an unsigned dropper looks like, in the one
 * dialog anyone checks, and it is the field `built-version.ts` reads to catch an
 * installer bundling a stale agent. The PyInstaller build got all three from
 * its spec; this is the same three for the Rust one:
 *
 * - **VERSIONINFO**, with the PyInstaller agent's strings exactly, so Explorer's
 *   Properties and `Get-Item ... .VersionInfo` read the same across the swap.
 *   The version is `package.json`'s, cross-checked against `Cargo.toml` and
 *   against what the binary itself prints for `--version` - three answers that
 *   must agree before anything is written, because a VERSIONINFO that disagrees
 *   with `hello` is worse than none.
 * - **The app's icon**, `electron/resources/icon.ico` - `win.icon` in
 *   `electron-builder.yml`, and byte-identical to `local-agent/icon.ico`
 *   (`scripts/brand/icon.ts`).
 * - **A manifest that says `asInvoker`.** The PyInstaller agent said
 *   `requireAdministrator`, which is why `--version` raised a UAC prompt
 *   (CLAUDE.md §6). The SCM ignores the level when it starts a service, the
 *   installer is already elevated, and a person running `install` unelevated
 *   gets `main.rs`'s "needs an elevated prompt" - so the level bought nothing
 *   but the prompt. The `supportedOS` list is the PyInstaller one, so Npcap's
 *   DLLs see the same OS version in this process that they saw in that one.
 *
 * ## Why after the link, and why `resedit`
 *
 * No resource compiler exists on this machine: the GNU toolchain's
 * self-contained kit has `ld` and `dlltool` but no `windres`, and there is no
 * `rc.exe` without the Windows SDK. The build.rs crates (`embed-resource`,
 * `winresource`) all shell out to one of those two.
 *
 * `resedit` is what **electron-builder itself** stamps `Inwire.exe` with
 * (`app-builder-lib/out/util/resEdit.js`), pure JavaScript, already installed by
 * that dependency - so the agent's resources are written by the same code that
 * writes the app's, and no new tool enters the build.
 *
 * **It must run before signing.** Rewriting a PE's resources rewrites the bytes
 * a signature covers; `resedit` drops the certificate table outright rather
 * than leave one that no longer verifies. So the order is cargo, this,
 * `scripts/sign/sign.ps1` on the output (all three in `build-rust.ps1`), then
 * `iscc` - and this refuses an input that is already signed, because a signed
 * input here means the order has been got wrong somewhere upstream.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Data, NtExecutable, NtExecutableResource, Resource } from 'resedit';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const rel = (p: string) => relative(root, p).split('\\').join('/');

const INPUT = join(root, 'agent-rs', 'target', 'release', 'inwire-agent.exe');
const OUTPUT = join(root, 'agent-rs', 'dist', 'inwire-agent-windows.exe');
const ICON = join(root, 'electron', 'resources', 'icon.ico');

/** en-US, Unicode - the Translation the PyInstaller agent carried. */
const LANG = 1033;
const CODEPAGE = 1200;

const RT_ICON = 3;
const RT_GROUP_ICON = 14;
const RT_VERSION = 16;
const RT_MANIFEST = 24;
/** CREATEPROCESS_MANIFEST_RESOURCE_ID: the one the loader reads for an exe. */
const MANIFEST_ID = 1;

/** VOS_NT_WINDOWS32 and VFT_APP, as the PyInstaller spec wrote them. */
const VOS_NT_WINDOWS32 = 0x40004;
const VFT_APP = 0x1;

function fail(message: string): never {
  console.error(`FAIL  ${message}`);
  process.exit(1);
}

// --- the version, three ways --------------------------------------------------

const version = (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string }).version ?? '';
const parts = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
if (!parts) fail(`package.json version is "${version}", which is not MAJOR.MINOR.PATCH`);
const [major, minor, patch] = parts.slice(1).map(Number);

const crate = /^version = "([^"]+)"$/m.exec(readFileSync(join(root, 'agent-rs', 'Cargo.toml'), 'utf8'))?.[1];
if (crate !== version) {
  fail(`agent-rs/Cargo.toml says ${crate ?? '(nothing)'} and package.json says ${version} - `
    + 'run `npm run sync:version`, then rebuild');
}

if (!existsSync(INPUT)) fail(`${rel(INPUT)} does not exist - run \`npm run build:agent\``);

// What the binary itself reports. `lib.rs` compiles CARGO_PKG_VERSION in, so a
// mismatch here is a build from before the last bump, not a typo anywhere.
let reported: string;
try {
  reported = execFileSync(INPUT, ['--version'], { encoding: 'utf8', timeout: 30_000 }).trim();
} catch (error) {
  fail(`${rel(INPUT)} --version did not run: ${(error as Error).message}`);
}
if (reported !== version) {
  fail(`${rel(INPUT)} reports ${reported}, package.json says ${version} - the build is stale; rebuild it`);
}

// --- the resources ------------------------------------------------------------

/** IMAGE_DIRECTORY_ENTRY_SECURITY: where an Authenticode signature lives. */
const SECURITY_DIRECTORY = 4;

// Loaded with `ignoreCert` so that a signed input reaches the message below
// rather than resedit's generic refusal.
const exe = NtExecutable.from(readFileSync(INPUT), { ignoreCert: true });
if (exe.newHeader.optionalHeaderDataDirectory.get(SECURITY_DIRECTORY).size !== 0) {
  fail(`${rel(INPUT)} is already signed - stamping must come BEFORE signing, not after`);
}
const res = NtExecutableResource.from(exe);

// Replaced rather than merged: the result is a function of the code and of
// this file, whatever an earlier tool may have left in the input.
for (let i = res.entries.length - 1; i >= 0; i--) {
  if ([RT_ICON, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST].includes(Number(res.entries[i].type))) {
    res.entries.splice(i, 1);
  }
}

const vi = Resource.VersionInfo.create({
  lang: LANG,
  fixedInfo: {
    // Four numbers, the fourth unused and zero - as the spec did it.
    fileVersionMS: ((major << 16) | minor) >>> 0,
    fileVersionLS: (patch << 16) >>> 0,
    productVersionMS: ((major << 16) | minor) >>> 0,
    productVersionLS: (patch << 16) >>> 0,
    fileFlagsMask: 0x3f,
    fileFlags: 0,
    fileOS: VOS_NT_WINDOWS32,
    fileType: VFT_APP,
    fileSubtype: 0,
    fileDateMS: 0,
    fileDateLS: 0,
  },
  strings: [{
    lang: LANG,
    codepage: CODEPAGE,
    // The PyInstaller agent's strings, verbatim. OriginalFilename is the
    // INSTALLED name, which is the name the service's ImagePath has always
    // had - cargo's `inwire-agent.exe` is a build detail nobody installs.
    values: {
      CompanyName: 'Inwire',
      FileDescription: 'Inwire capture agent',
      FileVersion: version,
      InternalName: 'inwire-agent-windows',
      OriginalFilename: 'inwire-agent-windows.exe',
      ProductName: 'Inwire',
      ProductVersion: version,
    },
  }],
});
vi.replaceAvailableLanguages([{ lang: LANG, codepage: CODEPAGE }]);
vi.outputToResourceEntries(res.entries);

const icon = Data.IconFile.from(readFileSync(ICON));
if (icon.icons.length === 0) fail(`${rel(ICON)} holds no images`);
Resource.IconGroupEntry.replaceIconsForResource(res.entries, 1, LANG, icon.icons.map((i) => i.data));

const MANIFEST = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
`;
const manifestBytes = Buffer.from(MANIFEST, 'utf8');
res.entries.push({
  type: RT_MANIFEST,
  id: MANIFEST_ID,
  lang: LANG,
  codepage: 0,
  bin: manifestBytes.buffer.slice(manifestBytes.byteOffset, manifestBytes.byteOffset + manifestBytes.byteLength),
});

res.outputResource(exe);
// `generate` also recomputes the PE checksum, which the linker had set.
const output = Buffer.from(exe.generate());

mkdirSync(dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, output);

// --- read back, from the file on disk -------------------------------------------

// Running it is the check a resource reader cannot make: a manifest the loader
// rejects fails at CreateProcess ("side-by-side configuration is incorrect"),
// which is exactly how the SCM would meet it.
let stampedReports: string;
try {
  stampedReports = execFileSync(OUTPUT, ['--version'], { encoding: 'utf8', timeout: 30_000 }).trim();
} catch (error) {
  fail(`the stamped exe does not start: ${(error as Error).message}`);
}
if (stampedReports !== version) fail(`the stamped exe reports ${stampedReports}, expected ${version}`);

const back = NtExecutableResource.from(NtExecutable.from(readFileSync(OUTPUT)));
const readVersion = Resource.VersionInfo.fromEntries(back.entries)[0]
  ?.getStringValues({ lang: LANG, codepage: CODEPAGE }).FileVersion;
if (readVersion !== version) fail(`the stamped VERSIONINFO reads ${readVersion ?? '(nothing)'}`);

const sha256 = createHash('sha256').update(output).digest('hex');
console.log(`stamped   ${rel(OUTPUT)}`);
console.log(`  from    ${rel(INPUT)} (${statSync(INPUT).size.toLocaleString('en-US')} bytes)`);
console.log(`  size    ${output.byteLength.toLocaleString('en-US')} bytes`);
console.log(`  version ${version} (package.json = Cargo.toml = --version = VERSIONINFO)`);
console.log(`  icon    ${icon.icons.length} image(s) from ${rel(ICON)}`);
console.log('  level   asInvoker');
console.log(`  sha256  ${sha256}`);
console.log('  signed  not yet - `npm run build:agent` signs it next (scripts/sign/sign.ps1)');
process.exit(0);
