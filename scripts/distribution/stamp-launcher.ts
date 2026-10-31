/**
 * Turns cargo's output into the `inwire` launcher the installer ships.
 *
 *   npx tsx scripts/distribution/stamp-launcher.ts
 *
 * Reads `launcher-rs/target/release/inwire.exe`, writes
 * `launcher-rs/dist/inwire.exe`. Run by `npm run build:launcher`
 * (`scripts/distribution/build-launcher.ps1`) straight after `cargo build`; it is
 * in `check.ts`'s NOT_TESTS because it writes a file.
 *
 * The same three resources, by the same mechanism, as `scripts/agent/stamp-agent.ts`
 * (read its header for why `resedit`, and why this must run BEFORE signing):
 * VERSIONINFO from package.json, the app's icon, and an `asInvoker` manifest.
 * The launcher matters here for one more reason than the agent did: it compares
 * its own compiled-in version with the ProductVersion of the `Inwire.exe` beside
 * it, so a VERSIONINFO that disagrees with `--version` would be a launcher that
 * can never pair with its own app. The version is therefore cross-checked three
 * ways - package.json, launcher-rs/Cargo.toml, and what the binary prints - before
 * anything is written.
 *
 * A signed input is refused: signing comes after stamping, never before.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Data, NtExecutable, NtExecutableResource, Resource } from 'resedit';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const rel = (p: string) => relative(root, p).split('\\').join('/');

const INPUT = join(root, 'launcher-rs', 'target', 'release', 'inwire.exe');
const OUTPUT = join(root, 'launcher-rs', 'dist', 'inwire.exe');
const ICON = join(root, 'electron', 'resources', 'icon.ico');

/** en-US, Unicode - the Translation the agent carries. */
const LANG = 1033;
const CODEPAGE = 1200;

const RT_ICON = 3;
const RT_GROUP_ICON = 14;
const RT_VERSION = 16;
const RT_MANIFEST = 24;
const MANIFEST_ID = 1;

const VOS_NT_WINDOWS32 = 0x40004;
const VFT_APP = 0x1;
const SECURITY_DIRECTORY = 4;

function fail(message: string): never {
  console.error(`FAIL  ${message}`);
  process.exit(1);
}

const version = (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string }).version ?? '';
const parts = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
if (!parts) fail(`package.json version is "${version}", which is not MAJOR.MINOR.PATCH`);
const [major, minor, patch] = parts.slice(1).map(Number);

const crate = /^version = "([^"]+)"$/m.exec(readFileSync(join(root, 'launcher-rs', 'Cargo.toml'), 'utf8'))?.[1];
if (crate !== version) {
  fail(`launcher-rs/Cargo.toml says ${crate ?? '(nothing)'} and package.json says ${version} - `
    + 'run `npm run sync:version`, then rebuild');
}

if (!existsSync(INPUT)) fail(`${rel(INPUT)} does not exist - run \`npm run build:launcher\``);

let reported: string;
try {
  reported = execFileSync(INPUT, ['--version'], { encoding: 'utf8', timeout: 30_000 }).trim();
} catch (error) {
  fail(`${rel(INPUT)} --version did not run: ${(error as Error).message}`);
}
if (reported !== `inwire ${version}`) {
  fail(`${rel(INPUT)} reports "${reported}", package.json says ${version} - the build is stale; rebuild it`);
}

const exe = NtExecutable.from(readFileSync(INPUT), { ignoreCert: true });
if (exe.newHeader.optionalHeaderDataDirectory.get(SECURITY_DIRECTORY).size !== 0) {
  fail(`${rel(INPUT)} is already signed - stamping must come BEFORE signing, not after`);
}
const res = NtExecutableResource.from(exe);

for (let i = res.entries.length - 1; i >= 0; i--) {
  if ([RT_ICON, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST].includes(Number(res.entries[i].type))) {
    res.entries.splice(i, 1);
  }
}

const vi = Resource.VersionInfo.create({
  lang: LANG,
  fixedInfo: {
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
    values: {
      CompanyName: 'Inwire',
      FileDescription: 'Inwire command-line launcher',
      FileVersion: version,
      InternalName: 'inwire',
      OriginalFilename: 'inwire.exe',
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
const output = Buffer.from(exe.generate());

mkdirSync(dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, output);

// Read back from disk, and run it: a manifest the loader rejects fails at
// CreateProcess, which is how a person would meet it.
let stampedReports: string;
try {
  stampedReports = execFileSync(OUTPUT, ['--version'], { encoding: 'utf8', timeout: 30_000 }).trim();
} catch (error) {
  fail(`the stamped exe does not start: ${(error as Error).message}`);
}
if (stampedReports !== `inwire ${version}`) fail(`the stamped exe reports "${stampedReports}", expected "inwire ${version}"`);

const back = NtExecutableResource.from(NtExecutable.from(readFileSync(OUTPUT)));
const strings = Resource.VersionInfo.fromEntries(back.entries)[0]
  ?.getStringValues({ lang: LANG, codepage: CODEPAGE });
if (strings?.ProductVersion !== version) fail(`the stamped VERSIONINFO ProductVersion reads ${strings?.ProductVersion ?? '(nothing)'}`);

const sha256 = createHash('sha256').update(output).digest('hex');
console.log(`stamped   ${rel(OUTPUT)}`);
console.log(`  from    ${rel(INPUT)} (${statSync(INPUT).size.toLocaleString('en-US')} bytes)`);
console.log(`  size    ${output.byteLength.toLocaleString('en-US')} bytes`);
console.log(`  version ${version} (package.json = Cargo.toml = --version = VERSIONINFO)`);
console.log(`  icon    ${icon.icons.length} image(s) from ${rel(ICON)}`);
console.log('  level   asInvoker');
console.log(`  sha256  ${sha256}`);
console.log('  signed  not yet - `npm run build:launcher` signs it next (scripts/sign/sign.ps1)');
process.exit(0);
