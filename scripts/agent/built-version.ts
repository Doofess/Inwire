/**
 * A built artifact carries the version its source says it does.
 *
 *   npx tsx scripts/agent/built-version.ts
 *
 * ## Why this exists, and why `version.ts` beside it was not enough
 *
 * `scripts/agent/version.ts` holds six **source literals** to `package.json` -
 * `agent_version.py`, `REQUIRED_AGENT_VERSION`, `MyAppVersion` in both `.iss`
 * files, `Cargo.toml`. It is thorough and it passes, and it cannot see the
 * failure that actually happened:
 *
 * `installer/output/Inwire-Setup.exe` sat in the tree bundling **agent
 * 3.8.0** while all six literals read 4.0.0 and agreed with each other
 * perfectly. Installing it registered an agent the app compares against
 * `REQUIRED_AGENT_VERSION`, finds older, and reports as **"not connected"** -
 * a state with no instruction attached to it, produced by an installer that
 * completed successfully. It also registered the service **auto-start**,
 * because the binary predated the commit that made it demand-start (ADR 0035).
 *
 * The artifact was simply older than the source, and nothing in this
 * repository looks at an artifact's version. That is the same hole
 * `preload-sandbox.ts` closed on the other side of the build: it reads the
 * **built** bundle, because what esbuild inlined is harmless and what it left
 * as a runtime `require` is fatal - a distinction the source cannot make.
 *
 * ## What it reads
 *
 * The Windows version resource of each built exe, via PowerShell's
 * `VersionInfo`, which is the same field Explorer's Properties tab shows and
 * the same one that revealed the 3.8.0 above.
 *
 * ## Why it SKIPS rather than fails when nothing is built
 *
 * `npm run check` does not build, and CI on ubuntu never will - there is no
 * cargo run and no `iscc` there. A missing artifact has not failed anything. A
 * **present and stale** one has, which is the whole distinction this file
 * exists to draw, and it is the one `tree-coverage.ts` draws too.
 *
 * ## The Rust agent gets more than its version checked
 *
 * Its resources are not written by a spec file the way PyInstaller's were:
 * cargo emits none, and `scripts/agent/stamp-agent.ts` adds them after the
 * link. So beyond the version, the ones a person or Windows actually reads are
 * held here - the strings Explorer shows, the manifest's execution level, and
 * the icon. The expected values are written out below rather than imported
 * from the stamper, because a check that reads its answers from the code under
 * test agrees with that code by construction.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Data, NtExecutable, NtExecutableResource, Resource } from 'resedit';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

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

const version = (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string }).version;
if (typeof version !== 'string') {
  console.log('FAIL  package.json declares no version');
  process.exit(1);
}
console.log(`      package.json declares ${version}\n`);

/**
 * The version resource of a Windows exe, or null when it cannot be read.
 *
 * PowerShell rather than a PE parser: reading a VS_VERSIONINFO block by hand
 * is a hundred lines of structure-walking for a field the OS already exposes,
 * and this script only ever runs on the machine that did the build.
 *
 * **The path travels in the environment, never in the script text.** The
 * obvious spellings are both wrong: interpolating it makes the path part of
 * the program, and `-args` is a `-File` thing that `-Command` appends to the
 * command string instead - which is a PowerShell parse error on the first
 * path containing a colon, so every artifact read as unreadable. An
 * environment variable is the one form with no quoting question in it at all.
 */
function fileVersion(exe: string): string | null {
  try {
    const out = execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      '(Get-Item -LiteralPath $env:INWIRE_ARTIFACT).VersionInfo.FileVersion',
    ], { encoding: 'utf8', timeout: 30_000, env: { ...process.env, INWIRE_ARTIFACT: exe } });
    const trimmed = out.trim();
    return trimmed.length > 0 ? trimmed : null;
  } catch {
    return null;
  }
}

/** The agent the installer ships: cargo's output, stamped by `stamp-agent.ts`. */
const RUST_AGENT = join(root, 'agent-rs', 'dist', 'inwire-agent-windows.exe');

/** Every built thing that stamps a version, and what it is. */
const ARTIFACTS: { path: string; what: string }[] = [
  {
    path: RUST_AGENT,
    what: 'the Rust agent the installer ships',
  },
  {
    // No longer shipped on Windows (ADR 0037), and still buildable - so a
    // stale one is still worth naming before somebody registers it by hand.
    path: join(root, 'local-agent', 'dist', 'inwire-agent-windows', 'inwire-agent-windows.exe'),
    what: 'the PyInstaller agent, not shipped',
  },
  {
    path: join(root, 'release', 'win-unpacked', 'Inwire.exe'),
    what: 'the packed app',
  },
  {
    path: join(root, 'installer', 'output', 'Inwire-Setup.exe'),
    what: 'the compiled installer',
  },
];

const present = ARTIFACTS.filter((a) => existsSync(a.path));
if (present.length === 0) {
  console.log('SKIP  nothing is built - `npm run build:agent`, `npm run pack` and '
    + '`iscc installer/setup.iss` produce what this reads.');
  process.exit(0);
}

for (const artifact of present) {
  const name = relative(root, artifact.path).split(sep).join('/');
  const stamped = fileVersion(artifact.path);
  if (stamped === null) {
    // Not a pass. An artifact that is present and unreadable is the state this
    // check exists to refuse, and reporting it as fine is how the last one
    // shipped.
    check(`${name} carries a readable version`, stamped, version);
    continue;
  }
  // `FileVersion` on a PyInstaller build reads back as "4.0.0"; electron-builder
  // stamps four components ("4.0.0.0"). Both are the same claim, so the
  // comparison drops a trailing zero component rather than demanding a shape
  // neither tool agreed to produce.
  const normalised = stamped.replace(/^(\d+\.\d+\.\d+)\.0$/, '$1');
  check(`${name} (${artifact.what}) is built from ${version}`, normalised, version);
}

/**
 * The rest of what the stamp promises, read with the same library that wrote
 * it but against literals written here.
 *
 * `resedit` rather than PowerShell for these because none of them is a field
 * `VersionInfo` exposes - the manifest and the icon are raw resources - and
 * because it is pure JavaScript, so this half needs no Windows to run.
 */
function rustAgentResources(exe: string): void {
  const name = relative(root, exe).split(sep).join('/');
  let entries: ReturnType<typeof NtExecutableResource.from>['entries'];
  try {
    entries = NtExecutableResource.from(NtExecutable.from(readFileSync(exe), { ignoreCert: true })).entries;
  } catch (error) {
    check(`${name} parses as a PE with resources`, (error as Error).message, 'no error');
    return;
  }

  const info = Resource.VersionInfo.fromEntries(entries)[0];
  const strings = info?.getStringValues({ lang: 1033, codepage: 1200 }) ?? {};
  // The PyInstaller agent's strings, so Explorer reads the same across the
  // swap. OriginalFilename is the installed name - the one the service's
  // ImagePath has always had - not cargo's `inwire-agent.exe`.
  check(`${name} VERSIONINFO names the product and the file`, {
    CompanyName: strings.CompanyName,
    ProductName: strings.ProductName,
    FileDescription: strings.FileDescription,
    OriginalFilename: strings.OriginalFilename,
    ProductVersion: strings.ProductVersion,
  }, {
    CompanyName: 'Inwire',
    ProductName: 'Inwire',
    FileDescription: 'Inwire capture agent',
    OriginalFilename: 'inwire-agent-windows.exe',
    ProductVersion: version,
  });

  // asInvoker, never requireAdministrator: the PyInstaller agent's level is
  // what made `--version` raise a UAC prompt, and the SCM ignores it anyway.
  const manifest = entries.find((e) => Number(e.type) === 24 && Number(e.id) === 1);
  const xml = manifest ? Buffer.from(manifest.bin).toString('utf8') : '';
  check(`${name} carries a manifest`, manifest !== undefined, true);
  check(`${name} manifest asks for asInvoker`,
    /<requestedExecutionLevel\s+level="([^"]+)"/.exec(xml)?.[1] ?? null, 'asInvoker');

  // The app's icon, image for image. `win.icon` in electron-builder.yml.
  const ico = Data.IconFile.from(readFileSync(join(root, 'electron', 'resources', 'icon.ico')));
  const group = Resource.IconGroupEntry.fromEntries(entries)[0];
  const images = group?.getIconItemsFromEntries(entries) ?? [];
  // A PNG-compressed image (the 256 px one, usually) comes back raw; the rest
  // as DIBs. Either way the bytes are what is compared.
  const bytes = (item: (typeof images)[number]) => Buffer.from(item.isRaw() ? item.bin : item.generate());
  const same = images.length === ico.icons.length
    && images.every((image, i) => bytes(image).equals(bytes(ico.icons[i].data)));
  check(`${name} carries the app's icon (electron/resources/icon.ico)`, same, true);
}

if (existsSync(RUST_AGENT)) rustAgentResources(RUST_AGENT);

const absent = ARTIFACTS.filter((a) => !existsSync(a.path));
if (absent.length > 0) {
  console.log(`\n      ${absent.length} artifact(s) not built, so not checked:`);
  for (const a of absent) console.log(`        ${relative(root, a.path).split(sep).join('/')}`);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED - rebuild the artifact, or it will install a version the app refuses.`);
  process.exit(1);
}
console.log('Every built artifact present matches package.json.');
process.exit(0);
