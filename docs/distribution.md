# Distribution

How Inwire reaches a Windows PC from a terminal, and what each piece may do.
The decision is [ADR 0069](decisions/0069-release-channels-and-the-inwire-command.md);
this is the mechanics.

> **Not live.** No public command in this document works yet. There is no
> public signing certificate, `updates.inwire.app` does not resolve and there
> is no WinGet package ID. The code refuses rather than guesses until each one
> exists (see [Release status](#release-status)). Do not publish instructions
> from this file until that section says ready.

## Channels

| Channel | Who runs it | What it runs |
|---|---|---|
| Update Center (0032) | the app, when the person clicks Update | the signed installer, then exits for Restart Manager |
| PowerShell bootstrap | a person, in a terminal | the signed installer, waits, reads the version back |
| Git Bash bridge | a person, in Git Bash | the PowerShell bootstrap, unchanged |
| WinGet | a person, through `winget` | the signed installer |

All four install the same `Inwire-Setup.exe` for a version. None registers the
capture service itself and none installs Npcap: Npcap's own wizard runs from
the Update Center, because its licence is shown with it (ADR 0032).

## Identities

These are fixed. Changing one breaks upgrades or uninstall on every PC that has
Inwire.

| What | Value |
|---|---|
| Desktop AppId in `installer/setup.iss` | `{{F384C012-C351-40DE-B9E9-62AC2B6ED001}` |
| Uninstall key it registers (HKLM, 64-bit view) | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1` |
| Capture service | `InwireAgent` |
| Capture executable | `{app}\agent\inwire-agent-windows.exe` |
| Launcher | `{app}\bin\inwire.exe` |
| Obsolete standalone-agent AppId (removed by setup, never reused) | `{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}` |
| Legacy service (removed by setup, never reused) | `NetViewAgent` |

The uninstall key's `}}_is1` is not a typo: `setup.iss` writes the AppId as
`{{GUID}`, Inno reads `{{` as an escaped brace, and the key is named after
what remains. `InstalledProductVersion` in `setup.iss` explains how a single
brace once hid an installed version.

A future endpoint product needs its own AppId, service, executable basename
and directory, none of them above. It does not exist; `-Product EndpointAgent`
answers "unavailable".

## The `inwire` command

A console launcher, `inwire.exe`, is installed beside the app and put on the machine PATH, so `inwire` in any terminal opens Inwire (or brings the running window forward) and returns.

### Layout

    <install dir>\Inwire.exe            the app (GUI subsystem)
    <install dir>\bin\inwire.exe        the launcher (console subsystem, 0.3 MB, no dependencies)
    <install dir>\agent\...             the capture agent

`bin` holds the launcher and nothing else, so it is the only directory on PATH: putting the install directory there would make every file in it runnable by name from any prompt. The launcher is built from `launcher-rs/` by `npm run build:launcher` (cargo, then VERSIONINFO stamped by `scripts/distribution/stamp-launcher.ts`, then signed by `scripts/sign/sign.ps1`, in that order, as the agent is), is a payload file of the signed-installer check, and carries the product version (`npm run sync:version`, held by `scripts/agent/version.ts`).

### What it accepts

| invocation | result |
|---|---|
| `inwire` | start Inwire detached and return; if it is already running the app's own single-instance handler focuses the existing window (`app.requestSingleInstanceLock` and `second-instance` in `electron/main.ts`, which restores a minimised window and focuses it) |
| `inwire --version` | prints `inwire <version>` |
| `inwire --help` | prints the usage |
| anything else | usage on stderr, exit 64 |

"Anything else" is exact: `-h`, `/?`, `--Help`, `--help --version`, an extra argument, a non-UTF-8 argument. Nothing is forwarded to the app. `--help` and `--version` read nothing from disk and call nothing else.

The app is found from the launcher's own path only: `<launcher>\..\..\Inwire.exe`, and the launcher must be in a folder named `bin` (case-insensitive). Neither the current directory nor PATH is consulted, so a planted `Inwire.exe` in either is never run. It is started by absolute path, with no arguments, from the app's folder, with no console and the launcher's standard handles not inherited, so `inwire | more` or a script capturing its output ends when the launcher does.

### Exit codes

| code | meaning |
|---|---|
| 0 | printed help or version, or started Inwire |
| 64 | usage error |
| 65 | the `Inwire.exe` beside it reports a different product version (or none); `x.y.z` against ProductVersion, tolerating a trailing `.0` only. A launcher and an app from different installs refuse to pair. |
| 66 | payload missing: no `Inwire.exe` at the expected place, or the launcher is not at `<app>\bin\inwire.exe` |
| 71 | the launch failed (the OS error is shown), or whether the terminal is elevated could not be determined |
| 77 | the terminal is elevated; nothing is started |

### Elevated terminals

Inwire does not run as an administrator (the dissector must not parse hostile bytes with that token), so from an elevated prompt `inwire` prints that and to open a normal terminal, and exits 77 without starting anything. If elevation cannot be read from the process token it refuses with 71 rather than guess.

### The PATH entry

The installer owns exactly one segment of the **machine** PATH: `{app}\bin`.

- **Adding.** After the files and the service are in place it reads `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path` as its raw, unexpanded text (`RegQueryStringValue` returns a `REG_EXPAND_SZ` value without expanding it; `scripts/distribution/path-tests.iss` checks this against the real Inno runtime, it is not taken from the documentation), appends `;{app}\bin` and writes it back with `RegWriteExpandStringValue`, so the type stays `REG_EXPAND_SZ`. Every other entry keeps its exact text, order, case, quoting and empty segments (`%SystemRoot%\system32` is not expanded). The match for "already there" ignores case, surrounding quotes and a trailing backslash, and is for comparison only. Re-installing and upgrading are idempotent.
- **A different `inwire`.** Before adding, every other absolute PATH entry (environment variables expanded for this check only) is searched for `inwire.exe`, `.com`, `.bat`, `.cmd` or `.ps1`. If one exists the installer does not touch PATH, logs it, and shows a message naming that file and the absolute path of Inwire's own launcher. The user's own PATH is not read.
- **Ownership.** The exact entry added is recorded in `HKLM\Software\Inwire\LauncherPathEntry`, written before PATH is. An install into a different folder first removes the entry the earlier install recorded.
- **Uninstalling.** Only if that value exists, segments equal to it are removed (all other text is left byte-identical), PATH is written back, and the value and its key are deleted. An `{app}\bin` that was already on PATH before Inwire was installed has no marker and is never removed. One cosmetic exception to "returns what it started from": a PATH that ended in `;` loses that trailing empty segment when our entry, appended after it, is removed.
- **New terminals.** `ChangesEnvironment=yes` makes Setup broadcast `WM_SETTINGCHANGE`, which Explorer, and so every terminal opened afterwards, picks up. A terminal that was already open does not change its PATH; open a new one. (VS Code's terminals and some shells ignore the broadcast until restarted.)

### Why an executable and not a script shim

- A `.ps1` shim is refused outright under the default Restricted/AllSigned policies (measured: it fails under `-ExecutionPolicy Restricted`; the exe prints `inwire <version>`).
- A `.cmd` shim works only from a shell: a caller that starts a process without one (Node's `spawnSync('inwire')`, Python's `subprocess` without `shell=True`) gets `ENOENT` for it and the exe's version for the exe, measured with Node 26 on this machine. It also runs the install path through `cmd`'s quoting, where `&`, `%` and `^` in a folder name are hazards.
- The launcher is not slower: median of 20 runs of `inwire --version` was 18.1 ms against 22.7 ms for `cmd /c` on a one-line `.cmd` that echoes a version. It is 338,944 bytes (stamped, with the app icon).

### Tested with

`scripts/distribution/launcher-tests.ps1` (needs `npm run build:launcher`; the PATH tests need Inno Setup 6 or 7). It runs `installer/path.iss` under Inno (60 table cases), then drives the built exe in a `...\Inwïre & co\bin\inwire.exe` layout against compiled stand-ins for `Inwire.exe` (a matching version, a matching version with a `.0` fourth group, a mismatched one, a planted one in the current directory and on PATH) under Windows PowerShell 5.1.26100 and PowerShell 7.6.9, then `powershell -ExecutionPolicy Restricted -Command "& '<path>' --version"` and Git Bash 5.3.15. The 77 case runs only from an elevated prompt and is otherwise printed as SKIP.

## Release files

| File | Role |
|---|---|
| `distribution/release-policy.json` | build input: allowed hosts, descriptor URL, publisher pins, WinGet ID, endpoint switch |
| `scripts/distribution/release.ts` | the descriptor and policy validators |
| `scripts/distribution/generate.ts` | writes `release.json` from the final signed installer |
| `scripts/distribution/contracts.ts` | the assertions, run by `npm run check` |
| `distribution/fixtures/` | a test policy and the vectors both validators run; never a production fallback |

`release.json` holds one row per product:

```json
{
  "schema": 1,
  "artifacts": [
    { "product": "Desktop", "version": "0.5.0", "architecture": "x64",
      "url": "https://updates.inwire.app/…/Inwire-Setup.exe",
      "sizeBytes": 123456789, "sha256": "…64 hex…" }
  ]
}
```

Any bad row rejects the document. A URL must be HTTPS on an allowed host,
exactly, with no credentials, port or fragment. One row per product; a Desktop
row is required; an EndpointAgent row is refused while the policy says the
endpoint is unavailable.

Generate it from the bytes that will be published, after `npm run dist:signed`
has signed and timestamped them:

```powershell
npx tsx scripts/distribution/generate.ts --installer installer\output\Inwire-Setup.exe `
  --version 0.5.0 --url https://updates.inwire.app/<path>/Inwire-Setup.exe `
  --out release-artifacts\release.json --require-public
```

`--require-public` fails while any public input is missing. Without it the
same blockers print as warnings, which is how a local build is checked.

## Projections

One run of `scripts/distribution/generate.ts` measures the final signed installer once (size and SHA-256) and writes every projection from that measurement. Each is validated before any is written, and a refusal writes nothing.

| Output | Flag | Feeds | Validated by |
|---|---|---|---|
| `release.json` | `--out` | PowerShell bootstrap, Git Bash bridge | `readRelease` |
| `update-feed.json` | `--feed-out` (default beside `--out`) | Update Center, served as `manifest.json` on the feed host | the app's own `parseManifest` |
| WinGet manifests | `--winget-out <dir>` | WinGet, via the community repository | `winget validate` (by hand) |

The feed document is complete (`schema`, `generated`, an `inwire` row of kind `inwire-installer`). `--min-app-version` sets its `minAppVersion` and defaults to the release version. The feed URL is `manifest.json` beside the policy's descriptor URL, which is how our download is pinned to the feed host.

```powershell
npx tsx scripts/distribution/generate.ts --installer installer\output\Inwire-Setup.exe `
  --version 0.5.0 --url https://updates.inwire.app/<path>/Inwire-Setup.exe `
  --out release-artifacts\release.json --winget-out release-artifacts\winget --require-public
```

Exit codes: 0 written, 2 refused (bad arguments, invalid result), 3 blocked. WinGet output is blocked (exit 3, even without `--require-public`) while `wingetBlockers` is non-empty: no `desktopPackageId`, or no publisher pin. `--fixture` is for the tests: it needs a `--policy` under `distribution/fixtures/` and a policy whose hosts are all `.invalid`, so the production policy cannot satisfy it.

## WinGet

Manifests are schema 1.12.0 (the version Microsoft Learn shows as current; the installed client validates it), as three files: version, default locale (en-US) and installer, under `<dir>/<package-id>/<version>/`. None is committed (`distribution/winget/README.md`), and a locally valid manifest is not a live package.

The installer manifest says: `InstallerType: inno`, `Scope: machine`, `x64`, `ElevationRequirement: elevatesSelf` (the installer is `PrivilegesRequired=admin`, so Windows raises the UAC prompt; WinGet does not elevate it), `UpgradeBehavior: install`, `Commands: [inwire]`, and `ProductCode` and `AppsAndFeaturesEntries` set to the registered uninstall key `{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1`.

Switches. WinGet already passes `/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` (`/SILENT` for progress). The manifest adds only what WinGet does not, in `InstallerSwitches.Custom`: `/RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS`. Not in `Silent`, which would replace the defaults and repeat `/NORESTART`.

Return codes (nothing else nonzero counts as success):

| Code | ReturnResponse |
|---|---|
| 2, 5 | `cancelledByUser` |
| 8 | `rebootRequiredForInstall` |
| 3010 | `rebootRequiredToFinish` |

PATH. The installer puts `{app}\bin\inwire.exe` on the machine PATH, but a terminal that was already open keeps its old PATH: open a new one before running `inwire`. WinGet does not launch the app and the manifest does not claim it does.

Npcap stays separate. WinGet installs Inwire only; the driver is installed from the Update Center, where Npcap's own wizard and licence are shown (ADR 0032).

## Trust

The bootstrap installs only an installer whose Authenticode status is `Valid`
and whose signer certificate's SHA-256 (over its DER bytes) is one of the pins.
A valid signature by anyone else fails. Both checks, and the size and hash
check, run before UAC is asked for.

The pins come from `release-policy.json` and are compiled into the signed
bootstrap; the bootstrap downloads no policy. To compute a pin from a signed
file:

```powershell
$cert = (Get-AuthenticodeSignature .\Inwire-Setup.exe).SignerCertificate
[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)).Replace('-','').ToLowerInvariant()
```

Rotation adds the new pin a release before anything is signed with the new
certificate, and removes the old one only when no published descriptor names
an installer it signed.

The Update Center does not check the publisher. It checks the download host,
the size and the SHA-256 the feed names (`electron/updateCenter/verify.ts`).
That is weaker than the bootstrap, and ADR 0069 leaves it so until there is a
public certificate to pin.

## Release status

| Input | State |
|---|---|
| Public code-signing certificate, trusted on a clean PC | **missing**: the only certificate is "CN=Inwire Code Signing (this PC)" |
| `updates.inwire.app` serving HTTPS | **missing**: the name does not resolve |
| WinGet package ID | **missing** |
| Endpoint product | **does not exist**; out of scope until it does |

When the first two exist: put the certificate's pin in `release-policy.json`,
build and sign the release, generate `release.json` with `--require-public`,
and run the release checklist. Publishing is an owner action, recorded
separately; a valid local file is not a published one.
