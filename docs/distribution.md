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

## The PowerShell bootstrap

`install-inwire.ps1` downloads the signed desktop installer, verifies it and
runs it. It is built (`scripts/distribution/build-bootstrap.ps1`) into one
standalone script, `release-artifacts/bootstrap/install-inwire.ps1`: the core
logic (`distribution/Install-Inwire.Core.psm1`) is inlined, the policy is
embedded as a literal, and nothing is imported or read at runtime. Windows
PowerShell 5.1 and PowerShell 7 both run it. It never changes the execution
policy and never evaluates text as code; a machine whose policy blocks
unsigned or downloaded scripts is the person's to configure.

> Not live: see [Release status](#release-status). Built today, a bootstrap
> has no pinned publisher and exits 10.

### Usage

```powershell
.\install-inwire.ps1 [-Product Desktop|EndpointAgent] [-Version 1.2.3] [-Launch] [-Repair]
```

| Switch | Meaning |
|---|---|
| `-Product` | `Desktop` (default). `EndpointAgent` does not exist yet and answers exit 20 before anything else. |
| `-Version` | Must be `x.y.z` and exactly the version the descriptor publishes (one row per product). Another value is exit 11 naming the published version. An older value than what is installed is exit 10. |
| `-Launch` | After a successful install, start Inwire through `<InstallLocation>\bin\inwire.exe`. |
| `-Repair` | Install over an installed state that cannot be read, or the published version again over the same version. |

**Execution policy.** Windows client editions default to `Restricted`, under
which PowerShell runs no script file at all, signed or not; this machine's
`LocalMachine` policy is `RemoteSigned`, which runs a downloaded script only
when its signature is valid. The bootstrap does not work around either. On a
`Restricted` machine a person can start one PowerShell with
`powershell -ExecutionPolicy RemoteSigned -File .\install-inwire.ps1`, which
changes nothing beyond that process and is overridden where Group Policy sets
the policy; WinGet is the route that needs no script at all. Instructions
must not tell anyone to use `Bypass` or to change the policy permanently.

It prints a short summary and `exit`s with the contract code. The same result is
available as an object from `Invoke-InwireInstall` (fields `State`, `InstallPath`,
`InstalledVersion`, `Launched`, `LaunchMessage`, `ErrorCode`, `Message`,
`ExitCode`, `DiagnosticPath`), which is what the tests drive.

### Exit codes

| Code | State | Meaning |
|---|---|---|
| 0 | Installed, AlreadyInstalled | Installed and read back, or the same or a newer version is already there (nothing downloaded). |
| 2 | Cancelled | The UAC prompt was declined, or the installer reported it was cancelled (Inno codes 2 and 5). |
| 10 | Unavailable, Failed | Not Windows, not x64, no pinned publisher in this build, a malformed `-Version`, or a refused downgrade. |
| 11 | Failed | The descriptor or the download could not be fetched, or the descriptor is invalid, or the version is not published. |
| 12 | Failed | The download is not the declared size or SHA-256, or the signature is not `Valid` and pinned. Setup was not run. |
| 13 | Failed | Setup failed, timed out, reported a code this bootstrap does not map, exited 0 but the registry does not read back the published version, or the installed state was unreadable without `-Repair`. |
| 14 | Installed | Installed, but `-Launch` could not start Inwire (including: this PowerShell is elevated). |
| 20 | Unavailable | `-Product EndpointAgent`, which does not exist yet. |
| 3010 | RebootRequired | Installed and read back; Windows must restart. Not launched. |

The installer's own code is kept in `ErrorCode` (`12345` stays `12345`). A raw
non-zero code is never read as success.

### What it verifies, in order

Each step's failure stops before the next one.

1. The platform: Windows and x64. arm64 is refused (x64 under emulation is untested, so it is not claimed).
2. `-Product EndpointAgent` while the policy says it is unavailable: exit 20, no other call.
3. The policy pins at least one publisher certificate; `-Version` has the `x.y.z` shape.
4. The installed state, from the uninstall key, HKLM 64-bit view (`}}_is1`, the double brace is real). Versions are compared **numerically**, group by group, never as text.
5. The release descriptor from `descriptorUrl`, parsed strictly (it must be a JSON object; unknown keys, a bad row or a second row for a product reject the whole document). The rules mirror `scripts/distribution/release.ts`; `distribution/fixtures/release-vectors.json` is run by both and must agree.
6. No downgrade. The same version installs again only with `-Repair`.
7. A fresh private working folder under the user's temp, with fixed names `Inwire-Setup.exe` and `setup.log`.
8. The download (below), checked for size and SHA-256 as it streams.
9. The publisher: Authenticode status `Valid` **and** the SHA-256 of the signer certificate's DER bytes in the pinned list. A valid signature by anyone else is exit 12.
10. Only then elevation and setup.
11. The installer's code is mapped; the registry is read back (`Installed` and exactly the published version) before anything is called a success.

The size, hash and publisher checks all happen before UAC is asked for. Nothing
is trusted from the descriptor beyond what the embedded policy allows: the
hosts and the pins are in the signed script, not in the downloaded file.

### Download, proxy, timeouts and limits

- One `HttpClient`, the system proxy with the user's default credentials, certificate validation untouched, TLS 1.2 added to what is already enabled.
- Redirects (301, 302, 303, 307, 308) are followed by hand, at most five. Every URL, the first and each `Location`, must pass the descriptor's rule: `https`, the host equal to an allowed host (no suffix match), no credentials, no port (even `:443`) and no fragment. An https-to-http redirect is refused. A relative `Location` is resolved against the current URL.
- A missing `Content-Length`, or one different from the declared size, is refused. The body is counted as it arrives and reading stops the moment it passes the declared size. The declared size is at most 512 MiB.
- The SHA-256 is computed incrementally while the file is written to a `.partial` file, which becomes `Inwire-Setup.exe` only after both checks pass.
- Timeouts: the whole download 15 minutes, the descriptor 30 seconds with a 1 MiB cap, setup 30 minutes.
- Retries: at most two more attempts, only for faults that can pass (a 5xx answer, a timeout, a network or I/O error), each into a fresh partial file. A 4xx answer, a rule violation, or a size or hash mismatch is never retried.
- No proxy credentials or full exception objects are logged; failures carry one line of text.

### Elevation and launch

- Not elevated: the bootstrap starts `System32\WindowsPowerShell\v1.0\powershell.exe` with `-Verb RunAs` and a **constant** command line, `-NoProfile -NonInteractive -EncodedCommand <base64 of a fixed script>`. The installer and log paths reach that script in environment variables (`INWIRE_BOOT_INSTALLER`, `INWIRE_BOOT_LOG`), as `electron/updateCenter/elevate.ts` does, so no path is ever quoted into a privileged command. The script checks the file names, runs the installer with exactly `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS "/LOG=<log>"`, waits, and exits with the installer's code (70001 for its own faults).
- Already elevated: the installer is run directly with the same switches.
- A declined UAC prompt (a `Win32Exception` with code 1223, found in the exception chain, never by message text) is exit 2 with a UAC message, distinct from the installer's own cancel.
- On the 30-minute timeout nothing is stopped: exit 13, `ErrorCode` `Timeout`, the message says setup may still be running, and the working folder is kept.
- `-Launch` runs only when the install succeeded (or the same or a newer version was already present) and only from a normal shell. From an elevated shell the install completes, `Launched` is false, the message says to run `inwire` from a normal terminal, and the exit code is 14. It starts the absolute path `<InstallLocation>\bin\inwire.exe` read from the uninstall key, never `Path` and never the current directory. After a 3010 it does not launch and says to restart first.
- The working folder is removed on success, cancel and any failure before setup ran (so an installer that failed verification does not sit in temp); it is kept after a setup failure or timeout and named in `DiagnosticPath`.

### `-Repair`

Without `-Repair`, an installed state that cannot be read (the key exists but
the version does not parse, or the registry is unreadable) is exit 13 with a
message to rerun with `-Repair`: the bootstrap will not guess what it is
installing over. With `-Repair` it proceeds as for an absent install. For an
Inwire that reads fine, `-Repair` reinstalls the published version over the same
one.

### Tests

`scripts/distribution/bootstrap-tests.ps1` runs under both editions
(`powershell -NoProfile -File ...`, `pwsh -NoProfile -File ...`), and
`scripts/distribution/powershell-tests.ts` runs it inside `npm run check` on
Windows (it prints SKIP elsewhere). The state machine is tested against a
recording fake platform, the downloader against a fake transport, and the pin
comparison against an in-memory certificate. The bundle section signs a
throwaway copy with this PC's certificate when there is one and confirms that
changing one character of an embedded pin makes the signature read
`HashMismatch`.

### Still blocked, and not verified

- A public signing certificate (so a bootstrap can carry a pin), a reachable `updates.inwire.app`, and a WinGet package ID. Until the first, a built bootstrap exits 10.
- Not exercised by any test: a real UAC prompt, the elevated `-EncodedCommand` wrapper running a real installer (including that the environment variables reach the elevated PowerShell and that `ExitCode` is readable from a non-elevated parent), and a real proxy. They are the production adapters' only untested lines; run them once by hand against a signed release before publishing instructions.
- The script's timestamp is the countersignature `Set-AuthenticodeSignature` adds. A production build with this PC's certificate on 2026-10-31 came back timestamped and `Valid`; the tests themselves make no network call.
- A same-user process could swap the downloaded file between the check and the elevated run (the working folder is private to the user, the same trust boundary as the Update Center's download).

## The Git Bash bridge

`distribution/install-inwire.sh` runs the bootstrap you already downloaded and
verified, from Git Bash on Windows. It installs the Windows desktop app; it is
not a Linux or macOS installer.

```bash
bash install-inwire.sh [--product Desktop|EndpointAgent] [--version X.Y.Z] [--launch] [--repair] [--bootstrap PATH]
```

- The bootstrap is `install-inwire.ps1` beside the script unless `--bootstrap`
  names it.
- Product and version are checked before PowerShell runs (10 on a bad value),
  because `powershell -File` binds a value starting with `-` as a parameter:
  `--version -Launch` would otherwise launch. Arguments travel as an array;
  nothing is evaluated.
- PowerShell is `$SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe`,
  never `PATH`, `pwsh` or the current directory. No `-ExecutionPolicy` flag is
  passed, so a machine whose policy refuses the bootstrap refuses it here too.
- Inno's slash switches stay inside PowerShell, where MSYS cannot rewrite them;
  the bridge also sets `MSYS_NO_PATHCONV=1` for the call.
- Linux, macOS and WSL are refused with 10 before anything runs. WSL stays
  unadvertised until interop, the UAC prompt and the install location are
  tested from it.
- Exit codes are the bootstrap's, and 64 for a usage error. Reboot-required,
  3010, reaches Bash as **194** (3010 mod 256, a POSIX limit); the bridge says
  to restart.
- There is no `curl | bash` form, and none is documented.

Tested with `bash scripts/distribution/bash-tests.sh` under Git Bash 5.3.15
(a fake PowerShell under a temporary `SYSTEMROOT`), and against the real
Windows PowerShell 5.1 with the source bootstrap, which exits 10 (no pin) and
20 (`--product EndpointAgent`) through the bridge unchanged.

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
