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
