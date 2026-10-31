# Distribution release checklist

Run on release day, in order. Mechanics and trust are in [distribution.md](distribution.md); the decision is [ADR 0069](decisions/0069-release-channels-and-the-inwire-command.md). Values in `<angle brackets>` are placeholders to replace, not working commands.

Nothing here publishes by itself. Uploading, submitting to WinGet and announcing are owner actions.

## Prerequisites (stop if any is missing)

- [ ] A publicly trusted code-signing certificate exists and its SHA-256 pin (over the DER bytes, see `distribution.md`) is in `distribution/release-policy.json` `publisherCertificateSha256`, committed before signing.
- [ ] `updates.inwire.app` serves HTTPS and is the only host in `allowedHosts`.
- [ ] For WinGet: a real `desktopPackageId` (`<Publisher.Package>`) is in the policy.
- [ ] `package.json` version is the release version; `npm run sync:version` is clean.

## Build and sign

- [ ] `npm run dist:signed` (it refuses unsigned payloads).
- [ ] Verify every PE in the payload and `Inwire-Setup.exe`: `Get-AuthenticodeSignature` status `Valid`, timestamped, signer pin matches the policy.
- [ ] Verify the bootstrap script's signature (the signed standalone bootstrap).
- [ ] Record size and SHA-256 of `Inwire-Setup.exe`.

## Generate

From the final signed installer, never an earlier build:

```powershell
npx tsx scripts/distribution/generate.ts --installer installer\output\Inwire-Setup.exe `
  --version <x.y.z> --url https://updates.inwire.app/<path>/Inwire-Setup.exe `
  --out release-artifacts\release.json --feed-out release-artifacts\update-feed.json `
  --min-app-version <x.y.z> --winget-out release-artifacts\winget --require-public
```

- [ ] Exit code 0 and no warnings. Exit 3 means a blocker above is still open; fix it, do not work around it.
- [ ] `release.json`, `update-feed.json` and the WinGet folder agree on version, size and SHA-256 (they are written from one measurement).
- [ ] `winget validate --manifest release-artifacts\winget\<package-id>\<x.y.z>` succeeds.

## Upload and check access

- [ ] Upload the installer, `release.json` and the feed (as `manifest.json` on the feed host) to the allowed host. The feed goes last: it is what the Update Center reads.
- [ ] From a clean PC as a normal user (no repo, no certificate imported, no admin): download the installer URL, compare size and SHA-256 with the descriptor, and run the bootstrap's direct-download instructions.
- [ ] Redirects, if any, stay on allowed hosts over HTTPS.

## WinGet (owner action)

- [ ] Submit the generated manifests to the WinGet community repository. Record the pull request and, once merged, the listing separately; a submitted PR is not a listing.
- [ ] Keep the bootstrap's direct-download instructions available while catalog review is pending.
- [ ] After a listing exists: on a clean PC, `winget install --id <package-id>`, then open a **new** terminal and run `inwire`.

## Verification before release

- [ ] `npm run check` and `npm run build` are green on the release commit.
- [ ] Bootstrap tests pass under Windows PowerShell 5.1 and PowerShell 7 (`npx tsx scripts/distribution/powershell-tests.ts` runs both; it prints which edition it could not find).
- [ ] The Bash harness passes (`scripts/distribution/bash-tests.sh`).
- [ ] `scripts/distribution/launcher-tests.ps1` passes (needs `npm run build:launcher`; the PATH tests need Inno Setup). Its 77 case runs only from an elevated prompt; otherwise it prints SKIP, which is not a pass.
- [ ] Every shipped PE (app, agent, launcher, `Inwire-Setup.exe`) and the bootstrap script read `Valid` from `Get-AuthenticodeSignature`, with the pinned signer.

## Clean-machine verification

Everything above runs on a development PC with the development certificate and a repo. None of it proves that a stranger's clean Windows machine installs, runs `inwire`, upgrades and uninstalls correctly. `scripts/distribution/windows-drive.ps1` does that, by hand-assisted steps.

**Status: unverified.** The drive has NOT been run yet. As of 2026-10-31 no disposable machine exists for this PC. Until it has run against the signed release candidate and its result file is attached to the release record, the clean-machine items (fresh install, UAC decline, `-Launch` not elevated, the `inwire` command in a new shell, a custom install path, upgrade with an unsaved capture, Npcap untouched, clean trust, uninstall leaving user data and unrelated PATH entries, reinstall) are unverified, and the release record must say so. The manual matrix for everything else is [verification.md](verification.md); this does not duplicate it.

Prepare the machine:

- Use a VM snapshot of a clean Windows 11 (revert after each run), or Windows Sandbox. Windows Sandbox needs the optional feature enabled, administrator rights on the host and a reboot; it starts clean each time, so copy the files in through a mapped folder.
- It must not have Inwire, the development certificate "Inwire Code Signing (this PC)", Node, Rust or pwsh. The drive refuses if the certificate, `.signing.json` or a `.git` folder is found, or if PowerShell is elevated.
- Copy OUT of the checkout onto the machine: `windows-drive.ps1`, the signed bootstrap, and (for the upgrade scenario) an older `Inwire-Setup.exe`. Do not run the drive from the repo.
- Log in as a normal user (administrator account is fine, but not an elevated shell); you will click UAC prompts.

Run:

```powershell
$env:INWIRE_DISPOSABLE_MACHINE = '1'
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-drive.ps1 -List
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-drive.ps1 `
  -Bootstrap .\install-inwire.ps1 -OlderInstaller .\Inwire-Setup-old.exe `
  -ResultFile C:\drive-result.jsonl -IAmOnADisposableMachine
```

- [ ] Run every scenario (or pass `-Scenario <name>` one at a time). The tester answers the MANUAL prompts: `y` done as described, `n` done but not as described (fails the scenario), `s` skip.
- [ ] A scenario the tester skipped is SKIPPED and is not a pass; the drive says so in its summary. A MANUAL outcome passed on the tester's word for the manual steps.
- [ ] Run `no-npcap` once with Npcap installed and once without.
- [ ] Attach the result file (JSON lines: scenario, outcome, details, timestamp) to the release record, with the Windows build and the bootstrap and installer SHA-256.
- [ ] Any FAIL blocks the release. Fix the cause; do not edit the result file.

## Record

- Versions, installer size and SHA-256, signer pin.
- Each command run and its exit code and outcome.
- What was not run, stated as not run. A skipped check is not a pass.
- The WinGet PR and listing links, when they exist.
