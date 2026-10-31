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

## Windows drive (opt-in)

- [ ] Run `scripts/distribution/windows-drive.ps1` (Task 6; not written yet) on a disposable Windows machine or VM. It installs, so never on a development PC.

## Record

- Versions, installer size and SHA-256, signer pin.
- Each command run and its exit code and outcome.
- What was not run, stated as not run. A skipped check is not a pass.
- The WinGet PR and listing links, when they exist.
