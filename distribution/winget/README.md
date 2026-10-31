# distribution/winget

WinGet manifests are generated, not written here. `scripts/distribution/generate.ts --winget-out <dir>` writes them (schema 1.12.0, three files under `<dir>/<package-id>/<version>/`) once `distribution/release-policy.json` has a real `desktopPackageId` and a publisher certificate pin. Until both exist the generator refuses (exit 3), so **no manifest is committed to this repository**.

A manifest that passes `winget validate --manifest <folder>` is a locally valid file. It is not a live package: nothing has been submitted to the WinGet community repository, and submitting is an owner action recorded in the release checklist (`docs/distribution-release-checklist.md`).

Test manifests come from `distribution/fixtures/test-policy.json` (package `Example.Inwire`, host `download.example.invalid`) with `--fixture`. They name an installer that does not exist.
