# 0069 — Every release channel runs the one signed installer, and the terminal channel is explicit

**Status:** accepted 2026-10-31. The owner approved terminal installation and
an `inwire` command on 2026-10-17 and started that plan on 2026-10-31. Public
release through the new channels is **blocked** until the three inputs under
"What is not decided here" exist; the code and its tests land first.

## Context

Inwire has one way in: download `Inwire-Setup.exe`, run it. One way to stay
current: the Update Center (0032), which downloads the next installer and exits
so Restart Manager can replace the app. The owner wants a terminal path too —
install from PowerShell or Git Bash, open the app with `inwire` — and a WinGet
package once there is a publisher to list it under.

Each new entry point is a new way to nominate an executable that runs elevated.
The question this record answers is what they share and what each may do, so
that four front ends do not become four installers with four ideas of who owns
the capture service.

## Decision

### One artifact, one descriptor

Every desktop channel — Update Center, the PowerShell bootstrap, WinGet and the
Bash bridge — installs the same immutable signed `Inwire-Setup.exe` for a given
version. No channel wraps it, repackages it or registers `InwireAgent` itself:
the installer owns the service, its legacy cleanup and its replacement safety.

Release metadata is generated from the **final signed and timestamped bytes**
(`scripts/distribution/generate.ts`), never from a pre-sign build: signing
rewrites the bytes a hash covers. The descriptor (`release.json`) carries one
row per product, so `-Version` names the published version or nothing. There
is no downgrade, and no lexicographic version comparison anywhere.

### Hosts

`distribution/release-policy.json` allows exactly one host,
`updates.inwire.app`, the host the Update Center's feed already names
(`electron/updateCenter/manifest.ts`). One host for both channels means one
place to secure. Matching is exact, never by suffix. Redirects are followed only
to allowed hosts, over HTTPS.

### Trust

The bootstrap requires Authenticode status `Valid` **and** a signer certificate
whose SHA-256 over its DER encoding is in the pinned list. A valid signature
from someone else is a failure: a code-signing certificate is cheap, and "signed"
is not "signed by us". Both checks run before elevation.

The pins are embedded into the signed standalone bootstrap at build time
(`scripts/distribution/build-bootstrap.ps1`). They are never read from a
downloaded file, because whoever writes the file would choose the pins. The
bootstrap cannot vouch for itself; its trust starts at the published download
and its instructions, or at WinGet.

**Rotation:** a new certificate is added to the pins in one release before any
installer is signed with it, and the old pin stays until no published descriptor
names an installer it signed. Pins are never replaced by a subject-name test.

No channel imports a certificate into a trust store or changes execution policy.

### The Update Center is unchanged

It keeps its host allowlist and its size and SHA-256 check (`verify.ts`), and
still does **not** verify the publisher. Extending it is a separate decision
for when there is a public certificate to pin; this record does not claim it.
It also keeps its no-wait lifecycle: it exits so Restart Manager can replace
the app, where the bootstrap, an external process, waits for the installer and
reads the installed version back.

### Terminal updates are explicit

The bootstrap and WinGet are things a person runs. Nothing schedules them,
nothing in the app calls them, and no new renderer or startup network access
comes with them. The Update Center remains the only in-app updater.

### The `inwire` command

The installer places a small Rust console launcher at `{app}\bin\inwire.exe`
and adds that one directory to the machine `Path`. It accepts no arguments,
`--help` or `--version`, and nothing else; it opens or focuses the app and
returns. It finds `Inwire.exe` from its own location, never from the current
directory or `Path`. It does not start the app from an elevated terminal.

An executable rather than a `.cmd` or `.ps1` shim, because execution policy
governs scripts and an enterprise `Restricted` or `AllSigned` policy must not
break a command the installer put there.

The installer records the exact `Path` entry it added and uninstall removes
only that. Every other entry keeps its raw text, its `%variable%` form and its
position. If another `inwire` command is already on `Path`, setup reports the
collision and does not add its directory.

### Identities

Desktop AppId `{F384C012-C351-40DE-B9E9-62AC2B6ED001}` (registered as
`{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1`, the double brace is Inno's
escaping and is load-bearing), service `InwireAgent`, executable
`inwire-agent-windows.exe`. The obsolete standalone-agent AppId
`{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}` and the `NetViewAgent` service are
cleanup targets of the desktop installer and are never reused.

A future endpoint product gets its own AppId, service name, executable basename
and directory, all different from the above, because the desktop upgrade's
fallback terminates processes by image name. `-Product EndpointAgent` is in the
command contract and answers "unavailable" (exit 20) before any download until
that product exists.

## What is not decided here

These are external inputs, not defaults to invent. Until each exists, the code
that needs it refuses rather than guesses:

1. **A public signing identity.** The current certificate is
   "CN=Inwire Code Signing (this PC)", trusted on this machine only. With no pin,
   a built bootstrap refuses to install (exit 10) and `generate.ts
   --require-public` fails.
2. **A reachable release host.** `updates.inwire.app` does not resolve today.
3. **A WinGet package ID.** No manifest is generated without one.

## Consequences

- A terminal install is as strong as its pin list, and only as strong: a
  compromised host can serve a stale but genuinely signed installer, which the
  bootstrap would accept only if it is the version the descriptor names, and
  never as a downgrade.
- The Update Center is weaker than the bootstrap until it gains a publisher
  check. Recorded rather than hidden.
- Two validators read the descriptor, TypeScript at release time and PowerShell
  in the bootstrap. One vector file, `distribution/fixtures/release-vectors.json`,
  is run by both so that they cannot drift unnoticed.
