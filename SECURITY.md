# Security

## Reporting a vulnerability

Please report privately through GitHub's **[Security Advisories](../../security/advisories/new)**
rather than opening a public issue. That form is private to the maintainer until
an advisory is published.

Include what you would want if you were fixing it: the Inwire version
(`Settings → Updates` shows it), the Npcap version, whether the capture agent was
running, and the smallest sequence of steps that reproduces the problem. If a
capture file triggers it, please say so before attaching one — captures contain
whoever's traffic was on the wire, and a public advisory thread is the wrong
place for that.

Expect an acknowledgement within a week. This is a single-maintainer project, so
that is a realistic figure rather than a service level.

## What the attack surface actually is

Worth stating plainly, because it is unusual for a desktop application and it is
what shapes which reports matter most.

**Inwire parses hostile input by design.** Every frame it dissects was written by
somebody else, and the whole product is a parser for it. Bugs in
`src/services/dissectors/` are reachable by anyone who can put a packet on a
network the user is capturing, or who can get the user to open a `.pcap` file.
That is the highest-value area to look at.

**The capture agent runs as LocalSystem.** It is a separate process for exactly
that reason: it holds the capture handle and the driver's user-mode library, and
the process that parses hostile bytes is the one that does **not** have them.
It dissects nothing — a record it sends carries no protocol, no addresses and no
ports (ADR 0010) — so the privileged component's input surface is deliberately
tiny. On Windows it is a single Rust executable (ADRs 0037 and 0047), installed
under Program Files, where only administrators can replace it.

**The Electron binary is fused.** `runAsNode`, `enableNodeCliInspectArguments`
and `enableNodeOptionsEnvironmentVariable` are off, and `onlyLoadAppFromAsar` is
on. So `ELECTRON_RUN_AS_NODE=1 Inwire.exe` no longer turns the signed app into a
Node interpreter. A report of a way to run arbitrary code through the shipped
`Inwire.exe` is a real finding.

**The agent is reached over a named pipe, and the pipe's ACL is the
authorization** (ADR 0029). Its security descriptor is
`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`: SYSTEM and administrators get
everything, the interactive user gets read and write, and nobody else gets
anything. `WD`, `AN` and `NU` are absent deliberately, because a pipe answers
over SMB unless the descriptor says otherwise. There is no network listener, no
port and nothing to pair. A report showing the descriptor does not take effect —
for instance that a second local user can reach the pipe — is a real finding.

**The renderer is sandboxed.** `sandbox: true`, `contextIsolation: true`,
`nodeIntegration: false`, no service workers, every permission request denied,
and a preload that imports only `electron`. Anything that gets Node into the
renderer is a real finding.

**Nothing leaves the machine unasked.** There is no account, no backend and no
telemetry. Four optional lookups from the renderer and two from the main process
are the entire outbound surface; each is listed in `electron/csp.ts` with its
purpose, and each is behind a switch or a click. A request Inwire makes unbidden
would appear in the user's own capture, which is a trust problem specific to this
audience — so an unexpected outbound connection is a real finding.

## Known gaps, deliberately

These are documented shortcomings, not vulnerabilities to report. They are listed
because a security policy that only describes strengths is not worth reading.

- **The Windows build is signed with a certificate only the maintainer's PC
  trusts** (ADR 0047). It is self-issued, code-signing only, with `cA=FALSE`.
  On that one machine it is imported into the local Root store, so the
  installer, the app and the agent verify as Valid there. **On every other
  machine it is an untrusted root**: Windows shows "Unknown publisher" and
  SmartScreen warns. Smart App Control never counts it, even on that PC,
  because it accepts only certificates from CAs in Microsoft's Trusted Root
  Program. That is why there is no public download yet.
- **The signing key is a non-exportable software key with no prompt.** A process
  running as the maintainer's account could sign silently with it. What that
  buys an attacker is narrow: a binary that shows the Inwire publisher name, on
  that one PC. The certificate cannot vouch for a TLS server or issue other
  certificates.
- **Nothing verifies a signature at runtime.** The app does not check the
  agent's signature, or the agent the app's. The pipe's descriptor is the
  authentication.
- **Authenticode verification of downloads is not implemented.** The Update
  Center checks a sha256 against the feed and matches the download host against
  an exact list, but whoever controls the feed also writes the hash. This is
  written down because a hash check next to an elevation prompt looks like more
  assurance than it is.
- **ASAR integrity is stamped but not validated.** The fuse that makes Electron
  refuse a modified `app.asar` at startup, `enableEmbeddedAsarIntegrityValidation`,
  is still off. Its failure mode is an app that will not start, so it is a
  separate decision.
- **Npcap's default install is open to every local user.** Its installer leaves
  the capture devices readable and writable by `WD`, meaning any local account
  can read the machine's traffic and inject raw frames. Because Inwire captures
  through the agent, restricting the driver to administrators costs its users
  nothing, and `Settings → Updates` recommends and offers exactly that (ADR
  0033). This is Npcap's default rather than Inwire's doing, but the
  recommendation is ours.

## Supported versions

The latest release. This project does not backport.
