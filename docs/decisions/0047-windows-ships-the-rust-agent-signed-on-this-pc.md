# 0047 — Windows ships the Rust agent, signed on this PC

**Status:** accepted 2026-09-26. **Completes [0037](0037-the-agent-is-rust-on-windows.md)**:
the port it measured is now what the installer ships, and the blocker its
Consequences named — a code-signing certificate, and an elevated install to
replace the binary — is removed **for this PC and for no other machine**.
**Answers the "Signing" half of [0030](0030-one-installer-two-destinations.md)'s
"What is not decided here"**, for this PC only. The "Updates" half stays with
[0032](0032-the-update-center.md), and that ADR's Authenticode verification is still
not built. **Amends [0029](0029-the-app-and-the-agent-talk-over-a-named-pipe.md) on one
detail**: the Windows agent's `hello` carries no `authRequired` at all. Does not
touch 0033, because the agent is still a separate LocalSystem service, and does
not touch 0035. **Amended by [0048](0048-a-captures-adapters-are-fixed-for-its-life.md)**:
the `set_interfaces` restart below was ported to parity and is now gone from both
agents. A mid-capture selection is refused with `capture_running`.

## Context

0037 ended with the Rust agent measured and not shipped. The two reasons were
outside the code. First, the one-file argument is about what a certificate
covers, and there was no certificate. Second, replacing the installed binary
needs an elevated install. Until both were answered, the Python agent was what
ran.

**The Rust agent was also not yet the Python agent's equal.** The two were
audited against each other line by line, and the audit found nine differences
the app could see:

- With no Npcap installed, the Rust agent exited. The Python agent serves the
  pipe with an empty interface list.
- `set_interfaces` during a capture only stored the selection. The Python agent
  restarts on the new selection and tells every client.
- A refused start left the app reading "Capturing".
- A capture whose adapters had all died kept its handles, its pump and its
  owner.
- `restart_agent` was answered with a generic `state`.
- `hello.npcapAccess` was always null.
- `adapter_config` reported less than the Python agent does.
- `install` failed on every upgrade with `ERROR_SERVICE_EXISTS`.
- An SCM stop with a client connected could hang.

The golden vectors could not see any of these, because each one is behaviour
rather than format. All nine are fixed. The decisions now live in
`agent-rs/src/control.rs`, behind two traits. `runtime_tests.rs` drives the real
runtime over real pipes and the real fixture pcap.

## Decision

### 1. The installer ships the Rust agent

`installer/setup.iss` installs the stamped, signed exe from `agent-rs` as
`{app}\agent\inwire-agent-windows.exe`. That is the Python agent's own file name,
so the service's ImagePath is the same string before and after an upgrade. When
`install` finds an existing `InwireAgent` registration, it updates it in place,
as pywin32 did. `[InstallDelete]` removes the Python agent's `_internal` tree,
and the installer also removes pywin32's `PythonClass` key and its event-log
source.

macOS and Linux keep the Python agent (0037 §1). On Windows the Python agent
survives only as a comparison baseline, which
`agent-rs/switch-agent.ps1 -Python` puts back.

### 2. Signed with a certificate this PC trusts, and no other machine does

**The certificate** is `CN=Inwire Code Signing (this PC)`:

- RSA 3072, with a code-signing EKU only
- `cA=FALSE`, so it cannot issue other certificates
- a non-exportable key in `CurrentUser\My`
- valid to 2031-09-26

**The scripts:**

- `scripts/sign/new-cert.ps1` creates the certificate, unelevated.
- `scripts/sign/trust-cert.ps1` is the one elevated step. It adds the public
  half to `LocalMachine\Root` and `TrustedPublisher`, and first refuses any
  certificate that could be more than a code-signing anchor. `-Remove` undoes it.
- `scripts/sign/sign.ps1` makes every signature. It signs with SHA-256 and adds
  an RFC 3161 timestamp from DigiCert, so each signature stays valid after the
  certificate expires.

**`npm run dist:signed` is the release.** It runs three steps:

1. `build:agent` stamps the agent, then signs it.
2. `pack` flips the fuses, then signs `Inwire.exe` and its DLLs.
3. `iscc /DSIGN` runs `verify-payload.ps1` over everything `[Files]` installs,
   and refuses to compile if a single PE file is unsigned.

**The owner chose this over a publicly trusted certificate** (OV, EV, or Azure
Artifact Signing, formerly Trusted Signing). The reason is the one `CLAUDE.md` §8
already gave for setting signing aside: this is a machine the author works on,
not a fleet anybody ships to. A public certificate means identity validation and
a recurring cost outside this repository. Both would be spent on machines that
do not exist yet.

**This removes 0037's blocker on this PC only.** 0037 needed a trusted
certificate and one elevated install. On this PC both now exist: the certificate
is trusted here, and the owner ran the signed installer elevated, once. On any
other machine the chain ends at an untrusted root and the signature counts for
nothing. There, the blocker stands exactly as 0037 wrote it.

**No certificate is in the repository, and the build is not tied to this one.**
The build looks the certificate up by thumbprint, from `INWIRE_SIGN_THUMBPRINT`
or from `.signing.json`, which is gitignored. Replacing it with a real
certificate therefore means changing a thumbprint, not changing the build.
`scripts/sign/signing.ts` checks four things:

- one signer: electron-builder and Inno are both routed to `sign.ps1`
- no `.cer` or `.pfx` file is tracked
- `.signing.json` is ignored
- this machine's configured thumbprint appears in no committable file

**The key has no interactive protection, and that was accepted.**

- **The risk:** any process running as this user can sign with the key
  silently. "Non-exportable" stops `Export-PfxCertificate`, but not code that has
  the right tooling.
- **Why a prompt was refused:** a release makes seven signatures, so a prompt on
  each would make every build interactive.
- **How little it exposes:** with a code-signing-only EKU and `cA=FALSE`, the key
  cannot vouch for a TLS server or issue certificates. All such a process
  borrows is the publisher name on a UAC prompt, on this PC.

The full argument is in the header of `new-cert.ps1`.

## What signing buys, and what it does not

**What it buys, on this PC:**

- WinVerifyTrust reports the files Valid.
- The UAC prompt and file properties name "Inwire Code Signing (this PC)"
  instead of "Unknown publisher".
- A file changed after signing reads `TRUST_E_BAD_DIGEST`.
- A release cannot wrap an unsigned or stale payload, because the compile
  refuses.

**It also makes 0037's one-file argument true in practice.** The agent is one
file of about 750 KB, and the signature covers all of it. The Python agent was a
23 MB tree of `.pyd` files, and signing its wrapper would not have covered them.

**Nothing verifies a signature at runtime.**

- The app does not check the agent's signature before connecting. The pipe's
  descriptor is the authentication (0029), and the agent's image sits in Program
  Files, which only administrators can write.
- The agent does not check the app's signature.
- The Update Center checks a sha256 and an exact download host, never
  Authenticode (0032).

A signature here is policy: something Windows and a person consult. It is not a
check this code makes.

**It does not help with SmartScreen or Smart App Control, because neither
consults the local Root store.**

- SmartScreen judges files by Microsoft's reputation service.
- Smart App Control is in evaluation mode on this PC. It accepts only
  certificates issued by a CA in Microsoft's Trusted Root Program
  ([Code signing for Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)).
  If it moves to enforcement, it will judge this build as if it were unsigned.

## What parity measured

On 2026-09-26 both agents captured on the real Ethernet adapter at the same
moment, and each was sent the same commands:

- **Python:** the installed service.
- **Rust:** running in `debug` on a private pipe.

| | Python | Rust |
|---|---|---|
| frames delivered | 106,948 | 106,948, byte-identical |
| dropped | 0 | 0 |
| sequence numbers | 0..106,947, no gaps | the same |
| timestamps | exactly 1 µs off on 10.2% of frames, from float rounding | the driver's own, to the µs |
| CPU at 10 MB/s | 23.0% of a core | 10.1% |
| working set | 65–69 MB, plus an 82–90 MB PowerShell child per adapter read | 10–12 MB |
| first `hello` | 424–445 ms | 67–102 ms |
| `start_capture` to first batch | 15.8 ms | 12.6 ms |

**`adapter_config` was identical on all eight adapters, except for the
`source` labels.** The Rust agent reads the route table directly and says
`route` and `windows_iflist`. The Python agent says `powershell` and
`windows_iflist+powershell`. The label records which tool produced a value, so
it should differ.

**The two agents differed in five ways, and each is deliberate.** Every command,
error path, ownership case and watchdog case sent the same messages to the same
clients, with these exceptions. Each one is in `control.rs`, beside the
`agent.py` lines it departs from.

- **An idle capture has no owner.** When every adapter fails, `agent.py` leaves
  `capture_owner` set. Its idle `state` then names an owner, so every other
  window greys out Start for a capture that no longer exists.
- **A device name that is not in the adapter list is never opened**, so its
  `capture_failed` carries no `iface`. `agent.py` passes any string to libpcap,
  and Npcap also accepts `rpcap://` sources. A LocalSystem service should not
  hold that door open for a fault that only a stale selection produces.
- **Adapters are opened before `sniffing` is announced.** `agent.py` broadcasts
  `sniffing` first, so a selection that fails entirely tells every client
  "sniffing" and then "idle".
- **Nothing to capture on returns `no_interfaces`**, instead of a `sniffing`
  state over zero adapters.
- **A broken pipe to the owner stops the owner's capture**, just as the owner
  disconnecting does in both agents. `agent.py`'s `_send_to_owner` clears the
  owner when a send fails, and leaves the sniffer running with no owner until
  the last client leaves.

**One difference was a Rust defect, and it is fixed.** The live `kernelReceived`
counter was sampled up to a second before it was sent, which put it as much as
14,186 frames behind. It is now sampled at send time.

**One finding belonged to the app, and both agents triggered it.** On reconnect,
the app sends `set_interfaces` and then `start_capture`. The idle `state` that
`set_interfaces` broadcasts was read as "the capture stopped". So after any pipe
break mid-capture, the agent kept capturing while the UI said it had stopped.
`src/services/captureResync.ts` fixes it.

## Installed once, by the signed installer

The installer ran elevated on 2026-09-26, over the Python agent's install:

| | |
|---|---|
| the installer's own signature | Valid, `CN=Inwire Code Signing (this PC)`; exit code 0 |
| ImagePath | `"C:\Program Files\Inwire\agent\inwire-agent-windows.exe"`, unchanged |
| start type, account, dependency | `DEMAND_START`, LocalSystem, `npcap` |
| failure actions | restart/5000 three times, reset 86400, intact |
| what the Python agent left | `_internal` and pywin32's `PythonClass` key, both gone |
| unelevated `sc start` | `RUNNING` in 112 ms |
| the running agent | 9.6 MB |
| the failure-policy write | logged by the service at the installer's start and at the app's: `restart-on-failure policy written`, then `restart is available (service restart-on-failure policy confirmed)` |

The second log line matters. It is written only by a process whose id is the
one the SCM runs as `InwireAgent`. So the write that both agents used to skip
now happens under the real SCM.

**Every installed PE file verifies Valid, with one exception.**

- **Signed by Inwire:** the agent, `Inwire.exe`, `ffmpeg.dll`,
  `vk_swiftshader.dll`, `vulkan-1.dll` and `unins000.exe`.
- **Signed by Microsoft:** `d3dcompiler_47.dll` and `dxil.dll`.
- **Unsigned:** `dxcompiler.dll`.

`dxcompiler.dll` was left over from the 2026-09-22 build. Since then,
`electron/afterPack.cjs` has pruned it and `dxil.dll` from every pack, but Inno
adds files and never removes them. `[InstallDelete]` now names both files, so
the next install removes them.

**An upgrade keeps an uninstaller that has a newer version.** Inno skips
`unins000.exe` when the installed copy's version is newer ("Existing file is a
newer version. Skipping.").

- **What happened:** the first signed build came from a per-user Inno Setup 6.7.3
  (`Setup.e32` 51.1054). It was installed over an install made by Inno Setup 7
  (51.1055), so the old, unsigned uninstaller stayed. Every other file was
  signed, and the install reported success.
- **The fix:** `scripts/sign/build-signed.ps1` now picks the newest ISCC it can
  find. It ranks them by `Setup.e32`'s version, because `ISCC.exe`'s own version
  reads 0.0.0.0.
- **On this machine:** Inno Setup 7 is at `C:\Program Files\Inno Setup 7`.

**The GNU host is named on every command that builds something shipped:**
`cargo +stable-x86_64-pc-windows-gnu`.

- `rust-toolchain.toml` used to put the host in `channel`. rustup refuses that
  with "target tuple in channel name" wherever the toolchain is not already
  installed, which means every fresh machine and every CI runner.
- The file now says `stable`, and explains why.
- CI's `agent-rs` job tests, builds, stamps and reads back the crate on
  `windows-latest`. It does this unsigned: the runner has no certificate, and
  signing is deliberately not required there.

## Consequences

- **0037's Consequences are now history.** "Nothing ships yet" and "the Python
  agent is what is installed" record the period before this ADR, and a banner
  there says so.
- **What keeps the two agents in step:**
  - the golden wire vectors
  - the command vectors authored by the app
  - the control vectors
  - `message-coverage.ts`
  - `runtime_tests.rs`
  - running them side by side whenever behaviour changes

  A fix that lands in one agent and not the other is still the failure mode to
  watch for.
- **`switch-agent.ps1 -Python` replaces the signed exe with an unsigned tree.**
  The comparison is worth that cost. To come back, run `-Rust` or re-run the
  installer.
- **The fuses were already flipped**, and electron-builder signs after
  `afterPack`, which is the order the fuses need. The one Electron hardening
  still off is `enableEmbeddedAsarIntegrityValidation`. It stays a separate
  decision, because if it fails the app will not start.

## What is still owed

- **A publicly trusted certificate, for every other machine.** Until then:
  - there is no download
  - SmartScreen warns
  - Smart App Control in enforcement mode ignores the signature

  The build is ready for it. It needs only a new thumbprint.
- **`restart_agent`, round-tripped through the installed Rust agent.** The gate
  and the failure policy it depends on are both confirmed live (see the table
  above). What has not been watched is the exit itself on this build: pressing
  Restart Driver, seeing `restarting now`, and seeing the SCM start a new
  process about five seconds later.
- **The by-hand items that 0037 left:**
  - a capture through the UI against the installed agent
  - two clients over Fast User Switching
  - the pipe's descriptor taking effect under a second account

  All three are in `docs/verification.md`.
- **Authenticode verification in the Update Center** (0032). A check pinned to
  this certificate would pass on this PC and fail everywhere else, so it waits
  for the public certificate.
- **The Python agent stays.** macOS and Linux run it, and on Windows it is the
  baseline for comparison. Its `--onedir` build and hidden-imports list can go
  only once nothing compares against it.
