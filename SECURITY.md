# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**, or go straight to
<https://github.com/Doofess/Inwire/security/advisories/new>. Do not open a
public issue containing vulnerability details or sensitive captures.

Include the Inwire version (`Settings → Updates`), the Npcap version, whether
the capture agent was running, and the smallest steps that reproduce the issue.
If a capture triggers it, describe that before attaching one. Captures can
contain other people's traffic, credentials and decrypted content; key logs can
unlock encrypted traffic. Do not attach a sensitive capture or key log anywhere
public; prefer a small synthetic reproduction.

Expect an acknowledgement within a week. This is a single-maintainer project;
that is a response target, not a service level.

## Supported versions and distribution

Inwire is in development and has no public release yet. Only the latest 0.x
version is supported, and fixes are not backported. There is no public installer
download; see the [README](README.md#build-and-run) for building it and the
signing limitations below.

## Attack surface

Inwire parses hostile network traffic and imported pcap/pcapng files. Each
boundary below names the mechanism that holds it.

**The capture agent.** On Windows the Rust agent runs as LocalSystem. It holds
the Npcap handle and does not dissect captured protocols; its control protocol,
adapter operations and pcapng writer are privileged surfaces. Capture files are
created and deleted while impersonating the requesting pipe client, so their
filesystem access is limited to that client's rights. The service is demand
start: the app asks the Service Control Manager for it at launch, and the agent
stops itself two watchdog ticks after its last client leaves. The app holds no
stop right on the service ([ADR 0035](docs/decisions/0035-the-agent-lives-as-long-as-the-app.md)).
The Windows agent opens no network listener.

**The named pipe.** The agent's only Windows transport is a pipe with the
security descriptor `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`, and it rejects
remote pipe clients. SYSTEM and administrators have full access; **interactive
users may connect**. Multiple local clients are expected: capture ownership is
checked separately, and another client must not be able to stop or reconfigure
the owner's capture. The pipe ACL authenticates local access; it does not verify
the connecting program's publisher
([ADR 0029](docs/decisions/0029-the-app-and-the-agent-talk-over-a-named-pipe.md)).
There is no Windows pairing credential. The legacy macOS/Linux Python agent uses
an authenticated WebSocket instead; there is no desktop app for those platforms
yet.

**The renderer.** `sandbox: true`, `contextIsolation: true`,
`nodeIntegration: false`, no service workers, every permission request denied,
and a bundled preload that exposes specific APIs. The packaged binary has the
RunAsNode, Node inspector arguments and NODE_OPTIONS fuses off and loads only
from ASAR. Live capture is dissected in sandboxed Workers. **File import is
parsed on the renderer's main thread** (`PcapService.streamCaptureFile`): equally
sandboxed and without Node access, but not isolated in a Worker. The capture
store is a separate unprivileged utility process that owns the derived capture
files; the agent owns the original pcapng writer.

**The content security policy** is served as a header, not a meta tag. Its
`connect-src` lists exactly the renderer's hosts (below). It does not govern the
main process or utility processes, whose hosts are recorded separately.

**The followed key log.** Inwire can follow a TLS key-log file so that
connections a browser starts later can be decrypted
([ADR 0045](docs/decisions/0045-the-key-log-is-followed-not-loaded.md)). Main
polls the file and remembers its **path** across launches. The renderer cannot
supply a path: selection happens in main's own dialog or through
`SSLKEYLOGFILE`.

**The monitoring socket.** NetFlow v5 collection binds one UDP port in an
unprivileged utility process (`inwire-monitoring`), not in the agent or the
renderer ([ADR 0058](docs/decisions/0058-monitoring-intake-and-lifetime.md)).
Nothing listens until you press Start, and Start is needed again on every
launch. You choose a specific local IPv4 address and port; `0.0.0.0` is refused,
and the bind is exclusive so another process cannot share the port. Only
datagrams from the one configured exporter address are kept: datagrams from any
other sender are counted by source address and discarded, and never reach the
history. That is a source-address filter, **not authentication**: UDP source
addresses can be forged, so exporter data is untrusted. Datagrams are decoded in
a sandboxed Worker, intake is bounded, and shed datagrams are recorded as a gap.
Windows Firewall may ask whether to allow the app on the first bind.

**The speed test** runs in its own short-lived unprivileged utility process
([ADR 0054](docs/decisions/0054-an-internet-speed-test-against-cloudflare.md)).
It starts with Run and dials only Cloudflare's speed endpoints.

## Privacy and sensitive data

There is no account system or telemetry. Captures, monitoring history and
session data are stored locally, and capture files are sensitive even without
decryption keys. Every optional outbound connection is recorded in
`electron/csp.ts`. The renderer's hosts, in `OUTBOUND_HOSTS`:

| Host | Used for | Gate |
|---|---|---|
| `get.geojs.io` | Locations of public captured IP addresses | Geo-IP consent (`nameResolution.geoIp`) |
| `cloudflare-dns.com` | Reverse DNS lookups, at most four in flight | Reverse-DNS consent (`nameResolution.reverseDns`) |
| `ipapi.co` | The Network panel's public-identity section | Geo-IP consent |
| `tiles.openfreemap.org` | Map style, glyphs and tiles | No switch of its own; the map is shown once geo-IP is consented to |

The main process and utility processes reach these, which are deliberately **not**
in the policy (`MAIN_OUTBOUND_HOSTS`):

| Host | Used for | Gate |
|---|---|---|
| `updates.inwire.app` | The update manifest | `inwire.updates`: opt-in, off by default. The domain does not resolve yet, so a check is a quiet no-op |
| `npcap.com` (and `www.npcap.com`) | The Npcap installer download | An explicit install or reinstall click |
| `speed.cloudflare.com` | Speed test traffic | The Run button: one press, one test |

These services see the requesting machine's public address and the data needed
for the operation. Consent persists across launches; a new click is not required
for every lookup. The NetFlow collector only receives.

Imported TLS key material is held in memory rather than session storage. When
following a key-log file, Inwire remembers its path and reads it again on later
launches until following is stopped. Persisted frame records contain neither
keys nor decrypted plaintext; derived decrypted answers stay in memory. Pcapng
export can include decryption secrets when the user explicitly chooses that
option. Do not share such exports or key logs without considering the traffic
they expose.

## Known gaps

- Local development signing uses a self-issued, code-signing-only certificate.
  Its trust is limited to machines where it has been explicitly trusted; it is
  not a publicly trusted release identity. The certificate setup creates a
  non-exportable software key without a signing consent prompt. Code running
  as that account can use the key. See [ADR 0047](docs/decisions/0047-windows-ships-the-rust-agent-signed-on-this-pc.md).
- App and agent do not verify each other's Authenticode signatures. Downloaded
  installers are checked against the feed's exact size and SHA-256 and permitted
  HTTPS hosts, but **publisher signatures are not verified by Update Center**.
  The feed supplies the hash too. Npcap hosts are explicitly listed; Inwire
  artifacts must use the feed's host. Build-time signature checks are separate.
- ASAR integrity is stamped during packaging, but embedded ASAR integrity
  validation is not enabled.
- Nothing asserts that `PIPE_SDDL` in `agent-rs/src/pipe.rs` equals the
  descriptor above; only the Python agent's copy is checked. That the descriptor
  refuses a remote client has not been verified, because it needs a second
  machine.
- `crashReporter` is off: a renderer minidump would be a copy of the in-memory
  key log, which conflicts with [ADR 0008](docs/decisions/0008-key-material.md).
- Npcap can grant capture-device access to all local users unless its installer's
  administrator-only option is selected. Inwire recommends that restriction;
  the LocalSystem agent allows the app to capture with it enabled.
- The monitoring collector was measured against `softflowd` on one machine. No
  router or firewall has sent to it, and Cancel on the Windows Firewall prompt
  was not run against the packaged build
  ([measurements](docs/monitoring-v5-measurements.md#not-run)).

Reports of new exploits, unexpected exposure, or bypasses of the stated
boundaries are welcome.
