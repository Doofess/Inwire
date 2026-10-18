# Security

## Reporting a vulnerability

Email **[Rotem2207@gmail.com](mailto:Rotem2207@gmail.com)** privately.
Do not open an issue containing vulnerability details or sensitive captures.

Include the Inwire version (`Settings → Updates`), the Npcap version, whether
the capture agent was running, and the smallest steps that reproduce the issue.
If a capture triggers it, describe that before attaching one. Captures can
contain other people's traffic, credentials and decrypted content; key logs can
unlock encrypted traffic. Prefer a small synthetic reproduction when possible.

Expect an acknowledgement within a week. This is a single-maintainer project;
that is a response target, not a service level.

## Supported versions and distribution

Inwire is currently in development with no published releases. Report against
the current development version. The release policy is latest-only, without
backports. There is no public installer download yet. See the [README](README.md#build-and-run)
for building it and the signing limitations below.

## Current security boundaries

Inwire parses hostile network traffic and imported pcap/pcapng files. Live
dissection runs in sandboxed renderer Workers; file import currently parses in
the renderer. Neither has Node access. The renderer uses `sandbox: true`,
`contextIsolation: true`, `nodeIntegration: false`, no service workers and
denied browser permission requests. Its bundled preload exposes specific APIs.

On Windows the separate Rust capture agent runs as LocalSystem. It holds the
Npcap handle and does not dissect captured protocols. Its control protocol,
adapter operations and file writer are also privileged attack surfaces. Capture
files are created and deleted while impersonating the requesting pipe client,
so their filesystem access is limited to that client's rights.

The Windows agent uses a named pipe with
`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` and rejects remote pipe clients.
SYSTEM and administrators have full access; **interactive users may connect**.
Multiple local clients are expected: capture ownership is checked separately,
and another client must not be able to stop or reconfigure the owner's capture.
The pipe ACL authenticates local access; it does not verify the connecting
program's publisher. There is no Windows pairing token or network listener.
The legacy macOS/Linux Python agent uses an authenticated WebSocket instead;
there is no desktop app for those platforms yet.

The capture store is a separate, unprivileged Electron utility process. It owns
the derived capture files; the agent owns the original pcapng writer. See the
[architecture reference](docs/architecture.md) for process and data ownership.

## Privacy and sensitive data

There is no account system or telemetry. Captures and session data are stored
locally, and capture files are sensitive even without decryption keys. The
application's optional network operations are recorded in `electron/csp.ts`:

| Operation | Destination and trigger |
|---|---|
| IP geolocation | Public captured IP addresses to `get.geojs.io`, after geo-IP consent |
| Reverse DNS | Address queries to `cloudflare-dns.com`, after reverse-DNS consent |
| Public connection identity | `ipapi.co`, after geo-IP consent |
| Map | Style, glyphs and tiles from `tiles.openfreemap.org` when the consented map is used |
| Updates | The configured update feed; automatic launch checks are opt-in and off by default |
| Npcap download | `npcap.com` or `www.npcap.com`, on an install/reinstall action |
| Speed test | `speed.cloudflare.com`, on Run; generated upload bytes and network measurements |

These services see the requesting machine's public address and the data needed
for that operation. Consent can persist across launches; a new click is not
required for every lookup. The renderer CSP does not govern main-process traffic.

Imported TLS key material is held in memory rather than session storage. When
following a key-log file, Inwire remembers its **path** and reads it again on
later launches until following is stopped. The renderer cannot supply an
arbitrary path: selection happens in main's dialog or through `SSLKEYLOGFILE`.
Persisted frame records contain neither keys nor decrypted plaintext; derived
decrypted answers stay in memory. Pcapng export can include decryption secrets
when the user explicitly chooses that option. Do not share such exports or key
logs without considering the traffic they expose.

NetFlow monitoring is planned in [ADRs 0058–0060](docs/decisions/README.md),
but its UDP collector and history store are not implemented. Planned behavior
is not a guarantee about the current build.

## Current limitations

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
- The packaged Electron binary disables RunAsNode, Node inspector arguments and
  NODE_OPTIONS, and requires ASAR loading. ASAR integrity is stamped during
  packaging, but embedded ASAR integrity validation is not enabled.
- Npcap can grant capture-device access to all local users unless its installer's
  administrator-only option is selected. Inwire recommends that restriction;
  the LocalSystem agent allows the app to capture with it enabled.

These limitations describe the current design. Reports of new exploits,
unexpected exposure, or bypasses of the stated boundaries are still welcome.
