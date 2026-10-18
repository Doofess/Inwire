<img src="logo/inwire-layers-256.png" width="76" align="right" alt="">

# Inwire

Inwire is a packet analyzer for Windows. Capture traffic, see which processes
are using the network, and follow a connection packet by packet. You can also
open an existing capture and work through it offline.

It's still in development. There isn't an installer to download yet, so for
now you'll need to build it from source.

[![CI](https://github.com/Doofess/Inwire/actions/workflows/ci.yml/badge.svg)](https://github.com/Doofess/Inwire/actions/workflows/ci.yml)

## Working with traffic

You can capture from several adapters at once, narrow the capture with a
filter, or set it to start and stop on a schedule. Ring files let you keep
recording within a limit you choose.

The parser covers **142 dissected layers**, including DNS, TLS, QUIC, HTTP/1–3,
Windows networking and flow-export protocols. Display filters use Wireshark
field names, so familiar filters carry over.

Once you have a capture, you can:

- Inspect a packet's fields alongside its bytes, or follow a TCP, UDP or QUIC
  conversation in a ladder view.
- Load an SSL key log to read TLS and QUIC traffic, including HTTP/2 and HTTP/3.
- Find the process behind a connection and see which direction its traffic went.
- Look through conversations, endpoints, protocols and expert findings, or plot
  traffic and packet sizes. Statistics and the map use the packets currently
  in memory; the packet list and display filter can reach the whole capture.
- Compare the machine's network settings with what the capture shows, and run
  an internet speed test from the Network sidebar.
- Export packets to pcapng, pcap, CSV, JSON or Excel, create a PDF analysis report,
  or anonymise a capture before sharing it.

Captures are stored on disk. You can reopen the previous session after a
restart and reach packets that have left the memory buffer. Replacing a capture
requires your decision; a scheduled start warns about replacement when you arm
it, and a ring can remove its oldest files according to the limits you set.

Exports include the whole capture or the packets matching your display filter.
Excel has a size limit because the workbook has to fit in memory; for larger
exports, use CSV.

The app has Light, Dark, Dim and High Contrast themes, plus an option to follow
Windows.

## Watching a network

Inwire can also collect NetFlow v5 from one router, firewall or `softflowd`.
It listens on an address and port you choose (2055 by default) and keeps a
history on disk, up to a storage limit you set, that survives a restart. The
Monitoring screen, opened from the Network sidebar, shows traffic over time,
top endpoints and top conversations for any range, and one click on a host
filters the capture by it. Collection runs apart from capture, so starting,
clearing or importing a capture leaves it alone. Its numbers are checked
against tshark's decode of `softflowd`'s exports.

NetFlow v9, IPFIX and sFlow can be inspected inside a packet capture, but
aren't collected.

## What connects to the internet?

Captured packets stay on your machine. There are no accounts or telemetry.

IP lookups and reverse DNS are optional and send address queries to their
providers. After you enable geo-IP, the map also loads online tiles. Update
checks are opt-in, and Npcap is downloaded only when you ask to install it.
The speed test connects to Cloudflare when you press Run and can use up to
2 GB of traffic. The NetFlow collector only receives: it listens where you tell
it to and sends nothing.

Loaded decryption keys stay in memory unless you choose to include them in a
pcapng export. If you follow a key-log file, the app remembers its path and
reads it again on later launches.

See [SECURITY.md](SECURITY.md) for the details and known limitations.

## Build and run

You'll need Node.js 24+:

```powershell
npm ci
npm run start:app
```

That builds and opens the desktop app. You can import capture files without
installing a driver or running the capture service.

Live capture needs [Npcap](https://npcap.com/#download) and Inwire's Rust agent
installed as a Windows service. To build the agent and installer, you'll also
need [rustup](https://rustup.rs) with the `stable-x86_64-pc-windows-gnu`
toolchain and Inno Setup 6.3 or newer:

```powershell
npm run build:agent
npm run pack
iscc installer/setup.iss
```

Npcap is installed separately. Settings → Updates can download its official
installer; its licence wizard will open for you to complete. Administrator-only
driver access is recommended. The Inwire app itself runs without elevation.

The current signing setup uses a certificate trusted on the maintainer's PC.
Public downloads are waiting on a publicly trusted certificate.

## Development

The app uses Electron, React and TypeScript. Capture runs in a separate Rust
service so the app doesn't need administrator rights. macOS and Linux have a
Python agent, but no desktop app yet.

Use `npm run dev` for UI work and `npm run check` to run the checks.
[CONTRIBUTING.md](CONTRIBUTING.md) covers setup, testing and how changes are
handled. The [architecture decisions](docs/decisions/README.md) explain the
choices behind the code.

[SCOPE.md](SCOPE.md) describes where the project is going and what's in scope.

## License

MIT — see [LICENSE](LICENSE).
