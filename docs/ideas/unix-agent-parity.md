# The Unix agent at parity with the Rust agent: a brief

> **Nothing here is built.** Owner's direction, 2026-10-09: Inwire ships desktop
> apps for macOS and Linux, and the agent on those platforms must be the equal
> of the Rust agent that ships on Windows. The owner's first instinct was to get
> there with a bundled dumpcap. This brief records the facts, recommends the
> other route, and says how to do dumpcap properly if Phase 0 disagrees. Each
> phase that starts gets an ADR.

## Where things stand

- **Windows ships `agent-rs/`**: one signed 750 KB executable, a LocalSystem
  service, a named pipe whose ACL is the authentication (ADRs 0029, 0033, 0037,
  0047). It writes its own pcapng, ring and autostop (ADR 0052). **dumpcap is
  not needed on Windows**, and the owner is right about that: every item on
  the dumpcap comparison is done natively, and dumpcap measured worse on
  latency, live drop counts and adapter isolation.
- **macOS and Linux run `local-agent/agent.py`**: Python, a WebSocket with a
  pairing token, a root systemd unit or LaunchDaemon from
  `local-agent/unix/`, wire v4, and **no files**: it refuses ring and autostop
  with a sentence (ADR 0052). ADR 0037 deferred porting the Rust agent because
  "they have no desktop app to talk to yet". That premise is now withdrawn.
- **What is platform-neutral in `agent-rs/` already**: `framing`, `protocol`,
  `wire`, `pcapng`, `capture_file`, `session`, `runtime`, `control`,
  `adapters`, `agent_log`. The platform seams are exactly the modules `lib.rs`
  gates with its fourteen `#[cfg(windows)]` lines: `npcap` (libpcap FFI through
  `LoadLibraryExW`), `pipe` (named pipe plus `ImpersonateNamedPipeClient`),
  `service` and `restart` (SCM), `npcap_access` (the Npcap DACL),
  `sockets`, `host_feeds`, `if_table` (Windows socket and interface tables).

## Recommendation: port `agent-rs`, do not bundle dumpcap

Parity means the same code. The Rust agent's capture loop is a thin layer over
`pcap_create` / `pcap_set_snaplen` / `pcap_set_tstamp_precision` /
`pcap_set_buffer_size` / `pcap_activate` / `pcap_setfilter` / `pcap_next_ex`,
and libpcap on macOS and Linux exports the same symbols. dumpcap would replace
only that loop and add, per the measurements in ADR 0052 and
`scratchpad/dumpcap-research` (2026-09-26, loopback, pcapng to stdout):

| | Rust agent | dumpcap |
| --- | --- | --- |
| Marker-to-output latency | direct reads | p50 94 to 156 ms, p90 249 ms, max 265 ms (`CAP_READ_TIMEOUT`, compiled in) |
| Drop counts | continuous `capture_stats` | at exit only (one ISB, one `D` message) |
| One adapter fails | that adapter | the whole capture ends |
| Ring plus live stream | both | ring cannot stream to stdout |
| Privilege | root or capabilities, ours | the same, plus a child process of a root daemon |
| Distribution | our binary | 4.7 MiB GPLv2 and LGPL, source obligations, notarise or re-sign a third party's binary on macOS |

dumpcap does not remove the privilege problem, the service, the transport or
the protocol work. It removes the libpcap loop, which is the small part, and
charges for it in every row above. The port keeps `scripts/agent/message-coverage.ts`,
the shared golden vectors and the byte-identical capture comparison from ADR
0037 §2 as the parity proof, which a second engine cannot use.

## Phase 0: the spike that settles it

Completion: a number for each line below, written into the ADR that opens the
port. Budget one day. The owner's PC has Docker Desktop and WSL 2 (installed
2026-10-09; the Virtual Machine Platform feature finishes enabling on the next
reboot). A Linux container with `--cap-add NET_RAW --cap-add NET_ADMIN` is
enough for steps 1 to 3 on Linux; macOS needs GitHub Actions `macos-latest`
for the build check and a real Mac for capture.

1. `cargo check --target x86_64-unknown-linux-gnu` and
   `--target aarch64-apple-darwin` after moving the Windows modules behind
   `cfg(windows)` in `lib.rs`. Count what fails to compile; that is the port's
   real size.
2. A `libpcap` loader: `dlopen("libpcap.so.1")` on Linux,
   `dlopen("/usr/lib/libpcap.A.dylib")` on macOS, resolving the same symbol
   names `npcap.rs` resolves today. Open loopback, `pcap_next_ex`, write
   records. Measure marker-to-record latency the way `run.mjs` measured
   dumpcap. Expect single-digit milliseconds with immediate mode on.
3. Byte-compare one capture against the Python agent on the same interface,
   the way ADR 0037 compared 106,948 frames on Windows.
4. Only if 2 is not clearly better than dumpcap's row above, read the dumpcap
   section at the end and compare again with numbers.

## The port, in phases

Every phase lands behind the existing harness: golden vectors,
`message-coverage.ts`, the three live drives and the two-client drive, run on
the target OS.

**1. Platform seams.** One `platform` module with three traits and two
implementations: capture library (loader plus the handful of calls `npcap.rs`
wraps), transport (listen, accept, peer identity, write a file as the peer),
service host (start, stop, demand-start, logging). `lib.rs` stays the only
file that names an OS. The fourteen `cfg(windows)` lines are the inventory.

**2. libpcap on Unix.** Same calls, three differences to record in the IDB and
the ADR: `pcap_set_immediate_mode(1)` before activate, or BPF on macOS
buffers until its timeout and you have rebuilt dumpcap's latency; nanosecond
`if_tsresol` only where `pcap_get_tstamp_precision` confirms it (Linux yes,
macOS usually microseconds); datalinks you did not have on Windows (`DLT_NULL`
on the macOS loopback, `DLT_LINUX_SLL2` if the `any` pseudo-interface is
allowed; decide, and the dissector's link-type table follows). `pcap_setbuff`
is Npcap-only; `pcap_set_buffer_size` is the portable call and `npcap.rs`
already prefers it.

**3. Transport: the design ADR 0029 asked for.** A Unix domain socket, not a
WebSocket, and no token. ADR 0029 named the problem: there is no
interactive-user SID, so who may connect "comes down to a file mode, a group,
or reading the peer's credentials". Proposed answer, to be grilled before the
ADR: socket at `/run/inwire/agent.sock` (Linux) and `/var/run/inwire/agent.sock`
(macOS), directory `root:inwire` mode 0770, socket mode 0660, the installer
adds the console user to group `inwire`; the agent reads the peer's uid and
gid (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and logs it. The
analogue of `ImpersonateNamedPipeClient` for ADR 0052's capture files: create
the file, then `fchown` it to the peer's uid and gid and `fchmod` 0600, so
root never owns the user's captures. The WebSocket, the token and
`allowedOrigins` leave the Unix path with this phase; ADR 0029 gets the
amendment it reserved.

**4. Service host.** The units in `local-agent/unix/` already exist; swap
`ExecStart` and `ProgramArguments` to the binary. On Linux prefer
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` over `User=root`: the unit's
reason for root (scapy opening sockets lazily) does not apply to a static
binary. On macOS the LaunchDaemon runs as root; BPF devices need it or a
ChmodBPF-style group, and root is the honest choice for a daemon that owns
the capture. Demand start (ADR 0035) has a native equivalent on both: a
systemd `.socket` unit and launchd's `Sockets` key hand the listening socket
to the agent on first connect, which is better than the SCM dance, and the
idle self-stop stays as it is.

**5. Packaging and signing.** Linux: a static binary (musl, since libpcap is
`dlopen`ed and nothing links at build time), shipped in the `.deb`/`.rpm` or
tarball with `install.sh`. macOS: codesign with hardened runtime, notarise, and
ship inside the Electron app bundle with a privileged helper install, or as a
separate pkg; decide in the ADR. The Electron app itself for these platforms
is the larger project this brief does not cover (ADR 0027 says desktop app;
`electron-builder.yml` gains `dmg`, `AppImage`, `deb` targets).

**6. Retire the Python agent on Unix.** When the drives pass on both OSes,
`local-agent/` keeps its one remaining job: the Windows baseline for
`switch-agent.ps1 -Python`. The trigger for this, a desktop app there to talk
to, has fired; update `SCOPE.md`'s line that macOS and Linux retain the Python
agent, and ADR 0037 §1.

## If Phase 0 still says dumpcap: how to do it properly

Only read this if the spike's numbers favour it. The design below is what the
owner approved on 2026-09-28 before choosing "our own dumpcap"; the owner's
answers then were one dumpcap for all adapters, a Wireshark-style ring, the
Python agent stays native, GPL met by licence texts plus a written offer.

- **Spawn** `dumpcap -i <if> [-i <if>...] -f <filter> -s <snaplen> -n -w <path>`
  with `-b filesize:<KiB> -b files:<N>` for the ring and `-a duration:<s>` /
  `-a filesize:` / `-a files:` for autostop. `-w -` streams pcapng to stdout
  only without a ring; with a ring, follow the files instead.
- **Control** with `-Z none`, which makes dumpcap write sync-pipe messages to
  stderr in the `sync_pipe.h` format: one byte of type, three bytes of
  big-endian length, payload. Parse `F` (file opened: the ring hands you each
  new path), `P` (packets since last message), `D` (drops, sent once at exit),
  `E` and `B` (error, bad filter), `S` (success). `--signal-pipe` is
  Windows-only; on Unix stop with `SIGINT`, and `SIGUSR1` is the graceful quit.
  `--update-interval <ms>` sets how often `P` arrives.
- **Follow the ring** the way the store already follows the agent's ring
  (ADR 0052: segments, `floorOrdinal`, `recoverCapture`). Each `F` message
  is a new segment; dumpcap deletes the oldest when `files:` is exceeded and
  tells you nothing, so the store must tolerate a vanished segment.
- **Live drop counts do not exist.** Only the ISB at exit and the `D`
  message. Either accept that the status bar cannot show drops during a
  capture, or read `/proc/net/dev` and `netstat -ibd` yourself, which is the
  agent's job again.
- **Latency** is the compiled `CAP_READ_TIMEOUT`; no flag changes it. Expect
  the p90 above and say so in the UI.
- **Privilege** is unchanged: the daemon that spawns dumpcap runs as root or
  with capabilities, and dumpcap inherits them. There is no privilege the
  bundle buys you.
- **Distribution**: pin the exact Wireshark version, record its SHA-256, ship
  its `COPYING` and the LGPL texts, publish a written offer for the
  corresponding source, and on macOS either keep the Wireshark Foundation
  signature (then the app's notarisation must allow it) or re-sign under the
  product's identity. The installer's payload signature check (ADR 0047)
  needs the same story.
- **Keep the wire protocol**: the daemon still speaks wire v4 to the app and
  still rewrites dumpcap's EPBs into records, so the Unix agent is dumpcap
  plus most of the Rust agent anyway. That sentence is why Phase 0 is expected
  to pick the port.

## Rulings carried from earlier sessions

- Capture stays in the agent's process tree, never in the app (ADR 0033,
  `.out-of-scope/in-process-capture.md`).
- No listening network socket in the privileged agent; the flow collector and
  speed test run unprivileged in the app (`SCOPE.md`, Undecided).
- Write Windows facts as Windows facts; the code falls through on darwin and
  linux (`window.inwire?.platform`, `<html data-platform>`).
- Tests on real captures; fixtures with personal traffic stay untracked
  (ADR 0004).
