# agent-rs/CLAUDE.md

The Rust capture agent that ships on Windows (ADRs 0037, 0047); loaded when you work under `agent-rs/`. Build, version and installer mechanics for the Python twin are in `local-agent/CLAUDE.md`; the process topology is in `docs/architecture.md`.

## Parity with the Python agent

- Land every behaviour fix in both agents, or say why not. A fix in one is the failure mode here. ADR 0047 lists the five deliberate deviations; there are no others.
- The app can read only what `agent-rs/src/` emits: `scripts/agent/message-coverage.ts` fails on a message the app parses and Rust never writes.
- Control messages are held in both directions. `scripts/agent/control-vectors.json` is what the agent emits (checked by `scripts/agent/control-vectors.ts` against the app's parser); `scripts/agent/command-vectors.json` is what the app sends, made by the app's own `encodeAgentCommand`, checked by `scripts/agent/command-vectors.ts` and by the `command_vectors` test module in `agent-rs/src/protocol.rs`. Change a command and regenerate the fixture from the app, never from the Rust source.
- `set_interfaces` carries device **names**, not indices. Reading indices fell back to adapter 0, a dead `WAN Miniport`, reported as `sniffing`.
- The Rust `hello` has no `authRequired`, and `control-vectors.ts` fails on any `auth*` key. Do not add the pairing token to this agent.
- Binary framing is held by hand-written vectors: `scripts/agent/binary.ts`, `scripts/agent/pipe-framing.ts`, against `local-agent/test_protocol.py`. The record is version 4 (22 bytes, `u32` lengths, `u64` epoch-nanosecond timestamp).

## Version

- `package.json` is the only place the version is authored. `npm run sync:version` rewrites `agent-rs/Cargo.toml` and the crate's entry in `agent-rs/Cargo.lock`; `scripts/agent/version.ts` checks them every run. `lib.rs` reads `env!("CARGO_PKG_VERSION")` for `hello` and `--version`.
- The release build is `--locked`, so a lock still naming the previous version fails it. Sync before building.
- `scripts/agent/stamp-agent.ts` refuses unless `package.json`, `Cargo.toml` and the binary's own `--version` agree. Stamp first, sign second (`scripts/sign/sign.ps1`).

## Pipe and ACL

- The only Windows transport is the named pipe, `agent-rs/src/pipe.rs`. Every instance is `FILE_FLAG_OVERLAPPED` and every operation has its own `OVERLAPPED` and event. A synchronous handle queues `WriteFile` behind a blocked `ReadFile`: the handshake works and traffic stops.
- `PIPE_SDDL` (`pipe.rs`) is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. `IU` is the point: the service is LocalSystem, the app is not. `WD`, `AN` and `NU` stay absent because a pipe answers over SMB otherwise. Nothing asserts the Rust literal (`local-agent/test_protocol.py` reads only Python's); change it only with a second-account check from `docs/verification.md`.
- Every instance created while the agent holds none asks for `FILE_FLAG_FIRST_PIPE_INSTANCE` (`pipe::Held`), so a name another user created or recreated is refused, never joined. A lost instance is retried, not fatal. Another interactive user can still add an instance while the agent holds the name; ADR 0068 accepts that.
- Only a packet batch is ever shed (`outbound.rs`). Control messages have their own 4 MB cap, and passing it ends the session through `pipe::disconnect`, because the writer is blocked in a `WriteFile` the client is not draining.
- The service is demand start and stops itself two watchdog ticks after its last client leaves (ADR 0035). Do not grant the app `SERVICE_STOP`: it would be granted to every interactive logon.
- `restart_agent` is refused with `capture_busy` to a client that does not own the running capture. The exit comes 500 ms later and asks again then, so a capture another client started in between calls the restart off.
- The log folder (`agent_log.rs`) is SYSTEM's to rotate in, so the service makes it `LOG_DIR_SDDL`: owned by Administrators, protected DACL, users read only. It is opened once with `FILE_FLAG_OPEN_REPARSE_POINT` and secured through that handle, because checking a path and then securing the same path lets a junction be swapped in between. A log name that is a link, a directory, a hard link or a file another account owns (an owner can always rewrite its DACL) is removed; if one cannot be removed, the agent runs with no file log. Every log open passes `FILE_FLAG_OPEN_REPARSE_POINT`.
- It writes capture files as its connected client, never as SYSTEM. `scripts/agent/second-account-check.ps1` and `scripts/electron/capture-file-drive.ts` hold it.

## Npcap

- `wpcap.dll` is in `System32\Npcap`, off the default DLL search path. `agent-rs/src/npcap.rs` loads it by absolute path with `LOAD_WITH_ALTERED_SEARCH_PATH`. Do not rely on `PATH`.
- Open with `pcap_create` and `pcap_activate`, not `pcap_open_live`: the snaplen and nanosecond precision must be set between them. Snaplen is capped at 262,144.
- `pcap_setbuff` is Npcap's, not libpcap's, and works after activation. The kernel buffer is sized per core (4 MB a core, floor 32 MB, cap 256 MB) because Npcap splits it into one segment per processor. `docs/bursts-and-what-wireshark-does.md` has the comparison.
- `pcap_pkthdr` is 16 bytes on Windows. Read with `pcap_next_ex` directly; drops come from `pcap_stats` (`runtime.rs`).
- `start_capture` carries a libpcap filter and snaplen (ADR 0050). An unreadable option set is refused with `invalid_capture_options` (`control.rs`), never captured on defaults. A filter one adapter's link type rejects fails that adapter alone, in libpcap's words. `check_capture_filter` asks the same question of a dead handle (`protocol.rs`).
- The agent does not dissect and never adds source, destination, protocol or info to a record (ADR 0010).

## Build

- `npm run build:agent` builds on the GNU toolchain with `+stable-x86_64-pc-windows-gnu`, because `rust-toolchain.toml` cannot carry a host. `-- -Test` runs `cargo test` first.
- Cargo's output has no resources; the stamped copy at `agent-rs/dist/inwire-agent-windows.exe` is the payload.
- `agent-rs/switch-agent.ps1 -Python` puts the unsigned Python tree back for a comparison. Never ship from that state.
- Building does not replace the installed service. The live drives need the installed current agent.
