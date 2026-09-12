# local-agent/CLAUDE.md

Build and packaging mechanics for the capture agent. Loaded when working under
`local-agent/`. The rules that must never be got wrong — the version lock, and
what the pipe's descriptor grants — are repeated in the root `CLAUDE.md` so
they are always in context.

## What the agent is

A Python process that captures raw frames and does nothing else with them. It
reads with `pcap_next_ex` directly, batches records into a binary format, and
hands them to whoever asked. It does not dissect: a record carries no source,
destination, protocol, ports or info (ADR 0010).

On **Windows** it runs as the `InwireAgent` LocalSystem service, is installed by
the product's installer, and its only transport is a named pipe. On **macOS and
Linux** it installs from a tarball and keeps the WebSocket — and keeps the
pairing token with it, because there is no interactive-user SID to name on a
socket file and deciding who may open one is a genuinely different design.

## The transport, on Windows

`pipe_server.py` serves `\\.\pipe\inwire-agent` with the security descriptor:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
```

- `D:P` — protected, so nothing is inherited.
- `SY`, `BA` — SYSTEM and administrators, full access.
- **`IU`** — the interactive user, read and write. This is the whole point: the
  service is LocalSystem and the app deliberately is not, and the default DACL
  on a pipe a LocalSystem service creates admits SYSTEM and administrators
  **only**, so without this ACE the app could never connect to the service that
  exists to serve it.
- Absent, deliberately: `WD` (everyone), `AN` (anonymous), `NU` (network). A
  named pipe answers over SMB as `\\host\pipe\name` unless the descriptor says
  otherwise. `PIPE_REJECT_REMOTE_CLIENTS` says it a second time.

Because the kernel decides, the agent asks a pipe client for **no** token.
`register` skips it when the connection reports `kernel_authenticated`, so the
pairing question is never asked rather than merely answered.

**The handle is `FILE_FLAG_OVERLAPPED` and every operation carries its own
`OVERLAPPED` with its own event.** Without it, Windows serialises operations on
the handle: the writer thread's `WriteFile` queues behind the reader thread's
blocked `ReadFile` and waits for bytes that are not coming. Measured against
the real client — `hello` and the first reply arrived, everything after did
not. It works on the handshake, which is what anyone tests, and stops on the
traffic, which is what the pipe is for.

Threads rather than `loop.start_serving_pipe`, and not by preference: the
proactor creates its own pipe instances with the creating process's default
DACL, which for a LocalSystem service is exactly the descriptor that locks the
app out.

`pipe_frame.py` is the framing — a `u32` length, a `u8` kind, little-endian —
and its counterpart is `src/services/agentFraming.ts`. Both refuse a declared
length past 8 MB before allocating. Both assert the same hand-written byte
vectors: `test_protocol.py` here, `scripts/agent/pipe-framing.ts` there.

## The version lock

Three places must agree, and `test_protocol.py` enforces it:

| Where | What |
|---|---|
| `agent.py` | `AGENT_VERSION` |
| `src/services/agentProtocol.ts` | `REQUIRED_AGENT_VERSION` |
| `local-agent/installer/setup.iss` | `MyAgentVersion` |

Any change to the wire protocol or the agent's behaviour bumps it. It is an
**ordering** — the left-hand side of `isAgentOutdated` — so it only ever
climbs, and `test_protocol.py` refuses a reset: an agent left behind by an
earlier install would otherwise read as newer than required, which shows as
"not connected" rather than "update your agent".

`MyAppVersion` beside it is the **product** version, locked to `package.json`,
and is what Windows compares for an upgrade. The two stopped moving together
the moment one installer carried both.

## Building

```
pyinstaller local-agent/inwire_agent.spec
```

Output is `local-agent/dist/inwire-agent-windows/` — a **directory**, not a
file. The entry point is `service_windows.py`: the SCM host, and also the
`install` / `remove` / `start` / `stop` / `debug` CLI the installer drives.

### Why `--onedir`

A onefile build extracts its bundled DLLs to `%TEMP%\_MEI<random>` and executes
them from there. That is a textbook malware pattern — Defender's "block
executable files unless they meet a prevalence, age, or trusted list criterion"
ASR rule blocks it outright — and the extracted DLLs are unsigned however well
signed the wrapper is, because signing a wrapper does not sign what the wrapper
writes to disk. It also paid the extraction at every service start, on a
service that starts at boot.

onedir ships the DLLs beside the exe, where they can be signed and where an
administrator can see what is installed.

### VERSIONINFO

Generated inside the spec from `AGENT_VERSION` rather than written out: a
fourth copy of a version number would sit outside the three-place lock and
would eventually disagree with it. Before 3.8.0 the exe had none at all — no
company, no product, no version, which is also what an unsigned dropper looks
like in the one dialog anyone checks.

### The hidden imports, and why each is there

PyInstaller's static analysis does not see them, and this build is
`console=False`, so a module it quietly dropped shows up as a service that will
not start and says nothing about why.

- `agent`, `agent_log`, `config`, `interface_stats`, `logging_setup`,
  `adapters`, `sockets` — our own, imported inside functions or via `sys.path`.
- `packet_batch` — the binary frame format (3.2.0).
- `pipe_frame`, `pipe_server` — the pipe and its framing (3.8.0). The agent's
  **only** transport on Windows, so a dropped one is an app that never
  connects.
- `win32security`, `win32pipe`, `win32file`, `winerror` — the pipe's pywin32
  surface. `win32security` is what builds the security descriptor, which IS the
  access control: drop it and the agent starts, listens on nothing, and says so
  only in a log the app cannot reach because it cannot connect.
- `win32timezone` — the classic pywin32 omission. Imported at runtime by
  `pywintypes`; its absence shows up only as a service that refuses to start.
- `servicemanager`, `win32serviceutil`, `win32service`, `win32event` — the
  service machinery.
- `scapy.layers.all`, `scapy.layers.inet`, `scapy.layers.inet6`,
  `scapy.arch.windows` — scapy loads layers dynamically.

**Excluded:** `websockets`. `agent.py` does not import it on Windows at all,
and shipping a library the product cannot reach inside a signed installer is
not defensible.

### The installer

```
iscc installer/setup.iss
```

That is the **product's** installer, at the repository root — the app and the
agent in one, under its own AppId. It needs `npm run pack` and the PyInstaller
build to have run first. `local-agent/installer/setup.iss` is the older
agent-only installer and is what a machine with agent 3.x has; the unified one
uninstalls it, because it registers a service by the same name.

## Running it by hand

```
python local-agent/agent.py
```

As Administrator or root — raw capture needs elevation on every OS. On Windows
this needs Npcap already installed; the installer normally handles that.

Two things about the frozen exe. `debug` requires the service to be `install`ed
first, because pywin32's `debug` verb checks the SCM registry before running
any agent code — so the loop is `install` once, then `debug`. And `debug` is a
**log-file** diagnostic, not a console one: the exe is built `console=False`,
so `sys.stderr` is `None` and nothing appears on screen. Watch
`%ProgramData%\Inwire\agent.log`.

`--version` and `--init-config` produce output only through a redirect, for the
same reason — and both raise a **UAC prompt** when run by hand, because the exe
is built `uac_admin=True`. Harmless from the installer, which is already
elevated; it hangs a command typed at a prompt.

## macOS and Linux

One tarball, built from the real sources:

```
npx tsx scripts/agent/package-unix.ts --build
```

It writes to `release-artifacts/`, which is **not** under `public/` — Vite
copies `public/**` into `dist/` verbatim, so an artifact left there is packaged
inside the desktop app. That is how a stale 21 MB installer came to be two
thirds of a 30 MB renderer bundle.

The archive carries its own `install.sh`: a root-owned virtualenv, a systemd
unit or a LaunchDaemon, a pairing token, and an `uninstall` verb. It replaced
two bootstrap scripts that each embedded a copy of `agent.py` frozen around
2.1 — a copy that can go stale will, so there is no copy, and
`scripts/agent/package-unix.ts` fails if a module `agent.py` imports is missing
from the archive.

## Release checklist

A source-only bump ships nothing.

1. Bump the version in all three places.
2. `python local-agent/test_protocol.py`
3. `pyinstaller --noconfirm --clean local-agent/inwire_agent.spec`
4. `npm run pack`
5. `iscc installer/setup.iss`
6. Install it here, then `python local-agent/verify_protocol.py` against the
   live service — it checks `state` after every command, `capture_stats` while
   sniffing, and the error codes.

Neither `local-agent/dist/` nor `release-artifacts/` is tracked in git. Rebuild
rather than editing binaries.

## Logs

`%ProgramData%\Inwire\agent.log`, rotating. When the agent runs as a service
there is no console, so this is the only place to look. The app surfaces it in
Settings → Driver Info, which is also where it says **why** the agent is not
answering — not installed, disabled, stopped, or crash-looping — rather than
one word covering all four.
