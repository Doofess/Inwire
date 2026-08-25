# Agent Background Service: headless install, origin auth, connection-scoped capture

## Context

Phase 1 (`2026-08-25-agent-remote-control-design.md`) built a typed command
protocol, a pairing handshake, version detection, and interface selection.
It explicitly deferred four things to a second sub-project, on the grounds
that hiding the agent removes the two properties that bound the command
channel's risk (manual launch, visible console):

- Hidden/no-console build (`console=False`)
- Auto-start on login
- Wiring `setup.iss` up as the real distribution path
- A pairing story that survives having no console to print a token to

This spec is that second sub-project.

### What prompted it

After testing Phase 1 the user reported five problems. Three of them —
a stuck "Agent Idle" badge, start/stop not controlling the agent, and a
phantom "update available" notice — were **not code defects**. Both
compiled binaries (`local-agent/dist/netview-agent-windows.exe` and the
served copy in `public/downloads/`) were built 2026-08-25 15:08, predating
every Phase-1 commit to `agent.py` (20:46–22:02 the same day). The user was
testing a pre-Phase-1 agent that had none of the new protocol. Rebuilding
with PyInstaller resolved all three; no design change was needed and none
is included here.

The remaining two were genuine new requirements:

1. **A one-time install that leaves no window open**, after which the agent
   runs in the background and only captures when NetView is actually in use.
2. **The "Agent Connected" pill becomes an interface picker** with
   checkboxes, synced with the agent.

**This spec covers (1) only.** Requirement (2) is a separate pass; it reuses
the `set_interfaces` command Phase 1 already built and is deliberately not
designed here to keep this scope tight. The one coupling worth noting: this
spec deletes the pairing prompt that currently sits beside that pill, so the
interface-picker work should land after this, not in parallel.

### Decisions taken with the user

| Question | Decision |
|---|---|
| Tray icon acceptable? | **No.** Truly zero UI — nothing visible anywhere. |
| Auto-start mechanism | **Windows Service** (not Scheduled Task), running as LocalSystem. |
| Auth model | **Origin allowlist.** All pairing-token machinery is removed. |
| Allowed origins | **Configurable** via a JSON file, with localhost defaults. |

## Goals

- One elevated install. After it, the agent runs at boot with no UAC prompt,
  no console, no taskbar entry, no tray icon.
- Capture happens only while NetView is open and has asked for it.
- A hostile web page cannot reach the agent, receive packets, or drive it.
- When something breaks, there is a log to read.

## Non-goals

- macOS and Linux background-service equivalents. Those platforms keep
  today's manual-launch bootstrap scripts. Only Windows is in scope.
- The interface-picker UI redesign (separate pass, see above).
- Any auto-update mechanism. Updating means running a newer installer.
- Protecting against a hostile **native** process already running locally
  with administrator rights. Such a process can open raw sockets directly;
  the agent is not the weakest link in that scenario and pretending
  otherwise would drive bad design.

## Run model

`netview-agent-windows.exe` becomes a Windows service host built on
pywin32's `win32serviceutil.ServiceFramework`, compiled with
`console=False`.

**Verified feasible before writing this spec:** `pywin32` 312 installs and
its service modules (`win32serviceutil`, `win32service`, `win32event`,
`servicemanager`) import cleanly on the Python 3.14.7 toolchain this repo
builds with. This was the single largest feasibility risk in the design.

The exe becomes multi-modal. Invoked with a subcommand it acts as a CLI for
the installer; invoked by the Service Control Manager it runs the service:

| Invocation | Behavior |
|---|---|
| `netview-agent-windows.exe install` | Register the service, automatic start, LocalSystem account |
| `netview-agent-windows.exe start` / `stop` | Control a registered service |
| `netview-agent-windows.exe remove` | Deregister the service |
| `netview-agent-windows.exe debug` | Run the service body in the foreground with logging to stderr |
| Double-click, no arguments | Does nothing visible (by design) |
| Launched by the SCM | Runs the service |

Because `console=False`, none of these show a window. The installer checks
exit codes rather than reading output.

`python local-agent/agent.py` keeps working exactly as it does today, with a
console and stderr logging. That path is how development and debugging
happen and must not regress. Because `bootstrap_windows.py` is deleted (see
Files touched), a developer using this path installs Npcap themselves —
previously that script did it on their behalf. This is documented in
`CLAUDE.md` rather than left to be rediscovered.

### Service identity and privileges

The service runs as **LocalSystem** with **automatic** start. LocalSystem
holds the raw-socket rights packet capture requires, which is what removes
the recurring UAC prompt: elevation is granted once, at install, to the
installer.

`has_admin_privileges()` currently hard-exits when not elevated. Under the
SCM that check will pass, but its failure path must log and exit cleanly
rather than write to a stderr nobody is attached to.

## Install and uninstall

`local-agent/installer/setup.iss` already exists — Inno Setup, uninstaller,
Start Menu entry, `netview://` URI handler — but is wired to nothing; the
"Download Driver" button serves the raw PyInstaller exe. This spec makes
`setup.iss` the real distribution artifact.

### Build prerequisites

Neither prerequisite is present on the current build machine and both must
be installed before this work can produce an artifact:

- **Inno Setup 6.1 or newer** (`ISCC.exe`). Not currently installed.
  6.1 is the floor because the install sequence below relies on
  `DownloadTemporaryFile`.
- **pywin32** — installed during this spec's feasibility check
  (`pywin32` 312) and added to `requirements.txt`.

`setup.iss` as committed also references `redist\npcap-1.79.exe`, a file
that does not exist in the repo. It would fail to compile today. The
install sequence below removes that reference rather than adding the
binary.

Install sequence:

1. If Npcap is absent (`IsNpcapInstalled` already implements the check),
   download it at install time with Inno Setup's `DownloadTemporaryFile`
   from the official npcap.com distribution, then run it silently
   (`/S /winpcap_mode=no`).
2. Install the exe to `{app}`.
3. Write `%ProgramData%\NetView\config.json` if it does not already exist.
   An existing config is never overwritten — reinstalling or upgrading must
   not silently discard a customized origin allowlist.
4. Run `netview-agent-windows.exe install`, then `start`.

Uninstall runs `stop` then `remove` via `[UninstallRun]` before deleting
files, so no orphaned service registration is left behind. Npcap is **not**
uninstalled — other software may depend on it.

**Downloading Npcap rather than bundling it is a deliberate change from the
committed `setup.iss`, and it resolves that file's own licensing caveat
(`setup.iss:8-12`): redistributing and silently installing the Npcap
installer inside a packaged product requires an Npcap OEM license.**
Downloading it at install time from the official source is not
redistribution, so the caveat no longer applies. It also matches what
`bootstrap_windows.py` does today, and removes the missing-`redist`
build break. The cost is that installation requires network access, which
is acceptable: the machine is about to run a tool whose only purpose is
watching its network.

A failed download must abort the install with a message naming
https://npcap.com/#download, not leave a registered service that can never
capture.

The `netview://` URI handler in `setup.iss` becomes vestigial — its purpose
was launching a manually-started agent from the browser, which an
always-running service makes unnecessary. It is left registered but unused
rather than removed, to avoid churn in a file this spec is already changing
substantially.

### What the webapp serves

The download the "Download Driver" button offers changes from the raw
PyInstaller exe to the Inno Setup output:

- Built artifact: `local-agent/installer/output/NetView-Agent-Setup.exe`
- Copied to: `public/downloads/NetView-Agent-Setup.exe`
- `AGENT_DOWNLOADS.windows` in `src/services/platformDetect.ts` updates its
  `url` and `filename` to match.

macOS and Linux entries in that map are unchanged — those platforms keep
their existing manual-launch scripts, per Non-goals.

Serving the bare exe would now install nothing and register no service, so
this is a required change, not a cosmetic one.

## Configuration

`%ProgramData%\NetView\config.json`:

```json
{
  "allowedOrigins": [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173"
  ]
}
```

Port 3000 covers both the Vite dev server (`vite --port=3000`) and the
Express production server (`server.ts`, `PORT || 3000`). Port 4173 is Vite's
preview default. `localhost` and `127.0.0.1` are distinct origins to a
browser and both must be listed.

The service re-reads this file **on every incoming connection**, not once at
startup. The file is small and connections are infrequent, so the cost is
irrelevant, and it means adding an origin takes effect without restarting
the service. A malformed or missing file falls back to the built-in
defaults above and logs a warning — a typo in a config file must not leave
the user with an agent that refuses every connection and no visible way to
find out why.

## Authentication: origin allowlist

The `websockets` 17.0.1 server (`websockets.asyncio.server.serve`) accepts a
`process_request` callback that runs before the WebSocket upgrade completes
and may return an HTTP response to reject the handshake. Rejection uses
`connection.respond(403, ...)`.

Rules:

- `Origin` present and in `allowedOrigins` → handshake proceeds.
- `Origin` present and not in the list → **403, connection closed.** The
  client never receives `hello`, never receives a packet.
- `Origin` absent → **403.** Browsers always send `Origin` on cross-origin
  WebSocket handshakes; its absence means a non-browser client.

This is deliberately stricter than Phase 1, where an unauthenticated client
still received `hello` so the webapp could show "agent found, not paired".
That state no longer exists, so neither does the need to represent it.

### Why this replaces the pairing token

The threat that matters is a web page you visit reaching `localhost:8999`
and capturing your traffic. Browsers set `Origin` themselves and page
JavaScript cannot forge it, so an allowlist closes that threat completely,
with no token to deliver and no UI to deliver it through — which is what
makes it compatible with a zero-UI service.

A local native process *can* forge the header. It also already has raw
socket access, so it gains nothing by attacking the agent. Defending that
case was explicitly declared a non-goal above rather than left implicit.

The practical argument is just as strong: a LocalSystem service has no
console and no user session, so there is nowhere to print a token. Every
token-delivery alternative (a file the user opens and copy-pastes) is worse
UX guarding a threat the origin check already handles.

### Removals

All Phase-1 pairing machinery is deleted, not deprecated:

- Agent: `generate_pairing_token()`, `PAIRING_TOKEN`, `ConnectionAuth`,
  `GATED_COMMAND_TYPES`, `is_command_allowed()`, the `auth` message branch,
  the `authRequired` field in `hello`, and the `invalid_token` /
  `not_authenticated` error codes.
- Frontend: `PairingPrompt` in `Header.tsx`, the `pairingRequired` state and
  prop chain, `getStoredPairingToken` / `storePairingToken` /
  `clearStoredPairingToken`, the `auth` variant of `AgentCommand`, the
  `pendingAuthAckRef` reconnect-resync path in `App.tsx`, and the
  `invalid_token` branch of the error handler.

Phase 1's packet-broadcast auth gate in `_send_all` — the fix for its most
serious finding, where unauthenticated connections still received raw packet
data — is **not** simply deleted. Its guarantee is preserved and
strengthened: with origin rejection at the handshake, a disallowed
connection cannot exist to be broadcast to. `_send_all` loses its
per-connection auth check because every live connection is now, by
construction, an allowed one.

## Capture lifecycle

This is how "detect whether NetView is running" is satisfied.

```
Service starts (boot)          -> listening, sniffer idle
Allowed origin connects        -> hello { version, state, interfaces }
Client sends start_capture     -> sniffer starts, state broadcast
Client sends stop_capture      -> sniffer stops, state broadcast
Last connection closes         -> sniffer auto-stops
```

The auto-stop rule is the substantive addition: **when the connection count
reaches zero, the service stops sniffing.** Close the NetView tab and
capture halts. Traffic is never captured with nobody watching, which is the
property that makes an always-running background capture agent acceptable at
all.

Sniffing does not resume on reconnect. A fresh connection arrives idle and
must send `start_capture` again — inferring intent across a disconnect would
mean capturing without an explicit request.

Deliberately **not** implemented: scanning the process list for a browser,
or probing for the NetView page. An active WebSocket connection from an
allowed origin *is* the signal that NetView is running; it is exact,
requires no permissions, and does not involve inspecting what else the user
is running.

## Versioning

This is a breaking protocol change — `auth` is gone and unauthenticated
clients are rejected outright — so:

- `AGENT_VERSION` → `2.0.0`
- `REQUIRED_AGENT_VERSION` → `2.0.0`

Phase 1's version-mismatch machinery then does exactly what it was built
for: a leftover 1.1.0 agent reports as outdated and the webapp says so,
instead of failing in the confusing way that prompted this work. The
stale-binary incident in Context is precisely the failure mode this
prevents; it went undetected only because the stale binary predated the
version handshake itself.

Because a `1.x` agent cannot satisfy a `2.0.0` webapp, the webapp's
outdated-agent state must remain reachable and must point at the installer
download. That path already exists (the "Download Driver" item and its
update badge) and must not be removed alongside the pairing UI.

## Observability

With no console, every diagnostic currently going to `stdout`/`stderr` must
go to a file. `%ProgramData%\NetView\agent.log`, via
`logging.handlers.RotatingFileHandler` with a bounded size and a small
backup count, so an agent running for months cannot fill a disk.

All existing `print(...)` calls in `agent.py` become `logging` calls. When
run as `python agent.py` or via the `debug` subcommand, logging additionally
goes to stderr so today's development experience is unchanged.

Logged at minimum: service start/stop, interface enumeration results,
config load (including fallback-to-defaults warnings), every rejected
origin with the origin string, connect/disconnect with the resulting
connection count, capture start/stop including auto-stop, and any sniffer
thread exception.

This section is not optional polish. Once the console is gone, this log is
the only diagnostic channel that exists for either the user or a future
maintainer.

## Files touched

| File | Change |
|---|---|
| `local-agent/service_windows.py` | **New.** `ServiceFramework` subclass, subcommand dispatch, SCM entry point |
| `local-agent/agent.py` | Remove pairing; add origin check via `process_request`; add config loading; add auto-stop-on-last-disconnect; `print` → `logging`; version → 2.0.0 |
| `local-agent/config.py` | **New.** Config path resolution, load-with-defaults, origin matching (pure, testable) |
| `local-agent/logging_setup.py` | **New.** Rotating file handler + optional stderr handler |
| `local-agent/bootstrap_windows.py` | **Deleted.** Its only jobs were installing Npcap and launching the agent; the installer now does the first and the SCM the second |
| `local-agent/netview_agent.spec` | Entry point → `service_windows.py`; `console=False`; pywin32 hidden imports |
| `local-agent/installer/setup.iss` | Npcap via `DownloadTemporaryFile` (drops the missing `redist` reference); service install/start; config seeding; `[UninstallRun]` stop/remove |
| `local-agent/requirements.txt` | Add `pywin32` |
| `src/services/platformDetect.ts` | Windows download → `NetView-Agent-Setup.exe` |
| `CLAUDE.md` | Update the `local-agent/` section: service model, new build steps, Npcap now a developer prerequisite for `python agent.py` |
| `local-agent/test_protocol.py` | Remove pairing assertions; add origin-matching and config-fallback assertions |
| `src/services/agentProtocol.ts` | Remove token storage and `auth` command; `REQUIRED_AGENT_VERSION` → 2.0.0; drop `authRequired` |
| `src/App.tsx` | Remove pairing state, auth send, reconnect-resync auth path |
| `src/components/common/Header.tsx` | Remove `PairingPrompt` and its prop chain |

## Testing

The repo has no test framework. Existing pure-logic tests follow the
`local-agent/test_protocol.py` and `scripts/parity/crypto-vectors.ts`
convention: plain assertion scripts with a `check(name, actual, expected)`
helper and a failure counter. New tests follow it too.

**Automated (pure logic):**
- Origin matching: exact match allowed; unlisted origin rejected; absent
  origin rejected; case and trailing-slash variants behave as specified.
- Config loading: valid file parsed; missing file falls back to defaults;
  malformed JSON falls back to defaults; a file present but lacking
  `allowedOrigins` falls back.
- Lifecycle: connection count reaching zero triggers stop; a nonzero count
  does not. Tested against the existing injected-`spawn_fn` seam in
  `SnifferController`, which already separates logical sniffing state from
  real scapy threads.

**Manual (cannot be unit-tested):**
- Install via `setup.iss` on a clean machine; confirm service registered,
  running, automatic start, and **no window of any kind appears**.
- Reboot; confirm the service is running before any login.
- Open NetView; confirm connection, `hello`, and a successful capture.
- Close the tab; confirm the log records auto-stop.
- Point a page from a disallowed origin at `ws://localhost:8999`; confirm
  403 and a logged rejection.
- Uninstall; confirm the service is stopped and deregistered.

The `debug` subcommand exists to make the manual list tractable — running
the service body in the foreground is the only practical way to iterate on
a frozen service.

## Risks

**PyInstaller + pywin32 services is the finicky part.** Frozen service exes
register differently from plain scripts and need specific hidden imports
(`win32timezone` is the classic omission). The import feasibility check
above passed, but freezing is a separate risk from importing. The `debug`
subcommand and the log file are the mitigations, and this is where
implementation time should be expected to go — not in the protocol changes,
which are mostly deletions.

**A service is harder to recover from than a console app.** A crash loop at
boot with no UI is a bad failure mode. The service must be registered with
SCM failure actions that do not retry indefinitely, and any startup failure
must be logged before exit.

**Losing the console removes an implicit safety property.** Today a running
agent is visible; after this it is not. The auto-stop-on-disconnect rule and
the origin allowlist are what replace that visibility as the bound on the
agent's behavior, which is why neither is optional.

**The build now has a toolchain dependency that is not installed.** Inno
Setup must be present before this produces a shippable artifact. Everything
except the final installer can be built and tested without it, so this
blocks the last step rather than the work — but it blocks it completely, and
it is worth installing before starting rather than discovering at the end.
