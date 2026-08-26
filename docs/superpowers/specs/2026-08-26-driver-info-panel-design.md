# Driver Info Panel — Design

**Date:** 2026-08-26
**Status:** Approved
**Agent protocol version:** 2.0.0 → 2.1.0

## Problem

The capture agent became a headless Windows service in the previous
sub-project. That was the right call for everyday use — install once, no
console, no tray icon — but it removed the only window into what the agent
was doing. Its entire diagnostic surface is now
`%ProgramData%\NetView\agent.log`, written by a LocalSystem service into a
directory a browser page cannot read.

Every debugging round since the service landed has run the same way: the
user reproduces something in the browser, then opens the log file by hand in
a text editor to find out what the agent thought happened. The 51-interface
enumeration bug and the silently-failing installer were both diagnosed that
way.

This design puts that log in the app, next to the agent state the app
already knows, so troubleshooting does not require leaving the browser.

## Goals

- Show, in one place: whether the agent is reachable, what version it is,
  whether it is capturing, and which adapters it is capturing from.
- Stream the agent's own log lines live while the panel is open.
- Cost nothing while the panel is closed.

## Non-goals

- Log filtering, search, or level selection in the UI. The buffer is small
  and the browser's own find works. Add it later if it is actually missed.
- Exporting or downloading the log. The panel shows the file's path; the
  file itself is the export.
- Changing the log format, rotation policy, or destination.
- Reading logs from a previous run beyond what the backlog window happens to
  include.

## Decisions

Four decisions were settled before this document, and they constrain
everything below.

**Log lines come from the real agent log, streamed.** The alternative — a
client-side event log reconstructed from what the app observes on the socket
— needs no agent change at all, but is blind to everything that happens
inside the agent before it reaches the wire. Interface enumeration failures,
Npcap load failures, rejected origins, and service start errors all live
there, and they are the failures worth building a diagnostic panel for.

**Lines flow only while the panel is open.** The app subscribes on mount and
unsubscribes on unmount. Streaming to every client all the time would burn
bandwidth and browser memory continuously for something looked at rarely,
and would let log volume compete with packet throughput during a capture.
Fetch-on-demand with a Refresh button was rejected for the opposite reason:
the moment the panel is most useful is while a bug is being reproduced
live.

**Driver Info is a section inside the Settings modal**, not its own menu
entry. Settings today is a single small Appearance panel; it gains a left
sidebar with two sections. This matches the request literally and gives
Settings somewhere to grow.

**Live lines come from an in-process logging handler, not a file tailer.**
The agent is the only writer of `agent.log`, so there is nothing in that
file the logger did not produce. A handler on the `netview` logger delivers
each line the instant it is logged, with no polling latency, no file-position
bookkeeping, and no way for a `RotatingFileHandler` rollover mid-session to
desync anything. It also keeps working when the log file is unwritable —
the case where seeing the log matters most. A file tailer's one real
advantage, picking up lines from before the process started, is covered by
reading the file once for the backlog.

## Protocol changes

Additive. Two new commands, one new message.

### Commands (app → agent)

```json
{ "type": "subscribe_logs" }
{ "type": "unsubscribe_logs" }
```

Neither carries parameters. The backlog size is the agent's choice, not the
client's, so a client cannot ask for an expensive read.

### Message (agent → app)

```json
{
  "type": "log",
  "lines": [
    { "time": "2026-08-26 22:14:02,123", "level": "INFO", "message": "client connected (1 total)" }
  ]
}
```

The same message shape carries both the backlog (one message, up to 200
entries) and each live line (one message, one entry), so the app needs a
single handler rather than two.

`level` is a string for lines the agent produced through the logger, where
the level is known exactly. It is `null` for backlog lines read back from
the file that do not match the `asctime level message` format — traceback
continuation lines, most commonly — and those carry the raw text unchanged
in `message`. Nothing is dropped for being unparseable.

Structured entries rather than raw formatted strings: the agent already
knows each record's level, and making the app re-derive it with a regex
would discard information it was handed.

### Version and compatibility

`AGENT_VERSION`, `REQUIRED_AGENT_VERSION`, and `MyAppVersion` all move to
`2.1.0`. The existing three-way sync check in `test_protocol.py` enforces
that they move together.

A 2.0.0 agent ignores unknown message types, so an old agent degrades to an
empty log pane rather than breaking. Because `REQUIRED_AGENT_VERSION`
advances, an installed 2.0.0 service will show the app's "Update" badge
until it is rebuilt and reinstalled. That is correct: the feature does not
work without the new agent.

## Agent implementation

### Subscriber tracking

`AgentServer` gains `log_subscribers`, a set of sockets, alongside
`connections`. `subscribe_logs` sends the backlog and adds the socket;
`unsubscribe_logs` discards it.

`handle_disconnect` must discard from **both** sets. A socket left in
`log_subscribers` after its connection dies is the same class of leak as the
`register()` handshake leak fixed in the previous sub-project, and it gets
its own test for that reason.

### Backlog read

On `subscribe_logs`, read the tail of `agent.log`: seek to the end, read
back at most 64 KB, decode with `errors="replace"`, split into lines,
discard a partial first line, and keep the last 200. Reading the whole file
is not acceptable — rotation allows it to reach 1 MB.

A missing or unreadable log file is not an error. The agent sends an empty
`lines` array and continues; the panel simply starts empty and fills with
live lines.

### Live lines

A `WebSocketLogHandler(logging.Handler)` is attached to the `netview`
logger in `main()`, **immediately after `setup_logging()` returns**. That
ordering is load-bearing: `setup_logging` tears down existing handlers when
reconfigured, so installing before it would silently remove this one.

`emit()` formats the record into a `log` message entry and hands it to a
broadcast that returns immediately when `log_subscribers` is empty. With the
panel closed, the entire feature costs one set-emptiness check per log line.

### Reentrancy guard

Any log call reachable from the broadcast path re-enters `emit()`, which
broadcasts again. `_send_all` does not log today — it discards dead sockets
silently — but `handle_disconnect` does, and a future maintainer adding one
warning to the send path would create an infinite loop with no obvious
cause. A `threading.local()` flag, set for the duration of `emit()` and
checked on entry, makes the cycle structurally impossible instead of relying
on nobody ever adding that log line.

It must be thread-local rather than a module-level flag: sniffer threads log
concurrently with the asyncio loop, and a shared flag would let one thread's
guard suppress another thread's legitimate log line.

## UI implementation

### Settings modal restructure

`SettingsModal` gains a left sidebar with two sections, Appearance and
Driver Info, and widens to `max-w-3xl` to fit log lines. Appearance keeps
its current content unchanged.

### DriverInfoPanel

A new component in `src/components/common/`. Its status block reads entirely
from props that `App.tsx` already holds — `agentStatus`, `agentVersion`,
`agentOutdated`, `agentCaptureState`, `agentInterfaces`, `selectedInterfaces`
— so no new state is invented to describe the agent. It also displays the
resolved log file path as text, so the file remains directly reachable.

The log pane is a monospace list colored by level, auto-scrolling to the
newest line, with a Clear button. Manual scrolling upward pauses
auto-scroll; scrolling back to the bottom resumes it.

### App state

`App.tsx` owns an `agentLog` buffer capped at 1000 entries, oldest dropped
first — the same policy as the existing 4000-packet buffer. It sends
`subscribe_logs` when the panel mounts and `unsubscribe_logs` when it
unmounts, and clears the buffer on each subscribe, so a reconnect cannot
present a stale timeline stitched onto a fresh one.

## Error handling

| Condition | Behavior |
|---|---|
| Log file missing or unreadable on subscribe | Empty `lines` array; panel fills from live lines |
| Agent is 2.0.0 (no log support) | Command ignored by the agent; panel shows status only, plus the existing Update badge |
| Agent disconnects while panel is open | Subscription dies with the socket; on reconnect the panel resubscribes and clears |
| Send to a subscriber fails | `_send_all`'s dead-connection sweep must be extended to discard from `log_subscribers` as well as `connections`; today it only clears the latter |
| Malformed `log` message received | `parseAgentMessage` returns null, as it does for every other malformed shape |

## Security

Any origin on the allowlist can read the agent's log. The log contains
interface names and device paths, capture start/stop events, and the origins
of rejected connections — the last of these is the one thing here an
allowlisted client could not otherwise learn through the protocol it is
already speaking, and it is not packet contents or anything sensitive about
the network being captured. The default allowlist is localhost-only. This
does not meaningfully widen the agent's exposure.

## Testing

No test framework exists in this repo; both suites are plain assertion
scripts with a failure counter and a non-zero exit.

**`local-agent/test_protocol.py`** — the tail reader (normal case, file
shorter than the window, missing file), the backlog line parser (well-formed
line, continuation line, empty line), subscriber add and remove, disconnect
cleanup of both sets, and the reentrancy guard actually terminating
recursion.

**`scripts/agent-protocol/`** — parsing a well-formed `log` message,
rejecting malformed variants (missing `lines`, `lines` not an array, entries
that are not objects), and encoding both new commands.

**`local-agent/verify_protocol.py`** — a live end-to-end check against the
running service: subscribe, receive a backlog, send `start_capture`, and
observe the agent's own resulting log line arrive live.

**`npm run lint`** (`tsc --noEmit`) for the TypeScript side.

## Files touched

- `local-agent/agent.py` — subscriber set, subscribe/unsubscribe handling,
  backlog read, `WebSocketLogHandler`, version bump
- `local-agent/test_protocol.py` — new assertions
- `local-agent/verify_protocol.py` — live check
- `local-agent/installer/setup.iss` — `MyAppVersion`
- `src/services/agentProtocol.ts` — `AgentLogMessage`, parsing, two new
  commands, `REQUIRED_AGENT_VERSION`
- `scripts/agent-protocol/` — new assertions
- `src/components/common/SettingsModal.tsx` — sidebar restructure
- `src/components/common/DriverInfoPanel.tsx` — new
- `src/App.tsx` — `agentLog` buffer, subscribe/unsubscribe wiring
- `CLAUDE.md` — protocol message list, version references
