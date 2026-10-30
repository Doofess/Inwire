# 0068 — Another user on the machine can serve the agent's pipe, and the agent refuses a name it did not create

**Status:** accepted 2026-10-30. The owner chose this on the 2026-10-17
privilege-boundary review: harden the agent, record what it cannot close, and
do not verify the server from the app. **Amends 0029**, whose descriptor is
unchanged.

## Context

0029 made the pipe's security descriptor the authentication:
`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. The review looked at the other
direction, who may *serve* the name, and found two things in the agent and one
thing it cannot fix.

- **The agent joined a pipe someone else created.** `CreateNamedPipe` without
  `FILE_FLAG_FIRST_PIPE_INSTANCE` succeeds when the name already exists and the
  new instance's descriptor allows it. A user who created
  `\\.\pipe\inwire-agent` before the service started was therefore joined, not
  refused.
- **Losing an instance slot stopped the agent.** Each acceptor answered any
  `create_instance` failure by asking the whole agent to shut down
  (`runtime.rs`), so a user who took a slot could end the service.
- **A user can add an instance while the agent runs.** This is the part the
  agent cannot close; see the residual below.

## The measurement

On 2026-10-17, with a real pipe and an unelevated user:

| ACE for `IU` | A second process's `CreateNamedPipe` | Node's `net.connect` |
|---|---|---|
| `GRGW` (the shipped descriptor) | gets an instance | connects |
| `FRDC` (read plus write-data) | `ERROR_ACCESS_DENIED` | `EPERM` |

libuv's `open_named_pipe` asks for `GENERIC_READ | GENERIC_WRITE`, and
`GENERIC_WRITE` on a pipe includes `FILE_CREATE_PIPE_INSTANCE`. So the access
the app needs to connect is the same access that lets another user create an
instance. There is no descriptor that admits the app and refuses that, and
`PIPE_SDDL` therefore does not change.

## Decision

- **The first instance of the name is created with
  `FILE_FLAG_FIRST_PIPE_INSTANCE`**, before any acceptor thread starts. If it
  fails, the agent logs `{name} already exists - another process created it
  first, so the agent will not serve it: {error}` and stops with the reason
  "the pipe name is already in use". Slot 0 serves that instance. Both agents
  do this (`pipe.rs`, `runtime.rs`; `pipe_server.py`).
- **A later instance the system refuses is retried, not fatal.** The acceptor
  logs one warning per failing streak, sleeps `INSTANCE_RETRY` (one second) and
  asks again until a stop is requested. Both agents do this.

## The residual, accepted

Another interactive user on the machine can add a server instance while the
agent runs, or own the name while the service is stopped. The app's next
connection may then reach them.

What that gives them: they see the commands the app sends, and they can send
the app agent messages. The risk is **spoofed data reaching the dissector**, not
privilege: the app is not elevated, the agent is not involved, and a remote user
is still refused (`PIPE_REJECT_REMOTE_CLIENTS`, and no `WD`, `AN` or `NU`).

## Not done, and why

**Verifying the server from the app.** The check is `GetNamedPipeServerProcessId`
on the app's own connected handle, compared with the service's process. Node's
`net` exposes no handle to ask, so this means a native FFI dependency and a
transport of our own in place of `net.connect`. That is its own decision, and a
shipped dependency has to justify itself against the platform API first; it is
not made here.

## Consequences

- A user who creates the name before the service starts makes the service stop
  at start with a log line, instead of being served from their pipe. The app
  reads that as an agent that is not answering; the log line says why.
- Taking an instance slot costs the agent that slot for as long as it is held,
  not its life.
- The check in `docs/verification.md` (section 5, "The security descriptor took
  effect") records the residual as expected behaviour, so a second-account run
  that finds it is not read as a regression.
