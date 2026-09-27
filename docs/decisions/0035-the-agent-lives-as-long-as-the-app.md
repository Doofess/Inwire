# 0035 — The agent lives as long as the app, and shares its version

> **§3's ordering is amended by [0051](0051-the-version-is-0x-in-development.md).**
> The version is still the product's, but the app compares the agent's number to
> its own for equality, so it no longer only climbs - and it is 0.x while Inwire
> is in development. Why the product jumped to 4.0.0 below is the record of a
> constraint that is gone.

**Status:** accepted. **Retires reason #2 of `0033`** ("a capture can outlive
the window"); reasons #1 and #3 carry that decision unchanged. **Re-justifies
rather than reverses `0030`'s "`WP` is withheld" paragraph.** Does not touch
`0029` — the pipe and its descriptor are unchanged.

## Context

The `InwireAgent` service was installed `--startup auto`, so it ran from boot on
every machine that had ever installed Inwire, whether or not anyone opened it.
Closing the app stopped the *capture* — `watch_for_orphaned_capture` sheds the
sniffer when the last client leaves — and left a LocalSystem service running
with a capture driver loaded, for an application nobody had launched.

The app could not stop it: `installer/setup.iss` withholds `WP` (SERVICE_STOP)
on purpose. It could not start it quietly either, though it was meant to — the
installer already granted `RP` (SERVICE_START) on the `IU` ACE, and
`agentPipe.ts` never tried an unelevated `sc start`, so it raised a UAC prompt
every time and the grant bought nothing. Both ends recorded that as a known
loose end and neither had been closed.

Beside it, the agent carried **its own version number**, in six places, held by
two scripts covering different subsets of them.

Those look like two subjects. They are one: both are what is left of the agent
having once been a separate product, installed by its own installer, serving a
web page of any age.

## Decision

### 1. The service is demand-start, and stops itself

`installer/setup.iss` registers it `--startup manual`. Main asks the SCM for it
at `whenReady()`, before the window is created. The agent stops **itself** when
it has had no clients for two consecutive watchdog ticks.

**The agent stops itself rather than the app stopping it**, and that is the
load-bearing half:

- The app deliberately has no right to stop this service, and granting `WP`
  would grant it to `IU` — *any* interactive logon. A second Windows user could
  then stop a capture the first one is running. `0030`'s paragraph stands, with
  a better reason than it had.
- A self-stop survives the app crashing or being killed from Task Manager. An
  `sc stop` on the quit path does not, which is the case the guarantee most
  needs to hold in.
- The agent is the only party that knows whether some *other* client is still
  connected. Fast User Switching is real; capture ownership, client ids and
  `capture_busy` are all kept.

**Two ticks, not one.** `AgentPipeLink.recycle()` closes and reopens the pipe to
make the agent re-enumerate adapters after a driver install. That gap is
milliseconds, but a single-tick rule would let a tick land inside it and stop
the service the app is mid-way through reconnecting to.

**A startup grace period before the first client.** Between `sc start` and the
app's first connection the agent has no clients and has never had one; stopping
there is a service that kills itself before the thing that started it arrives —
which also reads to `pipeTransport.ts`'s short-connection counter as a crash
loop. It is a bound rather than "wait for ever", so an app that dies between
starting the service and connecting still gets cleaned up.

**`may_exit` is false on macOS and Linux.** They install from the tarball and
have no SCM to start the agent again on demand, so an agent that exited on
idleness would never come back. The orphan check itself still runs there — that
guarantee is unconditional.

### 2. Escalation is reached by one exit code and never by a timer

`sc.exe start` is tried **unelevated first**. Only `ERROR_ACCESS_DENIED` (5)
reaches `-Verb RunAs`, and only from an explicit click. `electron/serviceStart.ts`
classifies on numeric exit codes and never on `sc`'s localised text — the same
doctrine `agentService.ts` applies to `reg` over `sc query`, and
`updateCenter/elevate.ts` to a declined UAC prompt.

A UAC prompt nobody asked for, raised by an app the person has just launched, is
indistinguishable from malware to the one audience that should be most
suspicious of it. And on a disabled or uninstalled service it would ask them to
authorise something that cannot work, which they have no way to know before
answering. The automatic attempts are bounded, because the retry that drives
them runs for as long as the window is open.

### 3. The agent's version is Inwire's version

`package.json` is the only place a version is authored.
`local-agent/agent_version.py` is generated from it by `npm run sync:version`
and committed; `agent.py` imports it; `REQUIRED_AGENT_VERSION` and
`MyAppVersion` are literals that `scripts/agent/version.ts` holds to it on every
`npm run check`. `MyAgentVersion` is **deleted** from the shipping installer —
it was defined there and used nowhere.

**The product moved to 4.0.0 rather than the agent moving to 1.0.0.** The number
is the left-hand side of `isAgentOutdated`, so it is an ordering: an agent left
behind by an earlier install must read as *older*. One that reads as newer than
required shows in the UI as "not connected", a state with no instruction
attached to it — on exactly the machines most likely to hit it. Collapsing two
numbers means the survivor must be at least the highest either half ever
shipped, and the agent had shipped 3.9.0 while the app was on 1.0.0.

`local-agent/installer/setup.iss` keeps its stamps **frozen**. Nothing builds
it; it records what an agent-only install actually put on a machine, which is
what the unified installer reads in order to remove it.

## Consequences

**`0033` reason #2 is retired.** "A capture can outlive the window" — boot-time
start, unattended monitoring — is no longer true and is no longer claimed.
Reasons #1 (Npcap can be installed admin-only, because the app never needs a
capture handle) and #3 (the capture handle stays out of the process that parses
hostile bytes) are untouched and are what keep the agent a separate service.

**A cold start is paid per launch**, and `npm run dev` pays it per reload. The
existing 2-second watchdog tick is the only delay on the way down; on the way up
it is the SCM plus the agent's own start. `pipeTransport.ts` retries at
150/300/600/1200 ms before settling to the old flat 3 s, so a warm start is
usually inside the first attempt or two.

**A fixed 2,000 ms `connectedDelay` is deleted**, and with it a latched
`isFirstAttempt`. Together they meant a successful *retry* read "Agent not
running" for two seconds after `hello` had already been processed — the app knew
and was waiting out a timer to say so. `connected` is now gated on `hello`,
which is the message that proves the link works rather than that a pipe
answered; the hello timeout gets a status of its own, so an agent that accepts
and never replies stops reading as "Connecting…" for ever.

**`scripts/electron/smoke.ts` runs on a development machine for the first
time.** It used to SKIP whenever the real service held
`\\.\pipe\inwire-agent`, which on a development machine is always — so the one
script that drives a real Electron process end to end was silently not running.
`INWIRE_AGENT_PIPE` gives each run a private pipe name.

**`SvcStop` no longer stops the event loop out from under `main()`.** It asks
through the agent's own shutdown event, so `main()` returns and its
`finally: pipes.stop()` actually runs. Before this the pipe name was released by
the process dying rather than by anything that had decided to release it — a
latent bug that only became urgent once the service performs a shutdown every
time the app closes instead of once a reboot.

**`sniffer` is a declared module global.** It was undeclared and only assigned
in `main()`, so all three `sniffer is not None` guards raised `NameError`
instead of returning false for the whole window between process start and that
assignment. A guard that raises is the failure it was written to prevent, with a
worse message.

## What was considered and refused

**A linger timer.** Keeping the agent up for 30 seconds after the last client
would make `npm run dev` cheaper and would mean an app restart usually found the
service already running. It was refused as a literal reading of the requirement:
"stops entirely when the app is closed" should not have an asterisk, and a user
checking Task Manager should find nothing. An env-gated development grace
remains available if the reload cost bites.

**Granting `WP` and stopping the service from the app.** The brief asked for
`0030`'s paragraph to be reversed. It is re-justified instead: agent self-stop
needs no right at all, and `IU` is any interactive logon, so granting stop would
let a second user stop a capture the first is running. One line changes it —
`setup.iss`'s SDDL and the readback literal beside it, in `sddl.h` canonical
order, or the readback misreports.

**Automatic escalation after a failed unelevated start.** Refused; see decision 2.
