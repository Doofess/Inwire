# 0058 — Monitoring receives NetFlow v5 in its own utilityProcess, only while the app is open and only after Start

**Status:** accepted 2026-10-17. Measured in
[`docs/monitoring-v5-measurements.md`](../monitoring-v5-measurements.md);
nothing built yet.

## Context

The first monitoring milestone is a collector for NetFlow v5 export from one
router or firewall. It is not a capture. A collector binds a UDP port and
reads what an exporter sends it. A capture reads what crosses an adapter.
The measurement found that the two give different answers. With no listener,
the agent's capture saw every one of 2,000 datagrams, while Windows answered
only 300 of them with ICMP port unreachable. The exporter received no sign
either way that nothing was listening. Whatever the capture shows, a
collector has to be a socket.

Binding a socket is not opening a capture handle, so
[0033](0033-the-agent-stays-a-separate-service.md)'s rule is
not at stake. Nothing here touches Npcap, the agent or the pipe. What is at
stake is a new inbound port on a desktop machine. Windows Defender Firewall
asks about it, and an answer of Cancel cannot be undone without an
administrator.

## Decision

### A utilityProcess owns the socket and the journal

The speed test's pattern ([0054](0054-an-internet-speed-test-against-cloudflare.md),
`electron/speedTest/host.ts`): main forks a `utilityProcess` with
`serviceName: 'monitoring'`. That process binds the socket, assigns entry ids
and appends to the journal of
[0059](0059-monitoring-evidence-journal-and-rollups.md). It is unprivileged,
because a UDP bind on Windows needs no privilege at any port. Port 514 bound
as an ordinary user.

**The utility never decodes NetFlow.** Datagrams are hostile bytes from the
network. A sandboxed Worker in the renderer decodes them and builds the
rollups, as the pipeline Worker does for frames, and the utility stores what
it is given without reading it. A decoder fault therefore cannot corrupt the
evidence, and the process holding the filesystem never parses an exporter's
bytes. Main brokers a `MessageChannelMain` and sees no datagram.

### One source, one specific bind

The configuration is the exporter's IPv4 address, a **specific local IPv4
address** and one UDP port. Nothing else is configured.

- **`0.0.0.0` is refused.** A wildcard listens on every adapter, including
  ones the user never meant to expose, and Windows' rules would then follow
  the profile of whichever network the machine joins next. One address is
  one adapter.
- **The port is free text, defaulting to 2055.** It is the common default,
  but Cisco documents 9995 (see the survey).
- **The exporter address is an intake filter, not authentication.** A
  datagram from any other address is counted against its sender and never
  journalled. The count covers at most 16 addresses, with the rest in one
  overflow count, so a router sending from an unexpected interface is
  visible. UDP source addresses can be forged, so a passing datagram is
  *from the configured address*, not *from the router*.
- **A busy port is an error the sheet shows**, `EADDRINUSE`, in its own
  words. A local address the machine does not have is `EADDRNOTAVAIL`.
  Nothing is retried on another port.
- **The receive buffer is set to 8 MiB.** The default 64 KiB lost 100 of
  1,000 datagrams in a burst and 4,955 of 5,000 across a 2-second stall. At
  8 MiB both delivered everything. An exporter's cache expiry is exactly such
  a burst.

### Lifetime: open, explicitly started, and never past quit

- **Collection runs only while Inwire is open.** There is no service, no
  start at login and no tray.
- **Start is an explicit action every launch.** Opening history never binds
  a socket, and the app does not remember "was running". The bind belongs to
  the Start the user pressed, which is also why its firewall prompt comes
  where the user can see what caused it.
- **What keeps it running:** minimising, leaving the monitoring sheet, a
  renderer reload, a Worker crash. The utility keeps appending, and the new
  Worker catches up from its cursor.
- **What ends it:** Stop, quit and system suspend. Each writes a boundary, and
  the interval up to the next Start is a collection gap.
  - **Suspend** comes from `powerMonitor` in main and writes a `suspend`
    boundary. Resume shows the gap and does not restart by itself.
  - **Quit** drains at most once: stop intake, finish admitted writes, write
    the final boundary, flush, then let quit continue. A drain that takes
    more than 5 s is recorded as unclean, the utility is killed, and the
    journal is left for recovery. **`guardClose` is untouched.** An unsaved
    capture's cancelled close never reaches quit, so it cannot touch
    monitoring.
  - **A utility that exits** fails every pending query, reports through the
    runtime-exit channel, and needs Start again.

### The firewall: explain it, observe it, never change it

The app changes no firewall policy, writes no rule, runs no `netsh` and asks
for no elevation. What it does is explain the prompt beforehand and name the
cause afterwards. Observed on this machine with the dev `electron.exe`
(three runs, owner answering):

- **Binding creates the rules.** At the first bind, the firewall service adds
  inbound **Block** rules for the executable, one TCP and one UDP, on the
  Public profile only. The bind succeeds and reports `listening`.
- **The prompt** is a Windows Security dialog: *"Do you want to allow public
  and private networks to access this app?"*, naming the program and its
  publisher, with **Allow** and **Cancel** and no profile checkbox. **This
  corrects the spec**, which tells the user to choose *Private networks*.
  That choice is not offered.
- **While the prompt is open**, arriving datagrams are dropped silently. They
  are not queued and no ICMP is sent. The first seconds after Start may be
  lost.
- **Allow** turns the rules to Allow with no UAC prompt, and delivery starts
  at once.
- **Cancel** leaves Block rules in place, and Windows does not ask again. The
  socket stays `listening` with nothing arriving, which is the state the hint
  below exists for. Undoing it needs an administrator in *Windows Defender
  Firewall with Advanced Security*.

The packaged, fused `Inwire.exe`'s prompt, meaning what it names and which
publisher it shows, is **not run**. It is owed to the end-to-end task against
the installed build.

### Limits and timing

| Limit | Value |
|---|---|
| inbox, utility side | 1,024 datagrams or 8 MiB, whichever comes first; past it a datagram is shed, counted and recorded in a `gap` boundary |
| live credit to the Worker | 4 batches, each at most 64 datagrams or 256 KiB; a maximum-size datagram may go alone |
| history pages | at most 256 entries or 1 MiB |
| port handshake / request timeout | 15 s / 15 s |
| stop and quit drain | 5 s |
| source stale | 60 s without a valid v5 datagram; stale means *no recent export*, not *device offline* |
| durability flush | 1 s, plus every Stop |

Shedding in the inbox is counted separately from loss the kernel never
reports. The first is a number, and the second stays unknown. Status and
control replies never queue behind bulk data. At 7 a second the journal
append took 6.94 µs, so the inbox has more than four orders of magnitude of
headroom against the planning rate.

### What the exporters say

From the survey in the measurement report:

- **v5 is what the small end exports.** Sophos SFOS exports only v5,
  correcting the spec's working assumption that it sends v9. MikroTik,
  OPNsense and pfSense offer v5, and softflowd defaults to it.
- **The enterprise end is v9 or IPFIX.** Palo Alto and Meraki export only v9,
  and Cisco Flexible NetFlow defaults to it. The spec's v9/IPFIX gate stands.
- **30-minute active and 15-second inactive timeouts are the common
  default.** A long flow arrives as a record every half hour, which
  [0059](0059-monitoring-evidence-journal-and-rollups.md)'s receipt-time
  history shows as spikes.

## Later, not built

Collection while the app is closed, several sources, IPv6, v9 and IPFIX, a
bind chooser that lists adapters, and any change to firewall rules made on
the user's behalf.

## Consequences

- The monitoring utility is the third `utilityProcess` main forks and supervises,
  beside the store and the speed test, and it is distinguished from them by
  its `serviceName`.
- `electron/main.ts` gains a `will-quit` drain and a `powerMonitor` suspend
  handler. Both are pure decisions in a module that does not import
  Electron, so they run under `tsx`.
- A first Start may lose the seconds the prompt is open, and a Cancel loses
  everything until an administrator removes a rule. The sheet says so in
  advance rather than diagnosing it afterwards.
