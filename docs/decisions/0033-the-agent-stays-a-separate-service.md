# 0033 — The agent stays a separate service, and Npcap should be admin-only

**Status:** accepted. **Restates the reason for a decision that was never
re-examined**, and adds the half of it the app can act on. Does not supersede
anything: `0029` still owns the transport, `0032` still owns the update path,
and `0010` still owns what the agent does and does not do with a frame.

## Context

The agent was built for a web page. A tab cannot open a capture handle, so
capture had to happen somewhere else and stream in — and that "somewhere else"
became a privileged local service because raw capture needs elevation.

Phase 5 of the Electron migration deleted the page. Main is a Node process; it
can load a native module; a `utilityProcess` could hold a capture handle the
same way `electron/store/` holds the capture files. So the original reason is
gone, and `CLAUDE.md` was still carrying it verbatim: *"Runs as LocalSystem
because raw capture needs elevation on every OS."* Read by somebody looking for
weight to cut, that sentence describes a 34 MB Python tree, a service
registration, an SCM integration and a named pipe, all justified by a
constraint that no longer applies.

It is the wrong conclusion, and the reasons are worth more than the sentence.

### What Npcap actually does on install

Npcap's installer has a checkbox: **"Restrict Npcap driver's access to
Administrators only."** It is **not ticked by default**.

Unticked, the driver's device object is left open to every local user.
Measured on this machine, `\\.\NPCAP` carries:

```
D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;WD)
```

`WD` is Everyone. Any local account — a standard user, a service account, a
process with no elevation of any kind — can open the capture devices, read
every frame this machine sends or receives, and **write raw frames onto the
wire**. On a machine with more than one account, or with any service running as
a low-privileged identity, that is a local privilege problem that does not
announce itself: nothing on screen says the driver is open, and everything
works exactly as well either way.

Ticked, the DACL keeps `SY` and `BA` and drops the rest, and only an elevated
process can capture.

### What Wireshark does, and the trade it cannot avoid

On Unix, Wireshark solved this by **privilege separation**: `dumpcap` is a
small program that holds the capability and does nothing but capture, and the
GUI and the dissection engine run as an ordinary user. The dissection engine is
the part that parses attacker-controlled bytes, and it is deliberately the part
with no privileges.

On Windows it cannot do the same thing, because there is no way to hand a
capture handle to a program that runs on demand as the user without either
elevating that program every time or leaving the driver open. So Wireshark's
installer offers the checkbox and states the consequence: tick it, and **you
must run Wireshark as Administrator to capture**. The two options are
open-driver-with-unprivileged-GUI, or restricted-driver-with-elevated-GUI. A
lot of Windows installs end up on the first one, because the second means the
whole dissection engine runs at Administrator.

Inwire already has the thing that makes the trade unnecessary. There is a
LocalSystem process, it already holds the handle, and it already dissects
nothing (`0010`).

## Decision

**The agent stays a separate LocalSystem service, and Inwire recommends that
Npcap be installed admin-only.**

Three reasons, in the order they carry weight:

1. **It makes admin-only free.** With the agent holding the handle, the app
   never opens a capture device, so restricting the device to Administrators
   costs the user nothing — not an elevation prompt, not a lost feature, not a
   changed workflow. Without the agent, the same restriction would mean either
   no capture at all or an Electron renderer full of hostile bytes running as
   Administrator.
2. **Capture can outlive the window.** Boot-time start, a ring buffer that was
   already filling before anyone opened the UI, unattended monitoring across a
   logout — none of which a capture handle owned by a GUI process can offer,
   because the handle dies when the window does. The service model is the
   precondition for all of it, and it is already built.
3. **The handle and the driver's user-mode library stay out of the app.**
   `wpcap.dll` and `Packet.dll` are a kernel driver's user-mode surface, loaded
   into whatever process captures. Keeping them in a process that parses
   nothing keeps them away from the dissector, and keeps Inwire off Electron's
   native-module ABI — which is rebuilt for every Electron major, and which
   `CLAUDE.md`'s dependency rule already says nothing lands on without a
   measurement.

**The app never elevates, and never opens a capture handle.** That is `0030`'s
invariant, and this decision is what keeps it affordable.

## Consequences

- **The Update Center has to detect the mode and say so.** A recommendation
  nobody can act on is a lecture, and a recommendation shown to somebody who
  already ticked the box is noise. The Npcap row reads the mode and states it —
  administrators only, all users, or **unknown**, which is a third answer and
  is not rounded to either.
- **The mode is two facts, not one.** Npcap records the choice in the registry
  (`AdminOnly` under `HKLM\SOFTWARE\Npcap`, 32-bit view); the kernel enforces
  the DACL on the device object. They can disagree — the value is edited, the
  driver is not restarted — and when they do **the DACL wins**, because it is
  what actually admits a process. The registry answers only when no DACL was
  readable. Saying "administrators only" over a device open to `WD` would be
  exactly the confident-wrong-answer failure this codebase keeps writing down.
- **The DACL is read by the agent**, which runs as SYSTEM and is the part of
  the system that can be relied on to read it. It reports the **SDDL string**,
  not a verdict: the agent states facts and the app decides, the same rule
  `0010` sets for frames. The decision is then a pure function in TypeScript
  over a registry shape and a DACL string, asserted in
  `scripts/electron/update-center.ts` — which is also what makes "unreadable"
  and "absent" testable answers rather than accidents.
- **Reinstalling is the only way to change the mode**, and it is Npcap's wizard
  that changes it. Inwire runs the same download → verify → elevate path as any
  other install, and says, before the prompt, which checkbox to tick and why.
  **No flags are passed**, here as everywhere: `/S` is the OEM silent-install
  feature and the free licence does not grant it (`0032`).
- **Continuous capture stays possible.** Nothing in this decision builds it,
  but nothing in the topology forecloses it either, and a future session
  weighing it will find the process it needs already running.
- **No native capture addon in the app.** Not in main, not in a
  `utilityProcess`, not behind a flag. `CLAUDE.md`'s banner carries this.
- The Windows-only half of this has no macOS/Linux equivalent yet: those
  platforms still use the tarball agent over a WebSocket, and their own
  permission models (`BPF` device ownership, `CAP_NET_RAW`) are a separate
  question this does not answer.

## What would reopen it

**Not weight.** That is the argument this decision exists to refuse in advance.
The Rust rewrite in `CLAUDE.md`'s Direction removes the weight argument
entirely — one signed exe, no interpreter, sub-second service start — and it
keeps the service model, because the service model is not what the weight was.

What *would* reopen it is a change in what Npcap is, or in how it is reached:

- Npcap gains a way to grant capture to a named unprivileged identity, so a
  process can hold a restricted handle without being Administrator.
- The licence changes such that the driver can be reached some other way, or a
  replacement driver exists with a different access model.
- Windows gains a supported way to pass a capture handle to an unprivileged
  process at launch — the `dumpcap` arrangement, which is what this decision is
  imitating with a service because a service is the only way to get it here.

None of those is about how many megabytes the agent is.
