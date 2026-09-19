# 0037 — The capture agent is Rust on Windows

**Status:** accepted; **the port is complete, measured — including as a
registered Windows service — and is not yet what ships.** Does
not supersede `0033` — the agent stays a separate LocalSystem service, and this
changes what it is written in and nothing about where it runs. Does not touch
`0029` (the pipe), `0010` (it dissects nothing) or `0005`'s surviving half (the
wire format). Builds on `0035`: demand start is what made start time matter.

## Context

`CLAUDE.md` §10 has carried "a Rust agent, as the first post-migration project"
for some time, with throughput as the implied argument. **That argument is dead,
and it was measured rather than reasoned away.** The Python sniffer thread costs
**2.87 µs of work per frame** on a real adapter here — a copy and a callback —
at a utilisation of 0.003. Python was never the constraint on the capture path.
The frames that were being lost were lost to a sleep in the pump, and that is
fixed in the Python agent.

So the port had to justify itself on something else. Three things, in the order
they matter:

**One signed executable.** The PyInstaller build is a 34 MB `--onedir` tree of
`.pyd` and `.dll` files. Signing a wrapper does not sign what the wrapper loads,
so the thing an administrator would be trusting is a directory of unsigned
native modules beside a signed exe. The Rust build is **449 KB, one file**. That
is the whole surface, and it is the surface a certificate would actually cover.

**Start time, which became load-bearing.** Before `0035` the service started at
boot and nobody was waiting. Demand start puts the agent's cold start on the
critical path of opening Inwire: the app asks the SCM at `whenReady()` and the
status bar says "not running" until the pipe answers. Measured here, **213 ms
just to `import agent`** — before PyInstaller's own bootstrap, before the
interpreter starts, and on a warm filesystem cache.

**Two defects that become unrepresentable rather than fixed.** The Python agent
crosses live libpcap handles to its event loop with a use-after-free window at
every stop; in Rust a `Capture` is `Send` but not `Sync` and the handle cannot
leave the thread that reads it. And it carried an undeclared module global whose
three `is not None` guards raised `NameError` instead of returning false — which
`0035` fixed by declaring it, and which a compiler would not have allowed to
exist.

## Decision

### 1. Windows only, and the Python agent stays

macOS and Linux keep the tarball and its WebSocket. They have no desktop app to
talk to yet, so porting for them would double the surface for no consumer, and
the pairing token those platforms keep is a genuinely different design — a
socket file has no interactive-user SID to name.

### 2. The port is byte-compatible first, and the format opens second

`scripts/agent/wire-vectors.json` holds the bytes, and Python, TypeScript and
Rust are each checked against **that file** rather than against their own copy.
Porting at byte-compatibility makes the existing hand-written vectors an
acceptance gate, so a format change later moves one fixture and three
implementations together with the port already proven underneath it.

**The 18→12-byte record is declined.** It is 0.53% of a real stream at the
measured mean, and it costs the property that a record can be dropped,
reordered and re-batched freely — which the disk-first work needs more of, not
less.

### 3. One dependency for JSON, and one for the SCM

`serde_json`, `default-features = false`, **no derive**. What it buys over
hand-rolling is a parser for input arriving over a pipe into a privileged
service, which is the one place in this process that reads anything from
outside.

`windows-service` for the SCM, and this one argues against the grain: `npcap.rs`
and `pipe.rs` both declare their Win32 surface by hand and take no dependency
for it. The difference is what a mistake costs. A mistake in the Npcap FFI is a
capture that fails loudly on the next frame. A mistake in service status
reporting is a service the SCM believes is `START_PENDING` for ever, or one that
reports `STOPPED` while its threads still hold the pipe name — failures **in the
SCM's bookkeeping**, where nothing in this process can observe them. CLAUDE.md's
dependency rule asks what a dependency buys over the platform API; here it buys
the one part of that API where a silent wrong answer is the default failure
mode.

### 4. Threads, not an async runtime

The whole agent is four long-lived loops: an acceptor per pipe instance, a
reader and a writer per connection, a sniffer and a pump per capture. The only
reason the Python one needed an event loop was that it had a WebSocket library
attached to it. Adding tokio would be a large dependency to express what
`thread::spawn` already expresses.

## What is proven, and what is not

**Proven.** 35 tests. The wire format against the shared golden vectors, in all
three implementations. The pipe against **the app's own client** —
`scripts/agent/pipe-interop.ts` connects with the same `net.connect` and the same
`agentFraming.ts` the renderer uses, which is where the overlapped-I/O trap lives.
The whole capture path against that client, decoded by the renderer's own
`agentBinary.ts`, with conservation asserted: delivered + shed + queued =
received, **residual 0 over 632,924 frames**.

**Also proven, by running it.** The runtime serves a real pipe and the app's own
client drove it to **131,781 frames / 2.88 GB, residual 0, no missing sequence
numbers**. The idle self-stop fires **2,200 ms** after the last client leaves —
inside the documented two ticks. Cold start to a served pipe is **56 ms**,
against Python's 213 ms for its imports alone, which is the number this decision
rests on.

**Running it found three defects that reading it had not.** The runtime ignored
`set_interfaces` and captured on whatever adapter came first — on this machine a
dead `WAN Miniport`, so it reported `sniffing` perfectly truthfully and
delivered nothing. The final `capture_stats` passed `None` for `droppedPipe`, so
the last message the app ever sees had a hole in exactly the figures somebody
checks when the numbers do not add up. And `--startup manual install` parsed
**`manual`** as the verb and exited 1 without registering anything — which is
the pywin32 `getopt` trap this crate's own header describes, arriving from the
opposite direction on the identical command line.

**And proven as a service, which is what this section used to say was missing.**
The Python agent's registration was removed, this binary was registered in its
place, driven, and the machine put back. `docs/verification.md` holds the table;
the four results that carry the decision:

`--startup manual install` — the installer's own line, the one that shipped
broken — **registers** rather than printing usage: `DEMAND_START`, LocalSystem,
the post-migration description. An **unelevated** `sc start` reaches `RUNNING`
in **16 ms at checkpoint 0**, which is `service.rs` reporting `Running` rather
than merely reaching it; a handler that never reports shows up as a start that
times out while the service works perfectly. The app's own client then drove
**184,614 frames / 4,039 MB over the production pipe with residual 0**. And the
idle self-stop reports `STOPPED` **2,436 ms** later **with exit code 0** —
load-bearing, because the installer sets `restart/5000` three times, so a
non-zero exit there would make a *demand-start* service restart itself every
five seconds for ever. Watched for sixteen.

**Two of the three "unrepresentable defects" arguments now have a third
companion, measured rather than reasoned:** 9.0 MB resident against the Python
agent's 66.2 MB, same role, same machine, read minutes apart.

**And the real Inwire window connects to it**, which was the other half of this
paragraph until `agent-rs/switch-agent.ps1` made swapping the two agents a
transaction rather than a checklist: with the Rust agent registered,
`scripts/electron/agent-live-drive.ts` reaches "Agent connected" in **807 ms**
and passes every SCM assertion unelevated.

**What is still by hand, and one of the two cannot be automated at all.** A
capture driven **through the UI** needs a real adapter, because
`filterCapturableInterfaces` removes loopback from the picker — so the one
adapter a harness could safely capture is the one the app is designed never to
offer, and a script capturing a person's real traffic is not a trade this
repository makes. The two halves that *are* covered meet in the middle: interop
drives a real capture handle over the production pipe, `smoke.ts` drives the
real UI and the whole frame path against the stub. The other is the
**two-client** `capture_busy` case, which needs two logons.

**Not ported.** `npcap_access.py` — the DACL on the Npcap device object, which
`hello` carries as `npcapAccess`. The Rust agent sends `None`, which falls back
to the registry answer. That is the weaker answer but never the wrongly
permissive one, which is the direction `npcapAccess.ts` says must not go wrong.
Also not ported: the socket table, the adapter configuration report, and the log
subscription — all answered with a `state` message rather than ignored, because
silence is the shape the app cannot diagnose.

## Consequences

**Nothing ships yet, and that is `0030`/`0032`'s constraint rather than this
one.** Phase 6 waits on a code-signing certificate outside this repository, and
replacing the installed binary needs elevation. Until then the **Python agent is
what is installed**, and it has every fix this work produced: the pump, the
shed accounting, the per-core kernel buffer, the orderly shutdown and the idle
self-stop.

**Two agents have to stay in step, and the tests are what keep them there.** The
shared golden vectors cover the wire format; `test_protocol.py` and
`agent-rs/src/session.rs` hold the same kernel-buffer shape; the interop scripts
drive the Rust one with the app's own client. What is *not* covered is behaviour
neither has a fixture for, and a fix applied to one and not the other is the
failure mode to watch for.

**The `--onedir` build and its whole hidden-imports list can eventually go**, and
with it `local-agent/CLAUDE.md`'s longest section. Not yet: it is what ships.
