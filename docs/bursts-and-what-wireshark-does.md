# Bursts, and what Wireshark does about them

*Written 2026-09-19, against `wireshark/wireshark` master as of that date.*

The question this answers: **a capture sometimes takes hundreds of thousands of
frames in a few seconds — probably a cloud service updating itself — and is
Inwire handling that the way a mature analyzer does?**

Mostly yes, and better in two places. One finding changed the code, and it is
the one that best explains the symptom.

Everything below is verified against Wireshark's source, man pages and wiki, with
line numbers from that snapshot. Where a claim comes from a forum post or an
issue thread rather than documentation, it says so.

---

## The finding that changed our code

**Npcap splits the adapter's kernel buffer into one segment per processor.**

From Npcap's maintainer in [nmap/npcap#30](https://github.com/nmap/npcap/issues/30),
mirrored in [npcap.com's API guide](https://npcap.com/guide/npcap-api.html):

> The buffer is split into a number of independent segments according to the
> number of processors on the system. When a packet is received by the driver,
> it is put into the buffer segment corresponding to the driver thread's current
> processor. If there is not enough room in that segment, the packet is dropped.

A burst does not spread itself across cores to suit us. So the agent's flat
32 MB `pcap_setbuff` was **32/N MB of usable slack** — 1 MB per core on this
32-core machine, which is *Npcap's own default* and a sixteenth of what asking
for 32 MB was meant to buy. That is exactly the shape that makes a burst appear
as driver drops on a machine with plenty of free memory.

`kernel_buffer_bytes()` now sizes from the core count: 4 MB per core, floored at
the old 32 MB so nothing shrinks, capped at 256 MB because this is **non-paged
kernel memory** and a 64-core machine must not be asked for a gigabyte of it
because somebody pressed Start. On this machine that is 128 MB rather than
32 MB — four times the per-core slack. In both agents, with the same constants
and the same assertions.

*Caveat, stated because it matters:* the per-processor split is documented by the
maintainer in an issue thread rather than in a specification, and we have not
measured the segmentation directly. The change is safe regardless — it asks for
more buffer, which is never worse — but the *reason* rests on that source.

---

## How the two are shaped

They are the same architecture, arrived at independently.

| | Wireshark | Inwire |
|---|---|---|
| Capture runs in | `dumpcap`, a separate process | the agent, a separate service |
| Why separate | privilege separation — the GUI runs unprivileged | the same, plus Npcap admin-only (ADR 0033) |
| Does the capturer dissect? | **No.** `grep -c epan dumpcap.c` → 0 | No (ADR 0010) |
| Frames reach the UI by | dumpcap writes a pcapng file; the GUI tails it | the agent batches over a pipe; the app writes the file |
| The IPC between them carries | counts and status, never frames (`sync_pipe.h`) | frames, in ~256 kB batches |
| UI update cadence | 100 ms (`--update-interval`) | 100 ms flush |

The one real divergence: **Wireshark's frames go through the filesystem and ours
go through a pipe.** Theirs has no producer/consumer coupling on frames at all —
a slow GUI falls behind reading its own file and dumpcap never notices. Ours has
a bounded queue that sheds, which is a coupling we have to account for and they
do not. That is what `droppedPipe` counts, and it is the stage they have no
equivalent of.

---

## Where we are ahead

**Drop accounting.** dumpcap tracks four counters — `pcap_drops` (kernel),
`drops` (its own queue), `flushed` (discarded during stop), and `ps_ifdrop`
(interface) — and prints all four with a percentage when run from a terminal.
**The GUI gets one scalar.** `report_packet_drops` sums three of them into
`SP_DROPS` and leaves `ps_ifdrop` out entirely; `ui/capture.c` explains why in
its own comment: *"on some systems, libpcap doesn't bother filling in
'ps_ifdrop' — it doesn't even set it to zero — so we don't bother looking at
it."*

So in Wireshark's status bar you cannot tell a kernel drop from a tool drop.
Inwire reports four stages separately, per second, and the Capture Health tab
shows each one named.

**`null` is not zero.** Wireshark carries a `drops_known` flag and omits the
whole field when `pcap_stats()` fails — which is right, and is the same rule as
our `droppedKernel: null`. We keep it one level further: `droppedPipe` from an
agent too old to report it reads "Not reported" rather than 0.

**Timing.** `report_packet_drops` has exactly **one call site**, in dumpcap's
capture-stop path; the interim `pcap_stats()` poll is present but wrapped in
`#if 0`. So — *inference from that structure, not documented* — the GUI's
`Dropped:` figure appears only when the capture ends. Ours arrives every second
while it runs, which is when somebody looking at a burst wants it.

**Queue bounds.** dumpcap's threaded mode bounds its queue at **1,000,000 bytes
and 1,000 packets**, with the source's own `/* XXX: Are these defaults good
enough? */` beside them. Ours is 30,000 packets and 32 MB, sized so the two
bounds are reached by different traffic rather than one making the other
unreachable.

**Batching.** On Windows dumpcap always calls `pcap_dispatch` with a count of
**1** — *"so that we can check the pipe after every packet"* (dumpcap.c:3824).
Wireshark's own HighSpeedCapturing wiki page notes tcpdump outperforming dumpcap
and guesses this is why. We read with `pcap_next_ex` on a sniffer thread and
batch in the pump, which is the arrangement that page wishes for.

---

## Where they are ahead, or where we simply differ

**Snaplen.** dumpcap's default is **262,144 bytes** — effectively no truncation;
the 68-byte folklore is long gone. Ours is 65,535, and it is a *format*
constraint rather than a choice: the wire record's `capLen` is a `u16`, so
65,535 is the largest frame the batch format can describe. `packet_batch.py`
refuses a longer one rather than masking it, which is right — a masked length
desynchronises the decoder and costs a whole batch — but it means a jumbo frame
or an LSO-coalesced segment above 64 KB is refused rather than truncated.
**Not currently a defect on any tested machine, and worth knowing before someone
captures on a 9 KB-MTU link with offload on.**

Wireshark's guidance treats snaplen as the main high-rate lever (the Performance
wiki's formula is `MTU + 18`). **We offer one now, and a capture filter beside
it** ([ADR 0050](decisions/0050-a-capture-is-narrowed-by-the-driver.md)): both are
applied by the driver, so a refused frame never reaches the kernel ring and a cut
one takes a snaplen's worth of it. What stood in the way was never the agent. It
was that a truncated frame was a dissection that failed - on the fixtures cut at
64 bytes, TCP reported lost segments on a capture that lost none - and that is
what 0050 fixed first, held to tshark by `scripts/parity/snaplen.ts`.

**Ring buffers.** `-b filesize:` / `-b files:` bound disk use over an unbounded
capture window. We have no rotation; the capture store grows and
`DISK_RESERVE_BYTES` stops the capture before the disk fills. Different answer
to the same problem, and ours keeps the whole capture rather than the last N
files — which is the right trade for an analyzer you scroll back through, and
the wrong one for unattended monitoring, which ADR 0035 has now retired anyway.

**Turning the UI off.** Wireshark's first piece of high-rate advice is *don't
capture with the GUI*, and its second is *turn off "Update list of packets in
real time"* — with that off, `cf_fake_continue_tail()` accumulates a count and
nothing is read or dissected until the capture stops. We have no equivalent, and
dissection is on the arrival path. That is what the disk-first work in the plan
is for, and it is the one structural thing Wireshark can do under load that we
cannot.

---

## What we changed, and what we deliberately did not

**Changed:** the kernel buffer is sized per core, in both agents, with
assertions in `test_protocol.py` and `agent-rs/src/session.rs` holding the
shape rather than the number — more cores must never mean less slack per core,
and the answer must stay bounded.

**Not changed, and why:**

- ~~**No snaplen option.**~~ Offered since ADR 0050, with a capture filter, once
  a cut frame stopped being a dissection that fails.
- **No ring buffer.** `DISK_RESERVE_BYTES` already stops a capture before the
  disk fills, and keeping the whole capture is the point of the store.
- **No "don't update in real time" switch.** The honest version of that is
  dissection off the capture path, not a checkbox that makes the packet list
  stop updating.
- **Not shedding newest instead of oldest.** Considered and deferred: after the
  pump fix, shedding should be rare enough that the direction matters less than
  the accounting does.

## Sources

Wireshark source: [`dumpcap.c`](https://github.com/wireshark/wireshark/blob/master/dumpcap.c),
[`capture/sync_pipe.h`](https://github.com/wireshark/wireshark/blob/master/capture/sync_pipe.h),
[`ui/capture.c`](https://github.com/wireshark/wireshark/blob/master/ui/capture.c),
[`capture/capture-pcap-util.c`](https://github.com/wireshark/wireshark/blob/master/capture/capture-pcap-util.c),
[`ui/qt/main_status_bar.cpp`](https://github.com/wireshark/wireshark/blob/master/ui/qt/main_status_bar.cpp).
Docs: [dumpcap(1)](https://www.wireshark.org/docs/man-pages/dumpcap.html),
[Wiki: Performance](https://wiki.wireshark.org/Performance),
[HighSpeedCapturing](https://wiki.wireshark.org/HighSpeedCapturing),
[CaptureSetup/CapturePrivileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges).
Npcap: [nmap/npcap#30](https://github.com/nmap/npcap/issues/30) *(issue thread,
from the maintainer)*, [The Npcap API](https://npcap.com/guide/npcap-api.html).
