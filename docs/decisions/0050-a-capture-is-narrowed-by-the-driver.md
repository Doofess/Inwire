# 0050 — A capture is narrowed by the driver

**Status:** accepted 2026-09-27. **Amends
[0005](0005-agent-wire-format.md)**: the wire record's timestamp is integer
nanoseconds (version 3). **Retires the "no snaplen option" line** in
`docs/bursts-and-what-wireshark-does.md`.

## Context

The owner asked for three things dumpcap would have given: capture filters, a
snaplen, and nanosecond timestamps. None of them needs dumpcap. Each is a
libpcap call the Rust agent can make itself: `pcap_setfilter`,
`pcap_set_snaplen` and `pcap_set_tstamp_precision`. Making them there keeps
the agent's latency (`pcap_setmintocopy(0)`, where dumpcap waits up to 250 ms)
and its live drop counts (dumpcap reports those only at exit).

What stood in the way was never the agent:

- **A snaplen was "a dissection that fails".** The bursts document said so
  and declined the option. Measured on the real fixtures cut with
  `editcap -s 64`, it was worse than failing. Truncation changed the Protocol
  column on 4,344 frames and the Info column on 11,338 that were right when
  whole. TCP read a cut segment as a short one, and the next segment as a hole
  behind it. So a capture with no loss reported "previous segment not
  captured" on most of its frames.
- **Nanoseconds could not reach the app.** The record carried an `f64` of
  microseconds, and epoch nanoseconds are past 2^53.

## Decision

**The driver applies both options, before a frame is copied anywhere.**
`start_capture` carries `filter` and `snaplen`, each left out when it asks
for nothing. The Rust agent opens with `pcap_create`, the snaplen and
nanosecond precision, then `pcap_activate`, and then applies the filter to
each handle.

Frames a filter refuses never reach the kernel ring. That is the one lever
that makes a burst of unwanted traffic cost nothing: every other stage only
decides who pays for it.

- **A start that cannot be read is refused, never defaulted.** The refusal is
  `invalid_capture_options`, with the sentence saying which option. A filter
  the agent ignored would be a capture of everything whose owner believes it
  is narrowed.
- **A filter one adapter cannot compile fails that adapter alone**, in
  libpcap's own words. This is the per-adapter rule every open failure
  already followed. `ether host` compiles for Ethernet and not for Npcap's
  loopback, which is `DLT_NULL`.
- **`check_capture_filter` answers in libpcap's words.** The filter is
  compiled on a dead handle for each link type among the chosen adapters, so
  it opens nothing and needs no privilege. The answer echoes the filter, so a
  stale answer can be recognised. The panel asks on each 400 ms pause in
  typing, and Start is blocked only by a filter the agent has refused.
- **Fixed for the life of a capture**, like the adapters (0048). A
  `start_capture` that joins a running capture keeps that capture's options,
  because they were applied to handles that are still reading.
- **Remembered** as a preference, as Wireshark remembers the last filter.
- **Recorded.** Every export's metadata carries "Capture filter" and
  "Snapshot length". A pcapng writes the snaplen into its IDB and the filter
  as `if_filter`, which capinfos reads back. An anonymised export withholds
  the filter whole, because BPF names hosts unquoted (`host example.com`).

**Timestamps are nanoseconds on the wire.**

- Record version 3 puts a `u64` of epoch nanoseconds in the same eight bytes.
  It is exact until 2554.
- Each interface reports the precision its driver gave (`tsPrecision`): 9 on
  Npcap, 6 from the Python agent.
- The app splits the stamp into whole microseconds and a remainder, from two
  `u32` halves and without a BigInt per frame. That is exact to 2^53
  microseconds, the year 2255. The golden vectors pin that limit.
- Npcap's clock ticks in 100 ns, so that is the precision a live capture
  actually gains.

**A cut frame is dissected from its headers, and says it was cut.**

- **Lengths come from headers.** TCP takes a cut segment's length from the IP
  header, so its analysis is the same cut as whole. An offload frame, whose
  IP length is 0, is as long as it was on the wire.
- **Checksums over missing bytes are Unverified.**
- **No subdissector is handed half a message.** DNS stops at a name that ran
  past the captured end instead of reading its type out of the cut label. A
  cut answer shows its type, as Wireshark's column does.
- **TLS on a cut segment:**
  - The segment is never fed to the record cursor. To the cursor it is a hole
    ending where the next segment starts.
  - It is named from what it holds, the way Wireshark names a segment it could
    not desegment: the records whose headers start in the kept bytes. A
    segment that opens mid-record takes the conversation's version with empty
    Info, or `SSL` and `Continuation Data` when no version is known.
- **`[Packet size limited during capture]`** is appended to every frame whose
  content ran past what was kept. "Content" is where its own headers say it
  ends (`dissect/captureShort.ts`).

**The marker is a superset of Wireshark's, on purpose.** Wireshark marks a
frame only when a dissector reads past the cut. A payload nothing reads, such
as QUIC's protected payload or a TLS record body mid-stream, is cut and
unmarked there. Here the fact "this was not all captured" does not depend on
whether a dissector happened to look.

**One place has no Wireshark rule to match.** Wireshark learns a mid-stream
connection's version from its Application Data headers on the inwire fixture,
and does not learn it from the same kind of header on bulk. Measured both
ways, learning from any header keeps as many Protocol cells as learning from
the handshake alone: 47,522 against 47,492 across the four cuts. Learning
from any header also says the more useful thing, so that is the rule.

## What holds it

- **`scripts/parity/snaplen.ts`** cuts each fixture at 64 and 128 bytes and
  compares against tshark on the same cut.
  - Exact: every whole TCP header keeps its `tcp.len`.
  - Floors in `acceptance.json`: the analysis flags kept, Protocol and Info
    kept against tshark, and frames both mark.
  - A ceiling: frames tshark marks and we don't.
  - `acceptance.ts` ratchets both, like the tree floors.

  Recorded at acceptance:

  | Cut | TCP analysis kept | Protocol kept | Marked by tshark but not here |
  |---|---|---|---|
  | inwire at 64 | 3,599 of 3,599 | 12,771 of 12,782 | 0 |
  | inwire at 128 | 7,577 of 7,577 | 12,775 of 12,782 | 0 |
  | bulk at 64 | 116 of 116 | 13,812 of 13,812 | 0 |
  | bulk at 128 | 14,486 of 14,486 | 8,430 of 13,812 | 0 |

  The bulk-at-128 figure is the inconsistency above.
- **`scripts/pipeline/revisit.ts`** rebuilds every frame of all four cuts from
  its record. There are zero wrong trees: every new path is a recorded
  tracker answer.
- **`agent-rs`'s tests** read the real fixture through the real `Live::open`
  with `arp` and a 32-byte snaplen. They compare against the fixture's own ARP
  frames, found by EtherType without libpcap. They also cover a filter that
  will not compile, and the check command against the real library.
- **The protocol vectors.** `command-vectors.json` carries both new commands,
  `control-vectors.json` the reply and the refusal, and `wire-vectors.json`
  version 3. `message-coverage.ts` lists them.
- **`scripts/session/capture-options.ts`** holds the start command, the
  stale-answer rule, the resync resuming with the same options, and the
  metadata rows. `scripts/export/pcapng.ts` holds the IDB through capinfos.

## The Python agent's deviations

The Python agent reads the same options with the same sentences. Its
differences, each one deliberate:

- **The filter goes on the raw handle.** scapy's `setfilter` logs a compile
  failure and carries on unfiltered.
- **The snaplen is cut in software.** scapy activates the handle at its own
  fixed snaplen before one could be asked for, so this agent has the same
  frames without the kernel-buffer saving.
- **It stamps in microseconds** and says `tsPrecision: 6`.

## Consequences

The product moves to 4.1.0, renumbered 0.4.1 by
[0051](0051-the-version-is-0x-in-development.md) before it was installed. An
agent from 4.0.0 sends version 2 records, which this app refuses, so
`REQUIRED_AGENT_VERSION` moves with it and the old agent reads as outdated
rather than as broken.

This is items 1–3 of the dumpcap comparison. The rest are what only dumpcap
gives, and are the next decision: ring buffers, per-interface end-of-capture
statistics, files identical to Wireshark's, and a capture engine maintained
elsewhere.
