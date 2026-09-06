# 0019 - Which way the frame went

**Status:** Accepted 2026-09-06.

## The fact

A capture taken **on an endpoint** knows something a capture taken anywhere
else cannot: whether the machine sent the frame, received it, or merely
overheard it. Wireshark has no way to answer it — nothing in a frame says which
of its two MACs belongs to the machine you are sitting at.

Everything downstream had been paying for the gap. The conversations table
splits A→B and B→A by whoever spoke first rather than by which end is *us*;
Follow Stream guesses the client from port numbers and discloses the guess; and
there was no way at all to ask "what did this machine send".

This is the third entry in the seam ADR 0009 opened, under the same rule:
**enrich only from the captured machine, never from a third party.** The host's
identity comes from the agent's `adapter_config` or its socket table — or, for
an imported file where there is no machine to ask, from the frames themselves.

## Where it is decided, and a departure from the brief

The specification said direction should be derived in the Worker. It is not,
and the reason is structural: **imports do not go through the Worker.**
`PcapService.parseCaptureFile` dissects on the main thread, and that is
deliberate — it is what makes live capture and file import produce identical
`Packet` shapes.

So the decision lives inside `decodeRawEthernetPacket`, which *both* paths
already call. The constraint's intent — that the main thread never invents a
direction — is preserved by there being one pure function that both sides run.
The Worker keeps ownership of the *inputs*, exactly as it already owns the
trackers.

Two stages within one dissection, because of where the data is:

- **From the MACs**, at the moment they are still the frame's own. The IPv4 and
  IPv6 branches overwrite `srcIp`/`dstIp` with network addresses further down,
  so a MAC-based decision has to be taken before them.
- **From the addresses**, after dissection, for links that have no MACs at all —
  a TUN-style VPN adapter, where this is not a fallback but the only signal that
  can ever fire.

## Three details that are not details

**The source MAC is tested before the destination.** Our own broadcasts and
multicasts go to a group address, so reading the destination first calls every
DHCP Discover, every ARP request and every mDNS query this machine sends
"received". Group traffic we did not send, we did receive; group traffic we
sent, we sent.

**Offload can only ever conclude `out`.** A frame larger than the link can carry
was handed to the sniffer above segmentation offload, and a required checksum
the NIC has not filled in yet is the same story — both are artefacts only a
*transmitting* stack leaves. Their absence proves nothing, so a tiebreaker that
concluded "in" from a frame of ordinary size would be inventing.

**Both ends local is not a direction.** Loopback, and a frame between two of one
machine's adapters, are cases where neither answer is more true than the other.

## One packed number, and why not the alternatives

`Packet.direction` packs the direction, the deciding signal and the duplicate
bit, following `colorSlot` (ADR 0015).

It really is three facts rather than one dressed up: the column's tooltip has to
name **which signal decided**, so the signal is stored whatever shape this
takes. An arrow somebody did not expect is owed a reason, and "the adapter's MAC
said so" and "the frame was too big to have arrived over Ethernet" are very
different confidences in the same glyph.

The two alternatives were rejected on facts:

- A **`Packet.fields` entry** costs ~30 B a frame against ~8 — 21 MB at a full
  512 MB buffer, immediately after the work that took a frame from 2,342 B to
  663 (ADR 0018).
- A **dense column** is ruled out outright by `POST_DISSECTION_KEYS`
  (`dissect/denseFields.ts`). `FieldBlockWriter.absorb` fills a row once and
  never again, while a host override has to re-derive direction for frames
  already in the buffer. A plain property can simply be reassigned.

`frame.direction` and `frame.duplicate` are `ALIASES` in `filter/fields.ts`
rather than registry fields. That is not a workaround: the registry contains no
`frame.*` abbrev at all, and every one of `frame.number`, `frame.len`,
`frame.time_*`, `frame.protocols` and `frame.interface_name` is already an alias
reading a `Packet` property. `sent`/`received` alias `out`/`in` through the same
multi-value read that makes `proto == tls` and `proto == tlsv1.2` both match one
frame — no new machinery.

## Inferring the host for an imported capture

Measured over `test/fixtures/inwire_capture_1788478187989.pcap`, comparing the
two MACs that account for 99.6% of its frames:

| | the host | the gateway |
|---|---|---|
| distinct source IPs | 1 | 77 |
| TTLs | 128 / 255 / 1 | 55, 54, 101 |
| frames over 1514 bytes | 315 | 0 |
| LLDP naming its own MAC | yes | no |

Every signal separates cleanly, and they are independent — a router's TTLs are
decremented *because* it routed, and it sees many source addresses *because* it
routed, but a NAT box, a bridge and a mirror port fail them differently. So
agreement between several is worth much more than any one.

The result on that file: `04:7c:16:52:db:17` at **0.860** confidence, with the
basis naming four signals. The gateway is independently confirmed three further
ways — the Router Advertisement source `fe80::4615:24ff:feaa:bbcc` is that MAC
in EUI-64 form, the DHCP ACK names the same router, and this machine's own OS
neighbour table agrees.

**Confidence is disclosed, not hidden.** An inferred arrow is marked and its
tooltip says so, the same discipline Follow Stream applies to its first-speaker
guess. A user override replaces the inference outright rather than being blended
with it: somebody who says which machine took a capture knows something the
scoring does not.

### The volume floor, and its two exemptions

A MAC that sent a handful of frames cannot be scored on ratios. But **self-LLDP
and a DHCP request are exempt**, and the exemption is the point of the floor
rather than a hole in it: the floor exists because *ratios* need a sample, and
those two are not ratios. They are a machine stating its own identity, and one
such frame says as much as a thousand would. A laptop that joins a network and
is captured for ten seconds sends exactly one DHCP Request.

## An LLDP frame is not necessarily a switch

The assumption this work corrected. Windows runs an LLDP agent, so an LLDP frame
in a capture is as likely to be the capturing host introducing *itself* as it is
to be a neighbour. The fixture contains exactly one LLDP frame, and it is the
host's own: chassis id `ROTEM`, port id `04:7c:16:52:db:17` — its own MAC.

Two consequences, both load-bearing:

- A frame whose LLDP port id equals its own source MAC is the **strongest
  host-identity signal available**, worth more than everything else combined.
- The Network panel records it as `selfAdvertisedName` and reports **"no
  neighbour LLDP seen"**. Reporting it as a neighbour would have named the
  machine as its own upstream device.

The verification plan for this work expected that frame to populate a neighbour
section. It does not, and should not.

## Cost

Nothing measurable. `NetworkFactsCollector.observe` runs on every frame on the
hot path: **18,938 frames/s without it and 18,946 with**, three runs each,
against a run-to-run spread of ±4% (`scripts/perf/throughput.ts`). An earlier
version of the comment in that method claimed a 2.5% saving from a change a
proper measurement could not distinguish from noise; it was corrected rather
than left standing.

Re-deriving the buffer after an import or an override is **chunked between
animation frames** (`services/redirect.ts`), reading back the `eth.src`/`eth.dst`
dense columns and mutating in place so every identity-keyed cache survives. A
synchronous pass is precisely the 202 ms stall ADR 0015 recorded, and the buffer
is larger now that it is bounded by memory rather than by a frame count.

## What the agent had to learn

`adapter_config` (agent 3.6.0) carries per-adapter configuration. Three notes
worth keeping:

- **The Windows registry carries the gateway's MAC.** `DhcpGatewayHardware`
  packs the gateway address, a hardware length and the address itself, so the
  common case needs no neighbour-table walk — verified decoding to
  `44:15:24:aa:bb:cc` on this machine, the same answer `Get-NetNeighbor` gives.
- **The join is exact.** Capture device names are `\Device\NPF_{GUID}` and
  `get_windows_if_list` is keyed by that same GUID. `agent.py` deliberately
  refuses that function *for the capture list* because it returns ~51 unusable
  bindings; using it as a **GUID-keyed side-channel** is a different use, and
  it replaces the longest-prefix display-name match `interface_stats.py` has to
  do with an exact one.
- **One field needs a subprocess.** Nothing free says whether an IPv6 address is
  a temporary privacy one, and it matters because it rotates. `Get-NetIPAddress`
  answers and returns `SuffixOrigin` as an **integer**, which is locale-proof in
  the strongest sense — a number cannot be translated. It costs 0.48 s, so it is
  cached against the address list; a quiet poll is 26 ms.

## Consequences

- `Packet.direction` is never persisted. A restored frame is re-dissected and
  decides again, which is right: the host identity may have changed since.
- pcapng writes the direction into `epb_flags`, the format's own field.
  **Transit has no encoding there** — the two bits describe a frame relative to
  the capturing interface, and a frame merely overheard is neither — so it is
  written as "not available", which is true, rather than squeezed into whichever
  bit is less wrong.
- Cross-adapter duplicates are **marked and never dropped**. This cannot tell a
  duplicated frame from a genuinely retransmitted identical one, and a capture
  that quietly discarded frames would be lying about what was on the wire.
