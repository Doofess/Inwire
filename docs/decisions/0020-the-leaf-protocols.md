# 0020 — The leaf protocols, and where cheap stops

> **Corrected by [0022](0022-a-stream-protocol-is-not-expensive-any-more.md)**,
> whose measurement reverses this file's central claim about what a TCP stream
> protocol costs. The cost argument is then completed by
> [0023](0023-decomposing-the-parser.md), which unblocks the tunnels named here,
> and [0024](0024-carrying-a-message-across-segments.md), which closes the fourth
> protocol and says why DCERPC is not next.

**Status:** accepted

## Context

"Add as many more dissectors as possible" is not one piece of work. Measured on
the eight protocols added before this batch, a dissector costs almost nothing at
runtime — the whole eight-detector content chain is **42.7 ns** on a payload
that matches none of them, against **42.1 µs** for a frame's full dissection, on
the **2.7%** of frames no port claimed. Total across both fixtures: 32 µs.

So the question is not what a dissector costs to run. It is what *kind* of
protocol is cheap, and the answer is sharp enough to plan around.

## Decision

A protocol is **cheap** when it is a *leaf*: one datagram in, one label out,
with no state carried between frames and no recursion into another protocol.
Eleven were added together on that basis — TFTP, NBDS, BFD, CoAP, PTP, HSRP,
VRRP, OSPF, RIP, RIPng and CDP — because each is ~250 lines of dissector and
~150 of assertion script, and none of them interacts with any of the others.

Everything that is not a leaf is a project, and the two ways of failing to be
one are worth naming separately.

**Cross-frame state.** SMB2, LDAP, Kerberos and BGP all run over TCP, so
reading them means reassembling a byte stream across segments — which is the
one thing this build does not do, and it is where essentially the whole
remaining Info gap already lives. Measured over both fixtures
(`PARITY_MAX_DIFFS=100000`), of **883** Info mismatches:

| group | inwire | bulk |
|---|---:|---:|
| `TCP (segment of reassembled PDU)` | 46 | 471 |
| `TLSv1.2` (the record cursor) | 48 | 157 |
| `TCP` | 19 | 120 |
| everything else (QUIC, ICMP, ICMPv6, LLDP) | 20 | 2 |

**861 of 883 — 97.5% — are the same problem**, and on the bulk fixture it is
99.7% of them. Adding a protocol on top of an unsolved reassembly problem
inherits it: SMB2 over a stream this build cannot reassemble would produce a
new column of mismatches with the same root cause, and would make that root
cause harder to fix rather than easier.

**Recursion.** GRE, VXLAN, L2TP and GTP are tunnels: tshark dissects *through*
them, replacing the outer addresses with the inner ones. That means recursing
into the L3 branch of `decodeTransportLayer`, which is **959 lines** and
already flagged for decomposition — and a half-GRE that names the tunnel
without recursing fails the oracle, because tshark would report the inner
addresses where this build reported the outer. The cost is the decomposition,
not the protocol.

## What the leaves still cost

Not zero, and in three places that are not the dissector:

- **The registration checklist** — nine touch points, most gated by
  `scripts/dissect/registry.ts`. Miss `PROTOCOL_NAME_MAP` and the frame carries
  a bogus second token that nests wrongly in the protocol hierarchy, which is a
  live bug NTP and STUN had.
- **Parity risk.** Naming something tshark declines to name *lowers* the
  Protocol floor. That is what ruled out RTP (its fingerprint is two version
  bits; Wireshark ships its own heuristic off) and the 1,239 RuneScape frames
  on TCP 43594 — genuinely undissected, and reading them would trade a measured
  parity drop for readability nobody asked for.
- **Getting the details right, which the RFC does not tell you.** Nine
  corrections in this batch came from probing the oracle and could not have
  been read out of a standard: a short TFTP block is marked `(last)`; port 3785
  is BFD *Echo* and has no format at all; Wireshark spells PTP's peer-delay
  messages out where IEEE 1588 abbreviates them; PTP Management has an Info
  grammar of its own with a 35-entry table whose capitalisation is not
  mechanically derivable; HSRP is only HSRP when addressed to its multicast
  group; RIP and RIPng write gratuitously different Info lines, one of them
  with a leading space; and CDP's Info line *ends* in two spaces.

## Consequences

Eleven protocols, 45 layer tokens, no measurable runtime cost, both fixtures
unchanged at their floors.

The batch also produced two gates that outlive it. `scripts/dissect/udp-ports.ts`
asserts that no two dispatch entries claim a port — true by inspection before,
and unchecked, in a lookup that returns the first match. And
`scripts/dissect/wireshark-abbrevs.ts` holds every registered field name to
`tshark -G fields`, which found that **27 of 339 abbrevs were names this build
had invented where the reference already had one**. That check is worth more
than any single dissector here: it defends the registry's actual promise, which
is that a filter learnt in Wireshark works unchanged.

Deliberately not done: GRE and the tunnels (need the `pcapParser.ts`
decomposition first), SMB2/LDAP/Kerberos (need TCP reassembly, and the BER
reader the SNMP dissector already built is only half of what LDAP and
Kerberos want), RTP (declined with evidence), and GLBP — whose Info line is
`G: 1, Hello, 192`, a Cisco TLV soup with no published spec, covering a need
HSRP and VRRP already cover.
