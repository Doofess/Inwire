# 0022 — A stream protocol is not expensive any more

**Status:** accepted. **Corrects `0020`**, whose central claim about TCP stream
protocols was already false when it was written.

## Context

ADR 0020 divided protocols into leaves (cheap, eleven added at once) and
everything else (a project). It gave two ways of failing to be a leaf, and the
first was:

> **Cross-frame state.** SMB2, LDAP, Kerberos and BGP all run over TCP, so
> reading them means reassembling a byte stream across segments — which is the
> one thing this build does not do, and it is where essentially the whole
> remaining Info gap already lives.

Both halves are wrong.

**The build does reassemble a byte stream.** `dissectors/http1.ts` keeps
`pending` (an incomplete header block), `bodyRemaining`, `chunked`, `trailer`
and `untilClose` per direction, carried across arrivals in `AppDirection` on the
TCP conversation — the same model Wireshark uses. It runs over TLS-decrypted
streams *and* over cleartext TCP. What was true is narrower: that machinery was
only ever wired to HTTP ports, so nothing else could reach it.

**The Info gap is not there.** ADR 0021 measured it: the remaining 130
mismatches are two-pass facts, frames this build reads and the reference does
not, and 50 lone inconsistencies inside the reference's own desynchronised
regions. Reassembly is not in the list.

## Decision

**LDAP was built as the probe**, deliberately the cheapest test of the claim
rather than the most valuable protocol. It cost one dissector file and one
assertion script — the same shape as any of the eleven leaves — plus two things
that were genuinely new.

**One:** LDAP is length-delimited BER, so its framing is the envelope's own TLV
length and the reader `snmp.ts` built handles the rest. No general reassembler
was needed, and none was written. A message split across segments is declined
rather than half-read, the rule DNS-over-TCP already followed.

**Two:** it is the **first non-leaf dissector here**, and the state it needs is
tiny. `searchResDone` reports how many `searchResEntry` messages preceded it,
which no single frame knows. That is one `Map` per connection, hung off
`TcpConnection` beside the TLS conversation, optional because most connections
are neither, and bounded because message ids only climb.

So the correct division is not "leaf versus stream". It is **how much state, and
of what shape**:

| | cost |
|---|---|
| no state (the eleven leaves) | a dissector and a script |
| a counter or a cursor per connection (LDAP) | the same, plus a field on `TcpConnection` |
| a byte buffer per direction (HTTP/1.1) | already built, and reusable |
| recursion into another dissector (the tunnels) | still a project — see below |

## What this says about the rest of the group

SMB2 and Kerberos are now the same shape as LDAP. SMB2 is a 4-byte NetBIOS
session length in front of a fixed header; Kerberos is BER, so `ber.ts` covers
it as it covered LDAP. Neither needs anything that does not now exist.

**The tunnels are untouched by this.** GRE, VXLAN, L2TP and GTP still require
recursing into the L3 branch, and `decodeTransportLayer` is 977 lines with
`decodeRawEthernetPacket` at 877 — 1,854 of `pcapParser.ts`'s 3,466 in two
functions. ADR 0020's second reason stands exactly as written: the cost is the
decomposition, not the protocol.

## Consequences

46 protocols. The claim that gated three of them is retired with evidence
rather than left in place to gate them again.

The harness gained what the next stream protocol will want: `tcpFrame`, and a
`statefulTcp` option so a suite's cases are decoded against one
`TcpStreamTracker` and cross-frame state survives between them. `scripts/ldap/
dissect.ts` drives one real conversation rather than a bag of frames, because a
counter is only exercised in order.

And the lesson from 0021 held again, in the other direction this time: 0020's
claim was plausible, written down, and wrong, and the way that was settled was
to build the smallest thing that tested it.
