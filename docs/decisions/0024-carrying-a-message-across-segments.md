# 0024 — Carrying a message across segments, and the protocol that is not next

**Status:** accepted. Completes the thread `0020` opened and `0022` corrected.

## Context

ADR 0020 named four protocols as the ones a leaf dissector could not reach —
SMB2, LDAP, Kerberos and BGP — on the grounds that reading them meant
reassembling a byte stream, "the one thing this build does not do". ADR 0022
showed that claim was already false. Three of the four have since been written.
This is the fourth, and it is the only one of them that actually needed the
reassembly 0020 was worried about.

## Decision 1 — BGP reads the stream; its four siblings do not

DNS-over-TCP, LDAP, SMB2 and Kerberos all share one rule: **a message whose
declared length runs past the captured bytes is declined rather than
half-read.** It is a good rule. A half-read message is a confident wrong
answer, which is the failure mode `dissectors/heuristics.ts` exists to avoid,
and for those four a split message is an oddity — LDAP's messages are a few
hundred bytes, Kerberos' fit a datagram by construction.

BGP cannot have that rule, because for BGP the split message *is* the traffic.
A peering that carries anything carries full-table UPDATEs, and one of those
runs to RFC 4271's 4 kB ceiling — 65 kB under RFC 8654's extended messages —
against a 1,460-byte segment. A dissector that declined them would read the
KEEPALIVEs and nothing else: the half of a BGP capture nobody opens an analyzer
for.

So `dissectors/bgp.ts` carries two things forward, and they are different:

- **`owed`** — the body bytes still due on a message whose header was already
  read. Its *type* travels with it, because the frame that completes a message
  is the one the reference names it in.
- **`header`** — the rarer case of a segment boundary landing inside the
  nineteen header bytes, where not even the type is known yet. At ~19 bytes in
  1,460 this is about 1.3% of boundaries; without it the direction would never
  resynchronise, and 1.3% of a long peering is not an edge case.

Both are bounded by construction — `header` never reaches nineteen bytes,
`owed` is a 16-bit length counting down — so this adds nothing that grows for
the length of a capture, which is what `0014` asks of tracker state.

**The state is per direction, not per connection.** LDAP's and SMB2's live on
`TcpConnection`; BGP's lives on `TcpDirection`, beside the TLS record cursor.
The two halves of a peering are independent byte streams and a message boundary
in one says nothing about where the other is.

One consequence worth stating: a message reassembled from carried bytes gets
tree rows with **no byte ranges**, because it describes bytes that are mostly
not in this frame's hex dump. That is the rule IPv4 fragment reassembly and TLS
record reassembly already follow.

### The one deliberate difference from the reference

A segment that *begins* a multi-segment message gets an **empty** Info column
from tshark — not `[TCP segment of a reassembled PDU]`, which is what that same
message's *later* segments get. The asymmetry is an artefact of where its BGP
dissector clears the column before asking for more bytes. An empty Info column
tells a reader nothing, so such a frame reads here as the plain TCP segment it
is — which is also exactly what the reference gives for the middle segment of
the same message. `scripts/bgp/dissect.ts` states this as an exception with its
reason attached, rather than omitting the case.

## Decision 2 — DCERPC is not the next protocol, and the reason is measured

`dcerpc` has been the largest name in `UNDISSECTED` for as long as the list has
existed, it pairs with SMB2 over named pipes, and a corporate network runs on
it. It was the obvious next step. It was probed first, and it is not.

Asked directly (tshark 4.6.8), a DCERPC frame's Protocol and Info columns are
**not the RPC layer at all** once a context is bound:

```
bind SRVSVC          DCERPC   Bind: call_id: 1, ... 1 context items: SRVSVC V3.0 (32bit NDR)
request ctx0 op15    SRVSVC   NetShareEnumAll request
request ctx1 op0     LSARPC   lsa_Close request
```

The bind maps a context id to an interface UUID; a later Request names only the
context and an opnum; and the reference resolves both, replacing the Protocol
column with the **interface's** name and the Info column with the
**operation's**. Getting there needs an interface table (~100 UUIDs), a
per-interface opnum table (~1,500 operations), and — where the reference
appends `[Malformed Packet]` or operation detail — the NDR argument dissectors
underneath them, which are the largest subtree in Wireshark's dissector set by
file count.

A dissector that read the RPC header and stopped would be **correct on
interfaces nobody uses and wrong on every interface they do** — precisely the
half-tunnel failure GRE taught in `0023`, arriving through a different door.
That is not a reason never to write it; it is a reason it is a project rather
than a session, and it should be scoped as one.

Two smaller findings from the same probe, worth keeping so nobody re-derives
them: **the byte order is in the packet** (`packed_drep`, and it governs the
UUID encoding too, so reading a bind big-endian yields a plausible wrong
interface rather than a failure), and **several PDUs in one segment report only
the last**, joining nothing — the Kerberos convention, not SMB2's `"; "`.

## Consequences

- `UNDISSECTED` loses `bgp` and holds nineteen names. `LAYERS` is 57 tokens.
- Four join conventions now exist for "several messages in one segment", none
  derivable from the others: LDAP `" | "`, SMB2 `"; "`, BGP `", "`, and
  Kerberos and DCERPC reporting only the last. Each was measured, not guessed.
- `scripts/filter/engine.ts` had a hand-picked example naming `bgp.type` as a
  field of an undissected protocol, and it failed the moment BGP landed — the
  third time that check has had to be re-pointed. It now names `dcerpc.opnum`,
  which Decision 2 gives a measured reason to expect to outlast the others.
