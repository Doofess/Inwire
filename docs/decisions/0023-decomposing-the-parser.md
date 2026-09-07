# 0023 — Decomposing the parser, and what the tunnels still need

**Status:** accepted. Completes the second half of `0020`'s cost argument, and
**unblocks** the tunnels it deferred.

## Context

ADR 0020 deferred GRE, VXLAN, L2TP and GTP with a reason that had nothing to do
with the protocols:

> **Recursion.** GRE, VXLAN, L2TP and GTP are tunnels: tshark dissects *through*
> them, replacing the outer addresses with the inner ones. That means recursing
> into the L3 branch of `decodeTransportLayer`, which is **959 lines** and
> already flagged for decomposition […] The cost is the decomposition, not the
> protocol.

That was right, and ADR 0022 confirmed it still stood after the stream-protocol
claim beside it fell over. This is the decomposition.

## What was done

`pcapParser.ts` went from **3,466 lines to 1,285**, and the two functions that
held almost all of it from 977 and 878 lines to **174 and 359**.

| module | what it is |
|---|---|
| `dissectors/networkLayer.ts` | the IPv4/IPv6 walk, the transport dispatch under it, and the twenty-one helpers only they use |
| `dissectors/tcpTransport.ts` | a TCP header, its options, the sequence analysis, and the dispatch between the five things that can claim its payload |
| `dissectors/udpTransport.ts` | the same for UDP |
| `dissectors/portless.ts` | IGMP, VRRP and OSPF - dispatched by protocol number, not by port |
| `dissect/transportShared.ts` | `checksumVerdict` and the ASCII helpers both decoders reach for |

Three of those five were named by comments the old code already carried. The
portless arms each repeated a note saying they were not port-based, and a
comment written three times is a grouping the code has not made.

## The decision that mattered

The transport branches each **returned a value**, so extracting them was a
transplant. The network branch **decides sixteen of its caller's locals**, and
that is a different problem: rewriting 533 lines to assign through
`state.srcIp = …` means touching every line, and an edit is where a mistake
hides.

So the sixteen are destructured in at the top of the new function and returned
at the bottom, and **the body moved without a character changing**. `layers` and
`filterFields` are containers that get appended to, so they pass by reference
and needed nothing. The property that made this safe is that the branch has
**no early returns** - it falls through to shared assembly code either way - so
it can become a function without any control flow being re-expressed.

## What made it verifiable

Two things, and neither is a unit test:

- **The parity harness.** Both fixtures are byte-identical after every step -
  19/50 and 66/80, the numbers they had before the first line moved. A refactor
  of the hottest code in the repo is only as safe as its oracle, and 27,640
  frames compared column by column is a good one.
- **`noUnusedLocals`.** After each extraction the compiler listed exactly the
  imports only that branch had used. That is a better completeness check than
  reading the diff, because it cannot be skimmed. The twenty-one helpers that
  moved with the network layer were identified the same way.

Throughput was measured rather than assumed, because the seed and return are two
object allocations per frame on the hot path: three runs each side, means 0.6%
apart with overlapping ranges. A single sample had suggested -4.7%, which is the
argument for taking three.

## Consequences

`decodeNetworkLayer(rawBytes, l3Offset, …)` is now a function that takes an
offset, which is precisely what a tunnel needs: read the outer header, find the
inner packet's offset, call it again, and report what comes back. GRE and VXLAN
are ordinary work now rather than a project.

Two cautions for whoever writes them. The reference reports the **inner**
addresses, so a half-tunnel that names the protocol without recursing lowers the
Protocol floor rather than raising it - the same trap that ruled out naming
things tshark declines to name (0020). And `layers` is appended to in place, so
a recursive call needs to think about where the inner packet's layers go in the
tree rather than letting them land at the end.
