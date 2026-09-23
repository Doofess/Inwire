# 0042 — Where the dissector's time actually goes, measured a second time

**Status:** accepted. Refines 0011's method rather than its conclusion.

## Context

ADR 0011 is this repository's founding performance lesson: a plan assumed the
discarded protocol tree was the cost of dissection, measured it, and found
**3.3%** — while `formatArrivalTime` was **38% of the entire profile**, building
an `Intl.DateTimeFormat` per call and throwing 25,716 of them away on a 12,858
frame capture.

**The instrument that found it was run by hand and never committed.** Nothing
under `scripts/` could reproduce that profile, so the next person to ask where
the time goes had to guess — and guessing is the failure mode 0011 exists to
document.

A performance plan was written against an audit of the ingest path. It named
five candidates, all the same shape: work whose cost scales with **payload
size** rather than header count, built into a tree that is cached for 4,000
frames and dropped unread.

## Decision

**`scripts/perf/profile.ts` is committed**, re-executing itself under
`node --cpu-prof` and aggregating self time by function. It is a measurement,
listed in `check.ts`'s `NOT_TESTS`, because a profile has no pass mark.

**And the rule it enforces by existing: no dissector change on performance
grounds until this has named the function it is meant to make cheaper.**

## What it said, on the `inwire` fixture

Four of the five candidates are **refuted**:

| candidate | claimed | measured (self) |
|---|---|---|
| `mediaType.ts` `dataLayer` | "the single largest string allocation on the ingest path" | **10 ms, 0.8%** |
| `transportShared.ts` `extractLiteralUrlOrHost` | 4 O(payload) allocations per data frame | **2 ms, 0.1%** |
| `addressFormat.ts` `formatMac` | 6 allocations per frame | **7 ms, 0.5%** |
| `macVendors.ts` `resolveMacVendor` | 4 uncached concatenations per frame | **1 ms** |
| **`quic.ts` `hexOfRange`** | hex for every QUIC packet without keys | **57 ms, 3.8%** |

Only the last survives: **4.5% of a 1,261 ms dissection**, and the largest
pure-leaf cost in this repository's own code. Real, worth having, and not
transformative — which is a sentence that is far cheaper to write now than after
the refactor.

The rest of the profile is where it should be. `encryptBlock` and `ghash`
together are 86 ms of AES-GCM, which is QUIC decryption doing its job.
`dissectTcpTransport` and `decodeRawEthernetPacket` carry large *total* times
and modest self times, which is what dispatch looks like.

`formatArrivalTime` does not appear. 0011's fix held.

## The trap that is hard-coded against

The first run of this script put `__name` at **152 ms, 10% of the profile,
attributed to `quic.ts`** — the one file the plan was about to optimise.

`__name` is esbuild's `keepNames` helper, wrapping every function definition so
stack traces survive minification. Where a module creates closures per call —
`quic.ts` does, once per packet — it is invoked per call too. It is **measured
absent from production**: `grep -c __name` on the built `pipeline.worker` bundle
answers `0`, and nothing in this repository sets `keepNames`. It is a property
of `tsx`, which is how every script here runs.

So it is folded into the tooling row by name, with the measurement in the
header. Deleting that fold reinstates a ghost that reads exactly like a real hot
spot, in exactly the file where one was expected.

**The same helper bit a second time, elsewhere**, which is why it is worth an
ADR rather than a comment: a Playwright probe in `smoke.ts` died with
`ReferenceError: __name is not defined`, because `tsx` wrapped a `const` inside
a callback that Playwright then serialised into a page with no such helper.
One artefact, two unrelated failures, both of which looked like something else.

## Consequences

- **Stage 4 of the performance plan is reduced to one function** and is not
  taken here. `hexOfRange` at 4.5% would need `ProtocolField.value` to carry a
  range instead of a string, every reader routed through one accessor, and
  `replay.ts`'s exact-string tree equality to prove none was missed. That is a
  reasonable trade to make deliberately, and a poor one to make because a plan
  said so before it was measured.
- **The four refuted candidates are recorded as refuted.** Without this they
  stay plausible forever and get re-proposed by the next audit, because each one
  is genuinely O(payload) and genuinely discarded — the reasoning was sound and
  the magnitude was wrong.
- 0011's conclusion is unchanged and its method is now reproducible.
