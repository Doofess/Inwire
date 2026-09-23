# 0044 — The cost was the formatting loop, not the string's existence

**Status:** accepted. Closes ADR 0042's one surviving candidate, and corrects
the remedy 0042 proposed for it.

## Context

ADR 0042 profiled the dissector and refuted four of five planned targets. One
survived: `quic.ts`'s `hexOfRange`, the largest pure-leaf cost in this
repository's own code, re-measured here at **72–83 ms of a ~1,297 ms pass**
across three runs.

**0042 then named the wrong fix, and named it precisely enough to be worth
correcting.** It proposed carrying a *range* instead of a string —
`ProtocolField.value` gaining a lazy form, every reader routed through one
accessor, `replay.ts`'s exact-string tree equality proving none was missed — and
concluded that this was "a reasonable trade to make deliberately, and a poor one
to make because a plan said so". It declined to take it.

That reasoning assumed the cost was **building a string nobody reads**. The
profile could not distinguish that from **building it badly**, because both are
self time in the same function.

## What the loop actually was

Four dissectors each carried a copy of it — `quic.ts`, `icmp.ts`,
`mediaType.ts` and `ber.ts` — and all four wrote:

```ts
out += bytes[i].toString(16).padStart(2, '0');
```

`toString(16)` allocates, `padStart` allocates again, twice per byte, for one of
**256 possible answers**. Then the separator is a second concatenation, so a
1,460-byte payload makes ~2,920 temporaries to produce one string.

Two lookup tables remove both: `HEX[256]` for the digits, and `SEPARATED[256]`
holding `':' + hex` so the separator costs no second concat. Measured over 2,000
passes of a 1,460-byte payload, three rounds each:

| | |
|---|---|
| `toString(16).padStart(2, '0')`, colon appended separately | 45.6–48.7 ms |
| `HEX[b]` table, colon appended separately | 17.8–20.0 ms |
| `parts[].join(':')` | 27.3 ms |
| **`SEPARATED[b]`** | **8.5–10.9 ms** |

The `join` row is recorded because it is the obvious answer and it is the second
worst: an array of 1,460 one-byte strings costs more than the rope V8 builds out
of `+=`.

## What it measured on the real dissector

`scripts/perf/profile.ts` on the `inwire` fixture, three runs a side,
**ranges non-overlapping on both numbers**:

| | dissection | that function's self time |
|---|---|---|
| before | 1292 / 1297 / 1308 ms | 72 / 82 / 83 ms — 4.59–5.37% |
| after | 1173 / 1191 / 1200 ms | 11 / 12 ms — 0.76–0.79%, and absent from one run's top 25 |

**106 ms, 8.2% of the whole dissection**, at 100.9–101.7 µs a frame falling to
91.2–93.3 µs.

The 8.2% is larger than the 5% the function itself accounted for, and the
arithmetic is not mysterious: `dataLayer` (9–11 ms) folded into the same helper,
and ~2,900 temporaries a frame not allocated is GC that does not run — GC is
inside the tooling row the profiler prints, so it never appeared as a candidate.

## Decision

**`src/services/dissect/hexBytes.ts` is the one implementation**, exporting
`hexColons` (the reference's `show` for an `FT_BYTES` field) and `hexRun` (BER's
run-together form). The four copies are gone.

**`ProtocolField.value` is unchanged, and the lazy-range refactor is not
merely deferred — it is withdrawn.** It was sized against a cost that no longer
exists. Reviving it would be a change to the tree's central contract to save the
11 ms that remain.

**`addressFormat.ts` keeps its own loop**, deliberately. Its inputs are 6 and 16
bytes, the profile puts `formatMac` at 7–13 ms, and a table has almost nothing
to remove at that length. A helper that reached every hex loop in the tree would
be tidier and would say the wrong thing about where the cost is.

## The clamp, which is the one way this could have gone wrong quietly

The four copies disagreed about bounds: `hexOfRange` clamped both ends because
"these offsets are derived from length fields an adversary writes", `hexColons`
clamped only the top, and `berHex` clamped neither. The shared helper clamps
both, for every caller.

**The table makes that clamp matter more than it did.** `bytes[-1]` is
`undefined`. Under the old per-byte `toString(16)` that threw a `TypeError` out
of the middle of dissection — loud, and findable. Under `HEX[undefined]` it is
`undefined` concatenated as the literal text `"undefined"` into a hex dump.

So `scripts/dissect/hex-bytes.ts` asserts the clamp rather than assuming it, and
was checked the way this repository checks a regression test: with the bug put
back. Removing the low clamp fails exactly two of its assertions and nothing
else in the suite; dropping `padStart` from the table fails eight.

## Consequences

- Dissection is ~8% faster for a change with no contract, no new type and no new
  reader — `parity-check.ts` and `tree-coverage.ts` both pass unchanged, which
  is the whole evidence that the strings are identical.
- **The profile named the right function and the wrong remedy.** That is the
  lesson to carry: self time says *where*, never *why*. The cheapest hypothesis
  — that a hot leaf is written badly — is worth eliminating before one that
  changes a contract, and 0042 went to the contract first.
- 0042's "Stage 4 is reduced to one function and is not taken here" is now
  resolved rather than open, and its proposed mechanism is withdrawn.
