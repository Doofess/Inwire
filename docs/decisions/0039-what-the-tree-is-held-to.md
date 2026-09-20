# 0039 — What the protocol tree is held to

**Status:** accepted

## Context

`parity-check.ts` compares six packet-list columns, the matched colour-rule
name and three fingerprint fields. `synthetic.ts` compares Protocol and Info.
Between them that is the whole tshark-backed gate — and `parity-check.ts` calls
`parseCaptureFile` **without `keepTrees`**, so it does not build `packet.layers`
at all.

Two consequences, and the second is worse than the first. A dissector that
stopped emitting half its rows would pass every check in this repository,
because the Info column would be unchanged. And the reverse question — *which
rows does the reference have that we do not* — had no answer, which makes "add
more depth" a matter of taste rather than a measurement.

`scripts/parity/tree-coverage.ts` answers it: `tshark -T pdml`, streamed frame
by frame, diffed against the union of every `ProtocolField.abbrev` in the tree
and every key in the flat field bag. It landed as a measurement, saying of
itself that *"choosing floors out of its output is a separate decision, taken
once there is an output to read."* This is that decision.

## Decision

### Counts, never ratios

**The denominator is not ours.** `theirs` is tshark's vocabulary. Floor `tls`
at its measured 15.8% and the day Wireshark 4.8 adds twenty `tls.*` fields it
becomes 15.1% and the build fails having changed nothing — broken by the oracle
upgrade `test/fixtures/README.md` *instructs* you to perform after a Wireshark
release. A gate that fails on its own prescribed maintenance is a gate people
delete.

`scripts/dissect/wireshark-abbrevs.ts` won this argument already, in the other
direction: it checks `ours ⊆ theirs`, which is immune to the reference growing
and fails only on a **rename** — and a rename is a genuine defect here, because
our abbrev is then no longer a name a user can type in Wireshark. That
asymmetry is not an accident of that file, it is the property worth reusing.

So the floored number is an absolute integer: the count of distinct abbrevs
**both** sides emit in a layer on a fixture. Not our raw count either — a floor
on our own output would pass just as happily on an abbrev we invented, which
stops it being a parity measurement at all.

### Four numbers, three directions

| number | direction |
|---|---|
| `tree.layers[layer]` — the intersection count | floor |
| `tree.protosNamed` | floor |
| `tree.ceilings.filterableNotInTree` | **ceiling** |
| `tree.ceilings.valueMismatches` | **ceiling** |
| `tree.counts.absentDistinct` | recorded, **never enforced** |

`filterableNotInTree` is the one section where every entry is a defect with no
judgement call: the app accepts a filter for a field the detail pane refuses to
show. Its membership is bounded by *our* vocabulary, so the reference cannot
grow it.

`valueMismatches` is a ceiling **at the measured number** rather than a floor at
zero, and the reason has to be recorded or somebody will try to close it:
`ourFrameFields` stringifies with `String(field.value)` while the reference's
`show` is a *display* string, so a genuine improvement — adding a field tshark
formats `0x0800 (IPv4)` where we print `0x0800` — raises the count. Raising the
ceiling is a normal argued commit. Classifying all 127 of them is the chase
ADR 0021 forbids.

### ADR 0021, applied to depth

**`absentDistinct` gets no ceiling, and that is the decision rather than an
omission.** Its denominator is tshark's again; more importantly, a ceiling
would convert a 621-item ranked *measurement* into a 621-item *backlog*, which
is exactly what ADR 0021 ended with the rule **a bucket is a defect only until
it is measured**. It is recorded with the `counts`/`enforce` idiom
`acceptance.json` already has, so there is a historical series with none of the
chase.

### Exemptions, and why two of the three cannot rot

`wireshark-abbrevs.ts`'s exemption lists need `stale` and `orphaned` checks
because their entries are bare names. Two of these three do not, because the
exemption is re-derived from a live fact on every run.

- **Decomposition** — `eth.dst.oui`, `eth.dst.lg`, `eth.dst_resolved` and their
  siblings, the reference re-presenting bits of an address it has already
  shown. Exempt **iff the parent abbrev is one we emit on that fixture**. The
  day a regression stops us emitting `eth.dst`, the exemption evaporates and
  four rows reappear at the top of the gap list. The first run proved the point
  in the other direction: `eth.addr.oui` and `eth.addr_resolved` are *not*
  exempt, because `eth.addr` is itself missing from the tree.
- **Protocols are derived, not exempted.** `mdns` and `llmnr` read as unnamed
  only because the comparison was against `frameProtocols` alone, while
  `filter/fields.ts` answers both barewords through `PROTOCOL_PREDICATES`.
  Subtracting `protocolNames()` removes them with **no entry to keep**.
- **Re-attribution**, which is the one with a rot check, and which started life
  as a mistake worth recording. 53 inwire frames read as missing
  `http.request.method`. They are `…udp:ssdp` on *both* sides; the reference's
  SSDP dissector simply reuses HTTP's field names. The first attempt exempted
  the `http.*` family on those frames — and that would have hidden a real hole,
  because this build registers `ssdp` as a layer token with **zero** fields, so
  those frames genuinely show nothing. The abbrev keeps its name and the
  per-layer table counts it under the protocol the frame **is**. `http 0/13`
  was never about HTTP. It is `ssdp 0/13`, and both facts are now true on
  screen.

### What the first run found, recorded rather than scheduled

- **`quic 0/40`.** A 479-line dissector with its own crypto, which decrypts
  Initials and labels the Protocol column, publishing not one `quic.*` abbrev
  on either surface.
- **`ssdp 0/13`**, above.
- **`prp 0/4`** — Parallel Redundancy Protocol, a trailer nothing here reads.
- **`icmp 2/11`**, and most of the gap is naming: `Identifier (BE)` and
  `Sequence Number (BE)` are drawn as rows carrying no `abbrev`.
- **~20 `tcp.*` names at 98% of frames**, most of them rows already on screen
  without an abbrev — and the fifteen `tcp.analysis.*` flags, which
  `dissect/tcpAnalysis.ts` computes check-for-check against Wireshark 4.6 and
  publishes into a string array that `filter/compile.ts` special-cases.

These are in `tree.unimplemented` with a sentence each, **not floored at 0**: a
zero floor protects nothing and reads as if it had been measured and accepted.
An entry may only leave that list by becoming a floor.

## Consequences

`npm run check` gains the gate — 151 discovered scripts to 152. It can be there because it skips
cleanly without tshark or the fixtures; `parity-check.ts` cannot, because it
**fails** on a missing fixture by ADR 0004's design, and CLAUDE.md claimed the
opposite until this landed.

`acceptance.json` grows a `tree` block per fixture, a sibling of `floors` and
never merged into it: `acceptance.ts` asserts every `floors` value is a
percentage, so a layer count of 24 would silently pass as one and a reference
vocabulary of 120 would fail as one — simultaneously useless and wrong.

The ratchets were watched firing before they were trusted: a lowered floor, a
**deleted** floor, a raised ceiling, and an `unimplemented` entry vanishing
without becoming a floor — four sabotages, four failures, exit 1. And the gate
itself was proved against a real regression by making `tcpTransport.ts` stop
emitting `tcp.window_size`, which took the `tcp` intersection from 24 to 23.

One thing that attempt taught, worth carrying: renaming the abbrev in
`fieldRegistry.ts` alone did **not** fail the gate, because the registry
*declares* a name and the dissector emits a literal. The two are held together
by `scripts/dissect/registry.ts`, not by this.
