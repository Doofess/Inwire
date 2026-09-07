# Architecture decisions

Phase 0 of `docs/specs/inwire-network-decoding-spec-v3.md`: the decisions every later
phase depends on, taken before dissector work multiplies the cost of changing them.
One file per decision, numbered, never edited after acceptance - a reversal is a new
file that supersedes the old one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-packet-data-model.md) | Two-phase packet model: summary on arrival, tree on demand | Accepted 2026-09-04 |
| [0002](0002-field-registry.md) | One field registry feeds the tree, the filter engine and the columns | Accepted 2026-09-04 |
| [0003](0003-worker-boundary.md) | Keep dissection synchronous; move the whole pipeline into one Worker | Accepted 2026-09-04 |
| [0004](0004-fixtures-and-privacy.md) | Fixture captures stay untracked; only aggregate counts are committed | Accepted 2026-09-04 |
| [0005](0005-agent-wire-format.md) | Agent wire format: `seq`, `iface`, `ts_us`, `capture_stats`, ownership, token | Accepted 2026-09-04 |
| [0006](0006-pcapng-writer-scope.md) | pcapng writer scope and the pcap fallback | Accepted 2026-09-04 |
| [0007](0007-what-crosses-the-worker-boundary.md) | What crosses the worker boundary: bytes yes, tree no — **corrects 0003** | Accepted 2026-09-04 |
| [0008](0008-key-material.md) | Where TLS key material lives, and where it does not | Accepted 2026-09-04 |
| [0009](0009-off-wire-enrichment.md) | Facts that did not come off the wire | Accepted 2026-09-04 |
| [0010](0010-raw-frame-capture.md) | The agent receives raw frames and dissects nothing | Accepted 2026-09-05 |
| [0011](0011-dissection-cost-is-not-the-tree.md) | Dissection's cost was not the tree — **re-scopes 0001** | Accepted 2026-09-05 |
| [0012](0012-stored-captures-persist.md) | A stored capture is discarded only when the user asks | Accepted 2026-09-05 |
| [0013](0013-what-a-million-frames-actually-cost.md) | What a million frames actually cost — **re-targets the buffer work** | Accepted 2026-09-05 |
| [0014](0014-bounding-the-trackers.md) | Bounding the trackers — per connection, not per frame — **extends 0013** | Accepted 2026-09-05 |
| [0015](0015-the-colour-index.md) | The colour index, and a strip that fills rather than blocks | Accepted 2026-09-05 |
| [0016](0016-pooling-the-per-frame-lists.md) | Pooling the per-frame lists — **continues 0013** | Accepted 2026-09-05 |
| [0017](0017-the-dense-sparse-split.md) | Dense columns and a sparse bag — **corrects 0013's conclusion** | Measured 2026-09-05 |
| [0018](0018-implementing-the-field-split.md) | Implementing the field split — **corrects 0017's central number** | Accepted 2026-09-05 |
| [0019](0019-packet-direction.md) | Which way the frame went | Accepted 2026-09-06 |
| [0020](0020-the-leaf-protocols.md) | The leaf protocols, and where cheap stops | Accepted 2026-09-06 |
| [0021](0021-where-the-parity-chase-stops.md) | Where the parity chase stops, and what is left is not a defect | Accepted 2026-09-07 |
| [0022](0022-a-stream-protocol-is-not-expensive-any-more.md) | A stream protocol is not expensive any more — **corrects 0020** | Accepted 2026-09-07 |

## Review outcome: amendments to the spec's execution order

The review agrees with Part C of the spec with two changes, recorded here so the spec
itself stays as approved.

1. **Phase 2 is split.** 2a (Windows correctness: `state` broadcast, `capture_stats`,
   `seq`/`iface`, installer fixes, rebuild and republish 3.1.0) ships before any
   dissector phase. 2b (capture ownership, token auth, macOS/Linux, lazy scapy) can
   run in parallel with Phases 3-5 because it touches no dissector code. Until 2b lands
   the app hides the macOS/Linux downloads.
2. **A short Phase 1b precedes Phase 4.** It introduces the types from 0001 and the
   registry module from 0002 with *no behaviour change*: `DissectSummary`,
   `dissectTree`, `ProtocolField.abbrev`, `fieldRegistry.ts`, and the assertion script
   that fails on an unregistered field. Phase 4 is then the first dissector written on
   the new shape rather than the first one migrated to it.

Revised order: 1 -> 1b -> 2a -> 3 -> 4 -> 5 -> (2b alongside) -> 6 -> 7 -> 8 -> 9 -> 10
-> 11 -> 12 -> 13.

## Recurring gate (end of every phase, 30 minutes)

- Parity delta vs the previous phase, both fixtures, per column; no column regressed.
- At least one new assertion script under `scripts/`, discovered by `npm run check`.
- `CLAUDE.md` describes the new behaviour; `docs/specs/...v3.md` phase marked done.
- A parity bucket is a defect only once measured (0021): build the smallest thing that
  tests the hypothesis and let the floors decide - two of three plausible fixes tried
  there made the numbers worse, one of them by 2,000 frames.
- No new dissector on the old eager-tree shape (0001); no field published without an
  `abbrev` (0002, enforced by script), and no `abbrev` the reference analyzer does not
  itself define (0020, enforced by `scripts/dissect/wireshark-abbrevs.ts`).
- No new `async` in the dissection path (0003).
- No fixture bytes, names or addresses in the diff (0004).
- Agent protocol change => version bumped in all three places (`test_protocol.py`).
