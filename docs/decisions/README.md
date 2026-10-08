# Architecture decisions

Phase 0 of `docs/specs/inwire-network-decoding-spec-v3.md`: the decisions every later
phase depends on, taken before dissector work multiplies the cost of changing them.
One file per decision, numbered, never edited after acceptance - a reversal is a new
file that supersedes the old one.

**That spec is historic and carries a banner saying so.** It was written while
Inwire was a web page, and the transport it prescribes - a pairing token, an
origin allowlist, WebSocket frames, port 8999 - is the transport `CLAUDE.md`'s
banner says must not come back. 0029 is what replaced it. Follow the link for
the dissector reasoning, never for a plan.

**The Status column records supersessions too.** An ADR is never edited after
acceptance, so this index and the forward banner on each superseded file are the
only places that say a decision has been overtaken - and a reader scanning the
column is the reader most likely to act on a stale one. It agrees with
`CLAUDE.md` §11, which is the same ledger in the same words.

| # | Decision | Status |
|---|---|---|
| [0001](0001-packet-data-model.md) | Two-phase packet model: summary on arrival, tree on demand | Accepted 2026-09-04; **re-scoped by 0011** |
| [0002](0002-field-registry.md) | One field registry feeds the tree, the filter engine and the columns | Accepted 2026-09-04 |
| [0003](0003-worker-boundary.md) | Keep dissection synchronous; move the whole pipeline into one Worker | Accepted 2026-09-04; **corrected by 0007** |
| [0004](0004-fixtures-and-privacy.md) | Fixture captures stay untracked; only aggregate counts are committed | Accepted 2026-09-04 |
| [0005](0005-agent-wire-format.md) | Agent wire format: `seq`, `iface`, `ts_us`, `capture_stats`, ownership, token | Accepted 2026-09-04; **authentication half superseded by 0029**; the timestamp is integer nanoseconds since **0050** (record version 3); both lengths are 32 bits since **0052** (version 4) |
| [0006](0006-pcapng-writer-scope.md) | pcapng writer scope and the pcap fallback | Accepted 2026-09-04 |
| [0007](0007-what-crosses-the-worker-boundary.md) | What crosses the worker boundary: bytes yes, tree no — **corrects 0003** | Accepted 2026-09-04; **amended by 0049**: a tree that is not carried is rebuilt from the frame's record, not by replaying its conversation |
| [0008](0008-key-material.md) | Where TLS key material lives, and where it does not | Accepted 2026-09-04; **weakened** — its "as old as the tab" premise, by 0027 |
| [0009](0009-off-wire-enrichment.md) | Facts that did not come off the wire | Accepted 2026-09-04 |
| [0010](0010-raw-frame-capture.md) | The agent receives raw frames and dissects nothing | Accepted 2026-09-05 |
| [0011](0011-dissection-cost-is-not-the-tree.md) | Dissection's cost was not the tree — **re-scopes 0001** | Accepted 2026-09-05 |
| [0012](0012-stored-captures-persist.md) | A stored capture is discarded only when the user asks | Accepted 2026-09-05; **mechanism superseded by 0025** |
| [0013](0013-what-a-million-frames-actually-cost.md) | What a million frames actually cost — **re-targets the buffer work** | Accepted 2026-09-05; **superseded by 0025** |
| [0014](0014-bounding-the-trackers.md) | Bounding the trackers — per connection, not per frame — **extends 0013** | Accepted 2026-09-05 |
| [0015](0015-the-colour-index.md) | The colour index, and a strip that fills rather than blocks | Accepted 2026-09-05 |
| [0016](0016-pooling-the-per-frame-lists.md) | Pooling the per-frame lists — **continues 0013** | Accepted 2026-09-05 |
| [0017](0017-the-dense-sparse-split.md) | Dense columns and a sparse bag — **corrects 0013's conclusion** | Measured 2026-09-05; **implemented by 0018**, which corrects its central number |
| [0018](0018-implementing-the-field-split.md) | Implementing the field split — **corrects 0017's central number** | Accepted 2026-09-05 |
| [0019](0019-packet-direction.md) | Which way the frame went | Accepted 2026-09-06 |
| [0020](0020-the-leaf-protocols.md) | The leaf protocols, and where cheap stops | Accepted 2026-09-06; **corrected by 0022** |
| [0021](0021-where-the-parity-chase-stops.md) | Where the parity chase stops, and what is left is not a defect | Accepted 2026-09-07 |
| [0022](0022-a-stream-protocol-is-not-expensive-any-more.md) | A stream protocol is not expensive any more — **corrects 0020** | Accepted 2026-09-07 |
| [0023](0023-decomposing-the-parser.md) | Decomposing the parser — **unblocks 0020's tunnels** | Accepted 2026-09-07 |
| [0024](0024-carrying-a-message-across-segments.md) | Carrying a message across segments — **closes 0020's fourth protocol**, and why DCERPC is not next | Accepted 2026-09-10 |
| [0025](0025-the-capture-lives-on-disk.md) | The capture lives on disk — **supersedes 0012's mechanism and 0013's storage**, and nothing deletes a frame to make room any more | Accepted 2026-09-11; **Decision 1's mechanism superseded by 0027** |
| [0026](0026-one-capture-on-disk.md) | One capture on disk — **closes 0025 §4**: no library, no launch prompt, and why a 5 GB capture makes the previous one worth less | Accepted 2026-09-11; **its quota arithmetic is void on a real disk** (0027) |
| [0027](0027-the-app-is-a-desktop-app.md) | The app is a desktop app — **supersedes 0025 Decision 1's mechanism** and dissolves the quota 0026 reasons from | Accepted 2026-09-12 |
| [0028](0028-where-the-capture-store-runs.md) | Where the capture store runs, and what the boundary costs — the measurement 0025 asked for: **the crossing is 16%** | Accepted 2026-09-12 |
| [0029](0029-the-app-and-the-agent-talk-over-a-named-pipe.md) | The app and the agent talk over a named pipe — **supersedes 0005's authentication half and deletes it**: the kernel answers the question the token was asked to answer | Accepted 2026-09-11; **amended by 0047**: the Windows agent's `hello` carries no `authRequired` at all |
| [0030](0030-one-installer-two-destinations.md) | One installer, two destinations, and the app never elevates — signing and updates deliberately **not** decided | Accepted 2026-09-12; **its Npcap paragraph is voided by 0032**; **its signing question is answered by 0047, for this PC only** |
| [0031](0031-a-filter-answers-over-the-whole-capture.md) | A display filter answers over the whole capture — **completes 0025**: one evaluator, a bitmap, and the boundary is the window | Accepted 2026-09-12 |
| [0032](0032-the-update-center.md) | Npcap is a prerequisite the app manages, not a payload the installer ships — **corrects 0030**: no silent install, a feed instead of a `#define`, and the version is not in `wpcap.dll` | Accepted 2026-09-12; **a signature now exists, trusted on this PC only (0047)**; verifying one is still not built |
| [0033](0033-the-agent-stays-a-separate-service.md) | The agent stays a separate LocalSystem service, and Npcap should be installed admin-only — the browser reason is gone and three better ones replace it | Accepted 2026-09-12 |
| [0034](0034-the-side-bar-is-a-place.md) | The side bar is a place, so Escape does not close it and navigating does not either — two negatives that leave no code behind to explain themselves | Accepted 2026-09-19 |
| [0035](0035-the-agent-lives-as-long-as-the-app.md) | The agent is demand-start and stops itself, and its version is the product's — retires 0033's reason #2, re-justifies 0030's withheld WP | Accepted 2026-09-19; **amended by 0051**: the version is compared for equality, not order, and is 0.x |
| [0036](0036-the-buffer-sizes-itself.md) | The packet buffer sizes itself from RAM and the V8 heap, and the renderer stands down before V8 aborts | Accepted 2026-09-19 |
| [0037](0037-the-agent-is-rust-on-windows.md) | The capture agent is Rust on Windows — one 449 KB signed exe instead of a 34 MB tree, and the throughput argument was measured and dropped | Accepted 2026-09-19; **driven end to end, including as a registered service**; **ships, signed on this PC, by 0047** |
| [0038](0038-bytes-and-rows-are-two-arrivals.md) | Bytes and rows are two arrivals, so a frame reaches disk before anything dissects it — and a dissection that throws no longer loses the frame | Accepted 2026-09-19; **0049** adds records out and revisit kits back on the same port |
| [0039](0039-what-the-tree-is-held-to.md) | What the protocol tree is held to: counts and not ratios, because the denominator is the reference's vocabulary rather than ours | Accepted 2026-09-20 |
| [0040](0040-follow-stream-shows-frames-not-payload.md) | Follow Stream shows a conversation's frames, not its payload — the alternative was to virtualise the payload, and what that would have cost is recorded | Accepted 2026-09-23 |
| [0041](0041-a-performance-ceiling-that-may-only-fall.md) | One performance ceiling that may only fall, and why every number that moves with the machine is printed instead — plus the measurement that silently measured something else | Accepted 2026-09-23 |
| [0042](0042-where-the-dissectors-time-actually-goes.md) | Where the dissector's time actually goes, measured a second time — four of five candidates refuted, and `__name` charged 10% of a profile to the wrong file | Accepted 2026-09-23 |
| [0043](0043-the-map-is-lazy-and-warmed.md) | The map's code is lazy and warmed rather than statically imported — 1.51 MB off the eager chunk for ~35 ms of launch, and a per-kilobyte figure that does not extrapolate | Accepted 2026-09-23 |
| [0044](0044-the-cost-was-the-loop-not-the-string.md) | The cost was the formatting loop, not the string's existence — one hex helper for four dissectors, 8.2% off dissection, and 0042's lazy-range refactor withdrawn rather than deferred | Accepted 2026-09-23 |
| [0045](0045-the-key-log-is-followed-not-loaded.md) | The TLS key log is followed from a remembered path rather than loaded once - a snapshot holds no secret for any connection a live capture sees; the renderer never names the file; amends 0008 on when key material enters memory | Accepted 2026-09-23; **0049** writes no key into a frame record |
| [0046](0046-export-is-the-whole-capture-streamed.md) | Export is the whole capture, streamed - disk below the window read in pages into a save that only takes the chosen name on commit; the filter is the list's own scan; a survey fixes the field columns; Excel is budgeted by a measured 720 B a cell; the PDF is an analysis and PDF import is gone | Accepted 2026-09-25 |
| [0047](0047-windows-ships-the-rust-agent-signed-on-this-pc.md) | Windows ships the Rust agent, signed with a certificate this PC trusts and no other machine does. It is at parity with the Python agent, measured side by side: 106,948 frames byte-identical, with five deliberate deviations. Nothing verifies a signature at runtime, and Smart App Control would not accept this one | Accepted 2026-09-26 |
| [0048](0048-a-captures-adapters-are-fixed-for-its-life.md) | A capture's adapters are fixed for its life - chosen before Start, changed only after Stop. The panel locks while capturing and both agents refuse a mid-capture `set_interfaces` with `capture_running`, which ends the restart that zeroed the drop counters; reverses one behaviour 0047 ported | Accepted 2026-09-26 |
| [0049](0049-a-frames-tree-is-rebuilt-from-its-own-record.md) | A frame's tree is rebuilt from its own record - Wireshark's model: arrival records every tracker answer a frame's dissection took, a fifth capture file keeps them (~60 B a frame), and a click dissects that one frame against its record instead of replaying its conversation. Every frame of the real fixtures revisits into the identical tree; decrypted content is never recorded, and still falls back to the replay - **amends 0007** | Accepted 2026-09-26 |
| [0050](0050-a-capture-is-narrowed-by-the-driver.md) | A capture is narrowed by the driver - a libpcap capture filter and a snaplen on `start_capture`, applied per adapter before a frame is read, checked live in libpcap's words, fixed for the capture and recorded in every export; nanosecond stamps on a version-3 wire record; a cut frame is dissected from its headers and marked, held to tshark on the fixtures cut at 64 and 128 bytes - **amends 0005** | Accepted 2026-09-27 |
| [0051](0051-the-version-is-0x-in-development.md) | The version is 0.x while Inwire is in development - 0.4.1, and the app compares the agent's number to its own for equality rather than order, so the number may go down; the anti-reset floor is deleted and a machine with 4.x uninstalls it once - **amends 0035** | Accepted 2026-09-28 |
| [0052](0052-the-agent-is-its-own-dumpcap.md) | The agent is its own dumpcap - it writes the capture's pcapng laid out block for block as dumpcap does (held byte for byte to two dumpcap-written files), rotates ring files and stops itself, writing only under the client's own identity; Wireshark's dumpcap was designed in and set aside; wire record version 4 with 32-bit lengths - **amends 0005 and 0050** | Accepted 2026-09-28, landing in phases |
| [0053](0053-the-live-path-falls-behind-on-disk.md) | The live path falls behind on disk, and dissects on every core - every app-side queue gets a budget and the agent's pcapng carries the rest, a hole is caught up from the file and never dissected across, the user is told how far behind live; a Sequencer owns everything numbered across conversations and TCP shards by connection (phase 3; the ADR said IP pair) in renderer Workers, not the store's process - **narrows 0038; answers CLAUDE.md §10's engine-side dissection** | Accepted 2026-10-08; phases 1-3 landed |

## Review outcome: amendments to the spec's execution order

The review agrees with Part C of the spec with two changes, recorded here so the spec
itself stays as approved.

> **Historic, like the spec it amends.** This is what the review decided on
> 2026-09-04 and is kept as that record, not as outstanding work. Phase 2b's
> "token auth" never shipped and must not: 0029 deleted the token and the origin
> check, and the pipe's ACL answers for both. The macOS/Linux downloads it
> mentions are no longer hidden behind that phase - those platforms have a
> tarball agent and no desktop app at all.

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
- Agent protocol change => bump `version` in **`package.json`**, then
  `npm run sync:version`, which rewrites `local-agent/agent_version.py`,
  `agent-rs/Cargo.toml` and the `inwire-agent` entry in `agent-rs/Cargo.lock`, then
  rebuild with `npm run build:agent` - the Rust agent compiles its version in, and its
  VERSIONINFO is stamped only when package.json, Cargo.toml and the binary agree. The
  agent's version is the product's (0035), so there is one number: it was four places,
  and before that three, held by two scripts covering different subsets.
  `scripts/agent/version.ts` holds every derived copy to `package.json` under
  `npm run check`, including the two deletions that keep it singular, and
  `scripts/agent/built-version.ts` holds the built exe. The app compares it for equality,
  not order (0051), so it may go down; it is 0.x while Inwire is in development.
