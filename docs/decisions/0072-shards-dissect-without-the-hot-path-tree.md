# 0072 — Shards dissect without the hot-path tree: a Frame, Ethernet, IP, TCP or UDP layer keeps only its findings, and a shard frame's tree always comes from its record

**Status:** accepted 2026-11-03. The owner chose the scope the same day ("hot
path first", "shards only") after the measurement below, and approved the
plan. It amends
[0011](0011-dissection-cost-is-not-the-tree.md), whose figure was right for the
dissection it measured and is not right for today's. It builds on
[0049](0049-a-frames-tree-is-rebuilt-from-its-own-record.md), which made the
record the way a tree comes back, and it takes the lever that
[0053](0053-the-live-path-falls-behind-on-disk.md) "Shard skew" measured and
left.

## Context

0011 measured the tree at 3.3% of a 166 µs dissection and concluded that not
building it "could not have delivered what was expected of it". Its instrument
(`scripts/perf/tree-cost.ts`) still says 4.6% and 8.8% on the two fixtures
today. But that instrument times allocating the tree's *shape* from prepared
strings, alone. It does not count formatting each value, or the collection
that a 52 kB-a-frame allocation rate costs a thread that does nothing else.

A TCP shard on `main` (a1691dd9), measured with `scripts/perf/shard-cost.ts`
over 100,000 frames of the 300k burst:

| | |
|---|---|
| shard time, fastest of 9 | 32.0 µs a frame |
| allocated (sampled) | 52,084 B a frame |
| garbage collector, share of self time | 12.3%, more than any dissector |

Six helpers build nothing but tree rows: `tcpFlagFields`,
`completenessFields`, `tcpAnalysisFields`, `segmentDataRows`, `reassemblyRows`
and `macAddressFields`. Stubbing them (a throwaway measurement, never
committed) cut allocation by 14% and took the shard to **28.2 µs**. The
comparison was interleaved with `main` in two clean rounds: 31.97 and 32.19
against 28.34 and 28.11. A third round was lost to a game running on the
machine. A tree cache of 1 against 2,000 trees made no measurable difference,
so the cost is building the tree, not keeping it.

A shard builds every tree and throws nearly all of them away. Only a click
reads one, and since 0049 a click on a frame no cache holds is answered from
its record, in one dissection (45–72 µs), by `revisitFromStore`. A shard's
cached tree saved that one dissection for the 2,000 most recent frames of each
shard, at the price of building the other 99%.

One thing walks the tree at arrival: `collectExpert` (`pcapParser.ts`), the
only producer of `Packet.expert` and `inwire.expert.category`. Dissectors hang
a finding on the tree node it is about (a TCP RST, a bad checksum, each TCP
analysis flag, the MTU note). Everything else the row carries (the field bag,
the dense columns, Info, the protocol chain, the record) is built beside the
tree, not from it.

## Decision

- **A synchronous scope says whether a tree is wanted**
  (`src/services/dissect/treeMode.ts`: `treeWanted()`, `withoutTree()`),
  shaped like `withDissectEnv`. It is not a `DissectEnv` field. The
  environment is the outside facts a record replays, and whether a tree is
  drawn is not a fact about the frame. `FrameDissector` takes
  `{ tree: false }` and runs the decode inside the scope.
- **The hot path honours it**: the Frame, Ethernet II, IPv4, IPv6, TCP and UDP
  layers. Every other dissector still builds its tree when asked not to. Its
  tree is dropped as before, and each one can follow when a profile names it.
- **A tree-free layer keeps only its findings.** It keeps its `name`,
  `summary` and `rawBytesRange`, and its `fields` hold only the nodes that
  carry an `expertInfo`, without children, in the depth-first order the full
  tree would have them. So `collectExpert`, the protocol chain, `nestLayers`
  and the row codec are unchanged, and the expert list keeps its order. The
  Frame layer's tree-only rows (`[Protocols in frame]`, the size-limited
  marker, `Character encoding`) are not built; Info still carries the marker.
- **The tree-on branch is the reference.** For every frame, the packed row,
  the record and the expert list are byte-identical between the two modes.
  `scripts/pipeline/tree-free-rows.ts` holds that on the fixtures, on a
  synthetic set that fires every hot-path finding, and on the burst when it is
  named.
- **Only shards run tree-free.** Lane 0, the single Worker, import, revisit
  and replay always build full trees. A shard keeps no tree cache. The merge
  no longer sends shards the rows and links their cached trees used to
  receive. A click on a shard frame goes straight to `revisitFromStore`.

## Consequences

- A click on a recent shard frame costs a store round trip and one record
  rebuild, where it used to cost nothing. The same is already true of every
  other frame below the cache.
- The shard's cache gave its trees two things a rebuilt tree must now get
  elsewhere (`src/services/pipeline/rebuiltTrees.ts`,
  `scripts/pipeline/rebuilt-trees.ts`): links a later frame writes in (a
  rebuilt tree one lands on, even mid-rebuild, is dropped and rebuilt with
  it), and the JA4 "Matches process" row, which comes back from the stored
  row's `inwire.process.ja4_match` with today's count, or none if the store
  no longer names that program.
- Removed: the shard's tree cache (`SHARD_CACHE_FRAMES`, about 2,000 trees,
  ~20 MB per shard), its `detail` message both ways, `treeFromShard`, and the
  coordinator's tree rows and patches for shard lanes.
- A dissector that gains a finding on the hot path must add it to the
  tree-free branch too. The equality assertion fails, naming the frame, when
  a fixture or the synthetic set carries the finding and the branch does not.
  A finding no capture exercises would slip through, which is why the
  synthetic set fires each one.
- **Measured result.** `shard-cost.ts`, burst300k, 100,000 frames, fastest of
  9, interleaved with `main` (a1691dd9) in three rounds, all three clean:

  | | `main` | tree-free shards |
  |---|---|---|
  | fastest, µs a frame | 31.06, 30.52, 30.14 | 18.34, 18.47, 18.17 |
  | median, µs a frame | 31.89, 31.56, 31.28 | 19.37, 19.31, 18.98 |
  | allocated (sampled) | 53,050 B a frame | 29,907 B a frame |

  That is about 40% off a shard frame and 44% off its allocation. TCP took
  the shard from 32.0 to 24.3 µs and Frame, Ethernet and IP to 19.3 (the
  workers' uncommitted sanity runs, Tasks 2 and 3). What is left is led by
  `decodeNetworkLayer`, `analyzeTcpSegment`, `dissectTcpTransport` and
  `decodeRawEthernetPacket`: the summary's own work and the tracker's, not
  tree rows.
- **The gate moved** (2026-11-04). `ui-burst-drive.ts --follow-only`, six
  shards, 1 GB buffer, `burst300k`, against `a1691dd9` built the same way and
  alternated run for run on a quiet machine:

  | | `a1691dd9` | tree-free shards |
  |---|---|---|
  | 60,000 offered (3 runs) | 59,000 / 58,300 / 59,000 advanced a second; lag 16,000-32,000 | 59,600 / 59,200 / 59,500; lag 14,000-27,000 |
  | 90,000 offered, ~86,000 sent (2 runs) | 65,500 / 63,900; lag climbing to 608,000 / 634,000 | **84,800 / 85,100**; lag flat at 33,000-97,000 |
  | Worker heap, every 2 s | 14-116 MB | 11-54 MB |

  No run skipped a frame or logged a pipeline warning. At 90,000 the old
  build fell behind exactly as 0053 recorded, because the hot connection's
  shard was the limit. The tree-free shard keeps up with everything the
  drive's agent sent. Where the new ceiling is has not been measured.
