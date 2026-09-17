# 0001 - Two-phase packet model: summary on arrival, tree on demand

> **Re-scoped by [0011](0011-dissection-cost-is-not-the-tree.md).** The two-phase
> split below is still how the app works, but the reason given for it was wrong:
> 0011 measured the cost and it was not the tree. Read 0011 before using this as
> an argument for anything.

**Status:** Accepted 2026-09-04

## Context

`decodeRawEthernetPacket` (`src/services/pcapParser.ts:424`) builds everything for
every frame on arrival: the `layers[]` tree, the flat `fields` bag, `info`, the
column values, and the tracker updates - synchronously, inside the WebSocket
`onmessage` handler. The tree is the expensive part and is read by exactly two
consumers, both detail panes (`ProtocolTreeView.tsx:187`, `PacketDetailModal.tsx:365`,
`packetDetailModel.ts:173`). Everything else - list, filters, colour rules, aggregates,
export, session store - reads columns, `fields`, `analysisFlags`, `frameProtocols`,
`streamId` and `rawBytes`. `sessionStore.ts` already drops `layers` and re-derives them
on restore, so the tree is already treated as reconstructible.

Phases 4-8 add a TLS layer, a QUIC layer, DNS answer sections, IPv4 options, IPv6
extension headers and TCP option subtrees. On the eager model each of those grows the
per-frame cost and memory for all 50,000 frames to serve the one frame someone is
looking at.

## Decision

Dissection is two functions with one shared input:

```ts
// src/services/dissect/types.ts  (Phase 1b)
export interface DissectInput {
  bytes: Uint8Array;          // captured bytes, a view over the batch buffer
  origLen: number;
  linktype: number;           // 1 Ethernet, 113 SLL, 276 SLL2, 101 raw IP, 0 loopback
  frameNo: number;
  tsUs: number;               // epoch microseconds (ADR 0005)
  iface: number;
}

export interface DissectSummary {
  // Column values
  source: string; destination: string;
  protocol: ProtocolType; protocolLabel?: string;
  info: string; length: number;
  srcPort?: number; dstPort?: number;
  // Everything filters, colour rules, aggregates and trackers need
  fields: Record<string, string | number | boolean>;   // keyed by abbrev (ADR 0002)
  frameProtocols: string[];
  analysisFlags?: string[];
  expert?: { severity: ExpertSeverity; group: string; message: string }[];
  streamId?: number;
  // Cheap positional facts the tree pass reuses so it never re-walks headers
  offsets: { l2: number; l3?: number; l4?: number; payload?: number; vlanDepth: number };
}

export function dissectSummary(input: DissectInput, ctx: DissectContext): DissectSummary;
export function dissectTree(input: DissectInput, summary: DissectSummary): ProtocolLayer[];
```

- `dissectSummary` runs once per frame, in arrival order, and is the only function
  allowed to mutate the trackers (`DissectContext` holds `TcpStreamTracker`,
  `IcmpEchoTracker`, `QuicFlowTracker`, the DNS pairing table and the TLS record
  cursors). It must be O(bytes) and allocate no tree nodes.
- `dissectTree` is pure with respect to trackers: it may read the summary and any
  per-stream facts the summary already captured (negotiated TLS version, relative
  sequence base, reassembly status) but never advances state. It is called by the
  detail panes through a memo of size 1 (the selected frame) plus a small LRU for
  hover/prefetch.
- `Packet.layers` becomes optional and is populated only through `dissectTree`.
  `sessionStore` keeps dropping it, as now.
- `Packet.timestamp` is retired in favour of `tsUs` (Phase 3); `relativeTime` and
  `timeDelta` stay as derived seconds.

Existing dissectors migrate when their phase touches them: TLS (4), TCP (5), L2/L3
(6), DNS (7), QUIC (8). Until migrated, `dissectSummary` wraps the old function and
throws away the tree; `dissectTree` calls it again. That double call is acceptable
because the old dissectors are small and the migration is bounded by the phase list.
**No new dissector may be written on the old shape.**

## Consequences

- Arrival cost falls to the summary; memory per frame is columns + fields + bytes.
- The summary pass must capture every per-stream fact the tree will need, because the
  tree cannot ask the tracker later. This is a real constraint on Phase 4 (TLS record
  cursor state must be stored on the summary of each frame that completes a record).
- The colour-rule `WeakMap<Packet, ...>` cache (`colorRules.ts:300`) keeps working as
  long as `Packet` identity is stable in the main thread, which ADR 0003 preserves.
- The parity harness compares summaries only; tree correctness is covered by
  per-dissector assertion scripts with byte-level fixtures (as `scripts/igmp`,
  `scripts/lldp` do today).
