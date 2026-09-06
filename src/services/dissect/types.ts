/**
 * The two-phase dissection contract (docs/decisions/0001-packet-data-model.md).
 *
 * Dissection is split into what every frame needs on arrival - the column
 * values, the filterable fields, the analysis flags, and the tracker updates
 * that only make sense in arrival order - and what only the selected frame
 * needs: the protocol tree. The first is `dissectSummary`, run once per frame
 * and the only place trackers may be advanced. The second is `dissectTree`,
 * run on demand, which may read what the summary recorded but never touches a
 * tracker, because by the time someone clicks a row the trackers have moved on.
 *
 * `decodeRawEthernetPacket` still does both at once for every dissector that
 * has not been migrated. Migration happens dissector by dissector as the spec's
 * phases touch them (TLS in 4, TCP in 5, L2/L3 in 6, DNS in 7, QUIC in 8); no
 * new dissector is written on the old shape. Until then `dissectSummary` runs
 * the old path and keeps its tree on `legacyLayers`, so `dissectTree` can hand
 * it back without decoding twice or re-running trackers.
 *
 * Nothing in this directory may import React or touch the DOM: the whole
 * pipeline moves into a Worker in Phase 11 unchanged
 * (docs/decisions/0003-worker-boundary.md), and an assertion script checks
 * the imports.
 */
import type { ExpertCategory, ProtocolLayer, ProtocolType } from '../../types/packet';
import type { TcpStreamTracker } from '../tcpStreamTracker';
import type { IcmpEchoTracker } from '../icmpEchoTracker';
import type { QuicFlowTracker } from '../quicFlowTracker';

/** pcap/pcapng link types this dissector distinguishes (LINKTYPE_* values). */
export const LINKTYPE = {
  NULL: 0,        // BSD loopback: 4-byte AF header
  ETHERNET: 1,
  RAW_IP: 101,
  LINUX_SLL: 113,
  LINUX_SLL2: 276,
} as const;

export interface DissectInput {
  /** Captured bytes. A view over a larger buffer whenever possible - never copied to be dissected. */
  bytes: Uint8Array;
  /** Wire length; equals `bytes.length` unless a snaplen truncated the capture. */
  origLen: number;
  linktype: number;
  /** 1-based frame number within the capture. */
  frameNo: number;
  /** Epoch microseconds. Exact as a JS number until the year 2255. */
  tsUs: number;
  /** Index into the capture's interface list; 0 for a single-interface capture. */
  iface: number;
}

export interface ExpertItem {
  /** What the reader should conclude - see `types/packet.ts`. */
  category: ExpertCategory;
  message: string;
}

/**
 * Everything the list, the filters, the colour rules, the aggregates and the
 * trackers need, and nothing the tree needs on its own.
 */
export interface DissectSummary {
  source: string;
  destination: string;
  srcPort?: number;
  dstPort?: number;
  protocol: ProtocolType;
  protocolLabel?: string;
  info: string;
  length: number;
  /** Keyed by registry abbrev (fieldRegistry.ts). */
  fields: Record<string, string | number | boolean>;
  frameProtocols: string[];
  analysisFlags?: string[];
  expert?: ExpertItem[];
  streamId?: number;
  /**
   * Header positions the summary pass established, so the tree pass never
   * re-walks encapsulation to find them. `vlanDepth` counts 802.1Q/QinQ tags.
   */
  offsets: { l2: number; l3?: number; l4?: number; payload?: number; vlanDepth: number };
  /**
   * The eagerly built tree, present only while a frame's dissectors are
   * un-migrated. Deleted when the last one moves to `dissectTree`.
   */
  legacyLayers?: ProtocolLayer[];
}

/** Per-capture state that only arrival-order processing may touch. */
export interface DissectContext {
  tcp: TcpStreamTracker;
  icmp: IcmpEchoTracker;
  quic: QuicFlowTracker;
  /** Live capture only: the adapter, for the Frame layer's interface rows. */
  captureInterface?: { name: string; label: string };
}

export type DissectSummaryFn = (input: DissectInput, ctx: DissectContext) => DissectSummary;
export type DissectTreeFn = (input: DissectInput, summary: DissectSummary) => ProtocolLayer[];
