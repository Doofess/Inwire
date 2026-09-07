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
import type { ExpertCategory, Packet, ProtocolLayer, ProtocolType } from '../../types/packet';
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

/**
 * What a transport decoder returns.
 *
 * Named rather than written inline on `decodeTransportLayer`, which is where it
 * lived while that function was the only thing that could produce one. Each
 * per-protocol branch is its own function now and they all answer in this
 * shape, so the shape needs a name they can share.
 */
export interface TransportResult {
  proto: Packet['protocol'];
  protocolLabel?: string;
  srcPort?: number;
  dstPort?: number;
  info: string;
  layer: ProtocolLayer;
  /**
   * Layers sitting above the transport header - DNS over UDP, for instance.
   * Separate from `layer` because the transport decoder owns exactly one
   * header of its own, and a subdissector that claims the payload adds to the
   * stack rather than replacing it.
   */
  extraLayers?: ProtocolLayer[];
  /**
   * Extra `frameProtocols` tokens for a dissector that claims the payload
   * without contributing a layer of its own - QUIC, whose only tree output is
   * the TLS handshake it carries, and SSDP, which is one request line. Without
   * these the bareword `quic` in a filter or a colour rule would have no layer
   * to find, which is the same gap the extension-header walker fills.
   */
  protocolTokens?: string[];
  streamId?: number;
  status?: Packet['status'];
  analysisFlags?: string[];
  fields?: Record<string, string | number>;
  icmpMatchedRequestFrameId?: number;
  /** Earlier frames that carried parts of a TLS record this segment completed. */
  reassembledFrom?: number[];
  /** Earlier frames whose Protocol label this segment's ServerHello settled. */
  labelPatches?: { frameId: number; protocolLabel: string }[];
  /** The query frame this DNS response answers, for its "[Response In]" patch. */
  dnsMatchedQueryFrameId?: number;
  /** Names this frame mapped to addresses, for passive name resolution. */
  resolvedNames?: { name: string; addresses: string[] }[];
}

/**
 * A change to an EARLIER frame's Info that only this frame can know about.
 *
 * "[TCP PDU reassembled in 12]" on frames 10 and 11 is written by frame 12,
 * the one that completed the record; "(reply in 42)" on a ping request is
 * written by the reply. Single-pass dissection cannot see the future, so the
 * frame that learns the fact hands it back and the caller patches the list -
 * the import path directly, the live path on its next flush.
 */
export interface InfoPatch {
  frameId: number;
  /** Appended to the frame's Info. */
  suffix?: string;
  /** Replaces the frame's Protocol label - a ClientHello re-labelled with the negotiated version. */
  protocolLabel?: string;
  /**
   * The frame that answered this DNS query. Recorded as a field rather than
   * appended to Info, because Wireshark shows it in the tree only - the query
   * row's Info stays as it was.
   */
  responseInFrame?: number;
}
