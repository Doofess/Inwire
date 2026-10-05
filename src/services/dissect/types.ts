/**
 * The types the dissection pass hands back: a transport decoder's result, an
 * info patch, and the link types the front door distinguishes.
 *
 * ## What this file used to hold, and why it does not
 *
 * ADR 0001 specified a **two-phase dissector**: `dissectSummary`, run once per
 * frame and the only place trackers may be advanced, and `dissectTree`, run on
 * demand for the one frame someone clicked. The interfaces for it were written
 * here - `DissectSummary` (with `offsets`, an `ExpertItem[]` and a
 * `legacyLayers` escape hatch) and `DissectInput` - and **the migration was
 * never done**: `decodeRawEthernetPacket` builds the full `ProtocolLayer[]` for
 * every frame, and every dissector added since is written on that shape.
 *
 * ADR 0011 measured it before anyone finished it, and the measurement went the
 * other way: the tree is **~6% of dissection**, not the 90 the plan assumed.
 * So the split *"remains the right contract - the tree is 89% of a buffer's
 * memory (ADR 0007) and the Worker already discards most of them - so it stays
 * a memory and design argument, not a speed one"*, and **anyone picking it up
 * should not expect it to move the frame rate**.
 *
 * The interfaces are gone because a type nothing implements is not a contract,
 * it is a claim that the work is underway. `git show` at
 * `docs/decisions/0011-dissection-cost-is-not-the-tree.md` is where the shape
 * lives now. Two traps if it is ever revived: `ExpertItem` here collided by
 * name with the live, differently-shaped `ExpertItem` in `services/expertInfo.ts`,
 * and a `legacyLayers` field is how a half-finished migration hides.
 *
 * Nothing in this directory may import React or touch the DOM
 * (docs/decisions/0003-worker-boundary.md): the pipeline runs in a Worker,
 * `src/workers/pipeline.worker.ts`, and an assertion script checks the imports.
 */
import type { Packet, ProtocolLayer } from '../../types/packet';

/**
 * A pcapng Decryption Secrets Block's type for an NSS key log: "TLSK" as four
 * ASCII bytes. The registry has others (WireGuard, ZigBee), none of which this
 * build produces or consumes.
 *
 * Here rather than beside the writer because the READER needs it too, and the
 * reader is `pcapParser.ts`, in the entry chunk: importing the constant from
 * the writer pulled the whole pcapng writer into every launch.
 */
export const DSB_SECRETS_TYPE_TLS_KEY_LOG = 0x544c534b;

/** pcap/pcapng link types this dissector distinguishes (LINKTYPE_* values). */
export const LINKTYPE = {
  NULL: 0,        // BSD loopback: 4-byte AF header
  ETHERNET: 1,
  RAW_IP: 101,
  // OpenBSD's loopback. The same 4-byte address family as NULL, except it is
  // always big-endian rather than the capturing host's order - which
  // `dissectNull` already resolves by checking both and letting the IP version
  // nibble settle it, so this maps onto that decoder rather than needing one.
  // Missing from this table meant an imported OpenBSD loopback capture fell
  // through to Ethernet, which is the same misparse as a live Npcap loopback
  // capture and for the same reason.
  LOOP: 108,
  LINUX_SLL: 113,
  LINUX_SLL2: 276,
} as const;

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
  /**
   * The datagram an ICMP error quotes back, for the caller to recurse into.
   *
   * It is handed back rather than dissected in place because only
   * `decodeNetworkLayer` holds the `layers` array the inner packet's own
   * layers belong in - the same reason GRE and VXLAN recurse from there. The
   * `end` is the quoted bytes' own bound: an error carries the original IP
   * header plus eight bytes of what followed it, and NOT the datagram whose
   * length that header declares.
   */
  embeddedNetwork?: { offset: number; etherType: number; end: number };
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
  /**
   * Links to a later frame that the earlier frame's TREE gains:
   * `{ 'tcp.reassembled_in': 12 }` on each segment frame 12 completed,
   * `{ 'icmp.resp_in': 42 }` on the request reply 42 answered. Written as
   * fields too, so they filter and are stored with the row; `TREE_LINKS` in
   * `infoPatch.ts` says which layer each is drawn under, and the revisit and
   * replay paths hand them back to a rebuilt tree.
   */
  links?: Record<string, number>;
}
