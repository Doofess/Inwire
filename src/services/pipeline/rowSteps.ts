/**
 * What `ingest` does to a row after dissection, split between a shard and the
 * merge (ADR 0053 phase 6).
 *
 * The single Worker, per row and in this order: `annotatePacket`,
 * `markLiveGap`, `learnOrLabelFingerprint`, `networkFacts.observe`. The first
 * two depend only on the row and the socket table, so a shard runs them on its
 * own copy of the table, before the row is packed and into the tree it keeps.
 * The last two are state in capture order - what a fingerprint has been seen
 * from, how often a MAC forwarded - so they stay on the coordinator, which runs
 * them in merged order from a `RowSide`: the few inputs they read, taken off
 * the row by the shard. `scripts/pipeline/row-steps.ts` holds the split to the
 * single Worker's output.
 */
import type { Packet, ProtocolField, ProtocolLayer } from '../../types/packet';
import type { FlowAnnotationStore } from '../flowAnnotations';
import type { HostIdentity } from '../direction';
import { annotatePacket } from '../dissect/processFields';
import { markLiveGap } from '../dissect/liveGapFields';
import { learnOrLabelFingerprint, type ClientFingerprintStore } from '../dissect/clientFingerprints';
import { forwardingOf, tlsFactsOf, type NetworkFactsCollector, type TlsFacts } from '../networkFacts';
import type { RowOverlay } from './rowOverlay';

/** The merge's inputs from one row. Every key is absent when the row has nothing for it. */
export interface RowSide {
  /** `tls.handshake.ja4`, when a non-empty string. */
  ja4?: string;
  /** `inwire.process.name`, only beside `ja4`: it decides between learning and labelling. */
  process?: string;
  /** The MAC this machine's off-link frame was addressed to (`forwardingOf`). */
  forwardTo?: string;
  /** The inputs of `observeTls`, only for a TLS frame with something in them to observe. */
  tls?: TlsFacts;
  /** `tls.stream` while it is still a placeholder, for the coordinator to settle. */
  tlsStream?: number;
  /** The row has a protocol `networkFacts.observe` reads whole: the merge needs it decoded. */
  needsRow?: true;
}

/** `ingest`'s first two steps, on a packet that still holds its tree. */
export function shardRowSteps(
  packet: Packet, annotations: FlowAnnotationStore, holeBefore: number | undefined,
): void {
  annotatePacket(packet, annotations);
  if (holeBefore !== undefined) markLiveGap(packet, holeBefore);
}

/** The side record of a row the shard steps have run on, or undefined when it would be empty. */
export function rowSide(packet: Packet, host: HostIdentity): RowSide | undefined {
  let side: RowSide | undefined;
  const fields = packet.fields;
  if (fields !== undefined) {
    const ja4 = fields['tls.handshake.ja4'];
    if (typeof ja4 === 'string' && ja4 !== '') {
      side = { ja4 };
      const process = fields['inwire.process.name'];
      if (typeof process === 'string' && process !== '') side.process = process;
    }
    const stream = fields['tls.stream'];
    if (typeof stream === 'number' && stream < 0) (side ??= {}).tlsStream = stream;
  }
  const forwardTo = forwardingOf(packet, host);
  if (forwardTo !== null) (side ??= {}).forwardTo = forwardTo;
  const protocols = packet.frameProtocols;
  if (protocols !== undefined) {
    for (let i = 0; i < protocols.length; i++) {
      switch (protocols[i]) {
        case 'tls': {
          const tls = tlsFactsOf(packet);
          // `observeTls` does nothing for a frame that is neither DoT nor named.
          if (tls.port === 853 || tls.sni !== null) (side ??= {}).tls = tls;
          break;
        }
        case 'dns': case 'dhcp': case 'bootp': case 'icmpv6': case 'arp': case 'lldp':
          (side ??= {}).needsRow = true;
          break;
        default: break;
      }
    }
  }
  return side;
}

export interface MergeContext {
  fingerprints: ClientFingerprintStore;
  facts: NetworkFactsCollector;
  host: HostIdentity;
}

/**
 * `ingest`'s last two steps, from a side record and in merged order.
 *
 * The match a fingerprint gains goes into `overlay` (made when it was null,
 * extended in place otherwise) and its tree row comes back as `frameRows`, for
 * the shard's cached tree. `tls.stream` is not touched: the coordinator settles
 * it, since it numbers streams in capture order.
 */
export function mergeRowSide(
  side: RowSide | undefined, ctx: MergeContext, overlay: RowOverlay | null,
): { overlay: RowOverlay | null; frameRows: ProtocolField[] } {
  if (side === undefined) return { overlay, frameRows: [] };
  let frameRows: ProtocolField[] = [];
  if (side.ja4 !== undefined) {
    const fields: Record<string, string | number> = { 'tls.handshake.ja4': side.ja4 };
    if (side.process !== undefined) fields['inwire.process.name'] = side.process;
    const stub: ProtocolLayer = { name: 'Frame', summary: '', fields: [] };
    learnOrLabelFingerprint(fields, ctx.fingerprints, [stub]);
    const match = fields['inwire.process.ja4_match'];
    if (match !== undefined) {
      ((overlay ??= {}).fields ??= {})['inwire.process.ja4_match'] = match;
      frameRows = stub.fields;
    }
  }
  if (side.forwardTo !== undefined) ctx.facts.observeForwardedTo(side.forwardTo, ctx.host);
  if (side.tls !== undefined) ctx.facts.observeTlsFacts(side.tls);
  return { overlay, frameRows };
}
