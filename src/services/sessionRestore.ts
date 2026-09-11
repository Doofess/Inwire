import { Packet, PacketStatus, ProtocolType } from '../types/packet';
import type { DnsTracker } from './dnsTracker';
import type { InfoPatch } from './pcapParser';
import { decodeRawEthernetPacket, indexOfFrame } from './pcapParser';
import { TcpStreamTracker } from './tcpStreamTracker';
import { IcmpEchoTracker } from './icmpEchoTracker';
import { QuicFlowTracker } from './quicFlowTracker';
import type { L3Tracker } from './l3Tracker';
import type { HostIdentity } from './direction';

/**
 * One frame in the smallest form `restoreBatch` can rebuild a Packet from.
 *
 * This was the shape a session was stored in, and it is now what the **tabular
 * importer** builds: a spreadsheet row is not a frame, and turning one into a
 * Packet is the same job as turning a stored frame into one, so the two share
 * this type and the function below rather than growing a second path that
 * decodes almost the same way.
 *
 * `raw` is absent when there are no bytes to dissect - the agent sent metadata
 * only, or the spreadsheet had no hex column. In that case `fallback` carries
 * the handful of display fields that packet ever had, so it comes back exactly
 * as unhelpful as it originally was rather than being silently dropped or,
 * worse, reconstructed with invented payload.
 */
export interface StoredFrame {
  id: number;
  /** Epoch milliseconds. Kept for frames stored before `tsUs` existed. */
  timestamp: number;
  /** Epoch microseconds; absent on frames stored by an older build. */
  tsUs?: number;
  relativeTime: number;
  timeDelta: number;
  length: number;
  interfaceName?: string;
  raw?: Uint8Array;
  fallback?: {
    source: string;
    destination: string;
    sourcePort?: number;
    destPort?: number;
    protocol: string;
    /**
     * The free-form protocol name, when it differs from the coarse `protocol`.
     *
     * A live agent frame never sets this - it has no dissector to name a layer.
     * A frame reconstructed from a spreadsheet row does: the Protocol column
     * holds what the packet list displayed ("TLSv1.2"), which is not a member
     * of `ProtocolType`, so the two halves have to travel separately.
     */
    protocolLabel?: string;
    info: string;
    /** Absent means 'ok', which is what a frame with no bytes to judge gets. */
    status?: PacketStatus;
  };
}

/**
 * Rebuilding live Packets from the frames a previous session stored.
 *
 * The rule this module exists to keep: a restored packet must be
 * indistinguishable from the one that was originally captured. That is why it
 * decodes through `decodeRawEthernetPacket` - the same function live capture
 * and pcap import both use - rather than reconstructing anything of its own.
 */

/**
 * The Packet built when the agent sent metadata but no bytes.
 *
 * Shared by live ingest and restore so the two cannot drift. Byte data is left
 * genuinely empty rather than fabricated: a frame with no captured bytes has
 * no hex dump, and inventing one would be worse than showing none.
 */
/** A stored frame's capture time in microseconds, whichever build stored it. */
export function storedFrameTsUs(frame: { tsUs?: number; timestamp: number }): number {
  return frame.tsUs ?? Math.round(frame.timestamp * 1000);
}

export function buildFallbackPacket(fields: {
  id: number;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  length: number;
  source?: string;
  destination?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  /** See `StoredFrame.fallback.protocolLabel` - set by tabular import only. */
  protocolLabel?: string;
  info?: string;
  status?: PacketStatus;
  /**
   * Where this frame came from, for the Frame layer and the interface column.
   *
   * Defaults to the live agent because that is who originally had no bytes to
   * send. A spreadsheet import passes its filename instead: a row read out of
   * `capture.csv` claiming it was captured on "Live Agent" is a small lie that
   * survives into the detail pane and the interface filter.
   */
  sourceLabel?: string;
  /** Why there are no bytes, in the Frame summary's parenthetical. */
  frameNote?: string;
}): Packet {
  const length = fields.length || 0;
  const sourceLabel = fields.sourceLabel || 'Live Agent';
  const frameNote = fields.frameNote || 'no raw capture data was available';
  return {
    id: fields.id,
    tsUs: fields.tsUs,
    relativeTime: fields.relativeTime,
    timeDelta: fields.timeDelta,
    source: fields.source || '0.0.0.0',
    destination: fields.destination || '0.0.0.0',
    sourcePort: fields.sourcePort,
    destPort: fields.destPort,
    protocol: (fields.protocol || 'TCP') as ProtocolType,
    protocolLabel: fields.protocolLabel,
    length,
    info: fields.info || 'Traffic',
    status: fields.status || 'ok',
    layers: [
      {
        name: 'Frame',
        summary: `Frame ${fields.id}: ${length} bytes (${frameNote})`,
        fields: [
          { name: 'Interface', value: sourceLabel },
          { name: 'Length', value: `${length} bytes` },
        ],
      },
    ],
    rawBytes: new Uint8Array(0),
    interfaceName: sourceLabel,
  };
}

export interface RestoreTrackers {
  tcpTracker: TcpStreamTracker;
  icmpTracker: IcmpEchoTracker;
  quicTracker: QuicFlowTracker;
  /** DNS query/response pairing; order-dependent like the others. */
  dnsTracker: DnsTracker;
  /**
   * IP fragments and ARP bindings. Optional so a caller that predates it - the
   * tabular importer, whose rows are already whole frames - still type-checks;
   * without it a restored capture simply does not report duplicate addresses.
   */
  l3Tracker?: L3Tracker;
}

/**
 * Decodes one batch of stored frames.
 *
 * Must be called in ascending id order across the whole restore, and with the
 * same tracker instances throughout: the TCP, ICMP and QUIC trackers are
 * stateful and order-dependent, so stream ids, retransmission flags and
 * request/reply pairings only come out matching the original capture if the
 * frames are replayed in the order they arrived. Batching exists to let the
 * caller yield to the browser between batches, not to reorder anything.
 *
 * Returns the packets plus any ICMP reply pairings found, which the caller
 * applies to already-restored packets the same way live ingest does.
 */
export function restoreBatch(
  frames: StoredFrame[],
  trackers: RestoreTrackers,
  /**
   * Adapter label -> adapter id, from the session's interface table.
   *
   * A stored frame remembers the label it was captured on; the Frame layer
   * also shows the id, and only this table can map back to it. Without it a
   * restored frame reports itself as an imported capture on "eth0" - which is
   * what the detail window surfaced.
   */
  interfaceIdByLabel?: Map<string, string>,
  /**
   * Overrides for frames that have no bytes, used by the tabular importer.
   *
   * A session restore leaves this unset and gets the live-agent wording it has
   * always had; a spreadsheet import names the file it came from instead.
   */
  fallbackOrigin?: { sourceLabel: string; frameNote: string },
  /**
   * Whether the restored frames carry their protocol tree.
   *
   * The app restores without it, for the same reason it imports without it: a
   * tree is 10.6 kB against the frame's own 1.2 kB and the detail pane is the
   * only thing that reads one, so it is rebuilt on demand
   * (docs/decisions/0007). Scripts that assert on tree content ask for it.
   */
  keepTrees = false,
  /**
   * Whose machine took the capture, from the session's own metadata.
   *
   * The direction pass that runs after a restore cannot stand in for this: the
   * checksum verdict is decided *during* dissection and lands in a tree row,
   * an expert finding and a dense column, none of which can be rewritten
   * afterwards. A restore without it shows "Bad checksum" on every frame this
   * machine sent - most of them, and exactly the offload artefact the expert
   * categories exist to stop reporting. See `SessionMeta.host`.
   */
  host?: HostIdentity,
): { packets: Packet[]; icmpReplies: { requestFrameId: number; replyId: number }[]; infoPatches: InfoPatch[] } {
  const packets: Packet[] = [];
  const icmpReplies: { requestFrameId: number; replyId: number }[] = [];
  const infoPatches: InfoPatch[] = [];

  for (const frame of frames) {
    // Only claim an adapter the session's own table can actually identify.
    //
    // A looser rule - trust `frame.interfaceName` whenever it is set - is
    // wrong, and measurably so: `Packet.interfaceName` falls back to the
    // literal string "eth0" when a frame had no capture interface, which is
    // indistinguishable from a real adapter label. Trusting it turned every
    // interface-less frame into one captured on an adapter named "eth0" and
    // broke the round-trip equality this module exists to guarantee.
    const interfaceId = frame.interfaceName ? interfaceIdByLabel?.get(frame.interfaceName) : undefined;
    const captureInterface = interfaceId !== undefined && frame.interfaceName
      ? { name: interfaceId, label: frame.interfaceName }
      : undefined;

    if (frame.raw && frame.raw.length > 0) {
      const decoded = decodeRawEthernetPacket(
        frame.raw,
        frame.id,
        storedFrameTsUs(frame),
        frame.relativeTime,
        frame.timeDelta,
        frame.length,
        trackers.tcpTracker,
        trackers.icmpTracker,
        trackers.quicTracker,
        trackers.dnsTracker,
        captureInterface,
        undefined,
        trackers.l3Tracker,
        host,
      );
      // The tree has done its work by here - it is what the fields, the Info
      // line and the expert findings were read out of - and keeping one per
      // frame is 89% of a restored buffer's memory. The detail pane rebuilds
      // the one tree it needs by replaying that frame's conversation
      // (docs/decisions/0007).
      if (!keepTrees) decoded.packet.layers = [];
      packets.push(decoded.packet);
      if (decoded.icmpMatchedRequestFrameId !== undefined) {
        icmpReplies.push({ requestFrameId: decoded.icmpMatchedRequestFrameId, replyId: frame.id });
      }
      if (decoded.infoPatches) infoPatches.push(...decoded.infoPatches);
    } else {
      packets.push(
        buildFallbackPacket({
          id: frame.id,
          tsUs: storedFrameTsUs(frame),
          relativeTime: frame.relativeTime,
          timeDelta: frame.timeDelta,
          length: frame.length,
          ...frame.fallback,
          ...fallbackOrigin,
        }),
      );
    }
  }

  return { packets, icmpReplies, infoPatches };
}

/**
 * Applies ICMP reply pairings to packets already in the buffer.
 *
 * A reply names a request that arrived earlier, so during a chunked restore
 * the request is usually in a batch that has already been committed. Returns
 * the same array unchanged when nothing matched, so React can skip the update.
 */
export function applyIcmpReplies(
  packets: Packet[],
  replies: { requestFrameId: number; replyId: number }[],
): Packet[] {
  if (replies.length === 0) return packets;
  const next = packets.slice();
  return applyIcmpRepliesInPlace(next, replies) ? next : packets;
}

/**
 * The same, written into `packets` directly. **The caller must own the array.**
 *
 * A reply names the frame it answers by id, so this reaches for that frame
 * rather than walking every frame to ask whether it is the one. The `.map` this
 * replaces cost 14.1 ms a pass at a million frames and ran on every flush that
 * carried a single reply (`scripts/perf/buffer-cost.ts`).
 */
export function applyIcmpRepliesInPlace(
  packets: Packet[],
  replies: { requestFrameId: number; replyId: number }[],
): boolean {
  let changed = false;
  for (const reply of replies) {
    const at = indexOfFrame(packets, reply.requestFrameId);
    if (at < 0) continue;
    const p = packets[at];
    packets[at] = { ...p, info: `${p.info} (reply in ${reply.replyId})` };
    changed = true;
  }
  return changed;
}
