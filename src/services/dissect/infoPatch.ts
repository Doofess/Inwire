/**
 * Applying a patch a later frame produced to an earlier frame's row.
 *
 * `dissect/types.ts` states the rule this implements: *"Single-pass dissection
 * cannot see the future, so the frame that learns the fact hands it back and
 * the caller patches the list."* They are Info suffixes (`[TCP PDU reassembled
 * in N]`, `[Reassembled in N]`), Protocol labels, and the tree links in
 * `TREE_LINKS` below. ICMP's `(reply in N)` suffix travels separately, as the
 * batch's `icmpReplies`.
 *
 * ## Why it is here and not in `pcapParser.ts`
 *
 * It lived there, next to the dissector that produces the patches, which read
 * naturally and cost more than it looked. `captureWriter.ts` applies patches to
 * rows still inside its staging horizon, so importing this pulled the whole
 * parser - and everything it reaches - into the **capture store process**,
 * which has no business knowing how to dissect anything and no DOM to satisfy
 * the types that come with it. (A line count stood here and went stale within
 * two commits; "the whole parser" is the part that was load-bearing.)
 *
 * Fifteen lines that need `Packet` and `InfoPatch` and nothing else. Beside the
 * type it implements is where they belong. `pcapParser.ts` re-exports it, so
 * every existing caller is unchanged.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from './types';

/**
 * Every fact a LATER frame writes into an earlier frame's tree, and where it
 * is drawn: the layer, and the row's label as the reference spells it.
 *
 * Single-pass dissection learns each of these only when the later frame
 * arrives, so they travel as patches - onto the buffered row, onto the stored
 * row, and into a tree still in the Worker's cache - and a tree rebuilt later
 * from the record or by a replay gets them back from the row's fields
 * (`treeLinksOf`). A network engineer navigates by exactly these rows: from a
 * segment to the frame its PDU was reassembled in, from a fragment to its
 * datagram, from a request to its answer.
 */
export const TREE_LINKS: Readonly<Record<string, { layer: string; name: string; after?: string }>> = {
  'dns.response_in': { layer: 'Domain Name System', name: '[Response In]' },
  'tcp.reassembled_in': { layer: 'Transmission Control Protocol', name: '[Reassembled PDU in frame]' },
  'ip.reassembled_in': { layer: 'Internet Protocol Version 4', name: '[Reassembled IPv4 in frame]' },
  'ipv6.reassembled.in': { layer: 'Internet Protocol Version 6', name: '[Reassembled IPv6 in frame]' },
  'icmp.resp_in': { layer: 'Internet Control Message Protocol', name: '[Response frame]' },
  'icmpv6.resp_in': { layer: 'Internet Control Message Protocol v6', name: '[Response In]' },
  // Drawn where the reference draws it, after the request's opnum.
  'dcerpc.response_in': { layer: 'Distributed Computing Environment / Remote Procedure Call (DCE/RPC)', name: 'Response in frame', after: 'dcerpc.opnum' },
};

/** Applies one patch to a packet, in place. */
export function applyInfoPatch(packet: Packet, patch: InfoPatch): void {
  if (patch.suffix) packet.info += patch.suffix;
  if (patch.protocolLabel) packet.protocolLabel = patch.protocolLabel;
  const links: Record<string, number> = { ...patch.links };
  if (patch.responseInFrame !== undefined) links['dns.response_in'] = patch.responseInFrame;
  for (const [abbrev, frame] of Object.entries(links)) {
    packet.fields = { ...(packet.fields ?? {}), [abbrev]: frame };
    const where = TREE_LINKS[abbrev];
    // The outermost layer of that name: an ICMP error quotes an IP header of
    // its own, and the link belongs to the frame's, not the quoted one's.
    const layer = where === undefined ? undefined : packet.layers?.find((l) => l.name === where.layer);
    if (where === undefined || layer === undefined || layer.fields.some((f) => f.abbrev === abbrev)) continue;
    const row = { name: where.name, value: frame, generated: true, linkToFrame: frame, abbrev };
    const at = where.after === undefined ? -1 : layer.fields.findIndex((f) => f.abbrev === where.after);
    if (at >= 0) layer.fields.splice(at + 1, 0, row);
    else layer.fields.push(row);
  }
}

/**
 * The tree links a frame's row already carries, for a tree rebuilt after the
 * later frame wrote them - by the record (`pipeline.worker.ts`) or by a replay
 * (`usePacketDetail.ts`). `read` is how that caller reads a field.
 */
export function treeLinksOf(read: (abbrev: string) => unknown): Record<string, number> | undefined {
  let out: Record<string, number> | undefined;
  for (const abbrev of Object.keys(TREE_LINKS)) {
    const value = read(abbrev);
    if (typeof value === 'number') (out ??= {})[abbrev] = value;
  }
  return out;
}
