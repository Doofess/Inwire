/**
 * Applying a patch a later frame produced to an earlier frame's row.
 *
 * `dissect/types.ts` states the rule this implements: *"Single-pass dissection
 * cannot see the future, so the frame that learns the fact hands it back and
 * the caller patches the list."* Four mechanisms produce them - `[TCP PDU
 * reassembled in N]`, `[Reassembled in N]`, `dns.response_in`, and ICMP
 * `(reply in N)`.
 *
 * ## Why it is here and not in `pcapParser.ts`
 *
 * It lived there, next to the dissector that produces the patches, which read
 * naturally and cost more than it looked. `captureWriter.ts` applies patches to
 * rows still inside its staging horizon, so importing this pulled the whole
 * 1,334-line parser - and everything it reaches - into the **capture store
 * process**, which has no business knowing how to dissect anything and no DOM
 * to satisfy the types that come with it.
 *
 * Fifteen lines that need `Packet` and `InfoPatch` and nothing else. Beside the
 * type it implements is where they belong. `pcapParser.ts` re-exports it, so
 * every existing caller is unchanged.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from './types';

/** Applies one patch to a packet, in place. */
export function applyInfoPatch(packet: Packet, patch: InfoPatch): void {
  if (patch.suffix) packet.info += patch.suffix;
  if (patch.protocolLabel) packet.protocolLabel = patch.protocolLabel;
  if (patch.responseInFrame !== undefined) {
    packet.fields = { ...(packet.fields ?? {}), 'dns.response_in': patch.responseInFrame };
    for (const layer of packet.layers ?? []) {
      if (layer.name !== 'Domain Name System') continue;
      layer.fields.push({
        name: '[Response In]', value: patch.responseInFrame, generated: true,
        linkToFrame: patch.responseInFrame, abbrev: 'dns.response_in',
      });
    }
  }
}
