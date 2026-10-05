/**
 * A frame's layer tokens as Wireshark spells `frame.protocols`:
 * `eth:ethertype:ip:tcp`, where `Packet.frameProtocols` holds
 * `frame:eth:ip:tcp`.
 *
 * Two differences, both in how the reference names what this build already
 * knows:
 * - **No `frame`.** The reference's list is of what the frame *carries*; this
 *   build lists the Frame layer itself, because a bare `frame` is a layer test
 *   like any other (`filter/fields.ts`).
 * - **`ethertype` after a header that dispatches on one.** The reference runs
 *   a separate EtherType dissector between Ethernet II, an 802.1Q tag or Linux
 *   cooked capture and what they carry, and lists it. An 802.3 frame hands
 *   over to LLC instead and has no such step: `eth:llc:stp`.
 *
 * The tree's `[Protocols in frame]` row and the `frame.protocols` filter both
 * read this, so a filter copied out of Wireshark - `frame.protocols contains
 * "eth:ethertype:ip"` - matches here too.
 */
const DISPATCHES_ON_ETHERTYPE = new Set(['eth', 'vlan', 'sll']);

export function protocolsInFrame(tokens: readonly string[]): string {
  const out: string[] = [];
  tokens.forEach((token, i) => {
    if (token === 'frame') return;
    out.push(token);
    const next = tokens[i + 1];
    if (DISPATCHES_ON_ETHERTYPE.has(token) && next !== undefined && next !== 'llc') out.push('ethertype');
  });
  return out.join(':');
}
