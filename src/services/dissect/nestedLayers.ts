/**
 * A protocol carried inside another protocol's tree, as the reference draws
 * one: NTLMSSP inside SPNEGO's negTokenTarg, SPNEGO inside GSS-API, NTLMSSP
 * inside a DCE/RPC Auth Info. Each is a protocol of its own - the frame's
 * chain reads `...smb2:gss-api:spnego:ntlmssp` and the bareword `ntlmssp`
 * answers - but its rows sit at one place inside its carrier's rows, and the
 * carrier's rows go on after it (SPNEGO's mechListMIC follows the NTLMSSP
 * message its responseToken held).
 *
 * So the dissector returns each as a layer of its own, which is where the
 * chain is read from, and says which row of the carrier it belongs under.
 * `nestLayers` moves it there once the chain has been taken - the same
 * order `nestQuotedLayers` keeps for an ICMP error's quoted datagram.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

/** The row each nested layer is drawn as, by layer. */
const HEADINGS = new WeakMap<ProtocolLayer, ProtocolField>();

/**
 * A heading row for `layer`, to be placed in the carrier's rows where the
 * reference draws the protocol. It is empty until `nestLayers` fills it.
 */
export function headingFor(layer: ProtocolLayer): ProtocolField {
  const heading: ProtocolField = {
    name: layer.summary || layer.name, value: '',
    ...(layer.rawBytesRange ? { rawBytesRange: layer.rawBytesRange } : {}),
  };
  HEADINGS.set(layer, heading);
  return heading;
}

/** Moves every layer that has a heading into it, and out of the frame's list. */
export function nestLayers(layers: ProtocolLayer[]): void {
  for (let i = layers.length - 1; i >= 0; i--) {
    const heading = HEADINGS.get(layers[i]);
    if (heading === undefined) continue;
    heading.children = layers[i].fields;
    layers.splice(i, 1);
  }
}
