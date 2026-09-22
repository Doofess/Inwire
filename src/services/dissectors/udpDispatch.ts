/**
 * Which subdissector reads a UDP payload, by the ports it arrived on.
 *
 * This was an `else if` chain in `pcapParser.ts` with one block per protocol,
 * each of them the same eight lines: run the dissector, and on a result copy
 * `protocolLabel`, `info`, the layer, the token and the fields into the
 * variables the caller is assembling. Six copies of it was tolerable; the
 * batch of leaf protocols that followed would have made it thirteen, and a
 * chain that long is where a missing `protocolTokens.push` hides - which is
 * exactly the bug `PROTOCOL_NAME_MAP` had for NTP and STUN.
 *
 * Only the **simple** protocols live here: the ones whose whole output is a
 * label, an Info line, one tree layer and a bag of fields. DHCP, DNS, NBNS and
 * QUIC stay where they are, because each returns something more - resolved
 * names, a matched query frame, a tracker's state - and folding them into a
 * table would mean the table's result type carried four optional members that
 * every entry below leaves unset.
 *
 * (That last clause used to read "nine of thirteen entries", counting the
 * table as it stood when it was split out. It has grown since - Kerberos
 * arrived in `9ac9111` - so it is stated as a property rather than a count,
 * which is what it was always asserting.)
 */
import type { ProtocolLayer } from '../../types/packet';

/** Everything a leaf UDP dissector produces. */
export interface SimpleUdpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * The table this file used to hold now lives in `dispatch.ts`, beside the
 * ethertype and IP-protocol tables that had the same shape and were three
 * separate `if` chains. What stays here is the result type every leaf UDP
 * dissector returns, which is imported by all fourteen of them.
 */
