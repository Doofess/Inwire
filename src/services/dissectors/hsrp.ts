/**
 * HSRP (RFC 2281), UDP 1985 - Cisco's answer to "which router is the gateway".
 *
 *   Hello (state Active)
 *   Coup (state Standby)
 *
 * Two or more routers share one virtual address; one is Active and the others
 * wait. The reason this is worth reading is that **a gateway failover is
 * invisible in the traffic it disrupts** - every host keeps sending to the
 * same address and the same virtual MAC, so the capture shows a few seconds of
 * loss with no cause in it. The cause is here: a Coup, a Resign, or an Active
 * router that simply stopped saying Hello.
 *
 * **A datagram on port 1985 addressed to a host is not HSRP**, and that rule
 * is in `udpDispatch.ts` rather than here. It is Wireshark's: verified by
 * probing, the reference analyzer reads a frame to 224.0.0.2 as HSRP and the
 * byte-identical frame to a unicast address as plain UDP. The port is
 * unregistered and low-numbered enough that something else will land on it,
 * and the group address is what separates a protocol from a coincidence.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';

export interface HsrpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** The all-routers group v1 uses, and v2's own. */
export const HSRP_V1_GROUP = '224.0.0.2';
export const HSRP_V2_GROUP = '224.0.0.102';

const OPCODES: Record<number, string> = { 0: 'Hello', 1: 'Coup', 2: 'Resign' };

const STATES: Record<number, string> = {
  0: 'Initial', 1: 'Learn', 2: 'Listen', 4: 'Speak', 8: 'Standby', 16: 'Active',
};

/** RFC 2281 §5: the packet is exactly 20 bytes. */
const PACKET_BYTES = 20;

const utf8 = new TextDecoder('utf-8', { fatal: false });

export function dissectHsrp(bytes: Uint8Array, start: number, end: number): HsrpResult | null {
  if (start + PACKET_BYTES > end) return null;
  const version = bytes[start];
  if (version !== 0) return null;   // v2 has a different, TLV-shaped packet
  const opcode = bytes[start + 1];
  const state = bytes[start + 2];
  const opcodeName = OPCODES[opcode];
  const stateName = STATES[state];
  if (opcodeName === undefined || stateName === undefined) return null;

  const helloTime = bytes[start + 3];
  const holdTime = bytes[start + 4];
  const priority = bytes[start + 5];
  const group = bytes[start + 6];
  // The eight authentication bytes are a cleartext password padded with NULs.
  // It is shown because RFC 2281 §5.1 is explicit that it provides no security
  // whatsoever - it exists to stop misconfiguration, not an attacker - so
  // hiding it would imply a protection that is not there.
  const authEnd = (() => {
    let e = start + 16;
    while (e > start + 8 && bytes[e - 1] === 0) e--;
    return e;
  })();
  const auth = utf8.decode(bytes.subarray(start + 8, authEnd));
  const virtualIp = formatIpv4Address(bytes, start + 16);

  const fields: Record<string, string | number> = {
    'hsrp.version': version,
    'hsrp.opcode': opcode,
    'hsrp.state': state,
    'hsrp.hellotime': helloTime,
    'hsrp.holdtime': holdTime,
    'hsrp.priority': priority,
    'hsrp.group': group,
    'hsrp.auth_data': auth,
    'hsrp.virt_ip': virtualIp,
  };

  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'hsrp.version', rawBytesRange: [start, start] },
    { name: 'Op Code', value: `${opcodeName} (${opcode})`, abbrev: 'hsrp.opcode',
      rawBytesRange: [start + 1, start + 1] },
    { name: 'State', value: `${stateName} (${state})`, abbrev: 'hsrp.state',
      rawBytesRange: [start + 2, start + 2] },
    { name: 'Hellotime', value: `Default (${helloTime})`, abbrev: 'hsrp.hellotime',
      rawBytesRange: [start + 3, start + 3] },
    { name: 'Holdtime', value: `Default (${holdTime})`, abbrev: 'hsrp.holdtime',
      rawBytesRange: [start + 4, start + 4] },
    { name: 'Priority', value: priority, abbrev: 'hsrp.priority',
      rawBytesRange: [start + 5, start + 5] },
    { name: 'Group', value: group, abbrev: 'hsrp.group', rawBytesRange: [start + 6, start + 6] },
    { name: 'Authentication Data', value: auth, abbrev: 'hsrp.auth_data',
      rawBytesRange: [start + 8, start + 15] },
    { name: 'Virtual IP Address', value: virtualIp, abbrev: 'hsrp.virt_ip',
      rawBytesRange: [start + 16, start + 19] },
  ];

  return {
    protocolLabel: 'HSRP',
    info: `${opcodeName} (state ${stateName})`,
    fields,
    layer: {
      name: 'Cisco Hot Standby Router Protocol',
      summary: `Cisco Hot Standby Router Protocol (${opcodeName})`,
      rawBytesRange: [start, start + PACKET_BYTES - 1],
      fields: rows,
    },
  };
}
