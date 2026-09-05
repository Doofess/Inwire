/**
 * DHCP (RFC 2131/2132) and DHCPv6 (RFC 8415) - the messages that put a device
 * on the network, and therefore the messages that name it: option 12 is the
 * hostname the device calls itself, option 60 its vendor class, option 55
 * the parameter list that fingerprints its operating system, option 81 its
 * FQDN. The passive name-resolution map (spec Phase 10) is fed from here.
 *
 * Info lines follow Wireshark: `DHCP Request  - Transaction ID 0xa3b590d4`
 * (the type name padded to eight characters, which is why "ACK" carries five
 * spaces) and `Solicit XID: 0x1a2b3c CID: ...` for v6.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

/**
 * One decoder, not one per call. `new TextDecoder()` is not free, and these
 * sites are per-DNS-label / per-field / per-frame - a CPU profile put
 * TextDecoder construction at 8% of a dissection run. It carries no state
 * across `decode()` calls unless `{stream: true}` is used, which nothing here
 * does, so a shared instance is exactly equivalent.
 *
 * `new TextDecoder()` and `new TextDecoder('utf-8', {fatal: false})` are the
 * same thing: utf-8, non-fatal, is the default.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

const MESSAGE_TYPE_NAMES: Record<number, string> = {
  1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform',
  9: 'Force Renew', 10: 'Lease query', 11: 'Lease Unassigned', 12: 'Lease Unknown', 13: 'Lease Active',
};

const OPTION_NAMES: Record<number, string> = {
  1: 'Subnet Mask', 2: 'Time Offset', 3: 'Router', 6: 'Domain Name Server', 12: 'Host Name', 15: 'Domain Name',
  26: 'Interface MTU', 28: 'Broadcast Address', 31: 'Perform Router Discover', 33: 'Static Route', 42: 'Network Time Protocol Servers',
  43: 'Vendor-Specific Information', 44: 'NetBIOS over TCP/IP Name Server', 46: 'NetBIOS over TCP/IP Node Type',
  47: 'NetBIOS over TCP/IP Scope', 50: 'Requested IP Address', 51: 'IP Address Lease Time', 52: 'Option Overload',
  53: 'DHCP Message Type', 54: 'DHCP Server Identifier', 55: 'Parameter Request List', 56: 'Message', 57: 'Maximum DHCP Message Size',
  58: 'Renewal Time Value', 59: 'Rebinding Time Value', 60: 'Vendor class identifier', 61: 'Client identifier',
  66: 'TFTP Server Name', 67: 'Bootfile name', 77: 'User Class Information', 81: 'Client Fully Qualified Domain Name',
  82: 'Agent Information Option', 93: 'Client System Architecture', 94: 'Client Network Device Interface',
  97: 'UUID/GUID-based Client Identifier', 108: 'IPv6-Only Preferred', 114: 'DHCP Captive-Portal', 116: 'DHCP Auto-Configuration',
  118: 'Subnet Selection Option', 119: 'Domain Search', 121: 'Classless Static Route', 125: 'V-I Vendor-specific Information',
  145: 'Forcerenew Nonce Protocol', 249: 'Private/Classless Static Route (Microsoft)', 252: 'Private/Proxy autodiscovery', 255: 'End',
};

const HARDWARE_TYPE_NAMES: Record<number, string> = { 1: 'Ethernet', 6: 'IEEE 802', 15: 'Frame Relay', 16: 'ATM', 20: 'Serial Line' };

export interface DhcpResult {
  protocolLabel: 'DHCP' | 'DHCPv6';
  info: string;
  fields: Record<string, string | number>;
  layer: ProtocolLayer;
  /** Facts other layers want: who this is. */
  hostname?: string;
  clientMac?: string;
  yourIp?: string;
  vendorClass?: string;
  parameterRequestList?: number[];
  messageType?: string;
}

const ip4 = (b: Uint8Array, p: number) => `${b[p]}.${b[p + 1]}.${b[p + 2]}.${b[p + 3]}`;
const mac = (b: Uint8Array, p: number, n: number) => Array.from(b.subarray(p, p + n)).map((x) => x.toString(16).padStart(2, '0')).join(':');
const u32 = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
const text = (b: Uint8Array, p: number, n: number) => utf8Decoder.decode(b.subarray(p, p + n)).replace(/\0+$/, '');

/** BOOTP/DHCP on UDP 67/68. */
export function dissectDhcp(b: Uint8Array, start: number, end: number): DhcpResult | null {
  if (end - start < 240) return null;
  const op = b[start];
  const htype = b[start + 1];
  const hlen = b[start + 2];
  const hops = b[start + 3];
  const xid = u32(b, start + 4);
  const secs = (b[start + 8] << 8) | b[start + 9];
  const flags = (b[start + 10] << 8) | b[start + 11];
  const ciaddr = ip4(b, start + 12);
  const yiaddr = ip4(b, start + 16);
  const siaddr = ip4(b, start + 20);
  const giaddr = ip4(b, start + 24);
  const chaddr = htype === 1 && hlen === 6 ? mac(b, start + 28, 6) : mac(b, start + 28, Math.min(16, hlen));
  const magic = u32(b, start + 236);
  if (magic !== 0x63825363) return null;

  const result: DhcpResult = {
    protocolLabel: 'DHCP', info: '', fields: {}, layer: { name: 'Dynamic Host Configuration Protocol', summary: '', fields: [] },
    clientMac: chaddr,
  };
  const optionFields: ProtocolField[] = [];
  let p = start + 240;
  let messageType: number | undefined;
  const fields = result.fields;
  while (p < end) {
    const code = b[p];
    if (code === 255) { optionFields.push({ name: 'Option: (255) End', value: '', rawBytesRange: [p, p] }); break; }
    if (code === 0) { p++; continue; }
    if (p + 1 >= end) break;
    const len = b[p + 1];
    const v = p + 2;
    if (v + len > end) break;
    const name = OPTION_NAMES[code] ?? 'Unknown';
    let value = '';
    switch (code) {
      case 53: messageType = b[v]; value = `${MESSAGE_TYPE_NAMES[b[v]] ?? 'Unknown'} (${b[v]})`; break;
      case 1: case 3: case 6: case 28: case 42: case 44: case 50: case 54: case 118: {
        const addrs: string[] = [];
        for (let q = v; q + 4 <= v + len; q += 4) addrs.push(ip4(b, q));
        value = addrs.join(', ');
        if (code === 50) fields['dhcp.option.requested_ip_address'] = addrs[0] ?? '';
        if (code === 54) fields['dhcp.option.dhcp_server_id'] = addrs[0] ?? '';
        break;
      }
      case 12: case 15: case 60: case 66: case 67: case 56: {
        value = text(b, v, len);
        if (code === 12) { result.hostname = value; fields['dhcp.option.hostname'] = value; }
        if (code === 60) { result.vendorClass = value; fields['dhcp.option.vendor_class_id'] = value; }
        if (code === 15) fields['dhcp.option.domain_name'] = value;
        break;
      }
      case 51: case 58: case 59: case 2: value = `(${u32(b, v)}s) ${describeSeconds(u32(b, v))}`; break;
      case 55: {
        const list = Array.from(b.subarray(v, v + len));
        result.parameterRequestList = list;
        value = list.map((c) => `${OPTION_NAMES[c] ?? 'Unknown'} (${c})`).join(', ');
        fields['dhcp.option.request_list'] = list.join(',');
        break;
      }
      case 57: value = String((b[v] << 8) | b[v + 1]); break;
      case 61: {
        const kind = b[v];
        value = kind === 1 && len === 7 ? `Ethernet: ${mac(b, v + 1, 6)}` : `type ${kind}: ${mac(b, v + 1, len - 1)}`;
        fields['dhcp.client_id'] = value;
        break;
      }
      case 81: {
        const flagsByte = b[v];
        const fqdn = text(b, v + 3, len - 3);
        value = `flags 0x${flagsByte.toString(16).padStart(2, '0')}, ${fqdn}`;
        fields['dhcp.fqdn.name'] = fqdn;
        break;
      }
      case 93: value = String((b[v] << 8) | b[v + 1]); break;
      case 119: value = `${len} bytes (domain search list)`; break;
      default: value = Array.from(b.subarray(v, v + len)).map((x) => x.toString(16).padStart(2, '0')).join(':');
    }
    optionFields.push({
      name: `Option: (${code}) ${name}`, value, rawBytesRange: [p, v + len - 1],
      children: [{ name: 'Length', value: len, rawBytesRange: [p + 1, p + 1] }],
    });
    p = v + len;
  }

  const typeName = messageType !== undefined ? (MESSAGE_TYPE_NAMES[messageType] ?? `Unknown (${messageType})`) : (op === 1 ? 'Boot Request' : 'Boot Reply');
  result.messageType = typeName;
  result.info = `DHCP ${typeName.padEnd(8)} - Transaction ID 0x${xid.toString(16).padStart(8, '0')}`;
  result.yourIp = yiaddr !== '0.0.0.0' ? yiaddr : undefined;
  fields['dhcp.type'] = op;
  fields['dhcp.id'] = xid;
  if (messageType !== undefined) fields['dhcp.option.dhcp'] = messageType;
  fields['dhcp.hw.mac_addr'] = chaddr;
  if (yiaddr !== '0.0.0.0') fields['dhcp.ip.your'] = yiaddr;
  result.layer = {
    name: 'Dynamic Host Configuration Protocol',
    summary: `Dynamic Host Configuration Protocol (${typeName})`,
    rawBytesRange: [start, end - 1],
    fields: [
      { name: 'Message type', value: op === 1 ? 'Boot Request (1)' : op === 2 ? 'Boot Reply (2)' : String(op), rawBytesRange: [start, start], abbrev: 'dhcp.type' },
      { name: 'Hardware type', value: `${HARDWARE_TYPE_NAMES[htype] ?? 'Unknown'} (0x${htype.toString(16).padStart(2, '0')})`, rawBytesRange: [start + 1, start + 1] },
      { name: 'Hardware address length', value: hlen, rawBytesRange: [start + 2, start + 2] },
      { name: 'Hops', value: hops, rawBytesRange: [start + 3, start + 3] },
      { name: 'Transaction ID', value: `0x${xid.toString(16).padStart(8, '0')}`, rawBytesRange: [start + 4, start + 7], abbrev: 'dhcp.id' },
      { name: 'Seconds elapsed', value: secs, rawBytesRange: [start + 8, start + 9] },
      { name: 'Bootp flags', value: `0x${flags.toString(16).padStart(4, '0')}, ${flags & 0x8000 ? 'Broadcast' : 'Unicast'}`, rawBytesRange: [start + 10, start + 11] },
      { name: 'Client IP address', value: ciaddr, rawBytesRange: [start + 12, start + 15] },
      { name: 'Your (client) IP address', value: yiaddr, rawBytesRange: [start + 16, start + 19], abbrev: 'dhcp.ip.your' },
      { name: 'Next server IP address', value: siaddr, rawBytesRange: [start + 20, start + 23] },
      { name: 'Relay agent IP address', value: giaddr, rawBytesRange: [start + 24, start + 27] },
      { name: 'Client MAC address', value: chaddr, rawBytesRange: [start + 28, start + 28 + Math.max(1, Math.min(16, hlen)) - 1], abbrev: 'dhcp.hw.mac_addr' },
      { name: 'Magic cookie', value: 'DHCP', rawBytesRange: [start + 236, start + 239] },
      ...optionFields,
    ],
  };
  return result;
}

function describeSeconds(s: number): string {
  if (s === 0xffffffff) return 'infinity';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d} day${d === 1 ? '' : 's'}`);
  if (h) parts.push(`${h} hour${h === 1 ? '' : 's'}`);
  if (m) parts.push(`${m} minute${m === 1 ? '' : 's'}`);
  if (sec || parts.length === 0) parts.push(`${sec} second${sec === 1 ? '' : 's'}`);
  return parts.join(', ');
}

// --- DHCPv6 --------------------------------------------------------------------

const V6_MESSAGE_NAMES: Record<number, string> = {
  1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply', 8: 'Release',
  9: 'Decline', 10: 'Reconfigure', 11: 'Information-request', 12: 'Relay-forw', 13: 'Relay-repl',
};
const V6_OPTION_NAMES: Record<number, string> = {
  1: 'Client Identifier', 2: 'Server Identifier', 3: 'Identity Association for Non-temporary Address', 5: 'IA Address',
  6: 'Option Request', 7: 'Preference', 8: 'Elapsed time', 12: 'Server unicast', 13: 'Status code', 14: 'Rapid Commit',
  16: 'Vendor Class', 17: 'Vendor-specific Information', 23: 'DNS recursive name server', 24: 'Domain Search List',
  25: 'Identity Association for Prefix Delegation', 26: 'IA Prefix', 39: 'Fully Qualified Domain Name', 82: 'SOL_MAX_RT',
};

export function dissectDhcpv6(b: Uint8Array, start: number, end: number): DhcpResult | null {
  if (end - start < 4) return null;
  const msgType = b[start];
  const name = V6_MESSAGE_NAMES[msgType];
  if (name === undefined) return null;
  const xid = ((b[start + 1] << 16) | (b[start + 2] << 8) | b[start + 3]) >>> 0;
  const optionFields: ProtocolField[] = [];
  const fields: Record<string, string | number> = { 'dhcpv6.msgtype': msgType, 'dhcpv6.xid': xid };
  const result: DhcpResult = { protocolLabel: 'DHCPv6', info: '', fields, layer: { name: 'DHCPv6', summary: '', fields: [] }, messageType: name };
  let p = start + 4;
  let cid = '';
  while (p + 4 <= end) {
    const code = (b[p] << 8) | b[p + 1];
    const len = (b[p + 2] << 8) | b[p + 3];
    const v = p + 4;
    if (v + len > end) break;
    let value = '';
    if (code === 1 || code === 2) {
      const duidType = (b[v] << 8) | b[v + 1];
      const hex = Array.from(b.subarray(v, v + len)).map((x) => x.toString(16).padStart(2, '0')).join('');
      value = `DUID type ${duidType}: ${hex}`;
      if (code === 1) { cid = hex; fields['dhcpv6.duid.bytes'] = hex; }
      if (duidType === 3 && len >= 10) result.clientMac = mac(b, v + 4, 6);
      if (duidType === 1 && len >= 14) result.clientMac = mac(b, v + 8, 6);
    } else if (code === 39) {
      value = text(b, v + 1, len - 1);
      result.hostname = value;
      fields['dhcpv6.client_domain'] = value;
    } else if (code === 8) {
      value = `${((b[v] << 8) | b[v + 1]) * 10} ms`;
    } else if (code === 6) {
      const list: number[] = [];
      for (let q = v; q + 2 <= v + len; q += 2) list.push((b[q] << 8) | b[q + 1]);
      value = list.map((c) => `${V6_OPTION_NAMES[c] ?? 'Unknown'} (${c})`).join(', ');
    } else {
      value = `${len} bytes`;
    }
    optionFields.push({ name: `${V6_OPTION_NAMES[code] ?? 'Unknown'} (${code})`, value, rawBytesRange: [p, v + len - 1] });
    p = v + len;
  }
  result.info = `${name} XID: 0x${xid.toString(16)}${cid ? ` CID: ${cid}` : ''}`;
  result.layer = {
    name: 'DHCPv6',
    summary: `DHCPv6 (${name})`,
    rawBytesRange: [start, end - 1],
    fields: [
      { name: 'Message type', value: `${name} (${msgType})`, rawBytesRange: [start, start], abbrev: 'dhcpv6.msgtype' },
      { name: 'Transaction ID', value: `0x${xid.toString(16).padStart(6, '0')}`, rawBytesRange: [start + 1, start + 3], abbrev: 'dhcpv6.xid' },
      ...optionFields,
    ],
  };
  return result;
}
