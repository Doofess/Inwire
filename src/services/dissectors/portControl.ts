/**
 * NAT-PMP (RFC 6886) and PCP (RFC 6887): how a host asks its gateway for an
 * external address and a port forward, on UDP 5351, and how the gateway
 * announces a restart to everyone on 5350.
 *
 *   External Address Response
 *   Map TCP Request
 *   Map Request: 51413 -> 51413 [TCP]
 *
 * macOS, iOS, game consoles and every BitTorrent client do this unprompted,
 * so a laptop's capture has it whether or not anybody configured a forward -
 * and it says what the router answered, which is the question when "the port
 * is open but nothing connects".
 *
 * One port, two protocols, told apart by the version byte as the reference
 * tells them: 0 is NAT-PMP, 1 and 2 are PCP. The reference names the PCP
 * layer `portcontrol` and NAT-PMP's `nat-pmp`, and so do the layers here.
 *
 * PCP writes every address as IPv6, an IPv4 one mapped (`::ffff:192.0.2.1`),
 * and the tree prints it exactly so (`formatIpv6Address`).
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';
import { hexColons } from '../dissect/hexBytes';
import type { LeafResult } from './dispatch';

const NAT_PMP_OPCODES: Record<number, string> = {
  0: 'External Address Request', 128: 'External Address Response', 1: 'Map UDP Request', 129: 'Map UDP Response',
  2: 'Map TCP Request', 130: 'Map TCP Response',
};
const NAT_PMP_RESULTS: Record<number, string> = {
  0: 'Success', 1: 'Unsupported Version', 2: 'Not Authorized/Refused', 3: 'Network Failure',
  4: 'Out of resources', 5: 'Unsupported opcode',
};
const PCP_OPCODES: Record<number, string> = { 0: 'Announce', 1: 'Map', 2: 'Peer' };
const PCP_RESULTS: Record<number, string> = {
  0: 'Success', 1: 'Unsupported Version', 2: 'Not Authorized/Refused', 3: 'Malformed Request',
  4: 'Unsupported opcode', 5: 'Unsupported option', 6: 'Malformed option', 7: 'Network failure', 8: 'No resources',
  9: 'Unsupported protocol', 10: 'User exceeds quota', 11: 'Cannot provide external port', 12: 'Address mismatch',
  13: 'Excessive remote peers',
};
const PCP_OPTIONS: Record<number, string> = {
  0: 'Reserved', 1: 'Third Party', 2: 'Prefer Failure', 3: 'Filter', 128: 'Description', 129: 'Prefix64', 130: 'Port Set',
};
/**
 * MAP's and PEER's shared rows, each under its own opcode's names - spelled
 * out whole, because a name assembled from a prefix is one the registry's
 * scanner cannot see.
 */
const MAP_ROWS = {
  nonce: 'portcontrol.map.nonce', protocol: 'portcontrol.map.protocol', internal: 'portcontrol.map.internal_port',
  suggestedPort: 'portcontrol.map.req_sug_external_port', suggestedIp: 'portcontrol.map.req_sug_external_ip',
  assignedPort: 'portcontrol.map.rsp_assigned_external_port', assignedIp: 'portcontrol.map.rsp_assigned_ext_ip',
} as const;
const PEER_ROWS = {
  nonce: 'portcontrol.peer.nonce', protocol: 'portcontrol.peer.protocol', internal: 'portcontrol.peer.internal_port',
  suggestedPort: 'portcontrol.peer.req_sug_external_port', suggestedIp: 'portcontrol.peer.req_sug_external_ip',
  assignedPort: 'portcontrol.peer.rsp_assigned_external_port', assignedIp: 'portcontrol.peer.rsp_assigned_ext_ip',
} as const;

/** The transports a mapping's Info names; the reference prints others as their number. */
const IP_PROTOCOLS: Record<number, string> = { 6: 'TCP', 17: 'UDP' };

const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const u32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const named = (table: Record<number, string>, value: number) => `${table[value] ?? 'Unknown'} (${value})`;
const utf8 = new TextDecoder('utf-8', { fatal: false });

function row(name: string, value: string | number, abbrev: string, from: number, length: number): ProtocolField {
  return { name, value, abbrev, rawBytesRange: [from, from + length - 1] };
}

/** NAT-PMP: a version 0 message. */
function natPmp(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start + 2 > end) return null;
  const opcode = b[start + 1];
  const response = opcode >= 128;
  const rows: ProtocolField[] = [
    row('Version', 0, 'nat-pmp.version', start, 1),
    row('Opcode', named(NAT_PMP_OPCODES, opcode), 'nat-pmp.opcode', start + 1, 1),
  ];
  const fields: Record<string, string | number> = { 'nat-pmp.version': 0, 'nat-pmp.opcode': opcode };
  let at = start + 2;
  if (response && at + 6 <= end) {
    fields['nat-pmp.result_code'] = u16(b, at);
    rows.push(
      row('Result Code', named(NAT_PMP_RESULTS, u16(b, at)), 'nat-pmp.result_code', at, 2),
      row('Seconds Since Start of Epoch', u32(b, at + 2), 'nat-pmp.sssoe', at + 2, 4),
    );
    at += 6;
  } else if (!response && opcode !== 0 && at + 2 <= end) {
    rows.push(row('Reserved', u16(b, at), 'nat-pmp.reserved', at, 2));
    at += 2;
  }
  if (opcode === 128 && at + 4 <= end) {
    const external = formatIpv4Address(b, at);
    fields['nat-pmp.external_ip'] = external;
    rows.push(row('External IP Address', external, 'nat-pmp.external_ip', at, 4));
  } else if ((opcode & 0x7f) !== 0 && at + 8 <= end) {
    fields['nat-pmp.internal_port'] = u16(b, at);
    fields['nat-pmp.external_port'] = u16(b, at + 2);
    rows.push(
      row('Internal Port', u16(b, at), 'nat-pmp.internal_port', at, 2),
      row(response ? 'Mapped External Port' : 'Requested External Port', u16(b, at + 2), 'nat-pmp.external_port', at + 2, 2),
      row(response ? 'Port Mapping Lifetime' : 'Requested Port Mapping Lifetime', u32(b, at + 4), 'nat-pmp.pml', at + 4, 4),
    );
  }
  const info = NAT_PMP_OPCODES[opcode] ?? `Unknown opcode (${opcode})`;
  return {
    protocolLabel: 'NAT-PMP',
    info,
    layer: { name: 'NAT Port Mapping Protocol', summary: `NAT Port Mapping Protocol, ${info}`, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
    token: 'nat-pmp',
  };
}

/** A PCP option (RFC 6887 §7.3): code, reserved, length, then data padded to four. */
function pcpOptions(b: Uint8Array, at: number, end: number): ProtocolField[] {
  const options: ProtocolField[] = [];
  while (at + 4 <= end && options.length < 64) {
    const code = b[at];
    const length = u16(b, at + 2);
    const data = at + 4;
    const stop = Math.min(end, data + length);
    const children: ProtocolField[] = [
      row('Option', named(PCP_OPTIONS, code), 'portcontrol.option.code', at, 1),
      row('Reserved', b[at + 1], 'portcontrol.option.reserved', at + 1, 1),
      row('Option Length', length, 'portcontrol.option.length', at + 2, 2),
    ];
    if (code === 1 && data + 16 <= stop) {
      children.push(row('Internal IP Address', formatIpv6Address(b, data), 'portcontrol.option.third_party.internal_ip', data, 16));
    } else if (code === 3 && data + 20 <= stop) {
      children.push(
        row('Reserved', b[data], 'portcontrol.option.filter.reserved', data, 1),
        row('Prefix Length', b[data + 1], 'portcontrol.option.filter.prefix_length', data + 1, 1),
        row('Remote Peer Port', u16(b, data + 2), 'portcontrol.option.filter.remote_peer_port', data + 2, 2),
        row('Remote Peer IP Address', formatIpv6Address(b, data + 4), 'portcontrol.option.filter.remote_peer_ip', data + 4, 16),
      );
    } else if (code === 128 && length > 0) {
      children.push(row('Description', utf8.decode(b.subarray(data, stop)), 'portcontrol.option.description', data, stop - data));
    } else if (code !== 2 && length > 0) {
      children.push({
        name: `Unknown option: ${code}`, value: '', abbrev: 'portcontrol.option.unknown',
        expertInfo: { message: `Unknown option: ${code}` },
      });
    }
    const padded = data + Math.ceil(length / 4) * 4;
    if (padded > stop && padded <= end) {
      children.push(row('Padding', hexColons(b, stop, padded), 'portcontrol.option.padding', stop, padded - stop));
    }
    options.push({
      name: 'Option', value: PCP_OPTIONS[code] ?? 'Unknown', abbrev: 'portcontrol.option',
      rawBytesRange: [at, Math.min(end, padded) - 1], children,
    });
    at = padded;
  }
  return options;
}

/** PCP: a version 1 or 2 message. Version 1 has no mapping nonce. */
function pcp(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start + 24 > end) return null;
  const version = b[start];
  const response = (b[start + 1] & 0x80) !== 0;
  const opcode = b[start + 1] & 0x7f;
  const opName = PCP_OPCODES[opcode] ?? `Unknown (${opcode})`;
  const direction = response ? 'Response' : 'Request';
  const rows: ProtocolField[] = [
    row('Version', version, 'portcontrol.version', start, 1),
    { ...row('R', direction, 'portcontrol.r', start + 1, 1), bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 } },
    { ...row('Opcode', named(PCP_OPCODES, opcode), 'portcontrol.opcode', start + 1, 1), bitfield: { bitOffset: 1, bitLength: 7, totalBits: 8 } },
  ];
  const fields: Record<string, string | number> = { 'portcontrol.version': version, 'portcontrol.opcode': opcode };
  let at: number;
  if (response) {
    fields['portcontrol.result_code'] = b[start + 3];
    rows.push(
      row('Reserved', b[start + 2], 'portcontrol.reserved', start + 2, 1),
      row('Result Code', named(PCP_RESULTS, b[start + 3]), 'portcontrol.result_code', start + 3, 1),
      row('Lifetime', u32(b, start + 4), 'portcontrol.lifetime_rsp', start + 4, 4),
      row('Epoch Time', u32(b, start + 8), 'portcontrol.epoch_time', start + 8, 4),
      row('Reserved', hexColons(b, start + 12, start + 24), 'portcontrol.rsp_reserved', start + 12, 12),
    );
  } else {
    rows.push(
      row('Reserved', u16(b, start + 2), 'portcontrol.reserved', start + 2, 2),
      row('Requested Lifetime', u32(b, start + 4), 'portcontrol.lifetime_req', start + 4, 4),
      row('Client IP Address', formatIpv6Address(b, start + 8), 'portcontrol.client_ip', start + 8, 16),
    );
  }
  at = start + 24;

  let info = `${opName} ${direction}`;
  const body: ProtocolField[] = [];
  if (opcode === 1 || opcode === 2) {
    const names = opcode === 1 ? MAP_ROWS : PEER_ROWS;
    const nonce = version >= 2 ? 12 : 0;
    if (at + nonce + 24 <= end) {
      if (nonce > 0) body.push(row('Mapping Nonce', hexColons(b, at, at + 12), names.nonce, at, 12));
      at += nonce;
      const protocol = b[at];
      const internal = u16(b, at + 4);
      const external = u16(b, at + 6);
      fields[names.internal] = internal;
      body.push(
        row('Protocol', protocol, names.protocol, at, 1),
        // The reference reads MAP's three reserved bytes as a number and
        // PEER's as bytes; drawn as each is drawn there.
        opcode === 1
          ? row('Reserved', (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3], 'portcontrol.map.reserved', at + 1, 3)
          : row('Reserved', hexColons(b, at + 1, at + 4), 'portcontrol.peer.reserved', at + 1, 3),
        row('Internal Port', internal, names.internal, at + 4, 2),
        response
          ? row('Assigned External Port', external, names.assignedPort, at + 6, 2)
          : row('Suggested External Port', external, names.suggestedPort, at + 6, 2),
        response
          ? row('Assigned External IP Address', formatIpv6Address(b, at + 8), names.assignedIp, at + 8, 16)
          : row('Suggested External IP Address', formatIpv6Address(b, at + 8), names.suggestedIp, at + 8, 16),
      );
      at += 24;
      if (opcode === 2 && at + 20 <= end) {
        body.push(
          row('Remote Peer Port', u16(b, at), 'portcontrol.peer.remote_peer_port', at, 2),
          row('Reserved', hexColons(b, at + 2, at + 4), 'portcontrol.peer.reserved', at + 2, 2),
          row('Remote Peer IP Address', formatIpv6Address(b, at + 4), 'portcontrol.peer.remote_peer_ip', at + 4, 16),
        );
        at += 20;
      }
      if (opcode === 1) info += `: ${internal} -> ${external} [${IP_PROTOCOLS[protocol] ?? protocol}]`;
    }
  }
  rows.push({ name: `${opName} ${direction}`, value: '', rawBytesRange: [start + 24, Math.max(start + 24, at) - 1], ...(body.length > 0 ? { children: body } : {}) });
  if (at < end) {
    rows.push({ name: 'Options', value: '', abbrev: 'portcontrol.options', rawBytesRange: [at, end - 1], children: pcpOptions(b, at, end) });
  }
  return {
    protocolLabel: `PCP v${version}`,
    info,
    layer: { name: 'Port Control Protocol', summary: `Port Control Protocol, ${opName} ${direction}`, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
    token: 'portcontrol',
  };
}

/** UDP 5350/5351: NAT-PMP by version 0, PCP by 1 or 2. */
export function dissectPortControl(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start >= end) return null;
  if (b[start] === 0) return natPmp(b, start, end);
  if (b[start] === 1 || b[start] === 2) return pcp(b, start, end);
  return null;
}

/**
 * Dropbox's LAN sync discovery (UDP 17500): a JSON broadcast every thirty
 * seconds from every Dropbox client on the segment, naming its host and
 * port. The reference draws it as a header of its own with the JSON beneath.
 */
export function dissectDropboxDiscovery(b: Uint8Array, start: number, end: number, json: (bytes: Uint8Array) => ProtocolLayer | null): LeafResult | null {
  if (start >= end || b[start] !== 0x7b /* { */) return null;
  const body = json(b.subarray(start, end));
  return {
    protocolLabel: body === null ? 'DB-LSP-DISC' : 'DB-LSP-DISC/JSON',
    info: body === null ? 'Dropbox LAN sync Discovery Protocol' : 'Dropbox LAN sync Discovery Protocol, JSON',
    layer: { name: 'Dropbox LAN sync Discovery Protocol', summary: 'Dropbox LAN sync Discovery Protocol', fields: [], rawBytesRange: [start, end - 1] },
    ...(body !== null ? { innerLayers: [body] } : {}),
  };
}
