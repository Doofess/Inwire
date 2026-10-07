/**
 * IEEE 1905.1a CMDUs (ethertype 0x893a) - the control protocol home mesh
 * routers use to describe their topology and link quality to each other, plus
 * the Wi-Fi Alliance's EasyMesh (Multi-AP) extensions on top of it. Common on
 * any capture taken behind a consumer router with mesh extenders, and on any
 * laptop joined to somebody else's: a Wi-Fi client overhears every multicast
 * one - topology discovery and notification, AP autoconfiguration search and
 * renew, push-button events.
 *
 * An 8-byte CMDU header, then a flat run of TLVs terminated by type 0. The
 * message and TLV names are the reference's own, generated into
 * `ieee1905Names.ts`; every TLV body below is held row for row to `tshark -T
 * pdml` by `scripts/ieee1905/dissect.ts`, and each layout was ported from the
 * reference's dissector rather than read off one vendor's mesh - the
 * hand-kept version had TLV types 6 and 7 swapped, names and bodies both,
 * which the fixture's own lengths happened to let through.
 *
 * **Where the reference reads bytes wrongly, this does not copy it**, and the
 * test leaves those rows out and asserts them itself: it reads IPv4 Type's
 * addresses little-endian (192.168.68.1 shows as 1.68.168.192), reads Push
 * Button Join's two MAC addresses two bytes long, and forgets to step past
 * the count in both interface power TLVs.
 *
 * A TLV with no body here draws its bytes as `ieee1905.tlv_data`, which is what
 * the reference draws for a type it has no dissector for. A fragment of a
 * message split across frames is drawn as `ieee1905.fragment.data` and its
 * TLVs are not read: the reference reassembles the pieces and this does not
 * yet.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv6Address, formatMac, toHex } from '../addressFormat';
import { MESSAGE_TYPES, TLV_TYPES } from './ieee1905Names';

/** The family the high byte of a media type names, then the variant within it. */
const MEDIA_TYPE_FAMILIES: Record<number, readonly string[]> = {
  0x00: ['IEEE 802.3u fast Ethernet', 'IEEE 802.3ab gigabit'],
  0x01: [
    'IEEE 802.11b (2.4 GHz)', 'IEEE 802.11g (2.4 GHz)', 'IEEE 802.11a (5 GHz)', 'IEEE 802.11n (2.4 GHz)',
    'IEEE 802.11n (5 GHz)', 'IEEE 802.11ac (5 GHz)', 'IEEE 802.11ad (60 GHz)', 'IEEE 802.11af (whitespace)',
    'IEEE 802.11ax', 'IEEE 802.11be',
  ],
  0x02: ['IEEE 1901 wavelet', 'IEEE 1901 FFT'],
  0x03: ['MoCA v1.1'],
};

const SERVICE_NAMES = ['Multi-AP Controller', 'Multi-AP Agent'];
const ROLE_NAMES = ['Registrar'];
const FREQ_BAND_NAMES = ['802.11 2.4 GHz', '802.11 5 GHz', '802.11 60 GHz', '802.11 6 GHz'];
const IPV4_ADDR_TYPES = ['Unknown', 'DHCP', 'Static', 'Auto-IP'];
const IPV6_ADDR_TYPES = ['Unknown', 'DHCP', 'Static', 'SLAAC'];
const PROFILE_VERSIONS = ['1905.1', '1905.1a'];
const POWER_STATES = ['PWR_OFF', 'PWR_ON', 'PWR_SAVE'];
const POWER_STATUSES = ['Request completed', 'No change made', 'Alternate change made'];

/**
 * The field names of TLVs that share a layout, spelled out whole so every one
 * is a literal `scripts/dissect/registry.ts` can find.
 */
const ADDRESS_FIELDS = {
  4: {
    count: 'ieee1905.ipv4_type.count', mac: 'ieee1905.ipv4_type.mac_address', addrCount: 'ieee1905.ipv4_type.addr_count',
    addrType: 'ieee1905.ipv4_type.addr_type', addr: 'ieee1905.ipv4_type.ipv4_addr', dhcp: 'ieee1905.ipv4_type.dhcp_server',
  },
  6: {
    count: 'ieee1905.ipv6_type.count', mac: 'ieee1905.ipv6_type.mac_address', addrCount: 'ieee1905.ipv6_type.addr_count',
    addrType: 'ieee1905.ipv6_type.addr_type', addr: 'ieee1905.ipv6_type.ipv6_addr', dhcp: 'ieee1905.ipv6_type.dhcp_server',
  },
} as const;
const POWER_FIELDS = {
  change: { count: 'ieee1905.power_chg.intf_count', mac: 'ieee1905.power_chg.mac_addr', state: 'ieee1905.power_chg.state' },
  status: { count: 'ieee1905.power_sts.intf_count', mac: 'ieee1905.power_sts.mac_addr', state: 'ieee1905.power_sts.state' },
} as const;
const SERVICE_FIELDS = {
  supported: { count: 'ieee1905.supported_service.service_count', service: 'ieee1905.supported_service.service' },
  searched: { count: 'ieee1905.searched_service.service_count', service: 'ieee1905.searched_service.service' },
} as const;

export interface Ieee1905DissectorResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields?: Record<string, string | number>;
}

const u16 = (b: Uint8Array, p: number) => (b[p] << 8) | b[p + 1];
const u32 = (b: Uint8Array, p: number) => (((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0);
const macAt = (b: Uint8Array, p: number) => formatMac(b.subarray(p, p + 6));
const hex = (b: Uint8Array, p: number, n: number) => toHex(b.subarray(p, p + n));
const hex2 = (n: number) => `0x${n.toString(16).padStart(2, '0')}`;
const ipv4At = (b: Uint8Array, p: number) => `${b[p]}.${b[p + 1]}.${b[p + 2]}.${b[p + 3]}`;
const ouiAt = (b: Uint8Array, p: number) => [b[p], b[p + 1], b[p + 2]].map((x) => x.toString(16).padStart(2, '0')).join(':');
/** `0x01, Multi-AP Agent`: a hex byte with its name appended, the reference's usual form. */
const named = (n: number, names: readonly string[]) => `${hex2(n)}, ${names[n] ?? 'Reserved'}`;
/** `1, DHCP`: the same with a decimal number. */
const namedDec = (n: number, names: readonly string[]) => `${n}, ${names[n] ?? 'Reserved'}`;
/** A zero-length byte field, which the reference shows as missing rather than empty. */
const bytesOrMissing = (b: Uint8Array, p: number, n: number) => (n > 0 ? hex(b, p, n) : '<MISSING>');

/** A fixed-width text field, up to its first NUL. */
function textAt(b: Uint8Array, p: number, n: number): string {
  let out = '';
  for (let i = p; i < p + n && i < b.length && b[i] !== 0; i++) out += String.fromCharCode(b[i]);
  return out;
}

/** A whole-byte-range field, which is most of what a TLV body is made of. */
const row = (name: string, value: string | number, abbrev: string, at: number, size: number): ProtocolField =>
  ({ name, value, abbrev, rawBytesRange: [at, at + Math.max(1, size) - 1] });

/** One bit of a byte, numbered from the most significant as the tree draws it. */
const bit = (name: string, set: boolean, abbrev: string, at: number, msbIndex: number, yes: string, no: string): ProtocolField =>
  ({ name, value: set ? yes : no, abbrev, rawBytesRange: [at, at], bitfield: { bitOffset: msbIndex, bitLength: 1, totalBits: 8 } });

/** A labelled group with no value of its own: "Bridging tuple 0", "IPv4 type list". */
const group = (name: string, from: number, to: number, children: ProtocolField[]): ProtocolField =>
  ({ name, value: '', rawBytesRange: [from, Math.max(from, to - 1)], children });

/**
 * The 2-byte media type, which the reference draws as a value plus its two
 * halves. The halves are not a bitfield - they are the two bytes, named
 * separately because the high byte selects the family (Ethernet, 802.11,
 * 1901, MoCA) and the low byte the variant within it.
 */
function mediaTypeRows(b: Uint8Array, at: number): ProtocolField {
  const high = b[at];
  const family = MEDIA_TYPE_FAMILIES[high];
  const name = family !== undefined ? family[b[at + 1]] ?? 'Reserved' : high === 0xff ? 'Unknown media' : 'Reserved';
  return {
    name: 'Media type',
    value: `0x${u16(b, at).toString(16).padStart(4, '0')}, ${name}`,
    abbrev: 'ieee1905.dev_info.media_type',
    rawBytesRange: [at, at + 1],
    children: [
      row('Media type bits 15 to 8', b[at], 'ieee1905.media_type.bits_15_to_8', at, 1),
      row('Media type bits 7 to 0', b[at + 1], 'ieee1905.media_type.bits_7_to_0', at + 1, 1),
    ],
  };
}

/** A list of one-byte services under its count, as Supported and Searched Service both are. */
function serviceRows(b: Uint8Array, v: number, end: number, kind: 'supported' | 'searched'): ProtocolField[] {
  const count = b[v];
  const label = kind === 'supported' ? 'Supported service' : 'Searched service';
  const services: ProtocolField[] = [];
  for (let i = 0; i < count && v + 1 + i < end; i++) {
    services.push(row(label, named(b[v + 1 + i], SERVICE_NAMES), SERVICE_FIELDS[kind].service, v + 1 + i, 1));
  }
  return [
    row(`${label} count`, count, SERVICE_FIELDS[kind].count, v, 1),
    group(`${label} list`, v + 1, v + 1 + services.length, services),
  ];
}

/** OUI, variant, then a length-prefixed blob: how a generic phy describes itself. */
function genericPhyRows(b: Uint8Array, p: number, end: number): { rows: ProtocolField[]; next: number } | null {
  if (p + 5 > end) return null;
  const specLen = b[p + 4];
  const specEnd = Math.min(end, p + 5 + specLen);
  return {
    rows: [
      row('Local interface OUI', ouiAt(b, p), 'ieee1905.local_intf.oui', p, 3),
      row('Local interface variant index', b[p + 3], 'ieee1905.local_intf.variant', p + 3, 1),
      row('Local interface media specific count', specLen, 'ieee1905.local_intf.media_count', p + 4, 1),
      row('Local interface media specific info', bytesOrMissing(b, p + 5, specEnd - p - 5), 'ieee1905.local_intf.spec_info', p + 5, specEnd - p - 5),
    ],
    next: specEnd,
  };
}

/**
 * One TLV's body, decoded per type.
 *
 * Every layout here was checked by summing its field sizes against the TLV's
 * own declared length on the fixture - a transmitter link metric is 12 bytes
 * of header plus 29 per link and declares 41 for one link, a receiver one is
 * 12 plus 23 and declares 35, and so on. A body that does not add up is a
 * body read wrongly, and the arithmetic catches it where eyes do not.
 *
 * An unknown type falls through to no rows at all, which leaves the TLV's own
 * type, length and byte range drawn and says nothing it cannot support.
 */
function tlvBodyRows(type: number, b: Uint8Array, v: number, len: number): ProtocolField[] {
  const end = v + len;
  const out: ProtocolField[] = [];

  switch (type) {
    case 0x01:
      if (len >= 6) out.push(row('1905 AL MAC address type', macAt(b, v), 'ieee1905.1905_al_mac_addr', v, 6));
      break;

    case 0x02:
      if (len >= 6) out.push(row('MAC address type', macAt(b, v), 'ieee1905.mac_addr', v, 6));
      break;

    case 0x03: {
      // AL MAC, then a count, then that many {MAC, media type, special info}.
      if (len < 7) break;
      out.push(row('1905 AL MAC address type', macAt(b, v), 'ieee1905.1905_al_mac_addr', v, 6));
      const count = b[v + 6];
      out.push(row('Local interface count', count, 'ieee1905.dev_info.local_int_cnt', v + 6, 1));
      let p = v + 7;
      for (let i = 0; i < count && p + 9 <= end; i++) {
        const specLen = b[p + 8];
        const children: ProtocolField[] = [
          row('MAC address type', macAt(b, p), 'ieee1905.mac_addr', p, 6),
          mediaTypeRows(b, p + 6),
          row('Special info length', specLen, 'ieee1905.dev_info.spec_info_len', p + 8, 1),
        ];
        if (specLen > 0 && p + 9 + specLen <= end) {
          children.push(row('Special info', hex(b, p + 9, specLen), 'ieee1905.dev_info.spec_info', p + 9, specLen));
        }
        out.push({ name: `Local interface ${i} device info`, value: macAt(b, p), rawBytesRange: [p, p + 8 + specLen], children });
        p += 9 + specLen;
      }
      break;
    }

    case 0x06: {
      // The local interface, then every non-1905 device seen through it.
      if (len < 6) break;
      out.push(row('Local interface MAC address', macAt(b, v), 'ieee1905.local_intf.mac_address', v, 6));
      const neighbors: ProtocolField[] = [];
      let p = v + 6;
      for (; p + 6 <= end; p += 6) neighbors.push(row('Neighbor MAC address', macAt(b, p), 'ieee1905.neighbor_al_mac_addr', p, 6));
      out.push(group('Non IEEE1905 neighbor devices', v + 6, p, neighbors));
      break;
    }

    case 0x07: {
      // The local interface, then every 1905 neighbour reachable through it,
      // each with one byte saying whether a bridge sits in between.
      if (len < 6) break;
      out.push(row('Local interface MAC address', macAt(b, v), 'ieee1905.local_intf.mac_address', v, 6));
      const neighbors: ProtocolField[] = [];
      let p = v + 6;
      for (; p + 7 <= end; p += 7) {
        neighbors.push(
          row('Neighbor MAC address', macAt(b, p), 'ieee1905.neighbor_al_mac_addr', p, 6),
          {
            // A bitmask's value names the flags that are set, as the reference's does.
            name: 'IEEE1905 neighbor flags', value: `${hex2(b[p + 6])}${b[p + 6] & 0x80 ? ', IEEE1905 bridges' : ''}`, abbrev: 'ieee1905.neighbor_flags', rawBytesRange: [p + 6, p + 6],
            children: [bit('IEEE1905 bridges', (b[p + 6] & 0x80) !== 0, 'ieee1905.bridges', p + 6, 0,
              'At least one IEEE 802.1 bridge exists between this device and the neighbor', 'No IEEE 802.1 bridges exist')],
          },
        );
      }
      out.push(group('IEEE1905 neighbor devices', v + 6, p, neighbors));
      break;
    }

    case 0x09: {
      // 12 bytes of who-to-whom, then 29 bytes per link.
      if (len < 12) break;
      out.push(
        row('Responder MAC address', macAt(b, v), 'ieee1905.responder_al_mac_addr', v, 6),
        row('Neighbor MAC address', macAt(b, v + 6), 'ieee1905.neighbor_al_mac_addr', v + 6, 6),
      );
      for (let p = v + 12; p + 29 <= end; p += 29) {
        out.push(
          row('Receiving AL MAC address', macAt(b, p), 'ieee1905.receiving_al_mac_addr', p, 6),
          row('Neighbor MAC address', macAt(b, p + 6), 'ieee1905.neighbor_al_mac_addr', p + 6, 6),
          mediaTypeRows(b, p + 12),
          row('IEEE 802.1 bridge flag', b[p + 14] === 0 ? '1905 link does not include an IEEE 802.1 bridge (0)'
            : b[p + 14] === 1 ? '1905 link includes one or more IEEE 802.1 bridges (1)' : `Unknown (${b[p + 14]})`, 'ieee1905.bridgeFlag', p + 14, 1),
          row('Packet errors', u32(b, p + 15), 'ieee1905.packetErrors', p + 15, 4),
          row('Transmitted packets', u32(b, p + 19), 'ieee1905.transmittedPackets', p + 19, 4),
          row('MAC throughput capacity', u16(b, p + 23), 'ieee1905.macThroughputCapacity', p + 23, 2),
          row('Link availability', u16(b, p + 25), 'ieee1905.linkAvailability', p + 25, 2),
          row('Phy rate', u16(b, p + 27), 'ieee1905.phyRate', p + 27, 2),
        );
      }
      break;
    }

    case 0x0a: {
      // The same 12-byte header, then 23 bytes per link.
      if (len < 12) break;
      out.push(
        row('Responder MAC address', macAt(b, v), 'ieee1905.responder_al_mac_addr', v, 6),
        row('Neighbor MAC address', macAt(b, v + 6), 'ieee1905.neighbor_al_mac_addr', v + 6, 6),
      );
      for (let p = v + 12; p + 23 <= end; p += 23) {
        out.push(
          row('Receiving AL MAC address', macAt(b, p), 'ieee1905.receiving_al_mac_addr', p, 6),
          row('Neighbor MAC address', macAt(b, p + 6), 'ieee1905.neighbor_al_mac_addr', p + 6, 6),
          mediaTypeRows(b, p + 12),
          row('Packet errors', u32(b, p + 14), 'ieee1905.packetErrors', p + 14, 4),
          row('Packets received', u32(b, p + 18), 'ieee1905.packets_received', p + 18, 4),
          row('RSSI', `0x${b[p + 22].toString(16).padStart(2, '0')}`, 'ieee1905.rssi', p + 22, 1),
        );
      }
      break;
    }

    case 0x08: {
      // Which neighbour's links to report - one, named, or all - and which way.
      if (len < 2) break;
      const specific = b[v] !== 0;
      const typeName = ['All neighbors', 'Specific neighbor'][b[v]];
      out.push(row('Link metric query type', typeName === undefined ? `Unknown (${b[v]})` : `${typeName} (${b[v]})`, 'ieee1905.link_metric_query_type', v, 1));
      const at = specific ? v + 7 : v + 1;
      if (specific) {
        if (len < 8) break;
        out.push(row('1905 AL MAC address type', macAt(b, v + 1), 'ieee1905.1905_al_mac_addr', v + 1, 6));
      }
      const requested = ['Tx link metrics only', 'Rx link metrics only', 'Both Tx and Rx link metrics'][b[at]];
      out.push(row('Link metrics requested', requested === undefined ? `Unknown (${b[at]})` : `${requested} (${b[at]})`, 'ieee1905.link_metrics_requested', at, 1));
      break;
    }

    case 0x0b:
      if (len < 3) break;
      out.push(row('Vendor specific OUI', ouiAt(b, v), 'ieee1905.vendor_specific.oui', v, 3));
      if (len > 3) out.push(row('Vendor specific information', hex(b, v + 3, len - 3), 'ieee1905.vendor_specific.info', v + 3, len - 3));
      break;

    case 0x80:
      if (len >= 1) out.push(...serviceRows(b, v, end, 'supported'));
      break;

    case 0x83: {
      // Radios, each with its operational BSSes, each with an SSID.
      if (len < 1) break;
      const radios = b[v];
      out.push(row('AP operational BSS radio count', radios, 'ieee1905.ap_bss_radio_count', v, 1));
      let p = v + 1;
      for (let r = 0; r < radios && p + 7 <= end; r++) {
        const intfCount = b[p + 6];
        const children: ProtocolField[] = [
          row('AP radio identifier', macAt(b, p), 'ieee1905.ap_radio_identifier', p, 6),
          row('AP operational interface count', intfCount, 'ieee1905.ap_bss_intf_count', p + 6, 1),
        ];
        let q = p + 7;
        for (let i = 0; i < intfCount && q + 7 <= end; i++) {
          const ssidLen = b[q + 6];
          if (q + 7 + ssidLen > end) break;
          children.push({
            name: `AP operational BSS Interface ${i}`, value: macAt(b, q), rawBytesRange: [q, q + 6 + ssidLen],
            children: [
              row('AP operational local interface MAC addr', macAt(b, q), 'ieee1905.ap_bss_local_intf_addr', q, 6),
              row('AP operational BSS local interface SSID len', ssidLen, 'ieee1905.ap_bss_local_intf_ssid_len', q + 6, 1),
              row('AP operational BSS local interface SSID', asText(b, q + 7, ssidLen), 'ieee1905.ap_bss_local_intf_ssid', q + 7, Math.max(1, ssidLen)),
            ],
          });
          q += 7 + ssidLen;
        }
        out.push({ name: `AP operational BSS ${r} info`, value: macAt(b, p), rawBytesRange: [p, q - 1], children });
        p = q;
      }
      break;
    }

    case 0x84: {
      // BSSes, each with the clients on it and how long each has been there.
      if (len < 1) break;
      const bssCount = b[v];
      out.push(row('Included BSS count', bssCount, 'ieee1905.assoc_client.bss_count', v, 1));
      let p = v + 1;
      for (let i = 0; i < bssCount && p + 8 <= end; i++) {
        const clients = u16(b, p + 6);
        const children: ProtocolField[] = [
          row('Associated BSS', macAt(b, p), 'ieee1905.assoc_client.bss', p, 6),
          row('Associated client count', clients, 'ieee1905.assoc_client.client_count', p + 6, 2),
        ];
        let q = p + 8;
        for (let c = 0; c < clients && q + 8 <= end; c++) {
          children.push({
            name: `Client ${c}`, value: macAt(b, q), rawBytesRange: [q, q + 7],
            children: [
              row('Associated client MAC address', macAt(b, q), 'ieee1905.assoc_client.mac_addr', q, 6),
              row('Time since last association', u16(b, q + 6), 'ieee1905.assoc_client.time_since', q + 6, 2),
            ],
          });
          q += 8;
        }
        out.push({ name: `Associated BSS ${i}`, value: macAt(b, p), rawBytesRange: [p, q - 1], children });
        p = q;
      }
      break;
    }

    case 0x94: {
      // 13 bytes: who, how busy, how many, and the estimated service params.
      if (len < 13) break;
      const flags = b[v + 9];
      out.push(
        row('Multi-AP agent BSSID', macAt(b, v), 'ieee1905.ap_metrics.bssid', v, 6),
        row('Channel utilization', b[v + 6], 'ieee1905.ap_metrics.channel_util', v + 6, 1),
        row('BSS STA count', u16(b, v + 7), 'ieee1905.ap_metrics.sta_count', v + 7, 2),
        {
          name: 'Estimated Service Parameters Flags', value: `0x${flags.toString(16).padStart(2, '0')}`,
          abbrev: 'ieee1905.ap_metrics.flags', rawBytesRange: [v + 9, v + 9],
          children: [
            bit('Include Estimated Service Parameters Information for AC=BE', (flags & 0x80) !== 0, 'ieee1905.ap_metrics.include_ac_eq_be_params', v + 9, 0, 'Included', 'Not included'),
            bit('Include Estimated Service Parameters Information for AC=BK', (flags & 0x40) !== 0, 'ieee1905.ap_metrics.include_ac_eq_bk_params', v + 9, 1, 'Included', 'Not included'),
            bit('Include Estimated Service Parameters Information for AC=VO', (flags & 0x20) !== 0, 'ieee1905.ap_metrics.include_ac_eq_vo_params', v + 9, 2, 'Included', 'Not included'),
            bit('Include Estimated Service Parameters Information for AC=VI', (flags & 0x10) !== 0, 'ieee1905.ap_metrics.include_ac_eq_vi_params', v + 9, 3, 'Included', 'Not included'),
          ],
        },
        row('Estimated service parameters AC=BE', hex(b, v + 10, 3), 'ieee1905.ap_metrics.est_param_be', v + 10, 3),
      );
      break;
    }

    case 0x96: {
      // 7 bytes, then 19 per BSS the station can see.
      if (len < 7) break;
      out.push(
        row('MAC address', macAt(b, v), 'ieee1905.assoc_sta_link_metrics.mac_addr', v, 6),
        row('Number of BSSIDs for STA', b[v + 6], 'ieee1905.assoc_sta_link_metrics.bssid_count', v + 6, 1),
      );
      let n = 0;
      for (let p = v + 7; p + 19 <= end; p += 19, n++) {
        out.push({
          name: `BSS ${n}`, value: macAt(b, p), rawBytesRange: [p, p + 18],
          children: [
            row('STA BSSID', macAt(b, p), 'ieee1905.assoc_sta_link_metrics.bssid', p, 6),
            row('Measurement time delta', u32(b, p + 6), 'ieee1905.assoc_sta_link_metrics.time_delta', p + 6, 4),
            row('Downlink data rate', u32(b, p + 10), 'ieee1905.assoc_sta_link_metrics.down_rate', p + 10, 4),
            row('Uplink data rate', u32(b, p + 14), 'ieee1905.assoc_sta_link_metrics.up_rate', p + 14, 4),
            row('Measured uplink RCPI for STA', b[p + 18], 'ieee1905.assoc_sta_link_metrics.rcpi', p + 18, 1),
          ],
        });
      }
      break;
    }

    case 0xa2:
      // 34 bytes, all of it counters, and the only TLV here with no repeat.
      if (len < 34) break;
      out.push(
        row('Associated STA MAC address', macAt(b, v), 'ieee1905.assoc_sta_traffic_stats.mac_addr', v, 6),
        row('Bytes Sent', u32(b, v + 6), 'ieee1905.assoc_sta_traffic_stats.bytes_sent', v + 6, 4),
        row('Bytes Received', u32(b, v + 10), 'ieee1905.assoc_sta_traffic_stats.bytes_rcvd', v + 10, 4),
        row('Packets Sent', u32(b, v + 14), 'ieee1905.assoc_sta_traffic_stats.packets_sent', v + 14, 4),
        row('Packets Received', u32(b, v + 18), 'ieee1905.assoc_sta_traffic_stats.packets_rcvd', v + 18, 4),
        row('Tx Packet Errors', u32(b, v + 22), 'ieee1905.assoc_sta_traffic_stats.tx_pkt_errs', v + 22, 4),
        row('Rx Packet Errors', u32(b, v + 26), 'ieee1905.assoc_sta_traffic_stats.rx_packet_errs', v + 26, 4),
        row('Retransmission Count', u32(b, v + 30), 'ieee1905.assoc_sta_traffic_stats.retrans_count', v + 30, 4),
      );
      break;

    case 0xb0: {
      // 7 bytes, then two per traffic class the station has queued anything on.
      if (len < 7) break;
      const tids = b[v + 6];
      out.push(
        row('MAC address', macAt(b, v), 'ieee1905.assoc_wf6_sta_status_report.mac_addr', v, 6),
        row('Number of Wi-Fi 6 TIDs', tids, 'ieee1905.assoc_wf6_sta_status_report.tid_count', v + 6, 1),
      );
      for (let i = 0; i < tids && v + 7 + i * 2 + 1 < end; i++) {
        const p = v + 7 + i * 2;
        out.push({
          name: `TID ${i} (${b[p]})`, value: b[p + 1], rawBytesRange: [p, p + 1],
          children: [
            row('TID', hex2(b[p]), 'ieee1905.assoc_wf6_sta_status_report.tid', p, 1),
            row('Queue Size', b[p + 1], 'ieee1905.assoc_wf6_sta_status_report.queue_size', p + 1, 1),
          ],
        });
      }
      break;
    }

    case 0xb3:
      if (len < 1) break;
      out.push(row('Multi-AP Profile', `${b[v] >= 1 && b[v] <= 3 ? `Multi-AP Profile ${b[v]}` : 'Reserved'} (${b[v]})`, 'ieee1905.multi_ap_version', v, 1));
      break;

    case 0xc6:
      // 10 bytes: the radio, the noise floor, and where its airtime went.
      if (len < 10) break;
      out.push(
        row('Radio unique ID', macAt(b, v), 'ieee1905.radio_metrics.radio_id', v, 6),
        row('Noise', b[v + 6], 'ieee1905.radio_metrics.noise', v + 6, 1),
        row('Transmit', b[v + 7], 'ieee1905.radio_metrics.transmit', v + 7, 1),
        row('ReceiveSelf', b[v + 8], 'ieee1905.radio_metrics.receive_self', v + 8, 1),
        row('ReceiveOther', b[v + 9], 'ieee1905.radio_metrics.receive_other', v + 9, 1),
      );
      break;

    case 0xc7:
      // 30 bytes of byte counters, split unicast / multicast / broadcast.
      // `Broadcast_bytes_sent`'s capital B is the reference's own
      // inconsistency and has to be matched exactly, not tidied.
      if (len < 30) break;
      out.push(
        row('BSSID', macAt(b, v), 'ieee1905.ap_extended_metrics.bssid', v, 6),
        row('UnicastBytesSent', u32(b, v + 6), 'ieee1905.ap_extended_metrics.unicast_bytes_sent', v + 6, 4),
        row('UnicastBytesReceived', u32(b, v + 10), 'ieee1905.ap_extended_metrics.unicast_bytes_received', v + 10, 4),
        row('MulticastBytesSent', u32(b, v + 14), 'ieee1905.ap_extended_metrics.multicast_bytes_sent', v + 14, 4),
        row('MulticastBytesReceived', u32(b, v + 18), 'ieee1905.ap_extended_metrics.multicast_bytes_received', v + 18, 4),
        row('BroadcastBytesSent', u32(b, v + 22), 'ieee1905.ap_extended_metrics.Broadcast_bytes_sent', v + 22, 4),
        row('BroadcastBytesReceived', u32(b, v + 26), 'ieee1905.ap_extended_metrics.broadcast_bytes_received', v + 26, 4),
      );
      break;

    case 0xc8: {
      // 7 bytes, then 22 per BSS.
      if (len < 7) break;
      out.push(
        row('Associated STA MAC Address', macAt(b, v), 'ieee1905.assoc_sta_extended_link_metrics.mac_addr', v, 6),
        row('BSSID count', b[v + 6], 'ieee1905.assoc_sta_extended_link_metrics.count', v + 6, 1),
      );
      let n = 0;
      for (let p = v + 7; p + 22 <= end; p += 22, n++) {
        out.push({
          name: `BSS #${n}`, value: macAt(b, p), rawBytesRange: [p, p + 21],
          children: [
            row('BSSID', macAt(b, p), 'ieee1905.assoc_sta_extended_link_metrics.bssid', p, 6),
            row('Last Data Downlink Rate', u32(b, p + 6), 'ieee1905.assoc_sta_extended_link_metrics.lddlr', p + 6, 4),
            row('Last Data Uplink Rate', u32(b, p + 10), 'ieee1905.assoc_sta_extended_link_metrics.ldulr', p + 10, 4),
            row('Utilization Receive', u32(b, p + 14), 'ieee1905.assoc_sta_extended_link_metrics.ur', p + 14, 4),
            row('Utilization Transmit', u32(b, p + 18), 'ieee1905.assoc_sta_extended_link_metrics.ut', p + 18, 4),
          ],
        });
      }
      break;
    }

    case 0x04: {
      // Bridging tuples, each a count and that many MAC addresses.
      if (len < 1) break;
      out.push(row('Bridging tuples count', b[v], 'ieee1905.bridging_info.tuples_count', v, 1));
      const tuples: ProtocolField[] = [];
      let p = v + 1;
      for (let t = 0; t < b[v] && p < end; t++) {
        const from = p;
        const count = b[p];
        const macs: ProtocolField[] = [row('Bridging MAC address count', count, 'ieee1905.bridging_info.mac_addr_count', p, 1)];
        p++;
        for (let m = 0; m < count && p + 6 <= end; m++, p += 6) macs.push(row('Bridging MAC address', macAt(b, p), 'ieee1905.bridging_info.mac_address', p, 6));
        tuples.push(group(`Bridging tuple ${t}`, from, p, macs));
      }
      out.push(group('Bridging tuples list', v + 1, p, tuples));
      break;
    }

    case 0x0d:
      if (len >= 1) out.push(row('Searched role', named(b[v], ROLE_NAMES), 'ieee1905.searched_role', v, 1));
      break;

    case 0x0e:
      if (len >= 1) out.push(row('Auto config frequency band', named(b[v], FREQ_BAND_NAMES), 'ieee1905.auto_config.freq_band', v, 1));
      break;

    case 0x0f:
      if (len >= 1) out.push(row('Supported role', named(b[v], ROLE_NAMES), 'ieee1905.supported_role', v, 1));
      break;

    case 0x10:
      if (len >= 1) out.push(row('Supported frequency band', named(b[v], FREQ_BAND_NAMES), 'ieee1905.supported.freq_band', v, 1));
      break;

    case 0x12: {
      // The media a push-button press applies to, each with its own blob.
      if (len < 1) break;
      out.push(row('Media types', b[v], 'ieee1905.event_notif.media_types', v, 1));
      if (b[v] === 0) break;
      const media: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < b[v] && p + 3 <= end; i++) {
        const from = p;
        const specLen = b[p + 2];
        const rows: ProtocolField[] = [mediaTypeRows(b, p), row('Special info length', specLen, 'ieee1905.dev_info.spec_info_len', p + 2, 1)];
        p += 3;
        if (specLen > 0 && p + specLen <= end) rows.push(row('Special info', hex(b, p, specLen), 'ieee1905.dev_info.spec_info', p, specLen));
        p = Math.min(end, p + specLen);
        media.push(group(`Media type ${i}`, from, p, rows));
      }
      out.push(group('Media type list', v + 1, p, media));
      break;
    }

    case 0x13:
      // 1905.1 Table 6-24: the sender, its event's message ID, then two MAC
      // addresses of six bytes each (the reference reads them as two).
      if (len < 20) break;
      out.push(
        row('Sender AL ID', macAt(b, v), 'ieee1905.sender.al_id', v, 6),
        row('Push button event message ID', `0x${u16(b, v + 6).toString(16).padStart(4, '0')}`, 'ieee1905.sender.msg_id', v + 6, 2),
        row('Joining MAC address of sender', macAt(b, v + 8), 'ieee1905.sender.joining_intf', v + 8, 6),
        row('New device MAC address', macAt(b, v + 14), 'ieee1905.new_device.intf', v + 14, 6),
      );
      break;

    case 0x14: {
      // The device, then each of its generic-phy interfaces.
      if (len < 7) break;
      const count = b[v + 6];
      out.push(
        row('1905 device AL MAC address', macAt(b, v), 'ieee1905.device_al_mac_addr', v, 6),
        row('Local interface count', count, 'ieee1905.dev_info.local_int_cnt', v + 6, 1),
      );
      if (count === 0) break;
      const interfaces: ProtocolField[] = [];
      let p = v + 7;
      for (let i = 0; i < count && p + 44 <= end; i++) {
        const from = p;
        const urlLen = b[p + 42];
        const specLen = b[p + 43];
        const urlEnd = Math.min(end, p + 44 + urlLen);
        const specEnd = Math.min(end, urlEnd + specLen);
        interfaces.push(group(`Local interface ${i} generic info`, from, specEnd, [
          row('Local interface MAC address', macAt(b, p), 'ieee1905.local_intf.mac_address', p, 6),
          row('Local interface OUI', ouiAt(b, p + 6), 'ieee1905.local_intf.oui', p + 6, 3),
          row('Local interface variant index', b[p + 9], 'ieee1905.local_intf.variant', p + 9, 1),
          row('Local interface variant name', textAt(b, p + 10, 32), 'ieee1905.local_intf.variant_name', p + 10, 32),
          row('Local interface URL octet count', urlLen, 'ieee1905.local_intf.url_byte_count', p + 42, 1),
          row('Local interface media specific count', specLen, 'ieee1905.local_intf.media_count', p + 43, 1),
          row('Local interface XML description URL', textAt(b, p + 44, urlEnd - p - 44), 'ieee1905.local_intf.url', p + 44, urlEnd - p - 44),
          row('Local interface media specific info', bytesOrMissing(b, urlEnd, specEnd - urlEnd), 'ieee1905.local_intf.spec_info', urlEnd, specEnd - urlEnd),
        ]));
        p = specEnd;
      }
      out.push(group('Local interface list', v + 7, p, interfaces));
      break;
    }

    case 0x15:
      // Three fixed 64-byte names: what the device calls itself, its maker, its model.
      if (len < 192) break;
      out.push(
        row('Device Id Friendly name', textAt(b, v, 64), 'ieee1905.device_id.friendly_name', v, 64),
        row('Device Id Manufacturer name', textAt(b, v + 64, 64), 'ieee1905.device_id.manuf_name', v + 64, 64),
        row('Device Id Manufacturer model', textAt(b, v + 128, 64), 'ieee1905.device_id.manuf_model', v + 128, 64),
      );
      break;

    case 0x16:
      if (len >= 1) out.push(row('Device control URL', textAt(b, v, len), 'ieee1905.device.control_url', v, len));
      break;

    case 0x17:
    case 0x18: {
      // Each interface, then each address on it with how it got it - read
      // in network byte order, which the reference's IPv4 reading is not.
      if (len < 1) break;
      const v6 = type === 0x18;
      const f = ADDRESS_FIELDS[v6 ? 6 : 4];
      const addrSize = v6 ? 16 : 4;
      const count = b[v];
      out.push(row(`Count of IPv${v6 ? 6 : 4} entries`, count, f.count, v, 1));
      if (count === 0) break;
      const entries: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < count && p + (v6 ? 23 : 7) <= end; i++) {
        const from = p;
        const rows: ProtocolField[] = [row('MAC address', macAt(b, p), f.mac, p, 6)];
        p += 6;
        if (v6) {
          rows.push(row('Link local address', formatIpv6Address(b, p), 'ieee1905.ipv6_type.link_local', p, 16));
          p += 16;
        }
        const addrCount = b[p];
        rows.push(row(`IPv${v6 ? 6 : 4} address count`, addrCount, f.addrCount, p, 1));
        p++;
        const addresses: ProtocolField[] = [];
        for (let a = 0; a < addrCount && p + 1 + addrSize * 2 <= end; a++) {
          const at = p;
          const show = (q: number) => (v6 ? formatIpv6Address(b, q) : ipv4At(b, q));
          addresses.push(group(`IPv${v6 ? 6 : 4} address ${a} info`, at, at + 1 + addrSize * 2, [
            row(`IPv${v6 ? 6 : 4} address type`, namedDec(b[at], v6 ? IPV6_ADDR_TYPES : IPV4_ADDR_TYPES), f.addrType, at, 1),
            row(`IPv${v6 ? 6 : 4} address`, show(at + 1), f.addr, at + 1, addrSize),
            row('DHCP server', show(at + 1 + addrSize), f.dhcp, at + 1 + addrSize, addrSize),
          ]));
          p += 1 + addrSize * 2;
        }
        if (addresses.length > 0) rows.push(group(`IPv${v6 ? 6 : 4} address list`, p - addresses.length * (1 + addrSize * 2), p, addresses));
        entries.push(group(`IPv${v6 ? 6 : 4} type ${i} info`, from, p, rows));
      }
      out.push(group(`IPv${v6 ? 6 : 4} type list`, v + 1, p, entries));
      break;
    }

    case 0x19: {
      // The generic-phy half of a push-button event.
      if (len < 1) break;
      out.push(row('Generic Phy media type count', b[v], 'ieee1905.button_push.phy_count', v, 1));
      const phys: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < b[v]; i++) {
        const phy = genericPhyRows(b, p, end);
        if (phy === null) break;
        phys.push(group(`Generic Phy media type ${i} info`, p, phy.next, phy.rows));
        p = phy.next;
      }
      out.push(group('Generic Phy media type list', v + 1, p, phys));
      break;
    }

    case 0x1a:
      if (len >= 1) out.push(row('1905 profile version type', namedDec(b[v], PROFILE_VERSIONS), 'ieee1905.profile.version', v, 1));
      break;

    case 0x1b: {
      // Interfaces powered off, each a MAC, a media type and a generic phy.
      if (len < 1) break;
      out.push(row('Powered off interface count', b[v], 'ieee1905.power_off.intf_count', v, 1));
      if (b[v] === 0) break;
      const interfaces: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < b[v] && p + 8 <= end; i++) {
        const phy = genericPhyRows(b, p + 8, end);
        if (phy === null) break;
        interfaces.push(group(`Powered off interface ${i} info`, p, phy.next, [
          // `ipv4_type.mac_address` is the reference's own choice of field here.
          row('MAC address', macAt(b, p), 'ieee1905.ipv4_type.mac_address', p, 6),
          mediaTypeRows(b, p + 6),
          ...phy.rows,
        ]));
        p = phy.next;
      }
      // "Generic Phy media type list" is the reference's label for this list too.
      out.push(group('Generic Phy media type list', v + 1, p, interfaces));
      break;
    }

    case 0x1c:
    case 0x1d: {
      // Interfaces and a power state: requested in a change, reported in a status.
      if (len < 1) break;
      const status = type === 0x1d;
      const f = POWER_FIELDS[status ? 'status' : 'change'];
      out.push(row(`Power ${status ? 'status' : 'change'} local interface count`, b[v], f.count, v, 1));
      const interfaces: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < b[v] && p + 7 <= end; i++, p += 7) {
        interfaces.push(group(`Power ${status ? 'status' : 'change'} interface ${i} info`, p, p + 7, [
          row(`Power ${status ? 'status' : 'change'} interface MAc addr`, macAt(b, p), f.mac, p, 6),
          row(status ? 'Power change status' : 'Power change requested state',
            namedDec(b[p + 6], status ? POWER_STATUSES : POWER_STATES), f.state, p + 6, 1),
        ]));
      }
      out.push(group(`Interface power ${status ? 'status' : 'change'} list`, v + 1, p, interfaces));
      break;
    }

    case 0x1e: {
      // Each local interface, the L2 neighbours on it, and the MACs behind each.
      if (len < 1) break;
      out.push(row('L2 neighbor interface count', b[v], 'ieee1905.l2_neighbor.intf_count', v, 1));
      if (b[v] === 0) break;
      const interfaces: ProtocolField[] = [];
      let p = v + 1;
      for (let i = 0; i < b[v] && p + 8 <= end; i++) {
        const from = p;
        const devices = u16(b, p + 6);
        const rows: ProtocolField[] = [
          row('L2 neighbor local interface MAC addr', macAt(b, p), 'ieee1905.l2_neighbor.mac_addr', p, 6),
          row('L2 neighbor device count', devices, 'ieee1905.l2_neighbor.dev_count', p + 6, 2),
        ];
        p += 8;
        const listFrom = p;
        const list: ProtocolField[] = [];
        for (let d = 0; d < devices && p + 8 <= end; d++) {
          const deviceFrom = p;
          const behind = u16(b, p + 6);
          const deviceRows: ProtocolField[] = [
            row('L2 neighbor interface MAC address', macAt(b, p), 'ieee1905.l2_neighbor.neighbor_mac_addr', p, 6),
            row('L2 neighbor behind MAC addr count', behind, 'ieee1905.l2_neighbor.neighbor_behind_count', p + 6, 2),
          ];
          p += 8;
          for (let m = 0; m < behind && p + 6 <= end; m++, p += 6) {
            deviceRows.push(row('L2 neighbor behind MAC addr', macAt(b, p), 'ieee1905.l2_neighbor.neighbor_behind_mac_addr', p, 6));
          }
          list.push(group(`Neighbor device ${d} info`, deviceFrom, p, deviceRows));
        }
        rows.push(group('Neighbor device list', listFrom, p, list));
        interfaces.push(group(`L2 neighbor device ${i} info`, from, p, rows));
      }
      out.push(group('L2 local interface list', v + 1, p, interfaces));
      break;
    }

    case 0x81:
      if (len >= 1) out.push(...serviceRows(b, v, end, 'searched'));
      break;

    case 0x92: {
      // A client joining or leaving one of the mesh's BSSes.
      if (len < 13) break;
      const flags = b[v + 12];
      out.push(
        row('Client mac address', macAt(b, v), 'ieee1905.assoc_event.client_mac', v, 6),
        row('Multi-AP agent BSSID', hex(b, v + 6, 6), 'ieee1905.assoc_event.agent_bssid', v + 6, 6),
        {
          name: 'Association event flags', value: `${hex2(flags)}${flags & 0x80 ? ', Association event' : ''}`,
          abbrev: 'ieee1905.assoc_event.flags', rawBytesRange: [v + 12, v + 12],
          children: [bit('Association event', (flags & 0x80) !== 0, 'ieee1905.assoc_event.assoc_event', v + 12, 0,
            'Client has joined the BSS', 'Client has left the BSS')],
        },
      );
      break;
    }

    case 0xa9: {
      // Three one-byte algorithm choices, each with only a 0 defined.
      if (len < 3) break;
      const choice = (n: number, name: string) => `${n === 0 ? name : 'Reserved'} (${n})`;
      out.push(
        row('Onboarding Protocols Supported', choice(b[v], '1905 Device Provisioning Protocol'), 'ieee1905.1905_layer_security_capability.onboarding_protocols_supported', v, 1),
        row('Message Integrity Algorithms Supported', choice(b[v + 1], 'HMAC-SHAR256'), 'ieee1905.1905_layer_security_capability.message_integrity_algorithms_supported', v + 1, 1),
        row('Message Encryption Algorithms Supported', choice(b[v + 2], 'AES-SIV'), 'ieee1905.1905_layer_security_capability.message_encryption_algorithms_supported', v + 2, 1),
      );
      break;
    }

    case 0xd3: {
      // A DPP chirp: flags, the enrollee's MAC if the flag says so, then a hash.
      if (len < 1) break;
      const flags = b[v];
      out.push({
        name: 'Chirp Value Flags', value: hex2(flags), abbrev: 'ieee1905.dpp_chirp_value.flags', rawBytesRange: [v, v],
        children: [
          bit('Enrollee MAC Address Present', (flags & 0x80) !== 0, 'ieee1905.dpp_chirp_value.flags.enrollee_mac_addr_present', v, 0, 'Present', 'Not present'),
          bit('Hash Validity Bit', (flags & 0x40) !== 0, 'ieee1905.dpp_chirp_value.flags.hash_validity_bit', v, 1,
            'Establish DPP authentication state pertaining to this hash value', 'Purge any DPP authentication state pertaining to this hash value'),
          { name: 'Reserved', value: hex2(flags & 0x3f), abbrev: 'ieee1905.dpp_chirp_value.flags.reserved', rawBytesRange: [v, v], bitfield: { bitOffset: 2, bitLength: 6, totalBits: 8 } },
        ],
      });
      let p = v + 1;
      if (flags & 0x80) {
        if (p + 6 > end) break;
        out.push(row('Destination STA MAC Address', macAt(b, p), 'ieee1905.dpp_chirp_value.dest_mac_addr', p, 6));
        p += 6;
      }
      if (p >= end) break;
      const hashLen = b[p];
      out.push(row('Hash Length', hex2(hashLen), 'ieee1905.dpp_chirp_value.hash_length', p, 1));
      if (hashLen > 0 && p + 1 + hashLen <= end) out.push(row('Hash Value', hex(b, p + 1, hashLen), 'ieee1905.dpp_chirp_value.hash_value', p + 1, hashLen));
      break;
    }

    case 0xdd: {
      // What the controller can do: two flags and six reserved bits.
      if (len < 1) break;
      const flags = b[v];
      const set = [[0x3f, 'Reserved'], [0x40, 'Early AP Capability'], [0x80, 'KiBMiB Counter']]
        .filter(([mask]) => (flags & (mask as number)) !== 0).map(([, name]) => `, ${name}`).join('');
      out.push({
        name: 'Controller Capability Flags', value: `${hex2(flags)}${set}`, abbrev: 'ieee1905.controller_capa.flags', rawBytesRange: [v, v],
        children: [
          { name: 'Reserved', value: (flags & 0x3f) !== 0, abbrev: 'ieee1905.controller_capa.reserved', rawBytesRange: [v, v], bitfield: { bitOffset: 2, bitLength: 6, totalBits: 8 } },
          { name: 'Early AP Capability', value: (flags & 0x40) !== 0, abbrev: 'ieee1905.controller_capa.early_ap_capa', rawBytesRange: [v, v], bitfield: { bitOffset: 1, bitLength: 1, totalBits: 8 } },
          { name: 'KiBMiB Counter', value: (flags & 0x80) !== 0, abbrev: 'ieee1905.controller_capa.kbmb_counter', rawBytesRange: [v, v], bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 } },
        ],
      });
      break;
    }

    default:
      // A type this does not read: its bytes, as the reference draws a type
      // it has no dissector for.
      if (type !== 0x00 && len > 0) out.push(row('TLV data', hex(b, v, len), 'ieee1905.tlv_data', v, len));
      break;
  }

  return out;
}

/** SSIDs are bytes, not text, and a non-printable one must not become a lie. */
function asText(b: Uint8Array, p: number, n: number): string {
  let out = '';
  for (let i = p; i < p + n && i < b.length; i++) out += b[i] >= 0x20 && b[i] < 0x7f ? String.fromCharCode(b[i]) : '.';
  return out;
}

/**
 * CMDU header layout from `start`: message version (1), reserved (1),
 * message type (2), message id (2), fragment id (1), flags (1); then TLVs.
 */
/**
 * The byte after a CMDU's End-of-message TLV, or -1 if there isn't one.
 *
 * Exists for `eth.padding`: a 1905 message is the only thing either fixture
 * carries whose length is stated by a terminator rather than by a header
 * field, so `declaredPayloadEnd` cannot read it the way it reads IPv4's Total
 * Length. Four frames of `inwire` are padded 1905 messages, and without this
 * they were the only padded frames drawing no pad.
 *
 * A second walk of the TLVs rather than a value threaded out of the
 * dissector, because the caller runs before any of the layers above Ethernet
 * are built - and it runs on 41 frames of 12,858.
 */
export function ieee1905MessageEnd(rawBytes: Uint8Array, start: number): number {
  let cursor = start + 8;
  while (cursor + 3 <= rawBytes.length) {
    const tlvType = rawBytes[cursor];
    const tlvLength = ((rawBytes[cursor + 1] << 8) | rawBytes[cursor + 2]) & 0x3fff;
    cursor += 3 + tlvLength;
    if (cursor > rawBytes.length) return -1;
    if (tlvType === 0x00) return cursor;
  }
  return -1;
}

export function dissectIeee1905(rawBytes: Uint8Array, start: number): Ieee1905DissectorResult | null {
  if (start + 8 > rawBytes.length) return null;

  const version = rawBytes[start];
  const reserved = rawBytes[start + 1];
  const messageType = u16(rawBytes, start + 2);
  const messageId = u16(rawBytes, start + 4);
  const fragmentId = rawBytes[start + 6];
  const flags = rawBytes[start + 7];

  const typeName = MESSAGE_TYPES[messageType];
  let info = typeName ?? `Unknown: ${messageType}`;

  const fields: ProtocolField[] = [
    { name: 'Message version', value: version, rawBytesRange: [start, start], abbrev: 'ieee1905.message_version' },
    { name: 'Message reserved', value: reserved, rawBytesRange: [start + 1, start + 1], abbrev: 'ieee1905.message_reserved' },
    { name: 'Message type', value: `${typeName ?? 'Unknown'} (0x${messageType.toString(16).padStart(4, '0')})`, rawBytesRange: [start + 2, start + 3], abbrev: 'ieee1905.message_type' },
    { name: 'Message id', value: `0x${messageId.toString(16).padStart(4, '0')}`, rawBytesRange: [start + 4, start + 5], abbrev: 'ieee1905.message_id' },
    { name: 'Fragment id', value: `0x${fragmentId.toString(16).padStart(2, '0')}`, rawBytesRange: [start + 6, start + 6], abbrev: 'ieee1905.fragment_id' },
    {
      name: 'Flags',
      // A bitmask's value names the flags that are set, and only those.
      value: `0x${flags.toString(16).padStart(2, '0')}${flags & 0x80 ? ', Last fragment' : ''}${flags & 0x40 ? ', Relay indicator' : ''}`,
      rawBytesRange: [start + 7, start + 7],
      abbrev: 'ieee1905.flags',
      children: [
        bit('Last fragment', (flags & 0x80) !== 0, 'ieee1905.last_fragment', start + 7, 0, 'This is the last fragment', 'This is not the last fragment'),
        bit('Relay indicator', (flags & 0x40) !== 0, 'ieee1905.relay_indicator', start + 7, 1, 'Relayed multicast', 'Neighbor multicast or unicast'),
      ],
    },
  ];

  let lastByte = rawBytes.length - 1;
  if ((flags & 0x80) === 0 || fragmentId !== 0) {
    // One piece of a message split across frames. Its TLVs start in one
    // frame and end in another, so nothing here can be read without the
    // others; the reference reassembles them, and says which piece this is
    // where it has not. 802.1Q-tagged 1905 is rare enough that the VLAN is 0.
    info += ` (Message ID: ${messageId}, Fragment ID: ${fragmentId}, VLAN ID: 0)`;
    if (start + 8 < rawBytes.length) {
      fields.push(row('Fragment Data', hex(rawBytes, start + 8, rawBytes.length - start - 8), 'ieee1905.fragment.data', start + 8, rawBytes.length - start - 8));
    }
  } else {
    // The TLV run. A 1-byte type, a 2-byte length whose top two bits are
    // reserved, then that many bytes. Type 0 ends the message; the bytes after
    // it are Ethernet padding and are not part of the CMDU.
    let cursor = start + 8;
    while (cursor + 3 <= rawBytes.length) {
      const tlvType = rawBytes[cursor];
      const lengthWord = u16(rawBytes, cursor + 1);
      const tlvLength = lengthWord & 0x3fff;
      const valueStart = cursor + 3;
      if (valueStart + tlvLength > rawBytes.length) {
        fields.push({
          name: '[Malformed TLV]', generated: true,
          value: `Type 0x${tlvType.toString(16).padStart(2, '0')} claims ${tlvLength} bytes, only ${rawBytes.length - valueStart} remain`,
        });
        break;
      }

      const tlvName = TLV_TYPES[tlvType];
      fields.push({
        name: tlvName ?? `Unknown: ${tlvType.toString(16).padStart(2, '0')}`,
        value: '',
        rawBytesRange: [cursor, valueStart + tlvLength - 1],
        children: [
          {
            name: 'TLV type', value: `${tlvName ?? 'Unknown'} (0x${tlvType.toString(16).padStart(2, '0')})`,
            abbrev: 'ieee1905.tlv_type', rawBytesRange: [cursor, cursor],
          },
          {
            name: 'TLV length', value: tlvLength, abbrev: 'ieee1905.tlv_length', rawBytesRange: [cursor + 1, cursor + 2],
            children: [
              { name: 'TLV length reserved', value: `0x${(lengthWord >> 14).toString(16)}`, abbrev: 'ieee1905.tlv_length.reserved', rawBytesRange: [cursor + 1, cursor + 2], bitfield: { bitOffset: 0, bitLength: 2, totalBits: 16 } },
              { name: 'TLV length length', value: tlvLength, abbrev: 'ieee1905.tlv_length.length', rawBytesRange: [cursor + 1, cursor + 2], bitfield: { bitOffset: 2, bitLength: 14, totalBits: 16 } },
            ],
          },
          ...tlvBodyRows(tlvType, rawBytes, valueStart, tlvLength),
        ],
      });

      cursor = valueStart + tlvLength;
      if (tlvType === 0x00) { lastByte = cursor - 1; break; }
    }
  }

  return {
    protocolLabel: 'ieee1905',
    info,
    fields: { 'ieee1905.message_type': messageType, 'ieee1905.message_id': messageId },
    layer: {
      name: 'IEEE 1905.1a',
      summary: `IEEE 1905.1a, ${typeName ?? `Unknown: ${messageType}`}`,
      rawBytesRange: [start, lastByte],
      fields,
    },
  };
}
