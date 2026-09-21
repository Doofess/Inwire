/**
 * IEEE 1905.1a CMDUs (ethertype 0x893a) - the control protocol home mesh
 * routers use to describe their topology and link quality to each other, plus
 * the Wi-Fi Alliance's EasyMesh (Multi-AP) extensions on top of it. Common on
 * any capture taken behind a consumer router with mesh extenders.
 *
 * An 8-byte CMDU header, then a flat run of TLVs terminated by type 0. Until
 * this file read them, the TLVs were an opaque byte range: the Info column
 * named the message and the detail pane had nothing under it, which meant the
 * one thing these frames are for - what the mesh thinks of its own links -
 * was invisible.
 *
 * **Every TLV body below was verified against `tshark -T pdml` on the
 * `inwire` fixture by arithmetic rather than by eye**: a body layout is right
 * only if the field sizes sum to the TLV's own declared length, and every one
 * here does. Where a table maps a number to a name and the fixture proves
 * only some of the entries, the comment says so.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatMac, toHex } from '../addressFormat';

/**
 * Message types. 0x0000-0x00ff are IEEE 1905.1a itself; 0x8000 and up are the
 * Wi-Fi Alliance's EasyMesh (Multi-AP) extensions. The inconsistent
 * capitalization between the two blocks mirrors the reference analyzer's own tables, which
 * this has to match exactly for the Info column to agree.
 */
const MESSAGE_TYPE_NAMES: Record<number, string> = {
  0x0000: 'Topology discovery',
  0x0001: 'Topology notification',
  0x0002: 'Topology query',
  0x0003: 'Topology response',
  0x0004: 'Vendor specific',
  0x0005: 'Link metric query',
  0x0006: 'Link metric response',
  0x0007: 'AP autoconfiguration search',
  0x0008: 'AP autoconfiguration response',
  0x0009: 'AP autoconfiguration WSC',
  0x000a: 'AP autoconfiguration renew',
  0x000b: '1905 push button event notification',
  0x000c: '1905 push button join notification',
  0x000d: 'Higher layer query',
  0x000e: 'Higher layer response',
  0x000f: 'Interface power change request',
  0x0010: 'Interface power change response',
  0x0011: 'Generic phy query',
  0x0012: 'Generic phy response',
  0x8000: 'ACK',
  0x8001: 'AP Capability Query',
  0x8002: 'AP Capability Report',
  0x8003: 'Multi-AP Policy Config Request',
  0x8004: 'Channel Preference Query',
  0x8005: 'Channel Preference Report',
  0x8006: 'Channel Selection Request',
  0x8007: 'Channel Selection Response',
  0x8008: 'Operating Channel Report',
  0x8009: 'Client Capability Query',
  0x800a: 'Client Capability Report',
  0x800b: 'AP Metrics Query',
  0x800c: 'AP Metrics Response',
  0x800d: 'Associated STA Link Metrics Query',
  0x800e: 'Associated STA Link Metrics Response',
  0x800f: 'Unassociated STA Link Metrics Query',
  0x8010: 'Unassociated STA Link Metrics Response',
  0x8011: 'Beacon Metrics Query',
  0x8012: 'Beacon Metrics Response',
  0x8013: 'Combined Infrastructure Metrics',
  0x8014: 'Client Steering Request',
  0x8015: 'Client Steering BTM Report',
  0x8016: 'Client Association Control Request',
  0x8017: 'Steering Completed',
  0x8018: 'Higher Layer Data',
  0x8019: 'Backhaul Steering Request',
  0x801a: 'Backhaul Steering Response',
};

/** TLV type names, matched to the reference's own strings. */
const TLV_TYPE_NAMES: Record<number, string> = {
  0x00: 'End of message',
  0x01: '1905 AL MAC address type',
  0x02: 'MAC address type',
  0x03: '1905 device information type',
  0x04: 'Device bridging capability',
  0x06: '1905 neighbor device',
  0x07: 'Non-1905 neighbor device list',
  0x08: 'Link metric query',
  0x09: '1905 transmitter link metric',
  0x0a: '1905 receiver link metric',
  0x0b: 'Vendor specific',
  0x0c: '1905 link metric result code',
  0x0d: 'SearchedRole',
  0x0e: 'AutoconfigFreqBand',
  0x0f: 'SupportedRole',
  0x10: 'SupportedFreqBand',
  0x11: 'WSC',
  0x80: 'Supported service information',
  0x81: 'Searched service information',
  0x82: 'AP radio identifier',
  0x83: 'AP operational BSS',
  0x84: 'Associated clients',
  0x94: 'AP metrics',
  0x96: 'Associated STA Link Metrics',
  0xa2: 'Associated STA Traffic Stats',
  0xb0: 'Associated Wi-Fi 6 STA Status Report',
  0xb3: 'Multi AP Profile',
  0xc6: 'Radio Metrics',
  0xc7: 'AP Extended Metrics',
  0xc8: 'Associated STA Extended Link Metrics',
};

/**
 * Media types, IEEE 1905.1-2013 Table 6-12.
 *
 * **Only 0x0001 and 0x0109 are proven by a capture** - they are what the
 * fixture's mesh advertises, and both are spelled here exactly as the
 * reference spells them, including its clipped "gigabit" with no "Ethernet"
 * after it. The rest are the standard's own table and are the names to
 * re-check first if a value ever reads oddly. An unknown value renders as its
 * number rather than being guessed at.
 */
const MEDIA_TYPE_NAMES: Record<number, string> = {
  0x0000: 'IEEE 802.3u fast Ethernet',
  0x0001: 'IEEE 802.3ab gigabit',
  0x0100: 'IEEE 802.11b (2.4 GHz)',
  0x0101: 'IEEE 802.11g (2.4 GHz)',
  0x0102: 'IEEE 802.11a (5 GHz)',
  0x0103: 'IEEE 802.11n (2.4 GHz)',
  0x0104: 'IEEE 802.11n (5 GHz)',
  0x0105: 'IEEE 802.11ac (5 GHz)',
  0x0106: 'IEEE 802.11ad (60 GHz)',
  0x0107: 'IEEE 802.11af',
  0x0108: 'IEEE 802.11ax',
  0x0109: 'IEEE 802.11be',
  0x0200: 'IEEE 1901 wavelet',
  0x0201: 'IEEE 1901 FFT',
  0x0300: 'MoCA v1.1',
};

/** EasyMesh roles a device can claim. */
const SERVICE_NAMES: Record<number, string> = {
  0x00: 'Multi-AP Controller',
  0x01: 'Multi-AP Agent',
};

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

/** A whole-byte-range field, which is most of what a TLV body is made of. */
const row = (name: string, value: string | number, abbrev: string, at: number, size: number): ProtocolField =>
  ({ name, value, abbrev, rawBytesRange: [at, at + size - 1] });

/** One bit of a byte, numbered from the most significant as the tree draws it. */
const bit = (name: string, set: boolean, abbrev: string, at: number, msbIndex: number, yes: string, no: string): ProtocolField =>
  ({ name, value: set ? yes : no, abbrev, rawBytesRange: [at, at], bitfield: { bitOffset: msbIndex, bitLength: 1, totalBits: 8 } });

/**
 * The 2-byte media type, which the reference draws as a value plus its two
 * halves. The halves are not a bitfield - they are the two bytes, named
 * separately because the high byte selects the family (Ethernet, 802.11,
 * 1901, MoCA) and the low byte the variant within it.
 */
function mediaTypeRows(b: Uint8Array, at: number): ProtocolField {
  const value = u16(b, at);
  return {
    name: 'Media type',
    value: `0x${value.toString(16).padStart(4, '0')}, ${MEDIA_TYPE_NAMES[value] ?? 'Unknown'}`,
    abbrev: 'ieee1905.dev_info.media_type',
    rawBytesRange: [at, at + 1],
    children: [
      row('Media type bits 15 to 8', b[at], 'ieee1905.media_type.bits_15_to_8', at, 1),
      row('Media type bits 7 to 0', b[at + 1], 'ieee1905.media_type.bits_7_to_0', at + 1, 1),
    ],
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
      // The local interface, then every 1905 neighbour reachable through it.
      if (len < 6) break;
      out.push(row('Local interface MAC address', macAt(b, v), 'ieee1905.local_intf.mac_address', v, 6));
      for (let p = v + 6; p + 7 <= end; p += 7) {
        out.push({
          name: 'IEEE1905 neighbor devices', value: macAt(b, p), rawBytesRange: [p, p + 6],
          children: [
            row('Neighbor MAC address', macAt(b, p), 'ieee1905.neighbor_al_mac_addr', p, 6),
            {
              name: 'IEEE1905 neighbor flags', value: `0x${b[p + 6].toString(16).padStart(2, '0')}`,
              abbrev: 'ieee1905.neighbor_flags', rawBytesRange: [p + 6, p + 6],
              children: [bit('IEEE1905 bridges', (b[p + 6] & 0x80) !== 0, 'ieee1905.bridges', p + 6, 0, 'Bridges present', 'No bridges')],
            },
          ],
        });
      }
      break;
    }

    case 0x07: {
      if (len < 6) break;
      out.push(row('Local interface MAC address', macAt(b, v), 'ieee1905.local_intf.mac_address', v, 6));
      for (let p = v + 6; p + 6 <= end; p += 6) {
        out.push({
          name: 'Non IEEE1905 neighbor devices', value: macAt(b, p), rawBytesRange: [p, p + 5],
          children: [row('Neighbor MAC address', macAt(b, p), 'ieee1905.neighbor_al_mac_addr', p, 6)],
        });
      }
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
          row('IEEE 802.1 bridge flag', b[p + 14] ? '1905 link includes an IEEE 802.1 bridge (1)' : '1905 link does not include an IEEE 802.1 bridge (0)', 'ieee1905.bridgeFlag', p + 14, 1),
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

    case 0x0b:
      if (len < 3) break;
      out.push(row('Vendor specific OUI', hex(b, v, 3), 'ieee1905.vendor_specific.oui', v, 3));
      if (len > 3) out.push(row('Vendor specific information', hex(b, v + 3, len - 3), 'ieee1905.vendor_specific.info', v + 3, len - 3));
      break;

    case 0x80: {
      if (len < 1) break;
      const count = b[v];
      out.push(row('Supported service count', count, 'ieee1905.supported_service.service_count', v, 1));
      for (let i = 0; i < count && v + 1 + i < end; i++) {
        out.push(row('Supported service', `${SERVICE_NAMES[b[v + 1 + i]] ?? 'Unknown'} (0x${b[v + 1 + i].toString(16).padStart(2, '0')})`, 'ieee1905.supported_service.service', v + 1 + i, 1));
      }
      break;
    }

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
            row('TID', b[p], 'ieee1905.assoc_wf6_sta_status_report.tid', p, 1),
            row('Queue Size', b[p + 1], 'ieee1905.assoc_wf6_sta_status_report.queue_size', p + 1, 1),
          ],
        });
      }
      break;
    }

    case 0xb3:
      if (len < 1) break;
      out.push(row('Multi-AP Profile', b[v], 'ieee1905.multi_ap_version', v, 1));
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

    default:
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
export function dissectIeee1905(rawBytes: Uint8Array, start: number): Ieee1905DissectorResult | null {
  if (start + 8 > rawBytes.length) return null;

  const version = rawBytes[start];
  const reserved = rawBytes[start + 1];
  const messageType = u16(rawBytes, start + 2);
  const messageId = u16(rawBytes, start + 4);
  const fragmentId = rawBytes[start + 6];
  const flags = rawBytes[start + 7];

  const typeName = MESSAGE_TYPE_NAMES[messageType] ?? `Unknown message type (0x${messageType.toString(16).padStart(4, '0')})`;

  const fields: ProtocolField[] = [
    { name: 'Message version', value: version, rawBytesRange: [start, start], abbrev: 'ieee1905.message_version' },
    { name: 'Message reserved', value: reserved, rawBytesRange: [start + 1, start + 1], abbrev: 'ieee1905.message_reserved' },
    { name: 'Message type', value: `${typeName} (0x${messageType.toString(16).padStart(4, '0')})`, rawBytesRange: [start + 2, start + 3], abbrev: 'ieee1905.message_type' },
    { name: 'Message id', value: `0x${messageId.toString(16).padStart(4, '0')}`, rawBytesRange: [start + 4, start + 5], abbrev: 'ieee1905.message_id' },
    { name: 'Fragment id', value: `0x${fragmentId.toString(16).padStart(2, '0')}`, rawBytesRange: [start + 6, start + 6], abbrev: 'ieee1905.fragment_id' },
    {
      name: 'Flags',
      value: `0x${flags.toString(16).padStart(2, '0')}, ${(flags & 0x80) !== 0 ? 'Last fragment' : 'More fragments'}`,
      rawBytesRange: [start + 7, start + 7],
      abbrev: 'ieee1905.flags',
      children: [
        bit('Last fragment', (flags & 0x80) !== 0, 'ieee1905.last_fragment', start + 7, 0, 'This is the last fragment', 'More fragments follow'),
        bit('Relay indicator', (flags & 0x40) !== 0, 'ieee1905.relay_indicator', start + 7, 1, 'Relayed multicast', 'Neighbor multicast or unicast'),
      ],
    },
  ];

  // The TLV run. A 1-byte type, a 2-byte length whose top two bits are
  // reserved, then that many bytes. Type 0 ends the message; the bytes after
  // it are Ethernet padding and are not part of the CMDU.
  let cursor = start + 8;
  let lastByte = rawBytes.length - 1;
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
      lastByte = rawBytes.length - 1;
      break;
    }

    fields.push({
      name: TLV_TYPE_NAMES[tlvType] ?? `Unknown TLV (0x${tlvType.toString(16).padStart(2, '0')})`,
      value: '',
      rawBytesRange: [cursor, valueStart + tlvLength - 1],
      children: [
        {
          name: 'TLV type', value: `${TLV_TYPE_NAMES[tlvType] ?? 'Unknown'} (0x${tlvType.toString(16).padStart(2, '0')})`,
          abbrev: 'ieee1905.tlv_type', rawBytesRange: [cursor, cursor],
        },
        {
          name: 'TLV length', value: tlvLength, abbrev: 'ieee1905.tlv_length', rawBytesRange: [cursor + 1, cursor + 2],
          children: [
            { name: 'TLV length reserved', value: `0x${(lengthWord >> 14).toString(16).padStart(4, '0')}`, abbrev: 'ieee1905.tlv_length.reserved', rawBytesRange: [cursor + 1, cursor + 2], bitfield: { bitOffset: 0, bitLength: 2, totalBits: 16 } },
            { name: 'TLV length length', value: tlvLength, abbrev: 'ieee1905.tlv_length.length', rawBytesRange: [cursor + 1, cursor + 2], bitfield: { bitOffset: 2, bitLength: 14, totalBits: 16 } },
          ],
        },
        ...tlvBodyRows(tlvType, rawBytes, valueStart, tlvLength),
      ],
    });

    cursor = valueStart + tlvLength;
    if (tlvType === 0x00) { lastByte = cursor - 1; break; }
  }

  return {
    protocolLabel: 'ieee1905',
    info: typeName,
    fields: { 'ieee1905.message_type': messageType, 'ieee1905.message_id': messageId },
    layer: {
      name: 'IEEE 1905.1a',
      summary: `IEEE 1905.1a, ${typeName}`,
      rawBytesRange: [start, lastByte],
      fields,
    },
  };
}
