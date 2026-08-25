/**
 * IEEE 1905.1a CMDU headers (ethertype 0x893a) - the control protocol home
 * mesh routers use to describe their topology and link quality to each other.
 * Common on any capture taken behind a consumer router with mesh extenders.
 *
 * Only the 8-byte CMDU header is parsed; the TLV payload that follows is not
 * summarized, because the message type alone is what Wireshark puts in the
 * Info column.
 */
import { ProtocolLayer } from '../../types/packet';

/**
 * Message types. 0x0000-0x00ff are IEEE 1905.1a itself; 0x8000 and up are the
 * Wi-Fi Alliance's EasyMesh (Multi-AP) extensions. The inconsistent
 * capitalization between the two blocks mirrors Wireshark's own tables, which
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

export interface Ieee1905DissectorResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields?: Record<string, string | number>;
}

/**
 * CMDU header layout from `start`: message version (1), reserved (1),
 * message type (2), message id (2), fragment id (1), flags (1).
 */
export function dissectIeee1905(rawBytes: Uint8Array, start: number): Ieee1905DissectorResult | null {
  if (start + 8 > rawBytes.length) return null;

  const version = rawBytes[start];
  const messageType = (rawBytes[start + 2] << 8) | rawBytes[start + 3];
  const messageId = (rawBytes[start + 4] << 8) | rawBytes[start + 5];
  const fragmentId = rawBytes[start + 6];
  const flags = rawBytes[start + 7];

  const typeName = MESSAGE_TYPE_NAMES[messageType] ?? `Unknown message type (0x${messageType.toString(16).padStart(4, '0')})`;

  return {
    protocolLabel: 'ieee1905',
    info: typeName,
    fields: { 'ieee1905.message.type': messageType, 'ieee1905.message.id': messageId },
    layer: {
      name: 'IEEE 1905.1a',
      summary: `IEEE 1905.1a, ${typeName}`,
      rawBytesRange: [start, rawBytes.length - 1],
      fields: [
        { name: 'Message version', value: version, rawBytesRange: [start, start] },
        { name: 'Message type', value: `${typeName} (0x${messageType.toString(16).padStart(4, '0')})`, rawBytesRange: [start + 2, start + 3] },
        { name: 'Message id', value: messageId, rawBytesRange: [start + 4, start + 5] },
        { name: 'Fragment id', value: fragmentId, rawBytesRange: [start + 6, start + 6] },
        {
          name: 'Flags',
          value: `0x${flags.toString(16).padStart(2, '0')}`,
          rawBytesRange: [start + 7, start + 7],
          children: [
            { name: 'Last fragment indicator', value: (flags & 0x80) !== 0 },
            { name: 'Relay indicator', value: (flags & 0x40) !== 0 },
          ],
        },
      ],
    },
  };
}
