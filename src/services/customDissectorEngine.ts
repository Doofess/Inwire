import { CustomDissectorRule, ProtocolLayer, ProtocolField } from '../types/packet';

const DEFAULT_CUSTOM_DISSECTORS: CustomDissectorRule[] = [
  {
    id: 'dissector-proto-iot',
    name: 'Industrial IoT Telemetry (Proto-IoT)',
    protocolName: 'PROTO_IOT',
    port: 18833,
    transport: 'UDP',
    magicHeaderHex: '494F54', // "IOT"
    magicOffset: 0,
    description: 'Proprietary smart factory telemetry protocol carrying telemetry sensors, vibration, and thermal readouts.',
    enabled: true,
    fields: [
      { name: 'Magic Header', offset: 0, length: 3, type: 'string', description: 'Protocol identifier ("IOT")' },
      { name: 'Version', offset: 3, length: 1, type: 'uint8', description: 'Protocol Version (e.g. v1 or v2)' },
      { name: 'Device ID', offset: 4, length: 2, type: 'uint16', description: 'Factory Node Cluster ID' },
      { name: 'Telemetry Opcode', offset: 6, length: 1, type: 'uint8', description: '0x01: Ping, 0x02: Sensor Temp, 0x03: Pressure Alert' },
      { name: 'Payload Data (Hex)', offset: 7, length: 8, type: 'hex', description: 'Raw IEEE sensor telemetry data' },
      { name: 'CRC Checksum', offset: 15, length: 2, type: 'uint16', description: 'Cyclic Redundancy Check' },
    ],
  },
  {
    id: 'dissector-fintech-fast',
    name: 'Ultra-Low Latency Order (FinFast)',
    protocolName: 'FINFAST',
    port: 9876,
    transport: 'TCP',
    magicHeaderHex: '4646', // "FF"
    magicOffset: 0,
    description: 'High-frequency exchange matching engine binary execution protocol.',
    enabled: true,
    fields: [
      { name: 'Header Token', offset: 0, length: 2, type: 'string', description: 'FinFast Token ("FF")' },
      { name: 'Message Type', offset: 2, length: 1, type: 'uint8', description: '1: New Order, 2: Fill, 3: Cancel, 4: Heartbeat' },
      { name: 'Order Sequence ID', offset: 3, length: 4, type: 'uint32', description: 'Nanosecond sequence index' },
      { name: 'Asset Symbol (Hex)', offset: 7, length: 4, type: 'hex', description: 'Ticker Symbol identifier' },
      { name: 'Price (Micro-Units)', offset: 11, length: 4, type: 'uint32', description: 'Fixed point price' },
      { name: 'Order Quantity', offset: 15, length: 2, type: 'uint16', description: 'Lot size execution quantity' },
    ],
  },
];

export class CustomDissectorEngine {
  private dissectors: CustomDissectorRule[] = [];

  constructor(initialDissectors?: CustomDissectorRule[]) {
    this.dissectors = initialDissectors || [...DEFAULT_CUSTOM_DISSECTORS];
  }

  public getDissectors(): CustomDissectorRule[] {
    return this.dissectors;
  }

  public addDissector(rule: CustomDissectorRule): void {
    this.dissectors.push(rule);
  }

  public updateDissector(id: string, updated: Partial<CustomDissectorRule>): void {
    this.dissectors = this.dissectors.map(d => (d.id === id ? { ...d, ...updated } : d));
  }

  public deleteDissector(id: string): void {
    this.dissectors = this.dissectors.filter(d => d.id !== id);
  }

  /**
   * Moves a dissector one slot earlier/later in the match order. Array order
   * *is* precedence here - dissectPayload() below returns the first match,
   * so when two enabled dissectors could both claim the same traffic (same
   * port, or magic bytes that happen to overlap), whichever comes first in
   * this list wins. Exposed so users can resolve that ambiguity themselves
   * instead of it being silently whatever order the rules were created in.
   */
  public moveDissector(id: string, direction: 'up' | 'down'): void {
    const index = this.dissectors.findIndex(d => d.id === id);
    if (index === -1) return;
    const swapWith = direction === 'up' ? index - 1 : index + 1;
    if (swapWith < 0 || swapWith >= this.dissectors.length) return;

    const reordered = [...this.dissectors];
    [reordered[index], reordered[swapWith]] = [reordered[swapWith], reordered[index]];
    this.dissectors = reordered;
  }

  /**
   * Evaluates application payload bytes against active custom dissectors
   */
  public dissectPayload(
    payloadBytes: Uint8Array,
    transport: 'TCP' | 'UDP',
    sourcePort?: number,
    destPort?: number,
    basePayloadOffset: number = 0
  ): { matchedDissector?: CustomDissectorRule; layer?: ProtocolLayer } | null {
    for (const dissector of this.dissectors) {
      if (!dissector.enabled) continue;

      // Check port match if specified
      if (dissector.port) {
        if (sourcePort !== dissector.port && destPort !== dissector.port) {
          continue;
        }
      }

      // Check transport
      if (dissector.transport !== 'ANY' && dissector.transport !== transport) {
        continue;
      }

      // Check magic header if specified
      if (dissector.magicHeaderHex) {
        const offset = dissector.magicOffset || 0;
        const magicBytes = hexStringToBytes(dissector.magicHeaderHex);
        if (payloadBytes.length < offset + magicBytes.length) {
          continue;
        }

        let magicMatch = true;
        for (let i = 0; i < magicBytes.length; i++) {
          if (payloadBytes[offset + i] !== magicBytes[i]) {
            magicMatch = false;
            break;
          }
        }
        if (!magicMatch) continue;
      }

      // Dissect fields
      const fields: ProtocolField[] = [];
      for (const fieldDef of dissector.fields) {
        if (fieldDef.offset >= payloadBytes.length) continue;
        const fieldBytes = payloadBytes.slice(
          fieldDef.offset,
          Math.min(payloadBytes.length, fieldDef.offset + fieldDef.length)
        );

        let parsedVal: string | number = '';
        if (fieldDef.type === 'uint8' && fieldBytes.length >= 1) {
          parsedVal = fieldBytes[0];
        } else if (fieldDef.type === 'uint16' && fieldBytes.length >= 2) {
          parsedVal = (fieldBytes[0] << 8) | fieldBytes[1];
        } else if (fieldDef.type === 'uint32' && fieldBytes.length >= 4) {
          parsedVal = (fieldBytes[0] << 24) | (fieldBytes[1] << 16) | (fieldBytes[2] << 8) | fieldBytes[3];
          parsedVal = parsedVal >>> 0; // Unsigned
        } else if (fieldDef.type === 'string') {
          parsedVal = String.fromCharCode(...fieldBytes).replace(/[^\x20-\x7E]/g, '.');
        } else {
          // Hex representation
          parsedVal = Array.from(fieldBytes)
            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
            .join(' ');
        }

        fields.push({
          name: fieldDef.name,
          value: parsedVal,
          description: fieldDef.description,
          rawBytesRange: [
            basePayloadOffset + fieldDef.offset,
            basePayloadOffset + fieldDef.offset + fieldBytes.length - 1,
          ],
        });
      }

      const layer: ProtocolLayer = {
        name: dissector.protocolName,
        summary: `${dissector.name} [Dissected by Custom Plugin] (${payloadBytes.length} bytes)`,
        rawBytesRange: [basePayloadOffset, basePayloadOffset + payloadBytes.length - 1],
        fields,
      };

      return { matchedDissector: dissector, layer };
    }

    return null;
  }
}

function hexStringToBytes(hex: string): number[] {
  const clean = hex.replace(/[^0-9A-Fa-f]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substring(i, i + 2), 16));
  }
  return bytes;
}
