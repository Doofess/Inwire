export type ProtocolType =
  | 'HTTP'
  | 'HTTPS'
  | 'TCP'
  | 'UDP'
  | 'DNS'
  | 'TLS'
  | 'ICMP'
  | 'ARP'
  | 'MQTT'
  | 'QUIC'
  | 'SSH'
  | 'CUSTOM';

export type PacketStatus = 'ok' | 'warning' | 'alert' | 'retransmit' | 'dropped';

export interface FieldHighlight {
  startByte: number; // 0-indexed byte offset in raw packet
  endByte: number;   // inclusive 0-indexed byte offset
  layerName: string;
  fieldName: string;
}

export interface ProtocolField {
  name: string;
  value: string | number | boolean;
  rawBytesRange?: [number, number]; // [startByte, endByte]
  description?: string;
  children?: ProtocolField[];
  isExpanded?: boolean;
}

export interface ProtocolLayer {
  name: string;
  summary: string;
  rawBytesRange?: [number, number];
  fields: ProtocolField[];
}

export interface AnomalyInfo {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  recommendation: string;
  mitreTechnique?: string;
}

export interface Packet {
  id: number;
  timestamp: number; // milliseconds epoch
  timeDelta: number; // delta from previous packet in seconds
  relativeTime: number; // seconds since capture start
  source: string;
  destination: string;
  sourcePort?: number;
  destPort?: number;
  protocol: ProtocolType;
  /**
   * The free-form protocol name shown in the Protocol column, matching what
   * Wireshark displays for the top-most dissected layer: "TLSv1.2", "ICMPv6",
   * "SSDP", "ieee1905". `protocol` above stays the coarse, closed-union key
   * that filters and color rules match on; this is display only. Absent when
   * the two would be identical.
   */
  protocolLabel?: string;
  /**
   * Decimal places the capture's timestamps are meaningful to - 6 for a
   * microsecond capture, 9 for nanosecond. Drives how many digits the Time
   * column renders, the way Wireshark follows the file's own resolution.
   */
  tsPrecision?: number;
  /**
   * Wireshark's tcp.analysis.* field names that fired for this frame
   * ("retransmission", "lost_segment", "keep_alive", ...). Empty or absent
   * when the segment looks normal. Display filters and color rules match on
   * these, which is how the "Bad TCP" rule distinguishes a genuinely broken
   * segment from a routine keep-alive.
   */
  analysisFlags?: string[];
  length: number; // in bytes
  info: string;
  status: PacketStatus;
  streamId?: number;
  streamPayload?: {
    direction: 'client_to_server' | 'server_to_client';
    payloadText: string;
    payloadType: 'text' | 'binary' | 'json' | 'tls_encrypted';
  };
  layers: ProtocolLayer[];
  rawBytes: Uint8Array;
  hexDump: string;
  asciiDump: string;
  anomalies?: AnomalyInfo[];
  interfaceName: string;
  colorRuleName?: string;
}

export interface CustomDissectorFieldDef {
  name: string;
  offset: number;
  length: number; // in bytes
  type: 'uint8' | 'uint16' | 'uint32' | 'string' | 'hex' | 'flags';
  description?: string;
}

export interface CustomDissectorRule {
  id: string;
  name: string;
  protocolName: string;
  port?: number;
  transport: 'TCP' | 'UDP' | 'ANY';
  magicHeaderHex?: string; // e.g. "504B54" (PKT)
  magicOffset?: number;
  description: string;
  enabled: boolean;
  fields: CustomDissectorFieldDef[];
  customParserJs?: string; // Optional custom JS parsing snippet
}

export interface ColorRule {
  id: string;
  name: string;
  filter: string;
  bgColor: string;
  textColor: string;
  enabled: boolean;
}

export interface FilterPreset {
  id: string;
  name: string;
  filter: string;
  category: 'Security' | 'Web' | 'Troubleshooting' | 'Custom';
  description: string;
}

export type UserRole = 'ADMIN' | 'SOC_ANALYST' | 'NETWORK_ENGINEER' | 'AUDITOR_GUEST';

export interface UserRolePermissions {
  canCapture: boolean;
  canExportPcap: boolean;
  canViewPayloads: boolean;
  canEditDissectors: boolean;
  canConfigureAlerts: boolean;
  canChangeColorRules: boolean;
  canClearBuffer: boolean;
}

export interface TrafficStats {
  totalPackets: number;
  totalBytes: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  protocolCounts: Record<string, number>;
  protocolBytes: Record<string, number>;
  anomaliesDetected: number;
  topTalkers: { ip: string; count: number; bytes: number }[];
  topPorts: { port: number; count: number; service: string }[];
  durationSeconds: number;
}
