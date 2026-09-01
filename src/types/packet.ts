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

  /**
   * Renders this field as Wireshark's dotted-binary row - `0110 .... =
   * Version: 6` - instead of the plain `name: value` line.
   *
   * `totalBits` is the width of the binary string to draw and is emitted by
   * the dissector, never derived here: IPv6 renders Version over 8 bits,
   * Traffic Class over 32 and Flow Label over 24, all inside the same 4-byte
   * word, so there is no rule the renderer could infer it from. Bits are
   * counted from the MSB of the byte at rawBytesRange[0].
   */
  bitfield?: {
    bitOffset: number;
    bitLength: number;
    totalBits: number;
  };

  /**
   * A synthetic field the dissector computed rather than read off the wire -
   * Wireshark shows these in [brackets]. They describe no bytes, so the tree
   * must not offer a byte highlight for them.
   */
  generated?: boolean;

  /** A reference to another frame (`[Response In: 11]`). Clicking selects it. */
  linkToFrame?: number;

  /** Analysis output surfaced inline, e.g. a suspected retransmission. */
  expertInfo?: {
    severity: 'chat' | 'note' | 'warn' | 'error';
    message: string;
  };
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
  /**
   * The protocol layers actually dissected in this frame, lowercase, outermost
   * first - Wireshark's `frame.protocols` (["eth","ethertype","ipv6","tcp"]).
   *
   * Display filters and color rules test protocol *presence* against this
   * rather than against `protocol`, which names only the top-most layer. A
   * TLSv1.2 frame has to satisfy the `tcp` rule, and a frame whose transport
   * layer failed to dissect must not, which a single top-most name can't
   * express.
   */
  frameProtocols?: string[];
  /**
   * Dissected field values under their Wireshark names ("tcp.flags",
   * "ipv6.hlim", "icmpv6.type"), so display filters can reference any field a
   * dissector produced without the filter engine needing a case for each one.
   */
  fields?: Record<string, string | number>;
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
  /** Optional: derived on demand via packetHexDump() rather than stored, so
   *  a large capture buffer does not carry a rendered dump per packet. */
  hexDump?: string;
  /** Optional: see hexDump. Use packetAsciiDump(). */
  asciiDump?: string;
  anomalies?: AnomalyInfo[];
  interfaceName: string;
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
  /**
   * A rule's own colors, used only as a fallback.
   *
   * Appearance belongs to the active packet theme (see services/packetThemes),
   * which keys its palette by rule id and covers every built-in rule - so for
   * those these are never read. They remain for a user-defined rule, which no
   * shipped theme can know about and which would otherwise render unpainted.
   *
   * The built-in rules still carry them so the shipped themes can be diffed
   * against the palette the list historically used.
   */
  bgColor?: string;
  textColor?: string;
  lightBgColor?: string;
  lightTextColor?: string;
  enabled: boolean;
}

/** A named display filter, applied from the Presets dropdown. */
export interface FilterPreset {
  id: string;
  name: string;
  filter: string;
  description: string;
}

/**
 * A user-created folder of presets.
 *
 * Presets are nested inside their group rather than pointing at one by id:
 * membership and within-group ordering are then the same fact - a preset's
 * position in this array - so a drag between groups cannot leave the two
 * disagreeing. Array order is display order, in the Settings panel and in the
 * Presets dropdown alike.
 */
export interface FilterPresetGroup {
  id: string;
  name: string;
  presets: FilterPreset[];
}

/**
 * The whole preset library, as persisted to localStorage.
 *
 * A wrapper object rather than a bare array so the stored shape has somewhere
 * to grow without a migration.
 */
export interface FilterPresetLibrary {
  groups: FilterPresetGroup[];
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
