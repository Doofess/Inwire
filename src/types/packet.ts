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

/**
 * How serious a finding is, in Wireshark's four levels.
 *
 * The app had two vocabularies for this: dissectors wrote `chat/note/warn/error`
 * onto tree rows while `AnomalyInfo` used `low/medium/high/critical`, and
 * nothing related them - so the same frame could be a "warning" in the tree and
 * a "high" in the alerts panel, and no view could rank the two against each
 * other. This is the one enum; `services/expertInfo.ts` maps the anomaly
 * severities onto it.
 */
export type ExpertSeverity = 'chat' | 'note' | 'warn' | 'error';

/**
 * Wireshark's expert groups, which is what its Expert Information dialog
 * sorts by. Declared by whoever raises the finding rather than guessed from
 * the message text: a dissector knows whether it is complaining about a
 * checksum or a sequence number, and a keyword match over prose does not.
 */
export type ExpertGroup =
  | 'Checksum'
  | 'Sequence'
  | 'Malformed'
  | 'Protocol'
  | 'Security'
  | 'Response';

export interface ExpertInfo {
  severity: ExpertSeverity;
  message: string;
  /** Defaults to `Protocol` where a dissector does not say. */
  group?: ExpertGroup;
}

export interface ProtocolField {
  name: string;
  value: string | number | boolean;
  /**
   * The field's filter name (`tcp.flags.syn`), from `services/dissect/fieldRegistry`.
   * A row that carries one can be turned into a filter or a column; a row
   * without one is display only. Present on every field a dissector also
   * publishes into `Packet.fields`.
   */
  abbrev?: string;
  rawBytesRange?: [number, number]; // [startByte, endByte]
  description?: string;
  children?: ProtocolField[];
  isExpanded?: boolean;

  /**
   * Renders this field as the reference analyzer's dotted-binary row - `0110 .... =
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
   * The reference analyzer shows these in [brackets]. They describe no bytes, so the tree
   * must not offer a byte highlight for them.
   */
  generated?: boolean;

  /** A reference to another frame (`[Response In: 11]`). Clicking selects it. */
  linkToFrame?: number;

  /** Analysis output surfaced inline, e.g. a suspected retransmission. */
  expertInfo?: ExpertInfo;
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
  /**
   * Capture time, epoch microseconds - the driver's own resolution, exact as a
   * JS number. Was milliseconds, which quietly threw away the three digits the
   * driver stamps and re-exported a capture at coarser precision than it came
   * in at.
   */
  tsUs: number;
  /** The full nanosecond stamp for a nanosecond-resolution capture file. */
  tsNanos?: bigint;
  timeDelta: number; // delta from previous packet in seconds
  relativeTime: number; // seconds since capture start
  source: string;
  destination: string;
  sourcePort?: number;
  destPort?: number;
  protocol: ProtocolType;
  /**
   * The free-form protocol name shown in the Protocol column, matching what
   * The reference analyzer displays for the top-most dissected layer: "TLSv1.2", "ICMPv6",
   * "SSDP", "ieee1905". `protocol` above stays the coarse, closed-union key
   * that filters and color rules match on; this is display only. Absent when
   * the two would be identical.
   */
  protocolLabel?: string;
  /**
   * Decimal places the capture's timestamps are meaningful to - 6 for a
   * microsecond capture, 9 for nanosecond. Drives how many digits the Time
   * column renders, the way the reference analyzer follows the file's own resolution.
   */
  tsPrecision?: number;
  /**
   * The reference analyzer's tcp.analysis.* field names that fired for this frame
   * ("retransmission", "lost_segment", "keep_alive", ...). Empty or absent
   * when the segment looks normal. Display filters and color rules match on
   * these, which is how the "Bad TCP" rule distinguishes a genuinely broken
   * segment from a routine keep-alive.
   */
  analysisFlags?: string[];
  /**
   * The protocol layers actually dissected in this frame, lowercase, outermost
   * first - the reference analyzer's `frame.protocols` (["eth","ethertype","ipv6","tcp"]).
   *
   * Display filters and color rules test protocol *presence* against this
   * rather than against `protocol`, which names only the top-most layer. A
   * TLSv1.2 frame has to satisfy the `tcp` rule, and a frame whose transport
   * layer failed to dissect must not, which a single top-most name can't
   * express.
   */
  frameProtocols?: string[];
  /**
   * Dissected field values under their conventional names ("tcp.flags",
   * "ipv6.hlim", "icmpv6.type"), so display filters can reference any field a
   * dissector produced without the filter engine needing a case for each one.
   */
  fields?: Record<string, string | number>;
  /**
   * Names this frame mapped to addresses - a DNS or mDNS answer set.
   *
   * Kept on the packet rather than handed to the caller as a side channel so
   * the passive name map can be derived from the buffer alone, which is what
   * makes it work identically for a live capture, an imported file and a
   * restored session (services/nameResolution.ts). One name maps to several
   * addresses, which is why this cannot live in the flat `fields` bag.
   */
  resolved?: { name: string; addresses: string[] }[];
  length: number; // in bytes
  info: string;
  status: PacketStatus;
  streamId?: number;
  streamPayload?: {
    direction: 'client_to_server' | 'server_to_client';
    payloadText: string;
    payloadType: 'text' | 'binary' | 'json' | 'tls_encrypted';
  };
  /**
   * Every finding this frame's dissectors raised, flattened.
   *
   * The same findings are attached to the tree rows they belong to, and until
   * Phase 11 that was the only place they lived - Expert Information built its
   * list by walking every frame's tree. The tree is dissected on demand now
   * (docs/decisions/0007), so a view that aggregates over the whole buffer
   * cannot go and get it; the findings themselves ride on the frame, which is
   * what `DissectSummary.expert` was for.
   *
   * Absent, not empty, on a frame with nothing to say - which is most of them.
   */
  expert?: ExpertInfo[];
  /**
   * The protocol tree. Empty on a frame that has not been asked about: it is
   * 10.6 kB per frame and the detail pane is the only thing that reads it, so
   * it is dissected on demand rather than carried (docs/decisions/0007).
   */
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
