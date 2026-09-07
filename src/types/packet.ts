import type { FieldBlock } from '../services/dissect/fieldBlock';

export type ProtocolType =
  | 'HTTP'
  | 'HTTPS'
  | 'TCP'
  | 'UDP'
  | 'DNS'
  | 'GRE'
  | 'LDAP'
  | 'SMB2'
  | 'TLS'
  | 'ICMP'
  | 'ARP'
  | 'MQTT'
  | 'QUIC'
  | 'SSH'
  | 'CUSTOM';

export type PacketStatus = 'ok' | 'warning' | 'alert' | 'retransmit' | 'dropped';

/**
 * What a finding means, and what the reader should conclude from it.
 *
 * This replaced a severity (`chat/note/warn/error`) that was doing three jobs
 * and none of them well. Measured over both fixtures, severity was dominated by
 * `error/Checksum` - and **every one of those was a false alarm**: 1,998 and
 * 3,459 findings, 100% of them on frames this machine SENT, where the NIC had
 * not filled the checksum in yet. A single axis that cannot separate "damaged"
 * from "not written yet" is not a severity, it is noise, and it is why the
 * colour rule that painted rows from it shipped disabled.
 *
 * Named after the conclusion rather than after the subsystem that spoke, which
 * is where this leaves Wireshark. Its seventeen groups - Reassemble, Undecoded,
 * Dissector bug - tell you which part of Wireshark raised the finding; they do
 * not tell you what to do about it. These eight tell you what it is.
 *
 * Two of them exist only because this app knows something Wireshark cannot.
 * `Unverifiable` and `CaptureGap` are both "the vantage point is the problem,
 * not the network" - the first needs `frame.direction` to know the frame was
 * ours, and the second is the sniffer admitting it missed frames rather than
 * blaming the wire.
 *
 * Ordering matters: it is the order the shipped colour rules sit in, and the
 * chain is first-match-wins. A frame that is both Broken and a Capture gap
 * paints as Broken.
 */
export type ExpertCategory =
  /** The frame is damaged or could not be decoded. */
  | 'Broken'
  /** A conversation was terminated: RST, abort, a port reused under a live one. */
  | 'Reset'
  /** The network lost or reordered something: retransmission, out-of-order. */
  | 'Loss'
  /** Certificates, address conflicts - worth a look before anything else. */
  | 'Security'
  /**
   * **This capture** is incomplete - the sniffer missed frames.
   *
   * Wireshark files "ACKed unseen segment" and "Previous segment not captured"
   * under Sequence, alongside real retransmissions, so a dropped capture reads
   * as a failing network. They are 2,427 frames of the inwire fixture - the
   * largest non-checksum group in it - and they say nothing about the wire.
   */
  | 'CaptureGap'
  /** The peer is throttling rather than failing: zero window, keep-alives. */
  | 'FlowControl'
  /**
   * Cannot be judged from here.
   *
   * A checksum on a frame this machine sent was never filled in - the NIC does
   * that after the sniffer sees it. Reporting that as an error is what made the
   * whole expert system unusable on a locally-taken capture.
   */
  | 'Unverifiable'
  /** Informational: NXDOMAIN, a duplicate across adapters. */
  | 'Note';

export interface ExpertInfo {
  message: string;
  /** Defaults to `Note` where a dissector does not say. */
  category?: ExpertCategory;
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
   * Which colouring rule this frame matched, as `ColorRulesEngine` packs it.
   *
   * A **cache**, owned entirely by that engine and meaningless outside it -
   * which is why it is one opaque number rather than a rule id. It is on the
   * packet because the alternative was a `WeakMap` entry per frame, measured at
   * 41 B against this field's 8 (`scripts/perf/color-index-cost.ts`), and
   * because the answer really is a property of the frame: a packet is immutable
   * once dissected and the chain is deterministic, so the rule it matches can
   * never change while the chain does not.
   *
   * Never persisted and never exported: `toStoredFrame` and the export writers
   * both build explicit objects, so this is inert in both. A frame restored
   * from disk simply arrives without it and is matched on first sight.
   */
  colorSlot?: number;
  /**
   * Which way this frame went, relative to the machine that captured it, the
   * signal that decided it, and whether it duplicates a frame already seen on
   * another adapter - packed into one number.
   *
   * The fact a capture taken *on an endpoint* has and one taken anywhere else
   * does not: Wireshark has no way to know which of the two MACs in a frame
   * belongs to the machine you are sitting at.
   *
   * Packed for the same reason `colorSlot` is, and it really is three facts
   * rather than one dressed up - the column's tooltip names the deciding
   * signal, so the signal has to be stored whatever shape this takes. A
   * `fields` entry would cost ~30 B a frame against ~8, and a dense column is
   * ruled out outright by `POST_DISSECTION_KEYS`, because a host override has
   * to re-derive direction for frames already in the buffer and a filled
   * column row cannot be rewritten.
   *
   * Absent means unknown, and unknown means nobody could answer - never that
   * the frame went nowhere. Read it through `services/direction.ts`; nothing
   * else should touch the bits.
   *
   * Not persisted (`toStoredFrame` builds an explicit object) - a restored
   * frame is re-dissected and decides again, which is right, because the host
   * identity may have changed since.
   */
  direction?: number;
  /**
   * The column block holding this frame's dense fields, and its row in it.
   *
   * Set when the frame joins the buffer (`services/dissect/fieldSplit.ts`);
   * absent on a frame that never did - one imported from a CSV, or replayed to
   * build a detail tree - which keeps its whole bag and reads exactly as it
   * always has. **The bag is the contract; the columns are an optimisation.**
   *
   * The block is referenced, not registered: when the buffer trims the last
   * frame that shares one, it becomes unreachable and the collector takes it.
   * Nothing rebases, and nothing is keyed by position in the buffer - which is
   * what makes this survive trimming, filtering and sorting alike.
   *
   * Never persisted and never exported, like `colorSlot`: `toStoredFrame` and
   * the export writers both build explicit objects.
   */
  cols?: FieldBlock;
  row?: number;
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

/**
 * What this build lets the user do.
 *
 * It was `UserRolePermissions`, one of four sets handed out by role from
 * `services/rbacService.ts`. No role ever reached it - `App.tsx` built the
 * admin set by hand and the role tables sat unread - so the name promised an
 * authorisation model the app does not have. Renamed to say what it is: a flat
 * set of capabilities, read at seventeen sites to gate real controls.
 *
 * `canConfigureAlerts` went with the alerts feature; nothing read it after the
 * anomaly model was removed.
 */
export interface Capabilities {
  canCapture: boolean;
  canExportPcap: boolean;
  canViewPayloads: boolean;
  canEditDissectors: boolean;
  canChangeColorRules: boolean;
  canClearBuffer: boolean;
}

