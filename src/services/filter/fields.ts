/**
 * Field resolution for the display-filter language.
 *
 * Everything a dissector publishes is known here because it is registered in
 * `dissect/fieldRegistry` - one line per field, and the filter engine, the
 * autocomplete and the "apply as column" catalogue all derive from that one
 * list (docs/decisions/0002-field-registry.md). This module adds only the
 * names the *engine* owns rather than a dissector: the aliases people actually
 * type (`src`, `port`, `len`), and the shaped `Packet` properties that have no
 * dissector behind them (`frame.number`, `status`, `tcp.stream`).
 *
 * A resolution is a reader, not a value: a name may map to more than one place
 * on the frame (`ip.addr` is source *or* destination, `tcp.port` is either
 * end), and a comparison matches when any of them does. That is Wireshark's
 * rule for a field that occurs more than once in a frame, and it is the reason
 * `ip.addr != 10.0.0.1` has to mean "neither end is 10.0.0.1" rather than
 * "some end differs" - which would be true of every frame that has two ends.
 */

import { Packet } from '../../types/packet';
import { FIELDS, FIELD_BY_ABBREV, FieldDef, FieldType, LAYERS } from '../dissect/fieldRegistry';

export type Scalar = string | number;

export interface FieldResolution {
  /** The canonical name, for error messages and round-tripping. */
  name: string;
  type: FieldType | 'unknown';
  /** False when nothing in this build can ever produce the field. */
  known: boolean;
  /**
   * Compare this field's text without regard to case.
   *
   * True where case carries no meaning on the wire - a protocol name, an
   * address, a MAC, an enum-like status - and false elsewhere, so
   * `proto == tls` and `ip.src == 2A06:C701::1` work while a name or a payload
   * string is still matched exactly.
   */
  ci: boolean;
  /** Every value this frame carries for the name; empty when it carries none. */
  read: (p: Packet) => Scalar[];
}

/** Types whose values are compared without regard to case. */
const CASE_INSENSITIVE_TYPES: ReadonlySet<FieldType> = new Set<FieldType>([
  'proto', 'ipv4', 'ipv6', 'mac',
]);

const LAYER_TOKENS: ReadonlySet<string> = new Set(LAYERS);

/** Reads one registered field out of the generic bag. */
function fromBag(abbrev: string): (p: Packet) => Scalar[] {
  return (p) => {
    const v = p.fields?.[abbrev];
    return v === undefined ? [] : [v];
  };
}

/** Reads the first of several registered fields that the frame actually has. */
function fromAny(...abbrevs: string[]): (p: Packet) => Scalar[] {
  return (p) => {
    const out: Scalar[] = [];
    for (const a of abbrevs) {
      const v = p.fields?.[a];
      if (v !== undefined) out.push(v);
    }
    return out;
  };
}

const one = (v: Scalar | undefined): Scalar[] => (v === undefined ? [] : [v]);

interface AliasDef {
  type: FieldType | 'unknown';
  /** Overrides the default drawn from `type`. */
  ci?: boolean;
  read: (p: Packet) => Scalar[];
}

/**
 * Names the engine resolves itself.
 *
 * Two kinds live here and nothing else may: short forms of a registered field
 * (`src` for `ip.src`), and properties of the `Packet` shape that no dissector
 * writes into `fields` (`frame.number`, `status`). A protocol field belongs in
 * the registry, not here - if it is added here it will be filterable and
 * invisible, which is the split the registry exists to close.
 */
const ALIASES: Record<string, AliasDef> = {
  // --- frame -----------------------------------------------------------------
  'frame.number': { type: 'uint', read: (p) => [p.id] },
  'frame.len': { type: 'uint', read: (p) => [p.length] },
  'frame.cap_len': { type: 'uint', read: (p) => [p.rawBytes.length] },
  'frame.time_relative': { type: 'time', read: (p) => [p.relativeTime] },
  'frame.time_delta': { type: 'time', read: (p) => [p.timeDelta] },
  'frame.time_epoch': { type: 'time', read: (p) => [p.tsUs / 1_000_000] },
  'frame.protocols': { type: 'string', read: (p) => [(p.frameProtocols ?? []).join(':')] },
  'frame.interface_name': { type: 'string', read: (p) => [p.interfaceName] },
  len: { type: 'uint', read: (p) => [p.length] },
  length: { type: 'uint', read: (p) => [p.length] },

  // --- addresses -------------------------------------------------------------
  // `source`/`destination` on the Packet are whichever of v4/v6 the frame
  // carried, already formatted; a registered ip.src is the same string. Reading
  // the Packet property means these also answer on the metadata-only frames the
  // agent sends when it has no raw bytes, which carry no `fields` bag at all.
  src: { type: 'string', ci: true, read: (p) => [p.source] },
  dst: { type: 'string', ci: true, read: (p) => [p.destination] },
  addr: { type: 'string', ci: true, read: (p) => [p.source, p.destination] },
  ip: { type: 'ipv4', read: (p) => [p.source, p.destination] },
  'ip.addr': { type: 'ipv4', read: (p) => [p.source, p.destination] },
  'ipv6.addr': { type: 'ipv6', read: fromAny('ipv6.src', 'ipv6.dst') },
  'eth.addr': { type: 'mac', read: fromAny('eth.src', 'eth.dst') },

  // --- ports -----------------------------------------------------------------
  port: { type: 'uint', read: (p) => [...one(p.sourcePort), ...one(p.destPort)] },
  'tcp.port': { type: 'uint', read: fromAny('tcp.srcport', 'tcp.dstport') },
  'udp.port': { type: 'uint', read: fromAny('udp.srcport', 'udp.dstport') },
  srcport: { type: 'uint', read: (p) => one(p.sourcePort) },
  dstport: { type: 'uint', read: (p) => one(p.destPort) },

  // --- summary columns -------------------------------------------------------
  // `proto` answers with both the displayed label ("TLSv1.2") and the coarse
  // key ("TLS"), so `proto == tls` typed by hand and `proto == tlsv1.2` from a
  // clicked breakdown segment resolve to the same frames.
  proto: { type: 'proto', read: (p) => (p.protocolLabel ? [p.protocolLabel, p.protocol] : [p.protocol]) },
  protocol: { type: 'proto', read: (p) => (p.protocolLabel ? [p.protocolLabel, p.protocol] : [p.protocol]) },
  info: { type: 'string', read: (p) => [p.info] },
  status: { type: 'string', ci: true, read: (p) => [p.status] },
  stream: { type: 'uint', read: (p) => one(p.streamId) },
  'tcp.stream': { type: 'uint', read: (p) => one(p.streamId) },
  'anomaly.severity': { type: 'string', ci: true, read: (p) => (p.anomalies ?? []).map((a) => a.severity) },
  'anomaly.type': { type: 'string', ci: true, read: (p) => (p.anomalies ?? []).map((a) => a.type) },
};

/**
 * Barewords that name a protocol this build understands but that is not a
 * layer token in `frameProtocols` - either because it is a coarse `protocol`
 * key rather than a dissected layer, or because it is a synthetic condition.
 */
const PROTOCOL_PREDICATES: Record<string, (p: Packet) => boolean> = {
  // `http` is a layer token now: it is in `frameProtocols` when the frame
  // actually carried an HTTP message, so the bareword resolves there and the
  // predicate that matched every frame on port 80 is gone.
  https: (p) => p.protocol === 'HTTPS',
  ssh: (p) => p.protocol === 'SSH',
  mqtt: (p) => p.protocol === 'MQTT',
  mdns: (p) => p.protocolLabel === 'MDNS',
  llmnr: (p) => p.protocolLabel === 'LLMNR',
  anomaly: (p) => (p.anomalies?.length ?? 0) > 0 || p.status === 'alert',
  proto_iot: (p) => p.protocol === 'CUSTOM' || p.info.includes('Proto-IoT'),
  finfast: (p) => p.protocol === 'CUSTOM' || p.info.includes('FinFast'),
};

/**
 * How to answer a layer test for a frame that recorded no layers at all.
 *
 * The only frames in that position are the metadata-only ones the agent sends
 * when it has no raw bytes to dissect; they carry a coarse `protocol` and
 * nothing else. This is a *last resort* and never overrides a recorded layer
 * list, because `Packet.protocol` defaults to `TCP` for any frame that never
 * reached a transport decoder - an ARP reply, an IGMP report, a broadcast
 * Ethernet frame. Consulting it for a frame that did dissect would paint all
 * of those as TCP, which is precisely what it did for one measurement before
 * the parity run caught it.
 */
const NO_LAYERS_FALLBACK: Record<string, (p: Packet) => boolean> = {
  tls: (p) => p.protocol === 'TLS' || p.protocol === 'HTTPS',
  quic: (p) => p.protocol === 'QUIC',
  dns: (p) => p.protocol === 'DNS',
};

/**
 * Protocols this build knows by name and does not dissect.
 *
 * A deliberately small, explicit list - the opposite of the hand-kept lists
 * the field registry exists to abolish, and it earns its place: Wireshark's
 * default colour rules, which Inwire ships, are written against protocols a
 * browser-based analyzer has not got to yet. Naming them here is what lets
 * those rules keep their filters and light up on their own when the dissector
 * lands, instead of being deleted now and rewritten later. Everything *not*
 * on this list and not in the registry is treated as a typo.
 *
 * `eth.fcs` is here for a different reason: a captured frame does not include
 * the Ethernet FCS, so the field can never have a value no matter what is
 * implemented.
 */
const UNDISSECTED = [
  // Routing and redundancy, from the reference analyzer's "Routing" and
  // "Checksum Errors" default rules.
  'hsrp', 'vrrp', 'carp', 'glbp', 'ospf', 'bgp', 'eigrp', 'rip', 'pim', 'isis', 'babel',
  // Discovery and management.
  'cdp', 'gvrp', 'ismp', 'vtp', 'dtp', 'edp',
  // Windows file sharing, from the "SMB" rule.
  'smb', 'smb2', 'nbss', 'nbns', 'netbios', 'dcerpc', 'browser',
  // Transport and application layers not yet decoded.
  'sctp', 'rtp', 'rtcp', 'sip', 'ldap', 'kerberos', 'radius', 'snmp',
  // Never available from a capture, whatever is implemented.
  'eth.fcs',
];
const UNDISSECTED_SET: ReadonlySet<string> = new Set(UNDISSECTED);

/**
 * True for a name that belongs to a protocol this build recognises but does
 * not decode - either the bareword itself (`ospf`) or a field under it
 * (`ospf.msg`). Such a name compiles to "matches nothing" and is reported as
 * a warning; anything else unknown is reported as a typo.
 */
export function isUndissected(name: string): boolean {
  if (UNDISSECTED_SET.has(name)) return true;
  return UNDISSECTED.some((prefix) => name.startsWith(prefix + '.'));
}

export function isLayerToken(name: string): boolean {
  return LAYER_TOKENS.has(name);
}

export function isProtocolBareword(name: string): boolean {
  return LAYER_TOKENS.has(name) || name in PROTOCOL_PREDICATES;
}

/** The presence test for a bareword, or null when the name names no protocol. */
export function layerPresence(name: string): ((p: Packet) => boolean) | null {
  if (LAYER_TOKENS.has(name)) {
    const fallback = NO_LAYERS_FALLBACK[name];
    return (p) => {
      const layers = p.frameProtocols;
      // A frame that recorded its layers and does not list this one has
      // genuinely not got it. Nothing else is consulted.
      if (layers && layers.length > 0) return layers.includes(name);
      return fallback ? fallback(p) : p.protocol.toLowerCase() === name;
    };
  }
  const direct = PROTOCOL_PREDICATES[name];
  return direct ?? null;
}

/**
 * Resolves a filter name to a reader. Returns a resolution with
 * `known: false` for a name nothing in this build produces, rather than
 * throwing: a colour rule written for a protocol Inwire does not dissect
 * should match nothing quietly, and the validator reports it separately.
 */
export function resolveField(name: string): FieldResolution {
  const alias = ALIASES[name];
  if (alias) {
    const ci = alias.ci ?? (alias.type !== 'unknown' && CASE_INSENSITIVE_TYPES.has(alias.type));
    return { name, type: alias.type, known: true, ci, read: alias.read };
  }

  const def = FIELD_BY_ABBREV.get(name);
  if (def) {
    return { name, type: def.type, known: true, ci: CASE_INSENSITIVE_TYPES.has(def.type), read: fromBag(name) };
  }

  return {
    name,
    type: 'unknown',
    known: false,
    ci: false,
    // Still reads the bag: a custom dissector may publish a name the registry
    // does not carry, and a filter on it should work rather than be dead.
    read: fromBag(name),
  };
}

/** Every name a filter may use, for validation and autocomplete. */
export function knownFieldNames(): string[] {
  return [...Object.keys(ALIASES), ...FIELDS.map((f) => f.abbrev)].sort();
}

/** Every bareword that tests for a protocol's presence. */
export function protocolNames(): string[] {
  return [...LAYER_TOKENS, ...Object.keys(PROTOCOL_PREDICATES)].sort();
}

/** The fields "Apply as column" offers, from the registry. */
export function columnCatalogue(): readonly FieldDef[] {
  return FIELDS.filter((f) => f.column !== undefined);
}
