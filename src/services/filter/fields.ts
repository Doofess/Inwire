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
import { DIRECTION_NAMES, directionOf, isDuplicate } from '../direction';
import { FIELDS, FIELD_BY_ABBREV, FieldDef, FieldType, LAYERS } from '../dissect/fieldRegistry';
import { fieldReader } from '../dissect/fieldAccess';
import { protocolsInFrame } from '../dissect/protocolsInFrame';
import type { Marks } from '../marks';

export type Scalar = string | number;

/**
 * What a filter reads that is not on the packet (ADR 0067).
 *
 * Today that is the capture's marks: `frame.marked` is true of a frame because
 * the user marked it after it was stored, so no row can carry it. A matcher
 * holds this **object**, not the set inside it, and reads `marked` on every
 * frame it decides: a caller that replaces `context.marked` is read by a
 * matcher compiled before it did, so a held matcher never keeps a stale set.
 * (A cache of RESULTS is another matter: see `incrementalFilter.ts`.)
 */
export interface FilterContext {
  marked?: Marks;
}

export interface FieldResolution {
  /** The canonical name, for error messages and round-tripping. */
  name: string;
  type: FieldType | 'unknown';
  /** False when nothing in this build can ever produce the field. */
  known: boolean;
  /**
   * Set when the name IS registered and is deliberately not filterable - shown
   * in the detail tree, never written into the bag. See `FieldDef.treeOnly`.
   *
   * Carried on the resolution rather than looked up from the registry by the
   * caller, so `compile.ts` keeps depending on this module alone and not on
   * `dissect/fieldRegistry` as well.
   */
  treeOnly?: true;
  /**
   * Compare this field's text without regard to case.
   *
   * True where case carries no meaning on the wire - a protocol name, an
   * address, a MAC, an enum-like status - and false elsewhere, so
   * `proto == tls` and `ip.src == 2001:DB8::1` work while a name or a payload
   * string is still matched exactly.
   */
  ci: boolean;
  /**
   * Every value this frame carries for the name; empty when it carries none.
   * Only `frame.marked` looks at the context; every other reader ignores it.
   */
  read: (p: Packet, context?: FilterContext) => Scalar[];
  /**
   * The reader looks at the context. Set so the compiler binds the context only
   * where it is read and leaves every other reader unwrapped: a wrapper per
   * read is a cost on the busiest path in the app.
   */
  contextual?: true;
}

/** Types whose values are compared without regard to case. */
const CASE_INSENSITIVE_TYPES: ReadonlySet<FieldType> = new Set<FieldType>([
  'proto', 'ipv4', 'ipv6', 'mac',
]);

const LAYER_TOKENS: ReadonlySet<string> = new Set(LAYERS);

/**
 * Reads one registered field, wherever the frame keeps it.
 *
 * Through `dissect/fieldAccess.ts` rather than off `p.fields` directly: a
 * frame's dense fields live in a column block rather than in the bag
 * (`docs/decisions/0017`), and this is the busiest read in the app - every
 * filter and every colour rule arrives here, once per frame per pass.
 */
function fromBag(abbrev: string): (p: Packet) => Scalar[] {
  // Resolved once, here, rather than per frame: this closure is built when an
  // expression is compiled and then run over the whole buffer, so it can know
  // which half of the frame its field lives in before it sees a frame.
  const read = fieldReader(abbrev);
  return (p) => {
    const v = read(p);
    return v === undefined ? [] : [v];
  };
}

/** Reads the first of several registered fields that the frame actually has. */
function fromAny(...abbrevs: string[]): (p: Packet) => Scalar[] {
  const readers = abbrevs.map(fieldReader);
  return (p) => {
    const out: Scalar[] = [];
    for (const read of readers) {
      const v = read(p);
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
  read: (p: Packet, context?: FilterContext) => Scalar[];
  /** See `FieldResolution.contextual`. */
  contextual?: true;
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
  // Present on every frame, 1 or 0, as in Wireshark: a bare `frame.marked` is
  // every frame and `frame.marked == 1` the marked ones. Read through the
  // context, not the packet; with no context nothing is marked. The registry
  // keeps its tree-only row, as it does for `frame.number`: an alias wins in
  // `resolveField`, so the name filters and the tree row is untouched.
  'frame.marked': {
    type: 'uint', contextual: true,
    read: (p, context) => [context?.marked?.has(p.id) ? 1 : 0],
  },
  'frame.cap_len': { type: 'uint', read: (p) => [p.rawBytes.length] },
  'frame.time_relative': { type: 'time', read: (p) => [p.relativeTime] },
  'frame.time_delta': { type: 'time', read: (p) => [p.timeDelta] },
  'frame.time_epoch': { type: 'time', read: (p) => [p.tsUs / 1_000_000] },
  // Spelled as the reference spells it (`eth:ethertype:ip:tcp`), so a filter
  // copied out of Wireshark matches here too.
  'frame.protocols': { type: 'string', read: (p) => [protocolsInFrame(p.frameProtocols ?? [])] },
  'frame.interface_name': { type: 'string', read: (p) => [p.interfaceName] },
  // Which way the frame went, relative to the capturing host. Two spellings
  // each, and the aliasing needs no new machinery: a reader may return several
  // values, which is how `proto == tls` and `proto == tlsv1.2` both match one
  // frame. `out` is what the column and the pcapng flag mean; `sent` is what
  // somebody types. Both are true of the frame, so both match it.
  'frame.direction': {
    type: 'string', ci: true,
    read: (p) => DIRECTION_NAMES[directionOf(p.direction)],
  },
  // Reads as nothing at all on a frame that is not a duplicate, rather than
  // as a false. That is what makes a bare `frame.duplicate` work: presence is
  // `read(p).length > 0`, and the engine's own rule is that a field a frame
  // does not carry never matches under any operator. `frame.duplicate == 1`
  // works too, for anyone who prefers to spell it out.
  'frame.duplicate': { type: 'uint', read: (p) => (isDuplicate(p.direction) ? [1] : []) },
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
  // `anomaly.severity` and `anomaly.type` were here. The anomaly detector was
  // two hard-coded TCP findings that duplicated the analysis flags, so both
  // names now answer as `inwire.expert.category`, which covers every finding
  // rather than those two.
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
  // `ssh` left when it became a layer token - see dissectors/ssh.ts. The
  // predicate it had matched every segment on port 22, bare ACKs included.
  mqtt: (p) => p.protocol === 'MQTT',
  mdns: (p) => p.protocolLabel === 'MDNS',
  llmnr: (p) => p.protocolLabel === 'LLMNR',
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
export const UNDISSECTED = [
  // Routing and redundancy, from the reference analyzer's "Routing" and
  // "Checksum Errors" default rules.
  // hsrp, vrrp, ospf and rip left this list when they became real layer
  // tokens; the ones here are the stateful or tunnelling half, which is a
  // different piece of work - see docs/decisions/0019.
  'carp', 'glbp', 'eigrp', 'pim', 'isis', 'babel',
  // Discovery and management. `cdp` left this list - see dissectors/cdp.ts.
  'gvrp', 'ismp', 'vtp', 'dtp', 'edp',
  // Windows file sharing, from the "SMB" rule.
  // `nbns` was here until it became a real layer token - see dissectors/nbns.ts,
  // and `smb2`, `smb` (SMB1), `browser`, `nbss` and `dcerpc` went the same
  // way - see dissectors/smb2.ts, smb.ts, nbss.ts and dcerpc.ts.
  'netbios',
  // Transport and application layers not yet decoded.
  // sip, radius, snmp and rtcp left this list when they became real layer
  // tokens. `rtcp` outstayed the others by a batch, which meant a misspelt
  // `rtcp.*` name was reported as "a protocol this build cannot decode"
  // rather than as the typo it was - the check below is what caught it.
  // `ldap` and `kerberos` left this list when they became real layer tokens -
  // see dissectors/ldap.ts and dissectors/kerberos.ts, and `rtp` when RTP
  // did - see dissectors/rtp.ts.
  'sctp',
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
 * Every registered abbrev, indexed by its lower-cased form.
 *
 * The parser lower-cases a field name, which was harmless while every abbrev
 * was lower case and is not any more: the reference analyzer spells ten of
 * them with capitals (`sip.Method`, `sip.Call-ID`, `radius.User_Name`,
 * `ptp.v2.mm.managementId`), and holding the registry to Wireshark's spelling
 * made those names unresolvable - `sip.Method` looked up `sip.method`, found
 * nothing, and was reported as a typo.
 *
 * Matching stays case-insensitive, which is deliberately **more forgiving than
 * Wireshark**, whose own filter names are case-sensitive. Someone typing
 * `sip.call-id` from memory should not be told it does not exist. What the
 * index adds is the canonical spelling to read the bag under, since that is
 * the key the dissector actually wrote.
 */
const BY_LOWERCASE_ABBREV: ReadonlyMap<string, FieldDef> = new Map(
  FIELDS.map((f) => [f.abbrev.toLowerCase(), f]),
);

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
    return {
      name, type: alias.type, known: true, ci, read: alias.read,
      ...(alias.contextual === true ? { contextual: true as const } : {}),
    };
  }

  // Exact first, then case-insensitively. `read` uses the REGISTERED spelling
  // rather than what was typed - the bag is keyed by what the dissector wrote.
  const def = FIELD_BY_ABBREV.get(name) ?? BY_LOWERCASE_ABBREV.get(name.toLowerCase());
  if (def) {
    return {
      name: def.abbrev,
      type: def.type,
      // A tree-only field is registered and drawn in the detail tree, and no
      // dissector writes it into the bag - so `fromBag` would answer `undefined`
      // for every frame and the comparison would quietly be false everywhere.
      // `known: false` is the honest resolution: it compiles to ALWAYS_FALSE
      // exactly as before, and `unknownNames` now has something to report, so
      // the filter bar can SAY the field is not filterable instead of returning
      // an empty list that looks like "no such traffic". See `FieldDef.treeOnly`.
      known: def.treeOnly !== true,
      ...(def.treeOnly === true ? { treeOnly: true as const } : {}),
      ci: CASE_INSENSITIVE_TYPES.has(def.type),
      read: fromBag(def.abbrev),
    };
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

/*
 * The three name lists below are built once and shared.
 *
 * `FIELDS`, `ALIASES`, `LAYER_TOKENS` and `PROTOCOL_PREDICATES` are all
 * module-level constants that nothing mutates at run time, so the answers
 * cannot change - and these were being recomputed AND re-sorted on every
 * keystroke in the filter bar, through `FilterEngine.getSuggestions`. The
 * registry is 969 fields; that is two sorts of about a thousand strings and
 * three array builds per character typed.
 *
 * `readonly` in the signatures rather than a convention in a comment: a shared
 * array that one caller sorts in place is a bug in every other caller, and the
 * type is what stops it. Every caller today only reads - `.filter`,
 * `.includes`, `new Set(...)`, spread - and this keeps it that way.
 *
 * Lazily rather than at module load, because `scripts/` imports this file for
 * checks that never ask for a name list, and the sort is real work.
 */
let knownFieldNamesCache: readonly string[] | undefined;
let treeOnlyFieldNamesCache: readonly string[] | undefined;
let protocolNamesCache: readonly string[] | undefined;

/**
 * Every name a filter may use, for validation and autocomplete.
 *
 * Tree-only fields are excluded. Offering a completion for a name that can
 * never match is worse than not offering it: it is the app telling the user the
 * filter is right.
 */
export function knownFieldNames(): readonly string[] {
  return knownFieldNamesCache ??= [
    ...Object.keys(ALIASES),
    ...FIELDS.filter((f) => f.treeOnly !== true).map((f) => f.abbrev),
  ].sort();
}

/** The registered names the tree shows and a filter cannot read. */
export function treeOnlyFieldNames(): readonly string[] {
  return treeOnlyFieldNamesCache ??=
    FIELDS.filter((f) => f.treeOnly === true).map((f) => f.abbrev).sort();
}

/** Every bareword that tests for a protocol's presence. */
export function protocolNames(): readonly string[] {
  return protocolNamesCache ??= [...LAYER_TOKENS, ...Object.keys(PROTOCOL_PREDICATES)].sort();
}

/** The fields "Apply as column" offers, from the registry. */
export function columnCatalogue(): readonly FieldDef[] {
  return FIELDS.filter((f) => f.column !== undefined);
}
