/**
 * The one list of every field a dissector may publish.
 *
 * Three things used to name fields independently: the protocol tree named
 * them for people ("Time to Live"), the dissectors wrote them into
 * `Packet.fields` under Wireshark's abbreviations ("ip.ttl"), and the filter
 * engine kept a hand-typed set of the abbreviations it would accept. Nothing
 * connected the three, so a field could be filterable but not visible, visible
 * but not filterable, or - as with several shipped colour rules - referenced by
 * name and produced by nothing, silently matching no packet ever.
 *
 * This module is the fix (docs/decisions/0002-field-registry.md). A field is
 * registered here first, one line; the filter engine's known names, the
 * autocomplete, and the column catalogue derive from it; a tree row that
 * carries the same `abbrev` gets "apply as filter" for free; and an assertion
 * script (scripts/dissect/registry.ts) fails the build when a dissector writes
 * a key that is not here, or when a key here has no writer left.
 *
 * Abbreviations are Wireshark's where Wireshark has the field, so a filter a
 * user already knows works unchanged and the tshark parity harness can name the
 * same thing on both sides. Fields with no Wireshark equivalent take an
 * `inwire.` prefix.
 */

import { ABBREV_BY_FLAG } from './tcpAnalysis';

export type FieldType =
  | 'uint'      // unsigned integer, compared numerically
  | 'int'
  | 'bool'      // 0/1 on the wire, `== 1` in filters
  | 'string'
  | 'bytes'     // hex string
  | 'ipv4'
  | 'ipv6'
  | 'mac'
  | 'time'
  | 'proto';    // a protocol name; equality only

export interface FieldDef {
  /**
   * Registered, shown in the protocol tree, and NOT filterable in this build.
   *
   * ## Why a field would be in that state at all
   *
   * A dissector can publish a value two ways: into `Packet.fields`, the bag a
   * filter reads, or as a `ProtocolField` row on a layer, which is what the
   * detail tree draws. Most fields do both. These do only the second - the
   * value is on screen, and nothing in the bag answers for it.
   *
   * ## Why they are marked rather than fixed or removed
   *
   * **Not fixed**, because writing 35 more keys into every matching frame's bag
   * is per-frame cost, and driving that down is a standing rule here - it is
   * what ADRs 0016, 0017 and 0018 are about. These are long, low-value strings
   * (a CNAME target, a TXT record, an SNMP value); the tree shows them on demand
   * for one frame, which is the right place to pay for them.
   *
   * **Not removed**, because the registration is doing real work: it carries the
   * Wireshark abbreviation that `scripts/dissect/wireshark-abbrevs.ts` holds
   * against `tshark -G fields`, and it is what names the row in the tree.
   *
   * ## What the flag changes
   *
   * `filter/fields.ts` resolves them as NOT known, so the filter bar says so
   * instead of returning an empty list. Before this they validated, autocompleted
   * and matched nothing - `dns.cname` was unfilterable while `dns.a`, two cases
   * along in the same switch, worked. The registry's own header names that exact
   * state as the thing it exists to prevent: "visible but not filterable".
   *
   * Making one filterable is a one-line change here plus a bag write in its
   * dissector, and `scripts/dissect/registry.ts` enforces the pairing in both
   * directions - a flagged field that gains a bag write fails, and an unflagged
   * one without a bag write fails.
   */
  treeOnly?: true;
  /** Filter name: `tcp.flags.syn`. Unique. */
  abbrev: string;
  /** What the tree and a column header call it: `Syn`. */
  label: string;
  type: FieldType;
  /**
   * The `frameProtocols` token that owns the field - the bareword a filter
   * uses to test for the layer's presence (`tcp`, `lldp`).
   */
  layer: string;
  /** Present when "Apply as column" should offer it. */
  column?: { label: string; align: 'left' | 'right' };
  /** Computed rather than read off the wire; shown in [brackets]. */
  generated?: boolean;
}

/**
 * Layer tokens, outermost first, exactly as they appear in
 * `Packet.frameProtocols`. Every `FieldDef.layer` is one of these.
 */
export const LAYERS = [
  // Outermost first, and that is the contract rather than a tidiness: this list
  // is where the autocomplete's order comes from, so a token appended at the
  // end reads as an application protocol however low in the stack it sits.
  // `cdp` belongs beside `lldp` for that reason, and `vrrp`/`ospf` beside
  // `igmp` - all three sit directly on their lower layer with no ports.
  'frame', 'eth', 'vlan', 'llc', 'sll', 'null', 'arp', 'stp', 'lldp', 'ieee1905', 'cdp',
  'ip', 'ipv6', 'gre', 'vxlan', 'icmp', 'icmpv6', 'igmp', 'vrrp', 'ospf', 'tcp', 'udp',
  // `nbdgm` and `hsrp` are spelt as the reference analyzer spells them rather
  // than as the Protocol column shows them (NBDS, HSRP): the filter name is
  // what a user types, and it has to be the one they already know.
  'dns', 'nbns', 'nbdgm', 'tls', 'quic', 'ssdp', 'dhcp', 'dhcpv6', 'ntp', 'stun',
  'syslog', 'radius', 'snmp', 'sip', 'rtcp', 'tftp', 'bfd', 'coap', 'ptp',
  'hsrp', 'rip', 'ripng', 'bgp', 'ldap', 'smb2', 'kerberos', 'http', 'http2', 'http3',
  // **What a message BODY is**, which the reference makes four protocols of
  // rather than fields on HTTP - so a JSON API response's chain really does
  // read `...tcp:http:json`. `data-text-lines` keeps its hyphens because that
  // is the name a user types, and `filter/lexer.ts`'s `WORD` class includes
  // `-` (checked, not hoped for). `data-text-lines` owns no fields: it is a
  // protocol with nothing but lines under it, which is why nothing below
  // carries that prefix.
  'json', 'media', 'data', 'data-text-lines',
  // IPv6 extension headers are their own filter tokens, as in Wireshark:
  // `ipv6.hopopts`, `ipv6.fragment`. They appear in frameProtocols rather
  // than as field prefixes, so they own no fields of their own.
  'ipv6.hopopts', 'ipv6.dstopts', 'ipv6.routing', 'ipv6.fragment', 'ipv6.ext', 'ah',
  // **X.509, which is three protocols in the reference and therefore three
  // tokens here.** `x509af` is the certificate's own frame (RFC 5280 §4.1),
  // `x509ce` the extensions, `pkix1implicit` the authority-information-access
  // description - and its protocol chain for a TLS 1.2 Certificate frame
  // really does read `...tls:x509sat:x509ce:pkix1implicit:x509ce`, measured on
  // the synthetic handshake in `scripts/tls/certificate.ts`.
  //
  // Adopting its names rather than inventing `tls.x509.*` ones is the
  // registry's whole promise applied to a layer neither fixture contains: a
  // filter learnt in Wireshark has to answer the same here. `x509sat` is
  // deliberately absent - it is the reference's generated string-attribute
  // tree, where one `uTF8String` row is every attribute of every name in the
  // chain and nothing says which is the subject's, so this build publishes a
  // composed Subject and Issuer under `tls.x509.*` instead and exempts them.
  'x509af', 'x509ce', 'pkix1implicit',
] as const;
export type LayerToken = (typeof LAYERS)[number];

const uint = (abbrev: string, label: string, layer: LayerToken, column?: FieldDef['column']): FieldDef =>
  ({ abbrev, label, type: 'uint', layer, ...(column ? { column } : {}) });
const str = (abbrev: string, label: string, layer: LayerToken, column?: FieldDef['column']): FieldDef =>
  ({ abbrev, label, type: 'string', layer, ...(column ? { column } : {}) });
const bool = (abbrev: string, label: string, layer: LayerToken): FieldDef =>
  ({ abbrev, label, type: 'bool', layer });
/**
 * Wraps a definition to say the tree shows it and a filter cannot read it.
 *
 * A wrapper rather than a fourth parameter on each helper, so the fact is
 * visible at the CALL SITE - `treeOnly(str('dns.cname', ...))` reads as the
 * exception it is, where a trailing `true` would not.
 */
const treeOnly = (def: FieldDef): FieldDef => ({ ...def, treeOnly: true });

export const FIELDS: readonly FieldDef[] = [
  // --- VXLAN --------------------------------------------------------------------
  // A layer-2 tunnel: the columns report the frame INSIDE it, so these are the
  // only three keys the outer header contributes. `eth.src`/`eth.dst` are
  // deliberately not rewritten from the inner frame - see dissectors/vxlan.ts.
  uint('vxlan.vni', 'VXLAN Network Identifier', 'vxlan'),
  uint('vxlan.flags', 'Flags', 'vxlan'),
  uint('vxlan.flag_i', 'VNI Valid', 'vxlan'),
  // --- Kerberos ---------------------------------------------------------------
  // The Protocol column reads KRB5 and the filter token reads `kerberos`; both
  // are the reference's own spellings. `cname_string`/`sname_string` are the
  // joined principal (`krbtgt/EXAMPLE.COM`), which is what the reference calls
  // the name-string list rather than the `cname`/`sname` structural elements.
  uint('kerberos.msg_type', 'Message Type', 'kerberos'),
  uint('kerberos.pvno', 'Protocol Version', 'kerberos'),
  uint('kerberos.error_code', 'Error Code', 'kerberos'),
  str('kerberos.realm', 'Realm', 'kerberos'),
  str('kerberos.crealm', 'Client Realm', 'kerberos'),
  str('kerberos.cname_string', 'Client Name', 'kerberos'),
  str('kerberos.sname_string', 'Server Name', 'kerberos'),
  // --- Ethernet --------------------------------------------------------------
  { abbrev: 'eth.src', label: 'Source', type: 'mac', layer: 'eth' },
  { abbrev: 'eth.dst', label: 'Destination', type: 'mac', layer: 'eth' },
  // The destination MAC's group bit - Wireshark publishes the same field.
  // Registered because the Broadcast colour rule needs it: Wireshark writes
  // that rule as `eth[0] & 1`, a raw byte poke, and a frame whose bytes the
  // buffer has released can no longer answer one (docs/decisions/0013 evicts
  // them past a window). A dissected field survives eviction; a byte read does
  // not.
  uint('eth.ig', 'IG bit', 'eth'),
  uint('eth.type', 'Type', 'eth'),
  uint('vlan.id', 'VLAN ID', 'vlan', { label: 'VLAN', align: 'right' }),

  // --- 802.2 LLC / SNAP ------------------------------------------------------
  // An 802.3 frame's type/length field is a length, and what follows is an LLC
  // header rather than a network header. Every STP BPDU on the wire is one.
  uint('llc.dsap', 'DSAP', 'llc'),
  uint('llc.ssap', 'SSAP', 'llc'),
  uint('llc.control', 'Control field', 'llc'),
  uint('llc.oui', 'Organization Code', 'llc'),
  uint('llc.type', 'Type', 'llc'),

  // --- IPv4 / IPv6 -----------------------------------------------------------
  { abbrev: 'ip.src', label: 'Source Address', type: 'ipv4', layer: 'ip' },
  { abbrev: 'ip.dst', label: 'Destination Address', type: 'ipv4', layer: 'ip' },
  uint('ip.ttl', 'Time to Live', 'ip', { label: 'TTL', align: 'right' }),
  uint('ip.hdr_len', 'Header Length', 'ip'),
  uint('ip.id', 'Identification', 'ip'),
  uint('ip.dsfield.dscp', 'Differentiated Services Codepoint', 'ip'),
  uint('ip.dsfield.ecn', 'Explicit Congestion Notification', 'ip'),
  bool('ip.flags.df', "Don't fragment", 'ip'),
  bool('ip.flags.mf', 'More fragments', 'ip'),
  uint('ip.frag_offset', 'Fragment Offset', 'ip'),
  uint('ip.opt.type', 'Option type', 'ip'),

  // The rows below were drawn - with the right value, byte range and bitfield -
  // long before they were named, which made them invisible to the filter
  // engine, to "Apply as filter" and to `scripts/parity/tree-coverage.ts`
  // alike. They are `treeOnly` rather than filterable because every one of
  // them is either a constant given the layer token (`ip.version` is 4
  // whenever `ip` is present, which is what the bareword already says) or a
  // decomposition of bytes the bag holds. Filterability is bought per field on
  // evidence of demand; a bag write here would also put four of them over
  // `dense-fields.ts`'s 20%-of-frames threshold and into `DENSE_FIELDS`.
  treeOnly(uint('ip.version', 'Version', 'ip')),
  treeOnly(uint('ip.dsfield', 'Differentiated Services Field', 'ip')),
  treeOnly(uint('ip.len', 'Total Length', 'ip')),
  treeOnly(uint('ip.flags', 'Flags', 'ip')),
  treeOnly(bool('ip.flags.rb', 'Reserved bit', 'ip')),
  treeOnly(uint('ipv6.version', 'Version', 'ipv6')),
  treeOnly(uint('ipv6.tclass', 'Traffic Class', 'ipv6')),
  treeOnly(uint('ipv6.tclass.dscp', 'Differentiated Services Codepoint', 'ipv6')),
  treeOnly(uint('ipv6.tclass.ecn', 'Explicit Congestion Notification', 'ipv6')),
  treeOnly(uint('ipv6.flow', 'Flow Label', 'ipv6')),
  treeOnly(uint('ipv6.plen', 'Payload Length', 'ipv6')),

  // --- the either-end names, which the filter engine already answered --------
  //
  // `eth.addr`, `ip.addr`, `ipv6.addr`, `tcp.port` and `udp.port` have always
  // worked in the filter bar, through `ALIASES` in `filter/fields.ts` - and
  // `resolveField` consults that map BEFORE the registry, so registering them
  // here changes nothing about how a filter is answered. What it buys is the
  // row: these five were the whole of `tree-coverage.ts`'s
  // `filterableNotInTree` ceiling, the one list where every entry is a defect
  // with no judgement call - the app accepted the filter and the detail pane
  // refused to draw it.
  //
  // `treeOnly` for the same reason: the value is already in the bag twice
  // under the two end-specific names, and a third copy would buy nothing.
  treeOnly({ abbrev: 'eth.addr', label: 'Address', type: 'mac', layer: 'eth' }),
  treeOnly({ abbrev: 'ip.addr', label: 'Source or Destination Address', type: 'ipv4', layer: 'ip' }),
  treeOnly({ abbrev: 'ipv6.addr', label: 'Source or Destination Address', type: 'ipv6', layer: 'ipv6' }),
  treeOnly(uint('tcp.port', 'Source or Destination Port', 'tcp')),
  treeOnly(uint('udp.port', 'Source or Destination Port', 'udp')),
  treeOnly(bool('eth.lg', 'LG bit', 'eth')),
  treeOnly(str('ipv6.src_addr_space', 'Source Address Space', 'ipv6')),
  treeOnly(str('ipv6.dst_addr_space', 'Destination Address Space', 'ipv6')),
  treeOnly(str('tcp.flags.str', 'TCP Flags', 'tcp')),

  // --- the per-layer conversation indices ------------------------------------
  //
  // The reference assigns a conversation index at every layer, and this build
  // had only `tcp.stream`. These four are the rest, plus TLS's own sequence.
  //
  // **These are the only fields in this wave that are NOT `treeOnly`**, and the
  // reason is not that somebody wants to filter on them - it is
  // `services/pipeline/replay.ts`. A detail tree is rebuilt by replaying one
  // conversation through fresh trackers, which would number it 0; the Worker
  // recovers the right number by reading it back off the target packet with
  // `fieldValue`, so it has to be in the bag to be recoverable. Filtering is
  // the bonus, not the argument. `eth.stream` and `ipv6.stream` land on 100%
  // and 65% of fixture frames, so both are declared in `DENSE_FIELDS` as
  // `dense-fields.ts` requires.
  uint('eth.stream', 'Stream index', 'eth'),
  uint('ip.stream', 'Stream index', 'ip'),
  uint('ipv6.stream', 'Stream index', 'ipv6'),
  uint('udp.stream', 'Stream index', 'udp'),
  treeOnly(uint('udp.stream.pnum', 'Stream Packet Number', 'udp')),
  treeOnly(str('udp.time_relative', 'Time since first frame', 'udp')),
  treeOnly(str('udp.time_delta', 'Time since previous frame', 'udp')),
  uint('tls.stream', 'Stream index', 'tls'),

  // The six completeness bits.  beside them has been drawn
  // since the tracker learned to summarise a handshake; these say WHICH of the
  // six things the capture actually contains, which is how a reader finds out
  // that a stream's relative sequence numbers are relative to a guess.
  treeOnly(str('tcp.completeness.str', 'Completeness Flags', 'tcp')),
  treeOnly(bool('tcp.completeness.syn', 'SYN', 'tcp')),
  treeOnly(bool('tcp.completeness.syn-ack', 'SYN-ACK', 'tcp')),
  treeOnly(bool('tcp.completeness.ack', 'ACK', 'tcp')),
  treeOnly(bool('tcp.completeness.data', 'Data', 'tcp')),
  treeOnly(bool('tcp.completeness.fin', 'FIN', 'tcp')),
  treeOnly(bool('tcp.completeness.rst', 'RST', 'tcp')),

  // --- DNS: rows the message already drew, and two it did not ---------------
  treeOnly(uint('dns.count.auth_rr', 'Authority RRs', 'dns')),
  treeOnly(uint('dns.count.add_rr', 'Additional RRs', 'dns')),
  treeOnly(bool('dns.flags.recavail', 'Recursion available', 'dns')),
  treeOnly(bool('dns.flags.z', 'Z', 'dns')),
  treeOnly(bool('dns.flags.authenticated', 'Answer authenticated', 'dns')),
  treeOnly(bool('dns.flags.checkdisable', 'Non-authenticated data', 'dns')),
  treeOnly(uint('dns.qry.class', 'Class', 'dns')),
  treeOnly(uint('dns.resp.class', 'Class', 'dns')),
  treeOnly(bool('dns.qry.qu', '"QU" question', 'dns')),
  treeOnly(bool('dns.resp.cache_flush', 'Cache flush', 'dns')),
  treeOnly(uint('dns.resp.len', 'Data length', 'dns')),
  // Not in the bytes: the reference derives both, and a query for a 200-byte
  // name with forty labels is exactly the shape worth filtering for.
  treeOnly(uint('dns.qry.name.len', 'Name Length', 'dns')),
  treeOnly(uint('dns.count.labels', 'Label Count', 'dns')),
  treeOnly(str('dns.time', 'Time', 'dns')),

  // The two subtree NODES themselves. Fifteen `tcp.analysis.*` verdicts have
  // been named since they were ported; the containers they hang under were
  // not, so `tcp.analysis` - a filter meaning "this segment has a finding at
  // all", on 56% of frames here - answered nothing.
  treeOnly(str('tcp.analysis', 'SEQ/ACK analysis', 'tcp')),
  str('tcp.analysis.flags', 'TCP Analysis Flags', 'tcp'),

  // The payload rows. UDP's already existed and was display-only; TCP had no
  // row at all, so an empty ACK and 1,440 unread bytes looked the same.
  treeOnly(str('tcp.payload', 'TCP payload', 'tcp')),
  treeOnly(str('udp.payload', 'UDP payload', 'udp')),

  // SOA carries seven fields and this build drew all seven without naming one,
  // so the record saying who is authoritative for a zone, and how long a
  // negative answer may be cached, could be read and not filtered on.
  treeOnly(str('dns.soa.mname', 'Primary name server', 'dns')),
  treeOnly(str('dns.soa.rname', 'Responsible authority mailbox', 'dns')),
  treeOnly(str('dns.soa.serial_number', 'Serial Number', 'dns')),
  treeOnly(str('dns.soa.refresh_interval', 'Refresh Interval', 'dns')),
  treeOnly(str('dns.soa.retry_interval', 'Retry Interval', 'dns')),
  treeOnly(str('dns.soa.expire_limit', 'Expire limit', 'dns')),
  treeOnly(str('dns.soa.minimum_ttl', 'Minimum TTL', 'dns')),

  // --- STP: the fields a spanning tree is actually diagnosed from ----------
  //
  // The four timers were eight bytes this build read past. Max Age and Hello
  // Time are how long a switch waits before deciding the root is gone, and
  // Forward Delay is why a port takes thirty seconds to pass traffic - the
  // three numbers anyone debugging a convergence problem reaches for first.
  treeOnly(uint('stp.protocol', 'Protocol Identifier', 'stp')),
  uint('stp.flags', 'BPDU flags', 'stp'),
  treeOnly(bool('stp.flags.tc', 'Topology Change', 'stp')),
  treeOnly(bool('stp.flags.tcack', 'Topology Change Acknowledgment', 'stp')),
  treeOnly(uint('stp.root.prio', 'Root Bridge Priority', 'stp')),
  treeOnly(uint('stp.root.ext', 'Root Bridge System ID Extension', 'stp')),
  { abbrev: 'stp.root.hw', label: 'Root Bridge System ID', type: 'mac', layer: 'stp', treeOnly: true },
  treeOnly(uint('stp.bridge.prio', 'Bridge Priority', 'stp')),
  treeOnly(uint('stp.bridge.ext', 'Bridge System ID Extension', 'stp')),
  { abbrev: 'stp.bridge.hw', label: 'Bridge System ID', type: 'mac', layer: 'stp', treeOnly: true },
  uint('stp.msg_age', 'Message Age', 'stp'),
  uint('stp.max_age', 'Max Age', 'stp'),
  uint('stp.hello', 'Hello Time', 'stp'),
  uint('stp.forward', 'Forward Delay', 'stp'),
  // LLC's own bits. The DSAP and SSAP bytes are a seven-bit service access
  // point plus one flag each, and the control byte of an unnumbered frame
  // carries its command in five scattered bits - all of which were drawn as
  // two hex digits and nothing else.
  treeOnly(str('llc.dsap.sap', 'SAP', 'llc')),
  treeOnly(str('llc.ssap.sap', 'SAP', 'llc')),
  treeOnly(bool('llc.ssap.cr', 'CR Bit', 'llc')),
  treeOnly(str('llc.control.ftype', 'Frame type', 'llc')),
  treeOnly(str('llc.control.u_modifier_cmd', 'Command', 'llc')),
  // QUIC's first byte, which this dissector read and never showed. The fixed
  // bit is the cheapest test for 'is this UDP payload QUIC at all'; the spin
  // bit flips once per round trip, so a passive observer can measure RTT on
  // a connection it cannot read a byte of. Both are outside header
  // protection, which is why they are here and the reserved bits are not.
  treeOnly(bool('quic.fixed_bit', 'Fixed Bit', 'quic')),
  treeOnly(bool('quic.spin_bit', 'Spin Bit', 'quic')),
  treeOnly(uint('quic.packet_length', 'Packet Length', 'quic')),
  treeOnly(str('quic.frame', 'Frame', 'quic')),
  treeOnly(str('ip.reassembled', 'Reassembled IPv4 fragments', 'ip')),
  uint('ipv6.reassembled', 'Reassembled IPv6 fragments', 'ipv6'),

  // --- NTP / STUN ------------------------------------------------------------
  // Dispatched by content as well as by port: STUN runs on whichever port an
  // ICE candidate got, and carries a magic cookie so it can be found there.
  uint('ntp.flags.vn', 'Version number', 'ntp'),
  uint('ntp.flags.mode', 'Mode', 'ntp'),
  uint('ntp.stratum', 'Peer Clock Stratum', 'ntp'),
  uint('stun.type', 'Message Type', 'stun'),
  uint('ip.proto', 'Protocol', 'ip'),
  uint('ip.checksum', 'Header Checksum', 'ip'),
  str('ip.checksum.status', 'Header checksum status', 'ip'),
  { abbrev: 'ipv6.src', label: 'Source Address', type: 'ipv6', layer: 'ipv6' },
  { abbrev: 'ipv6.dst', label: 'Destination Address', type: 'ipv6', layer: 'ipv6' },
  uint('ipv6.hlim', 'Hop Limit', 'ipv6', { label: 'Hop limit', align: 'right' }),
  uint('ipv6.nxt', 'Next Header', 'ipv6'),

  // --- TCP / UDP -------------------------------------------------------------
  uint('tcp.srcport', 'Source Port', 'tcp', { label: 'Src port', align: 'right' }),
  uint('tcp.dstport', 'Destination Port', 'tcp', { label: 'Dst port', align: 'right' }),
  uint('tcp.flags', 'Flags', 'tcp'),
  bool('tcp.flags.syn', 'Syn', 'tcp'),
  bool('tcp.flags.fin', 'Fin', 'tcp'),
  bool('tcp.flags.reset', 'Reset', 'tcp'),
  bool('tcp.flags.push', 'Push', 'tcp'),
  bool('tcp.flags.ack', 'Acknowledgment', 'tcp'),
  // The other five bits. Every one was already a row on screen, drawn by
  // `TCP_FLAG_ROWS` and carrying no abbrev - so `tcp.flags.urg` matched
  // nothing and the tree could not say which field it was showing.
  bool('tcp.flags.urg', 'Urgent', 'tcp'),
  bool('tcp.flags.ece', 'ECN-Echo', 'tcp'),
  bool('tcp.flags.cwr', 'Congestion Window Reduced', 'tcp'),
  bool('tcp.flags.ae', 'Accurate ECN', 'tcp'),
  uint('tcp.flags.res', 'Reserved', 'tcp'),
  uint('tcp.hdr_len', 'Header Length', 'tcp'),
  uint('tcp.urgent_pointer', 'Urgent Pointer', 'tcp'),
  // **The window as sent, beside `tcp.window_size` which is the scaled one.**
  // Both were already drawn; only the scaled row was named, so a filter could
  // not reach the number actually on the wire.
  uint('tcp.window_size_value', 'Window', 'tcp'),
  uint('tcp.window_size_scalefactor', 'Window size scaling factor', 'tcp'),
  uint('tcp.window_size', 'Calculated window size', 'tcp', { label: 'Window', align: 'right' }),
  uint('tcp.len', 'TCP Segment Len', 'tcp', { label: 'TCP len', align: 'right' }),
  uint('tcp.seq', 'Sequence Number', 'tcp'),
  uint('tcp.seq_raw', 'Sequence Number (raw)', 'tcp'),
  uint('tcp.ack', 'Acknowledgment Number', 'tcp'),
  uint('tcp.ack_raw', 'Acknowledgment Number (raw)', 'tcp'),
  uint('tcp.checksum', 'Checksum', 'tcp'),
  str('tcp.checksum.status', 'Checksum Status', 'tcp'),
  // The options region itself, then the two rows every option inside it
  // carries. All three were absent, so the tree could not say where the fixed
  // header ended or what kind an option was.
  treeOnly(str('tcp.options', 'TCP Options', 'tcp')),
  uint('tcp.option_kind', 'Kind', 'tcp'),
  uint('tcp.option_len', 'Length', 'tcp'),
  bool('tcp.options.nop', 'No-Operation (NOP)', 'tcp'),
  uint('tcp.options.mss_val', 'MSS Value', 'tcp'),
  uint('tcp.options.wscale.shift', 'Window Scale Shift', 'tcp'),
  bool('tcp.options.sack_perm', 'SACK Permitted', 'tcp'),
  uint('tcp.options.timestamp.tsval', 'Timestamp value', 'tcp'),
  uint('tcp.options.timestamp.tsecr', 'Timestamp echo reply', 'tcp'),
  uint('tcp.options.sack_le', 'TCP SACK Left Edge', 'tcp'),
  uint('tcp.options.sack_re', 'TCP SACK Right Edge', 'tcp'),

  // --- the options as OPTIONS, and what a SACK block is reporting ----------
  //
  // `tcp.options.mss`, `.wscale`, `.sack` and `.eol` name the option itself
  // where `.mss_val` and `.wscale.shift` name the number inside it - the
  // reference's own split, and the reason a reader clicking the value gets
  // its two bytes rather than the whole option. Like `tcp.options.nop`
  // above, all four are registered by the reference as sub-PROTOCOLS rather
  // than fields, so `wireshark-abbrevs.ts` carries them as exemptions with
  // that argument spelled out.
  treeOnly(str('tcp.options.mss', 'Maximum Segment Size', 'tcp')),
  treeOnly(str('tcp.options.wscale', 'Window Scale', 'tcp')),
  treeOnly(uint('tcp.options.wscale.multiplier', 'Multiplier', 'tcp')),
  treeOnly(str('tcp.options.sack', 'SACK', 'tcp')),
  treeOnly(str('tcp.options.eol', 'End of Option List (EOL)', 'tcp')),
  treeOnly(uint('tcp.options.sack.count', 'TCP SACK Count', 'tcp')),
  // RFC 2883. A D-SACK says the sender retransmitted something that had
  // already arrived - so whatever loss it reacted to was not loss, and the
  // retransmission was spurious. Nothing else in a capture says that.
  treeOnly(str('tcp.options.sack.dsack', 'D-SACK Sequence', 'tcp')),
  treeOnly(uint('tcp.options.sack.dsack_le', 'TCP D-SACK Left Edge', 'tcp')),
  treeOnly(uint('tcp.options.sack.dsack_re', 'TCP D-SACK Right Edge', 'tcp')),

  // --- what a frame does to the connection ---------------------------------
  //
  // `FT_NONE` in the reference: presence is the value, so each is drawn only
  // on the frame it is true of. `tcp.connection.fin_active` is the one that
  // earns its place - a FIN flag is on both halves of a close and says
  // nothing about which end hung up first, which is usually the question.
  treeOnly(bool('tcp.connection.syn', 'Connection establish request (SYN)', 'tcp')),
  treeOnly(bool('tcp.connection.synack', 'Connection establish acknowledge (SYN+ACK)', 'tcp')),
  treeOnly(bool('tcp.connection.fin', 'Connection finish (FIN)', 'tcp')),
  treeOnly(bool('tcp.connection.fin_active', 'This frame initiates the connection closing', 'tcp')),
  treeOnly(bool('tcp.connection.fin_passive', 'This frame undergoes the connection closing', 'tcp')),
  treeOnly(bool('tcp.connection.rst', 'Connection reset (RST)', 'tcp')),

  // --- a PDU that spanned segments -----------------------------------------
  //
  // `tcp.segment` is `FT_FRAMENUM` in the reference, which is why its row
  // carries `linkToFrame`: the point of the subtree is that the frames which
  // carried a PDU are reachable, not merely listed. This build tracked every
  // one of them from the day TLS records were first followed across
  // segments, and spent it all on a single composed string.
  treeOnly(str('tcp.segments', 'Reassembled TCP Segments', 'tcp')),
  treeOnly(uint('tcp.segment', 'TCP Segment', 'tcp')),
  treeOnly(uint('tcp.segment.count', 'Segment count', 'tcp')),
  treeOnly(uint('tcp.reassembled.length', 'Reassembled TCP length', 'tcp')),
  { abbrev: 'tcp.analysis.ack_rtt', label: 'The RTT to ACK the segment was', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.initial_rtt', label: 'iRTT', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.bytes_in_flight', label: 'Bytes in flight', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.duplicate_ack_num', label: 'Duplicate ACK #', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.duplicate_ack_frame', label: 'Duplicate to the ACK in frame', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.acks_frame', label: 'This is an ACK to the segment in frame', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.rto', label: 'The RTO for this segment was', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.rto_frame', label: 'RTO based on delta from frame', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.push_bytes_sent', label: 'Bytes sent since last PSH flag', type: 'uint', layer: 'tcp', generated: true },
  /*
   * **The fifteen verdicts, which were computed and never named.**
   *
   * `dissect/tcpAnalysis.ts` reimplements Wireshark 4.6's
   * `tcp_analyze_sequence_number` check for check and produces exactly these
   * fifteen names - and not one of them was a registered field. They lived in
   * `Packet.analysisFlags`, a string array, which `filter/compile.ts`
   * special-cases by prefix. So the filter worked while the NAME did not
   * exist: no autocomplete, nothing holding it to Wireshark's dictionary, no
   * abbrev on the tree row, and `tree-coverage.ts` counting all fifteen as
   * absent on a build that had computed every one of them.
   *
   * Registered and **not written into the bag**. The tree row carries the
   * abbrev and `compile.ts` keeps reading `analysisFlags`, so a filter is
   * answered with no per-frame cost at all - fifteen more keys on every TCP
   * frame is exactly what ADRs 0016 to 0018 drive down. `registry.ts`'s
   * completeness check is textual, so the abbrev literal in the dissector is
   * what keeps this honest.
   */
  ...([
    ['retransmission', 'This frame is a (suspected) retransmission'],
    ['fast_retransmission', 'This frame is a (suspected) fast retransmission'],
    ['spurious_retransmission', 'This frame is a (suspected) spurious retransmission'],
    ['out_of_order', 'This frame is a (suspected) out-of-order segment'],
    ['lost_segment', 'A segment before this frame was lost'],
    ['ack_lost_segment', 'ACKed segment that was not captured'],
    ['window_update', 'This is a TCP window update'],
    ['window_full', 'This frame has filled the receive window of the peer'],
    ['keep_alive', 'This is a TCP keep-alive segment'],
    ['keep_alive_ack', 'This is an ACK to a TCP keep-alive segment'],
    ['duplicate_ack', 'This is a TCP duplicate ack'],
    ['zero_window_probe', 'This is a TCP zero-window-probe'],
    ['zero_window', 'This is a ZeroWindow segment'],
    ['zero_window_probe_ack', 'This is an ACK to a TCP zero-window-probe'],
    ['reused_ports', 'A new tcp session is started with the same ports as an earlier session in this trace'],
  ] as const).map(([flag, label]): FieldDef =>
    // The name comes from `ABBREV_BY_FLAG` rather than being built here, so
    // there is one spelling of it in the codebase and `registry.ts` can see a
    // literal. See that table's own comment.
    ({ abbrev: ABBREV_BY_FLAG[flag], label, type: 'bool', layer: 'tcp', generated: true })),
  { abbrev: 'tcp.nxtseq', label: 'Next Sequence Number', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.stream.pnum', label: 'Stream Packet Number', type: 'uint', layer: 'tcp', generated: true },
  // **The stream index belongs to TCP.** It was emitted on the IP layer and
  // answered as a filter only by a synthetic reader in `filter/fields.ts`, so
  // it sat in tree-coverage's "a filter answers, the detail pane does not"
  // list - the one section where every entry is a defect by construction.
  { abbrev: 'tcp.stream', label: 'Stream index', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.time_relative', label: 'Time since first frame in this TCP stream', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.time_delta', label: 'Time since previous frame in this TCP stream', type: 'time', layer: 'tcp', generated: true },
  // Prose rather than the reference's numeric bitmask, which is a deliberate
  // divergence recorded in `tcpStreamTracker.ts`.
  treeOnly(str('tcp.completeness', 'Conversation completeness', 'tcp')),
  uint('udp.srcport', 'Source Port', 'udp', { label: 'Src port', align: 'right' }),
  uint('udp.dstport', 'Destination Port', 'udp', { label: 'Dst port', align: 'right' }),
  uint('udp.length', 'Length', 'udp'),
  uint('udp.checksum', 'Checksum', 'udp'),
  str('udp.checksum.status', 'Checksum Status', 'udp'),

  // --- ICMP ------------------------------------------------------------------
  uint('icmp.type', 'Type', 'icmp'),
  uint('icmp.code', 'Code', 'icmp'),
  uint('icmp.checksum', 'Checksum', 'icmp'),
  str('icmp.checksum.status', 'Checksum Status', 'icmp'),
  // **The echo identity, which the tree has always drawn and never named.**
  // `Identifier (BE)` and `Sequence Number (BE)` were rows with no abbrev on
  // 528 inwire frames, so `icmp.seq == 35141` - about as ordinary a filter as
  // exists - resolved to nothing at all. The reference draws the same sixteen
  // bits twice, big-endian and little-endian, because most ping
  // implementations count in host order and the wire value is the one nobody
  // recognises; both are filterable there and both are here now.
  uint('icmp.ident', 'Identifier (BE)', 'icmp'),
  uint('icmp.ident_le', 'Identifier (LE)', 'icmp'),
  uint('icmp.seq', 'Sequence Number (BE)', 'icmp'),
  uint('icmp.seq_le', 'Sequence Number (LE)', 'icmp'),
  { abbrev: 'icmp.resp_to', label: 'Request frame', type: 'uint', layer: 'icmp', generated: true },
  { abbrev: 'icmp.resptime', label: 'Response time', type: 'uint', layer: 'icmp', generated: true },
  // The echo payload. Tree-only deliberately: a ping may carry 65,500 bytes,
  // and hex of that in the per-frame bag is 131 kB a frame against a tree that
  // is built on demand and thrown away with the pane (ADR 0007). The reference
  // names it and then hides the row, showing the bytes through its `data`
  // dissector instead.
  treeOnly(str('icmp.data', 'ICMP Data', 'icmp')),
  // The four bytes between an error's code and the datagram it quotes. On
  // three types they carry the actionable half of the message - the MTU that
  // would have fitted, the offset of the header field that was wrong, the
  // gateway to use instead - and on the rest they are unused and say so.
  treeOnly(str('icmp.unused', 'Unused', 'icmp')),
  uint('icmp.mtu', 'MTU of next hop', 'icmp'),
  uint('icmp.pointer', 'Pointer', 'icmp'),
  { abbrev: 'icmp.redir_gw', label: 'Gateway Address', type: 'ipv4', layer: 'icmp' },

  uint('icmpv6.type', 'Type', 'icmpv6'),
  uint('icmpv6.code', 'Code', 'icmpv6'),
  uint('icmpv6.checksum', 'Checksum', 'icmpv6'),
  str('icmpv6.checksum.status', 'Checksum Status', 'icmpv6'),
  uint('icmpv6.echo.identifier', 'Identifier', 'icmpv6'),
  uint('icmpv6.echo.sequence_number', 'Sequence', 'icmpv6'),
  treeOnly(str('icmpv6.data', 'Data', 'icmpv6')),
  treeOnly(str('icmpv6.reserved', 'Reserved', 'icmpv6')),
  uint('icmpv6.mtu', 'MTU', 'icmpv6'),
  uint('icmpv6.pointer', 'Pointer', 'icmpv6'),
  // Neighbor Discovery. The target address is the whole content of a
  // solicitation and an advertisement, and until the options became a subtree
  // the tree for either message was Type and Code and nothing else.
  { abbrev: 'icmpv6.nd.ns.target_address', label: 'Target Address', type: 'ipv6', layer: 'icmpv6' },
  { abbrev: 'icmpv6.nd.na.target_address', label: 'Target Address', type: 'ipv6', layer: 'icmpv6' },
  { abbrev: 'icmpv6.nd.rd.target_address', label: 'Target Address', type: 'ipv6', layer: 'icmpv6' },
  treeOnly(str('icmpv6.nd.na.flag', 'Flags', 'icmpv6')),
  treeOnly(bool('icmpv6.nd.na.flag.r', 'Router', 'icmpv6')),
  treeOnly(bool('icmpv6.nd.na.flag.s', 'Solicited', 'icmpv6')),
  treeOnly(bool('icmpv6.nd.na.flag.o', 'Override', 'icmpv6')),
  treeOnly(uint('icmpv6.nd.na.flag.rsv', 'Reserved', 'icmpv6')),
  // Router Advertisement. How a passive observer learns an IPv6 network's
  // shape - the prefix hosts autoconfigure from, the resolvers they were
  // handed, and whether they were also told to use DHCPv6 - none of which is
  // recorded anywhere on the machine as having come from the router.
  uint('icmpv6.nd.ra.cur_hop_limit', 'Cur hop limit', 'icmpv6'),
  treeOnly(str('icmpv6.nd.ra.flag', 'Flags', 'icmpv6')),
  uint('icmpv6.nd.ra.flag.m', 'Managed address configuration', 'icmpv6'),
  uint('icmpv6.nd.ra.flag.o', 'Other configuration', 'icmpv6'),
  treeOnly(bool('icmpv6.nd.ra.flag.h', 'Home Agent', 'icmpv6')),
  treeOnly(str('icmpv6.nd.ra.flag.prf', 'Prf (Default Router Preference)', 'icmpv6')),
  treeOnly(bool('icmpv6.nd.ra.flag.p', 'ND Proxy', 'icmpv6')),
  treeOnly(bool('icmpv6.nd.ra.flag.s', 'SNAC Router', 'icmpv6')),
  treeOnly(uint('icmpv6.nd.ra.flag.rsv', 'Reserved', 'icmpv6')),
  uint('icmpv6.nd.ra.router_lifetime', 'Router lifetime', 'icmpv6'),
  uint('icmpv6.nd.ra.reachable_time', 'Reachable time (ms)', 'icmpv6'),
  uint('icmpv6.nd.ra.retrans_timer', 'Retrans timer (ms)', 'icmpv6'),
  // The option subtree. `icmpv6.opt` is the parent row - FT_NONE in the
  // reference, which is why its value is the parenthetical summary rather
  // than a number.
  treeOnly(str('icmpv6.opt', 'ICMPv6 Option', 'icmpv6')),
  treeOnly(str('icmpv6.opt.type', 'Type', 'icmpv6')),
  treeOnly(str('icmpv6.opt.length', 'Length', 'icmpv6')),
  treeOnly(str('icmpv6.opt.reserved', 'Reserved', 'icmpv6')),
  treeOnly(str('icmpv6.opt.linkaddr', 'Link-layer address', 'icmpv6')),
  treeOnly(str('icmpv6.opt.src_linkaddr', 'Source Link-layer address', 'icmpv6')),
  treeOnly(str('icmpv6.opt.target_linkaddr', 'Target Link-layer address', 'icmpv6')),
  treeOnly(uint('icmpv6.opt.mtu', 'MTU', 'icmpv6')),
  // **`icmpv6.opt.prefix` and `icmpv6.opt.rdnss` mean two things at once, and
  // the reference is why.** It emits each of them once per option and matches
  // a filter against ANY occurrence. The bag holds one value per key, so
  // `routerAdvertisementFields` writes the comma-joined list the Network panel
  // reads back, while the tree draws one row per option the way the reference
  // does. Closing that needs the filter engine to read repeated rows, which is
  // a change to the engine rather than to either writer.
  str('icmpv6.opt.prefix', 'Prefix', 'icmpv6'),
  uint('icmpv6.opt.prefix.length', 'Prefix Length', 'icmpv6'),
  treeOnly(str('icmpv6.opt.prefix.flag', 'Flag', 'icmpv6')),
  treeOnly(bool('icmpv6.opt.prefix.flag.l', 'On-link Flag (L)', 'icmpv6')),
  treeOnly(bool('icmpv6.opt.prefix.flag.a', 'Autonomous Address Configuration Flag (A)', 'icmpv6')),
  treeOnly(bool('icmpv6.opt.prefix.flag.r', 'Router Address Flag (R)', 'icmpv6')),
  treeOnly(bool('icmpv6.opt.prefix.flag.p', 'DHCPv6-PD Preferred Flag (P)', 'icmpv6')),
  treeOnly(uint('icmpv6.opt.prefix.flag.reserved', 'Reserved', 'icmpv6')),
  uint('icmpv6.opt.prefix.valid_lifetime', 'Prefix valid lifetime', 'icmpv6'),
  uint('icmpv6.opt.prefix.preferred_lifetime', 'Prefix preferred lifetime', 'icmpv6'),
  str('icmpv6.opt.rdnss', 'Recursive DNS server', 'icmpv6'),
  treeOnly(uint('icmpv6.opt.rdnss.lifetime', 'Lifetime', 'icmpv6')),
  // Multicast Listener Report v2 (RFC 3810). Every Windows machine emits these
  // on joining a link, so they are in any capture taken on one.
  treeOnly(uint('icmpv6.mldr.nb_mcast_records', 'Number of Multicast Address Records', 'icmpv6')),
  treeOnly(str('icmpv6.mldr.mar', 'Multicast Address Record', 'icmpv6')),
  treeOnly(str('icmpv6.mldr.mar.record_type', 'Record Type', 'icmpv6')),
  treeOnly(uint('icmpv6.mldr.mar.aux_data_len', 'Aux Data Len', 'icmpv6')),
  treeOnly(uint('icmpv6.mldr.mar.nb_sources', 'Number of Sources', 'icmpv6')),
  treeOnly(str('icmpv6.mldr.mar.multicast_address', 'Multicast Address', 'icmpv6')),
  treeOnly(str('icmpv6.mldr.mar.source_address', 'Source Address', 'icmpv6')),

  // --- IGMP ------------------------------------------------------------------
  uint('igmp.type', 'Type', 'igmp'),
  uint('igmp.version', 'IGMP Version', 'igmp'),
  { abbrev: 'igmp.maddr', label: 'Multicast Address', type: 'ipv4', layer: 'igmp' },
  uint('igmp.num_grp_recs', 'Num Group Records', 'igmp'),
  // The other ten, every one of which this dissector already drew with the
  // right value, byte range and bitfield and never named. `treeOnly`: a v3
  // report's record type and source count are read off the tree beside the
  // group they describe, and nothing outside the detail pane asks for them.
  //
  // `igmp.num_src` appears twice - once per group record, and once on a v3
  // query, where it counts the sources the querier is asking about rather
  // than the ones a host is reporting.
  treeOnly(uint('igmp.max_resp', 'Max Resp Time', 'igmp')),
  treeOnly(uint('igmp.checksum', 'Checksum', 'igmp')),
  treeOnly(uint('igmp.checksum.status', 'Checksum Status', 'igmp')),
  treeOnly(str('igmp.reserved', 'Reserved', 'igmp')),
  treeOnly(uint('igmp.record_type', 'Record Type', 'igmp')),
  treeOnly(uint('igmp.aux_data_len', 'Aux Data Len', 'igmp')),
  treeOnly(uint('igmp.num_src', 'Num Src', 'igmp')),
  treeOnly(bool('igmp.s', 'S', 'igmp')),
  treeOnly(uint('igmp.qrv', 'QRV', 'igmp')),
  treeOnly(uint('igmp.qqic', 'QQIC', 'igmp')),

  // --- ARP -------------------------------------------------------------------
  uint('arp.opcode', 'Opcode', 'arp'),
  { abbrev: 'arp.src.hw_mac', label: 'Sender MAC address', type: 'mac', layer: 'arp' },
  { abbrev: 'arp.src.proto_ipv4', label: 'Sender IP address', type: 'ipv4', layer: 'arp' },
  { abbrev: 'arp.dst.hw_mac', label: 'Target MAC address', type: 'mac', layer: 'arp' },
  { abbrev: 'arp.dst.proto_ipv4', label: 'Target IP address', type: 'ipv4', layer: 'arp' },

  // --- STP -------------------------------------------------------------------
  uint('stp.type', 'BPDU Type', 'stp'),
  uint('stp.version', 'Protocol Version Identifier', 'stp'),
  uint('stp.root.cost', 'Root Path Cost', 'stp'),
  uint('stp.port', 'Port identifier', 'stp'),

  // --- LLDP ------------------------------------------------------------------
  uint('lldp.chassis.subtype', 'Chassis Id Subtype', 'lldp'),
  str('lldp.chassis.id', 'Chassis Id', 'lldp'),
  uint('lldp.port.subtype', 'Port Id Subtype', 'lldp'),
  str('lldp.port.id', 'Port Id', 'lldp'),
  uint('lldp.time_to_live', 'Time To Live', 'lldp'),
  str('lldp.port.desc', 'Port Description', 'lldp'),
  str('lldp.tlv.system.name', 'System Name', 'lldp', { label: 'System name', align: 'left' }),
  str('lldp.tlv.system.desc', 'System Description', 'lldp'),
  str('lldp.tlv.system_cap', 'Capabilities', 'lldp'),
  str('lldp.mgn.addr.ip4', 'Management Address', 'lldp'),

  // --- LLDP: the TLV header, and the two organisations' own TLVs ------------
  //
  // `lldp.tlv.type` and `lldp.tlv.len` are on EVERY TLV including the ones
  // this build does not decode, which is where they matter most: an
  // undecoded TLV is exactly where a reader needs to know what the sender
  // called it and how many bytes it claimed.
  //
  // All `treeOnly`. LLDP is one frame in the fixtures and every name here is
  // either TLV framing or a bit of a capability word - read in the detail
  // pane beside the thing it qualifies, never as a column or a colour rule.
  treeOnly(uint('lldp.tlv.type', 'TLV Type', 'lldp')),
  treeOnly(uint('lldp.tlv.len', 'TLV Length', 'lldp')),
  treeOnly(str('lldp.pdu_type', 'LLDPDU Type', 'lldp')),
  // The reference names a port id after the subtype that produced it, so a
  // MAC-address port answers this rather than the generic `lldp.port.id`.
  treeOnly({ abbrev: 'lldp.port.id.mac', label: 'Port Id', type: 'mac', layer: 'lldp' }),
  treeOnly(str('lldp.orgtlv.oui', 'Organization Unique Code', 'lldp')),
  treeOnly(uint('lldp.ieee.802_3.subtype', 'IEEE 802.3 Subtype', 'lldp')),
  treeOnly(uint('lldp.ieee.802_3.mac_phy_auto_neg_status', 'Auto-Negotiation Support/Status', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.mac_phy_auto_neg_status.supported', 'Auto-Negotiation Supported', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.mac_phy_auto_neg_status.enabled', 'Auto-Negotiation Enabled', 'lldp')),
  treeOnly(uint('lldp.ieee.802_3.pmd_mau_type', 'Operational MAU Type', 'lldp')),

  // The sixteen advertised-capability bits, and the same sixteen read in the
  // opposite bit order. The `_inv` half is deliberately the WRONG reading -
  // see `pmdCapabilityRows` in dissectors/lldp.ts for why drawing it is what
  // makes a far-end byte-order bug distinguishable from an odd advertisement.
  treeOnly(uint('lldp.ieee.802_3.pmd_auto_neg_advertised_caps', 'PMD Auto-Negotiation Advertised Capability', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd', '1000BASE-T (full duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t', '1000BASE-T (half duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd', '1000BASE-X (full duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x', '1000BASE-X (half duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause', 'Asymmetric and Symmetric PAUSE', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause', 'Symmetric PAUSE', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause', 'Asymmetric PAUSE', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause', 'PAUSE (for full-duplex links)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd', '100BASE-T2 (full duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2', '100BASE-T2 (half duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd', '100BASE-TX (full duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx', '100BASE-TX (half duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4', '100BASE-T4', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd', '10BASE-T (full duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t', '10BASE-T (half duplex mode)', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other', 'Other or unknown', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd', '1000BASE-T (full duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t', '1000BASE-T (half duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd', '1000BASE-X (full duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x', '1000BASE-X (half duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause', 'Asymmetric and Symmetric PAUSE, inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause', 'Symmetric PAUSE, inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause', 'Asymmetric PAUSE, inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause', 'PAUSE (for full-duplex links), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd', '100BASE-T2 (full duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2', '100BASE-T2 (half duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd', '100BASE-TX (full duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx', '100BASE-TX (half duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4', '100BASE-T4, inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd', '10BASE-T (full duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t', '10BASE-T (half duplex mode), inverse bitorder', 'lldp')),
  treeOnly(bool('lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other', 'Other or unknown, inverse bitorder', 'lldp')),

  // LLDP-MED: what an endpoint says it can do. A phone advertising Network
  // Policy is asking the switch for a voice VLAN.
  treeOnly(uint('lldp.media.subtype', 'Media Subtype', 'lldp')),
  treeOnly(uint('lldp.media.subtype.caps', 'Media Capabilities', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.llpd', 'LLDP-MED Capabilities', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.network_policy', 'Network Policy', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.location_id', 'Location Identification', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.mdi_pse', 'Extended Power via MDI-PSE', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.mid_pd', 'Extended Power via MDI-PD', 'lldp')),
  treeOnly(bool('lldp.media.subtype.caps.inventory', 'Inventory', 'lldp')),
  treeOnly(uint('lldp.media.subtype.class', 'Class Type', 'lldp')),

  // --- TLS -------------------------------------------------------------------
  // **The record and handshake frames themselves**, which the tree has always
  // drawn as the rows everything else hangs off and never named - so
  // `tls.handshake` and `tls.record`, two of the most typed TLS filters there
  // are, resolved to nothing. Tree-only: they are container rows with no value
  // to carry, which is what FT_NONE means in the reference.
  treeOnly(str('tls.record', 'Record Layer', 'tls')),
  treeOnly(str('tls.handshake', 'Handshake Protocol', 'tls')),
  treeOnly(str('tls.ignored_unknown_record', 'Ignored Unknown Record', 'tls')),
  uint('tls.record.content_type', 'Content Type', 'tls'),
  // **TLS 1.3 writes `application_data` on the outside of every record after
  // the handshake** and puts the real content type inside the ciphertext, so
  // the reference renames the field rather than letting a reader take the
  // outer byte for the record's kind. Same row, different name, decided by
  // whether the record is encrypted.
  treeOnly(uint('tls.record.opaque_type', 'Opaque Type', 'tls')),
  uint('tls.record.version', 'Version', 'tls'),
  uint('tls.record.length', 'Length', 'tls'),
  treeOnly(str('tls.app_data', 'Encrypted Application Data', 'tls')),
  uint('tls.handshake.type', 'Handshake Type', 'tls'),
  treeOnly(uint('tls.handshake.length', 'Length', 'tls')),
  uint('tls.handshake.version', 'Version', 'tls'),
  // RFC 8446 §4.1.2: the value in this field MUST be ignored when
  // supported_versions is present, so a row called `Version` beside a list
  // naming TLS 1.3 is a row inviting the wrong conclusion. The reference
  // renames it; so does this, on the same condition.
  treeOnly(str('tls.handshake.legacy_version', 'Version (legacy)', 'tls')),
  treeOnly(str('tls.handshake.random', 'Random', 'tls')),
  // The first four of those 32 bytes were `gmt_unix_time` before RFC 8446
  // made the whole field random. A sender still filling them in is leaking
  // its wall clock to every observer on the path, which is worth being able
  // to ask about - and on a modern hello the nonsense date IS the answer.
  treeOnly(str('tls.handshake.random_time', 'GMT Unix Time', 'tls')),
  treeOnly(str('tls.handshake.random_bytes', 'Random Bytes', 'tls')),

  // --- what the record CONTAINS, known without reading it ------------------
  //
  // ALPN is negotiated in the clear, so an Application Data record nobody can
  // decrypt still has a protocol. This build computed it, used it to pick a
  // decoder and never told the reader; the reference says it on 824 frames of
  // the inwire fixture.
  treeOnly(str('tls.app_data_proto', 'Application Data Protocol', 'tls')),

  // --- extensions this build drew as a length and nothing else -------------
  //
  // `tls.handshake.extension.data` is the one that matters most, and it is
  // the one for extensions NOT listed here: an extension this build has
  // never heard of now shows its bytes instead of its size.
  treeOnly(str('tls.handshake.extension.data', 'Data', 'tls')),
  treeOnly(uint('tls.handshake.extensions_ec_point_formats_length', 'EC point formats Length', 'tls')),
  treeOnly(str('tls.handshake.extensions_ec_point_formats', 'Elliptic curves point formats', 'tls')),
  treeOnly(str('tls.handshake.extensions_ec_point_format', 'EC point format', 'tls')),
  treeOnly(uint('tls.compress_certificate.algorithms_length', 'Algorithms Length', 'tls')),
  treeOnly(str('tls.compress_certificate.algorithm', 'Algorithm', 'tls')),
  treeOnly(uint('tls.handshake.extensions_alps_len', 'ALPS Extension Length', 'tls')),
  treeOnly(str('tls.handshake.extensions_alps_alpn_list', 'Supported ALPS List', 'tls')),
  treeOnly(uint('tls.handshake.extensions_alps_alpn_str_len', 'ALPS string length', 'tls')),
  treeOnly(str('tls.handshake.extensions_alps_alpn_str', 'ALPS Next Protocol', 'tls')),

  // --- QUIC's transport parameters, which ride in the TLS handshake --------
  //
  // QUIC has no negotiation of its own, so extension 57 of the ClientHello
  // is where a client states its flow-control limits, its idle timeout and
  // its connection id. On an h3 connection it is the only place the
  // transport's settings appear in the clear at all - everything after the
  // handshake is encrypted.
  //
  // `tls.quic.parameter.type` is `FT_UINT64` in the reference and its GREASE
  // values run to the full 62 bits, which is why the row draws those as hex
  // rather than as a number a JS double would round.
  treeOnly(str('tls.quic.parameter.type', 'Type', 'tls')),
  treeOnly(uint('tls.quic.parameter.length', 'Length', 'tls')),
  treeOnly(str('tls.quic.parameter.value', 'Value', 'tls')),
  treeOnly(uint('tls.quic.parameter.max_idle_timeout', 'max_idle_timeout', 'tls')),
  treeOnly(uint('tls.quic.parameter.max_udp_payload_size', 'max_udp_payload_size', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_data', 'initial_max_data', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_stream_data_bidi_local', 'initial_max_stream_data_bidi_local', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_stream_data_bidi_remote', 'initial_max_stream_data_bidi_remote', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_stream_data_uni', 'initial_max_stream_data_uni', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_streams_bidi', 'initial_max_streams_bidi', 'tls')),
  treeOnly(uint('tls.quic.parameter.initial_max_streams_uni', 'initial_max_streams_uni', 'tls')),
  treeOnly(uint('tls.quic.parameter.ack_delay_exponent', 'ack_delay_exponent', 'tls')),
  treeOnly(uint('tls.quic.parameter.max_ack_delay', 'max_ack_delay', 'tls')),
  treeOnly(uint('tls.quic.parameter.active_connection_id_limit', 'active_connection_id_limit', 'tls')),
  treeOnly(uint('tls.quic.parameter.max_datagram_frame_size', 'max_datagram_frame_size', 'tls')),
  treeOnly(str('tls.quic.parameter.original_destination_connection_id', 'original_destination_connection_id', 'tls')),
  treeOnly(str('tls.quic.parameter.stateless_reset_token', 'stateless_reset_token', 'tls')),
  treeOnly(str('tls.quic.parameter.initial_source_connection_id', 'initial_source_connection_id', 'tls')),
  treeOnly(str('tls.quic.parameter.retry_source_connection_id', 'retry_source_connection_id', 'tls')),
  treeOnly(uint('tls.quic.parameter.google.initial_rtt', 'Google initial_rtt', 'tls')),
  treeOnly(str('tls.quic.parameter.google.connection_options', 'Google connection_options', 'tls')),
  treeOnly(str('tls.quic.parameter.google.user_agent', 'Google user_agent', 'tls')),
  // RFC 9368. A connection that negotiated down is otherwise
  // indistinguishable from one that only ever offered what it used.
  treeOnly(str('tls.quic.parameter.vi.chosen_version', 'Chosen Version', 'tls')),
  treeOnly(str('tls.quic.parameter.vi.other_version', 'Other Version', 'tls')),
  treeOnly(str('tls.handshake.session_id', 'Session ID', 'tls')),
  treeOnly(uint('tls.handshake.session_id_length', 'Session ID Length', 'tls')),
  treeOnly(uint('tls.handshake.cipher_suites_length', 'Cipher Suites Length', 'tls')),
  treeOnly(str('tls.handshake.ciphersuites', 'Cipher Suites', 'tls')),
  treeOnly(uint('tls.handshake.comp_methods_length', 'Compression Methods Length', 'tls')),
  treeOnly(str('tls.handshake.comp_methods', 'Compression Methods', 'tls')),
  treeOnly(uint('tls.handshake.comp_method', 'Compression Method', 'tls')),
  treeOnly(uint('tls.handshake.extensions_length', 'Extensions Length', 'tls')),
  // The extension subtree. Every extension was a Type and a Length row with
  // neither named, on 87 inwire frames - which is the thing the hello is
  // mostly MADE of, and `tls.handshake.extension.type == 65037` (ECH) was
  // unanswerable.
  treeOnly(str('tls.handshake.extension', 'Extension', 'tls')),
  treeOnly(str('tls.handshake.extension.type', 'Type', 'tls')),
  treeOnly(uint('tls.handshake.extension.len', 'Length', 'tls')),
  treeOnly(uint('tls.handshake.extensions_supported_groups_length', 'Supported Groups List Length', 'tls')),
  treeOnly(str('tls.handshake.extensions_supported_groups', 'Supported Groups List', 'tls')),
  // The signature algorithms, split into the hash and signature halves RFC
  // 8446 §4.2.3 defines them as - which is what makes "still offering SHA-1"
  // a filter somebody can write rather than a string they have to eyeball.
  treeOnly(uint('tls.handshake.sig_hash_alg_len', 'Signature Hash Algorithms Length', 'tls')),
  treeOnly(str('tls.handshake.sig_hash_algs', 'Signature Algorithms', 'tls')),
  treeOnly(str('tls.handshake.sig_hash_alg', 'Signature Algorithm', 'tls')),
  treeOnly(uint('tls.handshake.sig_hash_hash', 'Signature Hash Algorithm Hash', 'tls')),
  treeOnly(uint('tls.handshake.sig_hash_sig', 'Signature Hash Algorithm Signature', 'tls')),
  uint('tls.handshake.ciphersuite', 'Cipher Suite', 'tls'),
  str('tls.handshake.extensions_server_name', 'Server Name', 'tls', { label: 'SNI', align: 'left' }),
  str('tls.handshake.extensions_alpn_str', 'ALPN Next Protocol', 'tls', { label: 'ALPN', align: 'left' }),
  // **The frames the reference draws around the two values above.** An SNI is
  // one entry in a typed list and an ALPN is one string in another, and the
  // lengths and type bytes are how a malformed hello shows itself - a list
  // length that disagrees with the extension's own is the shape of a
  // fingerprint-evasion attempt and was invisible here.
  treeOnly(uint('tls.handshake.extensions_server_name_list_len', 'Server Name list length', 'tls')),
  treeOnly(str('tls.handshake.extensions_server_name_type', 'Server Name Type', 'tls')),
  treeOnly(uint('tls.handshake.extensions_server_name_len', 'Server Name length', 'tls')),
  treeOnly(uint('tls.handshake.extensions_alpn_len', 'ALPN Extension Length', 'tls')),
  treeOnly(str('tls.handshake.extensions_alpn_list', 'ALPN Protocol', 'tls')),
  treeOnly(uint('tls.handshake.extensions_alpn_str_len', 'ALPN string length', 'tls')),
  treeOnly(uint('tls.handshake.extensions.supported_versions_len', 'Supported Versions length', 'tls')),
  treeOnly(uint('tls.extension.psk_ke_modes_length', 'PSK Key Exchange Modes Length', 'tls')),
  treeOnly(str('tls.extension.psk_ke_mode', 'PSK Key Exchange Mode', 'tls')),
  treeOnly(uint('tls.handshake.extensions_key_share_client_length', 'Client Key Share Length', 'tls')),
  treeOnly(uint('tls.handshake.extensions_key_share_key_exchange_length', 'Key Exchange Length', 'tls')),
  // The share itself, which is what a reader compares across captures when
  // asking whether two connections reused a key.
  treeOnly(str('tls.handshake.extensions_key_share_key_exchange', 'Key Exchange', 'tls')),
  uint('tls.handshake.extensions.supported_version', 'Supported Version', 'tls'),
  uint('tls.handshake.extensions_supported_group', 'Supported Group', 'tls'),
  uint('tls.handshake.extensions_key_share_group', 'Key Share Group', 'tls'),
  bool('tls.handshake.extensions_ech', 'Encrypted Client Hello', 'tls'),
  str('tls.handshake.ja3', 'JA3', 'tls', { label: 'JA3', align: 'left' }),
  str('tls.handshake.ja3_full', 'JA3 Fullstring', 'tls'),
  str('tls.handshake.ja3s', 'JA3S', 'tls', { label: 'JA3S', align: 'left' }),
  str('tls.handshake.ja3s_full', 'JA3S Fullstring', 'tls'),
  str('tls.handshake.ja4', 'JA4', 'tls', { label: 'JA4', align: 'left' }),
  str('tls.handshake.ja4_r', 'JA4_r', 'tls'),
  uint('tls.alert_message.level', 'Level', 'tls'),
  uint('tls.alert_message.desc', 'Description', 'tls'),
  str('tls.x509.subject_cn', 'Subject CN', 'tls'),
  str('tls.x509.issuer_cn', 'Issuer CN', 'tls'),

  // --- X.509 -----------------------------------------------------------------
  // Every one of these is tree-only, and that is the per-frame cost argument
  // rather than a limitation: a chain is two to four certificates, each with
  // several names, usages and access descriptions, so a certificate frame
  // would carry dozens of bag keys against a tree that is built on demand and
  // thrown away with the pane (ADR 0007). The two CN fields above stay in the
  // bag, because they are the two anybody filters on.
  //
  // The key SIZE is not here at all. The reference's `x509af.subjectPublicKey`
  // is FT_BYTES - the key itself - so a field carrying 2048 under that name
  // would be a filter that works in this build and nowhere else, which is
  // exactly what `wireshark-abbrevs.ts` exists to catch. It is in the Public
  // Key Algorithm row's text.
  treeOnly(uint('x509af.version', 'version', 'x509af')),
  treeOnly(str('x509af.serialNumber', 'serialNumber', 'x509af')),
  // The algorithm the certificate was SIGNED with, which was skipped outright
  // - `i++; // signature algorithm` - and is the whole of what a deprecated
  // hash looks like from the outside.
  treeOnly(str('x509af.algorithm.id', 'Algorithm Id', 'x509af')),
  treeOnly(str('x509af.extension.id', 'Extension Id', 'x509af')),
  treeOnly(bool('x509af.critical', 'critical', 'x509af')),
  // subjectAltName, one row per name and one name per FORM. The dNSName half
  // was all this build read; an internal service whose certificate names only
  // its address read as a certificate with no names at all.
  treeOnly(str('x509ce.dNSName', 'dNSName', 'x509ce')),
  treeOnly(str('x509ce.rfc822Name', 'rfc822Name', 'x509ce')),
  // One name for every URI in a certificate - the SAN's, both access
  // locations and the CRL distribution point - which is the reference's own
  // choice, confirmed against it on the synthetic handshake.
  treeOnly(str('x509ce.uniformResourceIdentifier', 'uniformResourceIdentifier', 'x509ce')),
  treeOnly(str('x509ce.IPAddress.ipv4', 'iPAddress', 'x509ce')),
  treeOnly(str('x509ce.IPAddress.ipv6', 'iPAddress', 'x509ce')),
  treeOnly(bool('x509ce.cA', 'cA', 'x509ce')),
  treeOnly(uint('x509ce.pathLenConstraint', 'pathLenConstraint', 'x509ce')),
  treeOnly(str('x509ce.KeyUsage', 'KeyUsage', 'x509ce')),
  treeOnly(str('x509ce.KeyPurposeId', 'KeyPurposeId', 'x509ce')),
  treeOnly(str('pkix1implicit.accessMethod', 'accessMethod', 'pkix1implicit')),
  bool('tls.reassembled', 'Reassembled record', 'tls'),
  bool('inwire.tls.decrypted', 'Decrypted with a key log secret', 'tls'),

  // --- HTTP ------------------------------------------------------------------
  // Cleartext, and the plaintext of a TLS conversation a key log opened - the
  // same dissector reads both, so one set of names covers both.
  str('http.request.method', 'Request Method', 'http', { label: 'Method', align: 'left' }),
  str('http.request.uri', 'Request URI', 'http', { label: 'URI', align: 'left' }),
  str('http.request.version', 'Request Version', 'http'),
  str('http.response.version', 'Response Version', 'http'),
  uint('http.response.code', 'Status Code', 'http', { label: 'Status', align: 'right' }),
  str('http.response.phrase', 'Response Phrase', 'http'),
  treeOnly(str('http.response.code.desc', 'Status Code Description', 'http')),
  // **Presence, which is how you ask for requests without naming a method.**
  // SSDP's NOTIFY gets `http.notification` rather than `http.request`: it is a
  // request by syntax and answers nobody, and the reference separates them so
  // a filter can have the announcements without every M-SEARCH on the segment.
  bool('http.request', 'Request', 'http'),
  bool('http.response', 'Response', 'http'),
  bool('http.notification', 'Notification', 'http'),
  // The URI, decomposed. The path and the query are single and filterable; a
  // path SEGMENT and a query PARAMETER repeat, so they are rows rather than
  // bag keys - one key holds one value, and the tree is where the reference's
  // repeated fields can be represented at all.
  str('http.request.uri.path', 'Request URI Path', 'http'),
  treeOnly(str('http.request.uri.path.segment', 'Request URI Path Segment', 'http')),
  str('http.request.uri.query', 'Request URI Query', 'http'),
  treeOnly(str('http.request.uri.query.parameter', 'Request URI Query Parameter', 'http')),
  // The authority and the target together, which neither the start line nor
  // the Host header carries alone.
  str('http.request.full_uri', 'Full request URI', 'http'),
  // **The pairing, which needed no tracker.** Responses on one connection come
  // back in the order the requests went out - that is what pipelining IS - so
  // the queue lives with the connection in `appStream.ts` and a response takes
  // the head of its peer's. `http.response_in` on the REQUEST is deliberately
  // absent: it needs a patch to an earlier frame, the reference's own
  // single-pass mode does not emit it either, and `dns.response_in` already
  // sits in the coverage tool's INWIRE-ONLY list for exactly that reason.
  { abbrev: 'http.request_in', label: 'Request in frame', type: 'uint', layer: 'http', generated: true },
  { abbrev: 'http.time', label: 'Time since request', type: 'time', layer: 'http', generated: true },
  // Every header line's raw text, which the reference emits beside each named
  // header and hides. Repeated, so tree-only for the reason above.
  treeOnly(str('http.request.line', 'Request line', 'http')),
  treeOnly(str('http.response.line', 'Response line', 'http')),
  treeOnly(str('http.unknown_header', 'Unknown header', 'http')),
  // The headers HTTP has a name of its own for. The awkward spellings are the
  // reference's - `content_length_header` is the raw header where
  // `http.content_length` is the parsed number, and `accept_encoding` has one
  // underscore where `x_forwarded_for` has two - and `wireshark-abbrevs.ts`
  // is what keeps them that way.
  str('http.accept', 'Accept', 'http'),
  str('http.accept_encoding', 'Accept Encoding', 'http'),
  str('http.accept_language', 'Accept-Language', 'http'),
  str('http.authorization', 'Authorization', 'http'),
  str('http.cache_control', 'Cache-Control', 'http'),
  str('http.connection', 'Connection', 'http'),
  str('http.content_encoding', 'Content-Encoding', 'http'),
  str('http.content_length_header', 'Content-Length', 'http'),

  // --- the body, once there is one -----------------------------------------
  //
  // All `treeOnly`, and `http.file_data` is the one where that is not just
  // the default. The reference's `http.file_data` holds the body BYTES, so
  // `http.file_data contains "password"` is a query people already know how
  // to write; a bag write of a byte COUNT under that name would answer it
  // wrongly while looking right, which is the exact failure the registry's
  // "a filter learnt in Wireshark works here" promise exists to prevent.
  // If the bytes themselves ever become filterable, that is a `Uint8Array`
  // field type this registry does not yet have - not a number.
  //
  // `http.content_length` is the PARSED number beside the raw
  // `http.content_length_header` above, which is the reference's own split
  // and the only form `http.content_length > 1000000` can be asked of.
  treeOnly(str('http.file_data', 'File Data', 'http')),
  treeOnly(uint('http.content_length', 'Content length', 'http')),
  treeOnly(uint('http.chunk_size', 'Chunk size', 'http')),
  treeOnly(str('http.chunk_data', 'Chunk data', 'http')),
  treeOnly(str('http.chunk_boundary', 'Chunk boundary', 'http')),
  treeOnly(str('http.cookie_pair', 'Cookie pair', 'http')),

  // --- and what the body turns out to BE ------------------------------------
  //
  // `json.key` is the one here anybody types: `json.key == "error"` finds
  // every API response that failed, across every endpoint, without knowing
  // any of their shapes. It is `treeOnly` all the same - the bag is built for
  // every frame and kept for as long as the frame is (ADR 0007), and a
  // document with two hundred keys would put two hundred entries in it.
  //
  // **`media.type` is `FT_BYTES` in the reference**, holding the body rather
  // than the MIME string its name suggests. Matched, because the alternative
  // is a name people already know answering a different question here - the
  // same trap `http.file_data` carries.
  treeOnly(str('json.object', 'Object', 'json')),
  treeOnly(str('json.array', 'Array', 'json')),
  treeOnly(str('json.member', 'Member', 'json')),
  treeOnly(str('json.key', 'Key', 'json')),
  treeOnly(str('json.value.string', 'String value', 'json')),
  treeOnly(uint('json.value.number', 'Number value', 'json')),
  treeOnly(bool('json.value.true', 'True value', 'json')),
  treeOnly(bool('json.value.false', 'False value', 'json')),
  treeOnly(str('json.value.null', 'Null value', 'json')),
  treeOnly(str('media.type', 'Media type', 'media')),
  treeOnly(str('data.data', 'Data', 'data')),
  treeOnly(uint('data.len', 'Length', 'data')),
  treeOnly(str('data.text', 'Text', 'data')),
  str('http.content_range', 'Content-Range', 'http'),
  str('http.content_type', 'Content-Type', 'http'),
  str('http.cookie', 'Cookie', 'http'),
  str('http.date', 'Date', 'http'),
  str('http.host', 'Host', 'http'),
  str('http.last_modified', 'Last-Modified', 'http'),
  str('http.location', 'Location', 'http'),
  str('http.proxy_authenticate', 'Proxy-Authenticate', 'http'),
  str('http.proxy_authorization', 'Proxy-Authorization', 'http'),
  str('http.range', 'Range', 'http'),
  str('http.referer', 'Referer', 'http'),
  str('http.sec_websocket_accept', 'Sec-WebSocket-Accept', 'http'),
  str('http.sec_websocket_extensions', 'Sec-WebSocket-Extensions', 'http'),
  str('http.sec_websocket_key', 'Sec-WebSocket-Key', 'http'),
  str('http.sec_websocket_protocol', 'Sec-WebSocket-Protocol', 'http'),
  str('http.sec_websocket_version', 'Sec-WebSocket-Version', 'http'),
  str('http.server', 'Server', 'http'),
  str('http.set_cookie', 'Set-Cookie', 'http'),
  str('http.transfer_encoding', 'Transfer-Encoding', 'http'),
  str('http.upgrade', 'Upgrade', 'http'),
  str('http.user_agent', 'User-Agent', 'http'),
  str('http.www_authenticate', 'WWW-Authenticate', 'http'),
  str('http.x_forwarded_for', 'X-Forwarded-For', 'http'),

  // --- HTTP/2 ----------------------------------------------------------------
  uint('http2.type', 'Type', 'http2'),
  uint('http2.streamid', 'Stream Identifier', 'http2'),
  str('http2.headers.method', 'Method', 'http2', { label: 'Method', align: 'left' }),
  str('http2.headers.path', 'Path', 'http2', { label: 'Path', align: 'left' }),
  str('http2.headers.authority', 'Authority', 'http2'),
  uint('http2.headers.status', 'Status', 'http2', { label: 'Status', align: 'right' }),
  str('http2.headers.user_agent', 'User-Agent', 'http2'),
  str('http2.headers.content_type', 'Content-Type', 'http2'),

  // --- QUIC ------------------------------------------------------------------
  //
  // **The gap ADR 0039's tree coverage found.** `dissectors/quic.ts` reads every
  // one of these off the wire, decrypts what it can, and until this block
  // existed published none of them - `test/fixtures/acceptance.json` recorded
  // `quic` under `unimplemented` against 40 reference fields on `inwire` and 37
  // on `bulk`, rather than floored at 0, because a zero floor protects nothing
  // and reads as measured-and-accepted.
  //
  // Split between the bag and the tree on the standing per-frame-cost rule
  // (ADRs 0016-0018): the six a person actually filters on are bag-backed, and
  // the header's own accounting - the two connection-id lengths, the token
  // length, the Length field - is `treeOnly`. They are on screen for the one
  // frame someone opened, which is the right place to pay for them.
  //
  // Everything below the packet number needs the payload decrypted, so it is
  // present on Initial packets and on nothing else unless a key log was loaded.
  // `treeOnly` rather than bag-backed, and not for cost: the fact it carries is
  // already filterable through `quic.long.packet_type`, which is absent on a
  // short header and present on every long one.
  treeOnly(uint('quic.header_form', 'Header Form', 'quic')),
  uint('quic.long.packet_type', 'Packet Type', 'quic'),
  uint('quic.version', 'Version', 'quic'),
  treeOnly(uint('quic.dcil', 'Destination Connection ID Length', 'quic')),
  // The connection IDs are `bytes` - a hex string, compared as one - because
  // that is what they are on the wire and what the reference calls them. They
  // are the join key for a QUIC conversation the way a stream index is for TCP,
  // which is why these two carry a bag write where the lengths beside them
  // do not.
  { abbrev: 'quic.dcid', label: 'Destination Connection ID', type: 'bytes', layer: 'quic' },
  treeOnly(uint('quic.scil', 'Source Connection ID Length', 'quic')),
  { abbrev: 'quic.scid', label: 'Source Connection ID', type: 'bytes', layer: 'quic' },
  treeOnly(uint('quic.token_length', 'Token Length', 'quic')),
  treeOnly(uint('quic.length', 'Length', 'quic')),
  uint('quic.packet_number', 'Packet Number', 'quic'),
  uint('quic.frame_type', 'Frame Type', 'quic'),
  treeOnly(uint('quic.crypto.offset', 'Offset', 'quic')),
  treeOnly(uint('quic.crypto.length', 'Length', 'quic')),
  treeOnly(uint('quic.stream.stream_id', 'Stream ID', 'quic')),
  treeOnly(uint('quic.stream.offset', 'Offset', 'quic')),
  treeOnly(uint('quic.stream.length', 'Length', 'quic')),
  treeOnly(bool('quic.stream.fin', 'Fin', 'quic')),

  // --- HTTP/3 ----------------------------------------------------------------
  // Only ever present when a key log opened the QUIC packets that carried it:
  // unlike TLS over TCP, where the record layer is in the clear even when its
  // contents are not, a QUIC packet is protected header and all.
  uint('http3.frame_type', 'Frame Type', 'http3'),
  uint('http3.frame_streamid', 'Stream ID', 'http3'),
  str('http3.headers.method', 'Method', 'http3'),
  str('http3.headers.path', 'Path', 'http3'),
  str('http3.headers.authority', 'Authority', 'http3'),
  uint('http3.headers.status', 'Status', 'http3'),

  // --- Syslog ----------------------------------------------------------------
  //
  // `syslog.priority` is the byte on the wire; facility and level are the two
  // halves of it, and they are what anyone actually filters on - "show me
  // everything at ERR or worse" is `syslog.level <= 3`.
  uint('syslog.priority', 'Priority', 'syslog'),
  uint('syslog.facility', 'Facility', 'syslog'),
  uint('syslog.level', 'Level', 'syslog'),
  str('syslog.msg', 'Message', 'syslog', { label: 'Syslog message', align: 'left' }),

  // --- RTCP ------------------------------------------------------------------
  //
  // The SSRC is the join key: it is what ties a control packet to the media
  // stream it reports on, and the filter anyone tracing one call types.
  uint('rtcp.version', 'Version', 'rtcp'),
  treeOnly(bool('rtcp.padding', 'Padding', 'rtcp')),
  uint('rtcp.pt', 'Packet type', 'rtcp'),
  treeOnly(uint('rtcp.length', 'Length', 'rtcp')),
  uint('rtcp.senderssrc', 'Sender SSRC', 'rtcp', { label: 'RTCP SSRC', align: 'right' }),
  uint('rtcp.timestamp.rtp', 'RTP timestamp', 'rtcp'),
  uint('rtcp.sender.packetcount', "Sender's packet count", 'rtcp'),
  uint('rtcp.sender.octetcount', "Sender's octet count", 'rtcp'),

  // --- TFTP ------------------------------------------------------------------
  uint('tftp.opcode', 'Opcode', 'tftp'),
  str('tftp.source_file', 'Source File', 'tftp', { label: 'TFTP File', align: 'left' }),
  str('tftp.type', 'Type', 'tftp'),
  uint('tftp.block', 'Block', 'tftp'),
  uint('tftp.data_length', 'Data length', 'tftp'),
  uint('tftp.last_block', 'Last block', 'tftp'),
  uint('tftp.error.code', 'Error code', 'tftp'),
  str('tftp.error.message', 'Error message', 'tftp'),

  // --- NetBIOS Datagram Service ----------------------------------------------
  uint('nbdgm.type', 'Message Type', 'nbdgm'),
  uint('nbdgm.dgram_id', 'Datagram ID', 'nbdgm'),
  str('nbdgm.src.ip', 'Source IP', 'nbdgm'),
  uint('nbdgm.src.port', 'Source Port', 'nbdgm'),
  uint('nbdgm.dgram_len', 'Datagram length', 'nbdgm'),
  str('nbdgm.source_name', 'Source name', 'nbdgm', { label: 'NBDS Source', align: 'left' }),
  str('nbdgm.destination_name', 'Destination name', 'nbdgm'),
  uint('nbdgm.error_code', 'Error code', 'nbdgm'),

  // --- BFD -------------------------------------------------------------------
  uint('bfd.version', 'Version', 'bfd'),
  uint('bfd.diag', 'Diagnostic', 'bfd'),
  uint('bfd.sta', 'Session State', 'bfd', { label: 'BFD State', align: 'left' }),
  uint('bfd.flags', 'Message Flags', 'bfd'),
  uint('bfd.detect_time_multiplier', 'Detect Time Multiplier', 'bfd'),
  uint('bfd.message_length', 'Message Length', 'bfd'),
  uint('bfd.my_discriminator', 'My Discriminator', 'bfd'),
  uint('bfd.your_discriminator', 'Your Discriminator', 'bfd'),
  uint('bfd.desired_min_tx_interval', 'Desired Min TX Interval', 'bfd'),
  uint('bfd.required_min_rx_interval', 'Required Min RX Interval', 'bfd'),
  uint('bfd.required_min_echo_interval', 'Required Min Echo Interval', 'bfd'),

  // --- CoAP ------------------------------------------------------------------
  uint('coap.version', 'Version', 'coap'),
  uint('coap.type', 'Type', 'coap'),
  uint('coap.token_len', 'Token Length', 'coap'),
  str('coap.token', 'Token', 'coap'),
  uint('coap.code', 'Code', 'coap'),
  uint('coap.mid', 'Message ID', 'coap'),
  str('coap.opt.uri_path', 'Uri-Path', 'coap', { label: 'CoAP Path', align: 'left' }),
  str('coap.opt.uri_query', 'Uri-Query', 'coap'),
  uint('coap.payload_length', 'Payload length', 'coap'),

  // --- PTP -------------------------------------------------------------------
  uint('ptp.v2.messagetype', 'messageType', 'ptp'),
  uint('ptp.v2.versionptp', 'versionPTP', 'ptp'),
  uint('ptp.v2.messagelength', 'messageLength', 'ptp'),
  uint('ptp.v2.domainnumber', 'domainNumber', 'ptp'),
  uint('ptp.v2.flags', 'flags', 'ptp'),
  uint('ptp.v2.sequenceid', 'sequenceId', 'ptp'),
  uint('ptp.v2.sourceportid', 'sourcePortID', 'ptp'),
  str('ptp.v2.clockidentity', 'clockIdentity', 'ptp'),
  uint('ptp.v2.logmessageperiod', 'logMessageInterval', 'ptp'),
  uint('ptp.v2.an.grandmasterclockclass', 'grandmasterClockClass', 'ptp'),
  str('ptp.v2.an.grandmasterclockidentity', 'grandmasterClockIdentity', 'ptp'),
  uint('ptp.v2.an.localstepsremoved', 'stepsRemoved', 'ptp'),
  uint('ptp.v2.mm.managementId', 'managementId', 'ptp'),
  uint('ptp.v2.mm.action', 'actionField', 'ptp'),

  // --- HSRP ------------------------------------------------------------------
  uint('hsrp.version', 'Version', 'hsrp'),
  uint('hsrp.opcode', 'Op Code', 'hsrp'),
  uint('hsrp.state', 'State', 'hsrp', { label: 'HSRP State', align: 'left' }),
  uint('hsrp.hellotime', 'Hellotime', 'hsrp'),
  uint('hsrp.holdtime', 'Holdtime', 'hsrp'),
  uint('hsrp.priority', 'Priority', 'hsrp'),
  uint('hsrp.group', 'Group', 'hsrp'),
  str('hsrp.auth_data', 'Authentication Data', 'hsrp'),
  str('hsrp.virt_ip', 'Virtual IP Address', 'hsrp'),

  // --- VRRP ------------------------------------------------------------------
  uint('vrrp.version', 'Version', 'vrrp'),
  uint('vrrp.type', 'Type', 'vrrp'),
  uint('vrrp.virt_rtr_id', 'Virtual Rtr ID', 'vrrp'),
  uint('vrrp.prio', 'Priority', 'vrrp', { label: 'VRRP Priority', align: 'right' }),
  uint('vrrp.addr_count', 'Addr Count', 'vrrp'),
  uint('vrrp.auth_type', 'Auth Type', 'vrrp'),
  uint('vrrp.adver_int', 'Adver Int', 'vrrp'),
  uint('vrrp.short_adver_int', 'Max Adver Int', 'vrrp'),
  uint('vrrp.checksum', 'Checksum', 'vrrp'),
  str('vrrp.ip_addr', 'IP Address', 'vrrp'),

  // --- OSPF ------------------------------------------------------------------
  uint('ospf.version', 'Version', 'ospf'),
  uint('ospf.msg', 'Message Type', 'ospf'),
  uint('ospf.packet_length', 'Packet Length', 'ospf'),
  str('ospf.srcrouter', 'Source OSPF Router', 'ospf', { label: 'OSPF Router', align: 'left' }),
  str('ospf.area_id', 'Area ID', 'ospf'),
  uint('ospf.checksum', 'Checksum', 'ospf'),
  uint('ospf.auth.type', 'Auth Type', 'ospf'),
  str('ospf.hello.network_mask', 'Network Mask', 'ospf'),
  uint('ospf.hello.hello_interval', 'Hello Interval', 'ospf'),
  uint('ospf.hello.router_priority', 'Router Priority', 'ospf'),
  uint('ospf.hello.router_dead_interval', 'Router Dead Interval', 'ospf'),
  str('ospf.hello.designated_router', 'Designated Router', 'ospf'),
  str('ospf.hello.backup_designated_router', 'Backup Designated Router', 'ospf'),
  treeOnly(str('ospf.hello.active_neighbor', 'Active Neighbor', 'ospf')),
  uint('ospf.hello.neighbor_count', 'Neighbor count', 'ospf'),
  uint('ospf.db.interface_mtu', 'Interface MTU', 'ospf'),
  uint('ospf.db.dd_sequence', 'DD Sequence', 'ospf'),
  uint('ospf.ls.number_of_lsas', 'Number of LSAs', 'ospf'),

  // --- RIP and RIPng ---------------------------------------------------------
  // One dissector, two layer tokens: the versions share a preamble and nothing
  // else, so a filter naming `ripng` must not match a RIPv2 frame. The fields
  // are registered under `rip`, which is the abbreviation the reference
  // analyzer gives both.
  uint('rip.command', 'Command', 'rip'),
  uint('rip.version', 'Version', 'rip'),
  treeOnly(uint('rip.family', 'Address Family', 'rip')),
  str('rip.ip', 'IP Address', 'rip'),
  treeOnly(str('rip.netmask', 'Netmask', 'rip')),
  treeOnly(str('rip.next_hop', 'Next Hop', 'rip')),
  treeOnly(uint('rip.route_tag', 'Route Tag', 'rip')),
  uint('rip.metric', 'Metric', 'rip', { label: 'RIP Metric', align: 'right' }),
  uint('rip.route_count', 'Route count', 'rip'),

  // --- CDP -------------------------------------------------------------------
  uint('cdp.version', 'Version', 'cdp'),
  uint('cdp.ttl', 'TTL', 'cdp'),
  uint('cdp.checksum', 'Checksum', 'cdp'),
  str('cdp.deviceid', 'Device ID', 'cdp', { label: 'CDP Device', align: 'left' }),
  str('cdp.portid', 'Port ID', 'cdp', { label: 'CDP Port', align: 'left' }),
  str('cdp.software_version', 'Software Version', 'cdp'),
  str('cdp.platform', 'Platform', 'cdp'),
  uint('cdp.capabilities', 'Capabilities', 'cdp'),
  uint('cdp.native_vlan', 'Native VLAN', 'cdp'),
  str('cdp.duplex', 'Duplex', 'cdp'),
  str('cdp.nrgyz.ip_address', 'Address', 'cdp'),

  // --- SIP -------------------------------------------------------------------
  //
  // `sip.call_id` is a column because it is the one value that ties every frame
  // of a call together - the thing you filter on to see one conversation.
  str('sip.Method', 'Method', 'sip'),
  str('sip.r-uri', 'Request-URI', 'sip', { label: 'SIP URI', align: 'left' }),
  uint('sip.Status-Code', 'Status-Code', 'sip'),
  str('sip.Reason-Phrase', 'Reason-Phrase', 'sip'),
  str('sip.From', 'From', 'sip'),
  str('sip.To', 'To', 'sip'),
  str('sip.Call-ID', 'Call-ID', 'sip', { label: 'SIP Call-ID', align: 'left' }),
  str('sip.CSeq', 'CSeq', 'sip'),
  str('sip.User-Agent', 'User-Agent', 'sip'),

  // --- SNMP ------------------------------------------------------------------
  //
  // `snmp.community` is the credential, in the clear on v1 and v2c. It is a
  // column because its presence in a capture is itself the finding.
  uint('snmp.version', 'Version', 'snmp'),
  str('snmp.community', 'Community', 'snmp', { label: 'SNMP community', align: 'left' }),
  uint('snmp.request_id', 'Request Id', 'snmp'),
  uint('snmp.error_status', 'Error Status', 'snmp'),
  uint('snmp.error_index', 'Error Index', 'snmp'),
  str('snmp.name', 'Object Name', 'snmp', { label: 'SNMP OID', align: 'left' }),
  treeOnly(str('snmp.value', 'Value', 'snmp')),
  str('snmp.enterprise', 'Enterprise', 'snmp'),

  // --- GRE -------------------------------------------------------------------
  //
  // A tunnel contributes fields but almost never a Protocol label: the
  // reference reports the INNER packet in every column, so `gre` reaches
  // `frameProtocols` as a token while `ip`/`tcp` carry the naming. That is
  // exactly what makes `gre && tcp.port == 443` a useful filter.
  uint('gre.proto', 'Protocol Type', 'gre'),
  uint('gre.key', 'Key', 'gre'),
  uint('gre.sequence_number', 'Sequence Number', 'gre'),
  uint('gre.checksum', 'Checksum', 'gre'),

  // --- SMB2 ------------------------------------------------------------------
  //
  // Wireshark's own abbrevs, checked against `tshark -G fields`. Note
  // `smb2.read_length` and `smb2.write_length` are separate fields rather than
  // one `length`, which is what lets `smb2.write_length > 65536` mean what a
  // reader expects.
  // BGP. Every abbrev is the reference's own spelling, including the
  // capitalised labels ("Major error Code") and the per-major minor-code
  // fields - see `NOTIFY_MINOR_ABBREV` in dissectors/bgp.ts for why there are
  // seven of those rather than one.
  uint('bgp.type', 'Type', 'bgp'),
  uint('bgp.length', 'Length', 'bgp'),
  uint('bgp.open.version', 'Version', 'bgp'),
  uint('bgp.open.myas', 'My AS', 'bgp'),
  uint('bgp.open.holdtime', 'Hold Time', 'bgp'),
  str('bgp.open.identifier', 'BGP Identifier', 'bgp'),
  uint('bgp.open.opt.len', 'Optional Parameters Length', 'bgp'),
  uint('bgp.notify.major_error', 'Major error Code', 'bgp'),
  uint('bgp.notify.minor_error', 'Minor error Code (Message Header)', 'bgp'),
  uint('bgp.notify.minor_error_open', 'Minor error Code (Open Message)', 'bgp'),
  uint('bgp.notify.minor_error_update', 'Minor error Code (Update Message)', 'bgp'),
  uint('bgp.notify.minor_error_expired', 'Minor error Code (Hold Timer Expired)', 'bgp'),
  uint('bgp.notify.minor_error_state', 'Minor error Code (State Machine)', 'bgp'),
  uint('bgp.notify.minor_error_cease', 'Minor error Code (Cease)', 'bgp'),
  uint('bgp.notify.minor_error_route_refresh', 'Minor error Code (Route-Refresh message)', 'bgp'),
  uint('bgp.notify.minor_error_unknown', 'Minor error Code (Unknown)', 'bgp'),
  uint('bgp.route_refresh.afi', 'Address family identifier (AFI)', 'bgp'),
  uint('bgp.route_refresh.safi', 'Subsequent address family identifier (SAFI)', 'bgp'),
  uint('bgp.update.withdrawn_routes.length', 'Withdrawn Routes Length', 'bgp'),
  uint('bgp.update.path_attributes.length', 'Total Path Attribute Length', 'bgp'),
  uint('smb2.cmd', 'Command', 'smb2'),
  uint('smb2.msg_id', 'Message ID', 'smb2'),
  uint('smb2.flags', 'Flags', 'smb2'),
  uint('smb2.nt_status', 'NT Status', 'smb2'),
  uint('smb2.tid', 'Tree Id', 'smb2'),
  uint('smb2.sesid', 'Session Id', 'smb2'),
  str('smb2.tree', 'Tree', 'smb2', { label: 'SMB2 share', align: 'left' }),
  str('smb2.filename', 'Filename', 'smb2', { label: 'SMB2 file', align: 'left' }),
  str('smb2.find.pattern', 'Search Pattern', 'smb2'),
  uint('smb2.read_length', 'Read Length', 'smb2'),
  uint('smb2.write_length', 'Write Length', 'smb2'),
  uint('smb2.file_offset', 'File Offset', 'smb2'),
  uint('smb2.ioctl.function', 'Function', 'smb2'),

  // --- LDAP ------------------------------------------------------------------
  //
  // Every abbrev here was read out of `tshark -G fields` rather than invented,
  // which is what `scripts/dissect/wireshark-abbrevs.ts` exists to enforce -
  // it caught 27 invented names the last time a batch of dissectors landed.
  // Note `ldap.name` (the bind DN) and `ldap.entry` (the delete target) are
  // distinct from `ldap.objectName`, as they are in the reference.
  uint('ldap.messageID', 'Message ID', 'ldap'),
  uint('ldap.protocolOp', 'Protocol Op', 'ldap'),
  uint('ldap.resultCode', 'Result Code', 'ldap'),
  uint('ldap.version', 'Version', 'ldap'),
  str('ldap.name', 'Bind Name', 'ldap', { label: 'LDAP bind DN', align: 'left' }),
  str('ldap.authentication', 'Authentication', 'ldap'),
  str('ldap.baseObject', 'Base Object', 'ldap', { label: 'LDAP base', align: 'left' }),
  uint('ldap.scope', 'Scope', 'ldap'),
  uint('ldap.derefAliases', 'Deref Aliases', 'ldap'),
  str('ldap.objectName', 'Object Name', 'ldap', { label: 'LDAP object', align: 'left' }),
  str('ldap.entry', 'Entry', 'ldap'),
  str('ldap.matchedDN', 'Matched DN', 'ldap'),
  str('ldap.errorMessage', 'Error Message', 'ldap'),
  str('ldap.requestName', 'Request Name', 'ldap'),

  // --- RADIUS ----------------------------------------------------------------
  uint('radius.code', 'Code', 'radius'),
  uint('radius.id', 'Packet identifier', 'radius'),
  uint('radius.length', 'Length', 'radius'),
  { abbrev: 'radius.authenticator', label: 'Authenticator', type: 'bytes', layer: 'radius' },
  str('radius.User_Name', 'User-Name', 'radius', { label: 'RADIUS user', align: 'left' }),
  treeOnly(uint('radius.avp.type', 'AVP Type', 'radius')),
  treeOnly(uint('radius.avp.length', 'AVP Length', 'radius')),

  // --- NBNS ------------------------------------------------------------------
  //
  // NetBIOS name service. Wireshark's own abbrevs, which are `nbns.*` and not
  // `netbios.*` - the latter is the datagram service on port 138, a different
  // dissector. The name field is a column because "which machine is this" is
  // the question the protocol exists to answer.
  uint('nbns.id', 'Transaction ID', 'nbns'),
  uint('nbns.flags', 'Flags', 'nbns'),
  bool('nbns.flags.response', 'Response', 'nbns'),
  uint('nbns.flags.opcode', 'Opcode', 'nbns'),
  uint('nbns.flags.rcode', 'Reply code', 'nbns'),
  uint('nbns.count.queries', 'Questions', 'nbns'),
  uint('nbns.count.answers', 'Answer RRs', 'nbns'),
  uint('nbns.count.auth_rr', 'Authority RRs', 'nbns'),
  uint('nbns.count.add_rr', 'Additional RRs', 'nbns'),
  str('nbns.name', 'Name', 'nbns', { label: 'NetBIOS name', align: 'left' }),
  treeOnly(uint('nbns.type', 'Type', 'nbns')),
  treeOnly(uint('nbns.class', 'Class', 'nbns')),
  treeOnly(uint('nbns.ttl', 'Time to live', 'nbns')),
  treeOnly(uint('nbns.data_length', 'Data length', 'nbns')),
  treeOnly(str('nbns.nb_flags', 'Name flags', 'nbns')),
  { abbrev: 'nbns.addr', label: 'Addr', type: 'ipv4', layer: 'nbns' },

  // --- DNS -------------------------------------------------------------------
  uint('dns.id', 'Transaction ID', 'dns'),
  uint('dns.flags', 'Flags', 'dns'),
  bool('dns.flags.response', 'Response', 'dns'),
  uint('dns.flags.opcode', 'Opcode', 'dns'),
  treeOnly(bool('dns.flags.authoritative', 'Authoritative', 'dns')),
  treeOnly(bool('dns.flags.truncated', 'Truncated', 'dns')),
  treeOnly(bool('dns.flags.recdesired', 'Recursion desired', 'dns')),
  uint('dns.flags.rcode', 'Reply code', 'dns'),
  uint('dns.count.queries', 'Questions', 'dns'),
  uint('dns.count.answers', 'Answer RRs', 'dns'),
  str('dns.qry.name', 'Name', 'dns', { label: 'DNS name', align: 'left' }),
  uint('dns.qry.type', 'Type', 'dns'),
  treeOnly(str('dns.resp.name', 'Name', 'dns')),
  treeOnly(uint('dns.resp.type', 'Type', 'dns')),
  treeOnly(uint('dns.resp.ttl', 'Time to live', 'dns')),
  { abbrev: 'dns.a', label: 'Address', type: 'ipv4', layer: 'dns' },
  { abbrev: 'dns.aaaa', label: 'AAAA Address', type: 'ipv6', layer: 'dns' },
  treeOnly(str('dns.cname', 'CNAME', 'dns')),
  treeOnly(str('dns.ns', 'Name Server', 'dns')),
  treeOnly(str('dns.ptr.domain_name', 'Domain Name', 'dns')),
  treeOnly(str('dns.txt', 'TXT', 'dns')),
  treeOnly(uint('dns.srv.port', 'Port', 'dns')),
  treeOnly(str('dns.srv.target', 'Target', 'dns')),
  treeOnly(uint('dns.svcb.svcpriority', 'SvcPriority', 'dns')),
  treeOnly(str('dns.svcb.svcparam.alpn', 'SvcParam alpn', 'dns')),
  treeOnly(uint('dns.rr.udp_payload_size', 'UDP payload size', 'dns')),
  treeOnly(bool('dns.resp.z.do', 'DO bit', 'dns')),
  { abbrev: 'dns.response_to', label: 'Request In', type: 'uint', layer: 'dns', generated: true },
  { abbrev: 'dns.response_in', label: 'Response In', type: 'uint', layer: 'dns', generated: true },

  // --- DHCP ------------------------------------------------------------------
  uint('dhcp.type', 'Message type', 'dhcp'),
  uint('dhcp.id', 'Transaction ID', 'dhcp'),
  uint('dhcp.option.dhcp', 'DHCP Message Type', 'dhcp'),
  str('dhcp.option.hostname', 'Host Name', 'dhcp', { label: 'Hostname', align: 'left' }),
  str('dhcp.option.vendor_class_id', 'Vendor class identifier', 'dhcp'),
  str('dhcp.option.domain_name', 'Domain Name', 'dhcp'),
  str('dhcp.option.request_list_item', 'Parameter Request List', 'dhcp'),
  { abbrev: 'dhcp.option.requested_ip_address', label: 'Requested IP Address', type: 'ipv4', layer: 'dhcp' },
  { abbrev: 'dhcp.option.dhcp_server_id', label: 'DHCP Server Identifier', type: 'ipv4', layer: 'dhcp' },
  str('dhcp.client_id', 'Client identifier', 'dhcp'),
  str('dhcp.fqdn.name', 'Client FQDN', 'dhcp'),
  { abbrev: 'dhcp.hw.mac_addr', label: 'Client MAC address', type: 'mac', layer: 'dhcp' },
  { abbrev: 'dhcp.ip.your', label: 'Your (client) IP address', type: 'ipv4', layer: 'dhcp' },

  // --- the rest of the BOOTP header, and the shape of an option -------------
  //
  // Eleven of these were drawn with the right value and byte range and no
  // name; the rest are rows this dissector had the bytes for and never built.
  // `treeOnly` under the rule in the block above: DHCP is two frames in a
  // browsing capture and every one of these is either a constant given the
  // layer, a decomposition of bytes the bag already holds, or the TLV framing
  // itself - none of it is a column, a colour rule or a replay seed.
  //
  // `dhcp.option.type` is the option row, and it repeats once per option;
  // `dhcp.option.value` is the raw payload the reference hides by default and
  // draws anyway, because an option this build does not decode still has to
  // show its bytes somewhere.
  treeOnly(uint('dhcp.hw.type', 'Hardware type', 'dhcp')),
  treeOnly(uint('dhcp.hw.len', 'Hardware address length', 'dhcp')),
  treeOnly(uint('dhcp.hops', 'Hops', 'dhcp')),
  treeOnly(uint('dhcp.secs', 'Seconds elapsed', 'dhcp')),
  treeOnly(uint('dhcp.flags', 'Bootp flags', 'dhcp')),
  treeOnly(bool('dhcp.flags.bc', 'Broadcast flag', 'dhcp')),
  treeOnly(uint('dhcp.flags.reserved', 'Reserved flags', 'dhcp')),
  treeOnly({ abbrev: 'dhcp.ip.client', label: 'Client IP address', type: 'ipv4', layer: 'dhcp' }),
  treeOnly({ abbrev: 'dhcp.ip.server', label: 'Next server IP address', type: 'ipv4', layer: 'dhcp' }),
  treeOnly({ abbrev: 'dhcp.ip.relay', label: 'Relay agent IP address', type: 'ipv4', layer: 'dhcp' }),
  treeOnly(str('dhcp.hw.addr_padding', 'Client hardware address padding', 'dhcp')),
  treeOnly(str('dhcp.server', 'Server host name', 'dhcp')),
  treeOnly(str('dhcp.file', 'Boot file name', 'dhcp')),
  treeOnly(str('dhcp.cookie', 'Magic cookie', 'dhcp')),
  treeOnly(uint('dhcp.option.type', 'Option', 'dhcp')),
  treeOnly(uint('dhcp.option.length', 'Length', 'dhcp')),
  treeOnly(str('dhcp.option.value', 'Value', 'dhcp')),
  treeOnly(uint('dhcp.option.end', 'Option End', 'dhcp')),
  treeOnly(str('dhcp.option.padding', 'Padding', 'dhcp')),
  treeOnly({ abbrev: 'dhcp.option.subnet_mask', label: 'Subnet Mask', type: 'ipv4', layer: 'dhcp' }),
  treeOnly({ abbrev: 'dhcp.option.router', label: 'Router', type: 'ipv4', layer: 'dhcp' }),
  treeOnly({ abbrev: 'dhcp.option.domain_name_server', label: 'Domain Name Server', type: 'ipv4', layer: 'dhcp' }),
  treeOnly(uint('dhcp.option.ip_address_lease_time', 'IP Address Lease Time', 'dhcp')),
  // RFC 4702's flags byte: who may write this lease's DNS records, and in
  // which encoding the name that follows is written.
  treeOnly(uint('dhcp.fqdn.flags', 'Flags', 'dhcp')),
  treeOnly(uint('dhcp.fqdn.mbz', 'Reserved flags', 'dhcp')),
  treeOnly(bool('dhcp.fqdn.n', 'Server DDNS', 'dhcp')),
  treeOnly(bool('dhcp.fqdn.e', 'Encoding', 'dhcp')),
  treeOnly(bool('dhcp.fqdn.o', 'Server overrides', 'dhcp')),
  treeOnly(bool('dhcp.fqdn.s', 'Server', 'dhcp')),
  treeOnly(uint('dhcp.fqdn.rcode1', 'A-RR result', 'dhcp')),
  treeOnly(uint('dhcp.fqdn.rcode2', 'PTR-RR result', 'dhcp')),
  uint('dhcpv6.msgtype', 'Message type', 'dhcpv6'),
  uint('dhcpv6.xid', 'Transaction ID', 'dhcpv6'),
  str('dhcpv6.duid.bytes', 'DUID', 'dhcpv6'),
  str('dhcpv6.client_domain', 'Client Domain', 'dhcpv6'),

  // --- IPv6 extension headers ------------------------------------------------
  treeOnly(uint('ipv6.fraghdr.offset', 'Fragment Offset', 'ipv6')),
  treeOnly(bool('ipv6.fraghdr.more', 'More Fragments', 'ipv6')),
  treeOnly(str('ipv6.opt.router_alert', 'Router Alert', 'ipv6')),

  // --- Inwire's own ----------------------------------------------------------
  // Wireshark has no single field for "the worst thing any dissector said about
  // this frame" - its expert info is a per-item list, not a frame property. It
  // is one here because a colour rule and a display filter both want to ask the
  // question, and neither can walk a tree.
  str('inwire.expert.category', 'Expert category', 'frame', { label: 'Expert', align: 'left' }),
  // Which content detector claimed a payload no port dispatched. Published so
  // a wrong label can be traced to the rule that produced it rather than
  // guessed at - `inwire.heuristic == "Syslog"` is how you find them all.
  str('inwire.heuristic', 'Matched by heuristic', 'frame', { label: 'Heuristic', align: 'left' }),

  // Which program on this machine opened the socket the frame belongs to.
  //
  // Not on the wire and not derivable from it - it comes from the operating
  // system of the machine the capture was taken on, which is why no other
  // analyzer has it and why these sit on `frame` beside the capture metadata
  // rather than under a protocol. See `services/flowAnnotations.ts`.
  str('inwire.process.name', 'Process', 'frame', { label: 'Process', align: 'left' }),
  uint('inwire.process.pid', 'Process ID', 'frame', { label: 'PID', align: 'right' }),
  str('inwire.process.path', 'Process path', 'frame'),
  // Not "this IS that program" - "this fingerprint has only ever been seen
  // from that program, on this machine". Learned from frames the OS attributed
  // and applied to ones it could not, which is how a hello from ANOTHER
  // machine on the segment gets a name. See dissect/clientFingerprints.ts.
  str('inwire.process.ja4_match', 'Matches process', 'frame', { label: 'JA4 match', align: 'left' }),

  // --- IEEE 1905.1 -----------------------------------------------------------
  uint('ieee1905.message_type', 'Message type', 'ieee1905'),
  uint('ieee1905.message_id', 'Message id', 'ieee1905'),

  // --- IEEE 1905.1a / EasyMesh: the CMDU header and every TLV body ---------
  //
  // This layer was 2 of 97 - the worst in the fixtures - because the TLV run
  // after the 8-byte header was never read at all. All `treeOnly`: a mesh
  // control frame is read by expanding it, and none of this belongs in a
  // column, a colour rule or a replay seed.
  //
  // `ap_extended_metrics.Broadcast_bytes_sent`'s capital B is the reference's
  // own inconsistency with the six counters beside it. Matched, not tidied -
  // `wireshark-abbrevs.ts` holds every name here to `tshark -G fields`.
  treeOnly(uint('ieee1905.message_version', 'Message version', 'ieee1905')),
  treeOnly(uint('ieee1905.message_reserved', 'Message reserved', 'ieee1905')),
  treeOnly(uint('ieee1905.fragment_id', 'Fragment id', 'ieee1905')),
  treeOnly(uint('ieee1905.flags', 'Flags', 'ieee1905')),
  treeOnly(bool('ieee1905.last_fragment', 'Last fragment', 'ieee1905')),
  treeOnly(bool('ieee1905.relay_indicator', 'Relay indicator', 'ieee1905')),

  // The TLV framing: a type, then a length whose top two bits are reserved.
  treeOnly(uint('ieee1905.tlv_type', 'TLV type', 'ieee1905')),
  treeOnly(uint('ieee1905.tlv_length', 'TLV length', 'ieee1905')),
  treeOnly(uint('ieee1905.tlv_length.reserved', 'TLV length reserved', 'ieee1905')),
  treeOnly(uint('ieee1905.tlv_length.length', 'TLV length length', 'ieee1905')),

  // Addresses and media types, which appear in half the TLV types.
  treeOnly({ abbrev: 'ieee1905.1905_al_mac_addr', label: '1905 AL MAC address type', type: 'mac', layer: 'ieee1905' }),
  treeOnly({ abbrev: 'ieee1905.mac_addr', label: 'MAC address type', type: 'mac', layer: 'ieee1905' }),
  treeOnly({ abbrev: 'ieee1905.local_intf.mac_address', label: 'Local interface MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly({ abbrev: 'ieee1905.neighbor_al_mac_addr', label: 'Neighbor MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly({ abbrev: 'ieee1905.responder_al_mac_addr', label: 'Responder MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly({ abbrev: 'ieee1905.receiving_al_mac_addr', label: 'Receiving AL MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.dev_info.media_type', 'Media type', 'ieee1905')),
  treeOnly(uint('ieee1905.media_type.bits_15_to_8', 'Media type bits 15 to 8', 'ieee1905')),
  treeOnly(uint('ieee1905.media_type.bits_7_to_0', 'Media type bits 7 to 0', 'ieee1905')),

  // Device information and the neighbour lists - the topology half.
  treeOnly(uint('ieee1905.dev_info.local_int_cnt', 'Local interface count', 'ieee1905')),
  treeOnly(uint('ieee1905.dev_info.spec_info_len', 'Special info length', 'ieee1905')),
  treeOnly(str('ieee1905.dev_info.spec_info', 'Special info', 'ieee1905')),
  treeOnly(uint('ieee1905.neighbor_flags', 'IEEE1905 neighbor flags', 'ieee1905')),
  treeOnly(bool('ieee1905.bridges', 'IEEE1905 bridges', 'ieee1905')),

  // The link metrics, which is what a mesh actually argues about.
  treeOnly(uint('ieee1905.bridgeFlag', 'IEEE 802.1 bridge flag', 'ieee1905')),
  treeOnly(uint('ieee1905.packetErrors', 'Packet errors', 'ieee1905')),
  treeOnly(uint('ieee1905.transmittedPackets', 'Transmitted packets', 'ieee1905')),
  treeOnly(uint('ieee1905.packets_received', 'Packets received', 'ieee1905')),
  treeOnly(uint('ieee1905.macThroughputCapacity', 'MAC throughput capacity', 'ieee1905')),
  treeOnly(uint('ieee1905.linkAvailability', 'Link availability', 'ieee1905')),
  treeOnly(uint('ieee1905.phyRate', 'Phy rate', 'ieee1905')),
  treeOnly(uint('ieee1905.rssi', 'RSSI', 'ieee1905')),

  treeOnly(str('ieee1905.vendor_specific.oui', 'Vendor specific OUI', 'ieee1905')),
  treeOnly(str('ieee1905.vendor_specific.info', 'Vendor specific information', 'ieee1905')),
  treeOnly(uint('ieee1905.supported_service.service_count', 'Supported service count', 'ieee1905')),
  treeOnly(uint('ieee1905.supported_service.service', 'Supported service', 'ieee1905')),
  treeOnly(uint('ieee1905.multi_ap_version', 'Multi-AP Profile', 'ieee1905')),

  // The operational BSS list, and who is associated to each.
  treeOnly(uint('ieee1905.ap_bss_radio_count', 'AP operational BSS radio count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.ap_radio_identifier', label: 'AP radio identifier', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.ap_bss_intf_count', 'AP operational interface count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.ap_bss_local_intf_addr', label: 'AP operational local interface MAC addr', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.ap_bss_local_intf_ssid_len', 'AP operational BSS local interface SSID len', 'ieee1905')),
  treeOnly(str('ieee1905.ap_bss_local_intf_ssid', 'AP operational BSS local interface SSID', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_client.bss_count', 'Included BSS count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_client.bss', label: 'Associated BSS', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_client.client_count', 'Associated client count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_client.mac_addr', label: 'Associated client MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_client.time_since', 'Time since last association', 'ieee1905')),

  // AP metrics: how busy the radio is and what it thinks it can still carry.
  treeOnly({ abbrev: 'ieee1905.ap_metrics.bssid', label: 'Multi-AP agent BSSID', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.ap_metrics.channel_util', 'Channel utilization', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_metrics.sta_count', 'BSS STA count', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_metrics.flags', 'Estimated Service Parameters Flags', 'ieee1905')),
  treeOnly(bool('ieee1905.ap_metrics.include_ac_eq_be_params', 'Estimated Service Parameters for AC=BE', 'ieee1905')),
  treeOnly(bool('ieee1905.ap_metrics.include_ac_eq_bk_params', 'Estimated Service Parameters for AC=BK', 'ieee1905')),
  treeOnly(bool('ieee1905.ap_metrics.include_ac_eq_vo_params', 'Estimated Service Parameters for AC=VO', 'ieee1905')),
  treeOnly(bool('ieee1905.ap_metrics.include_ac_eq_vi_params', 'Estimated Service Parameters for AC=VI', 'ieee1905')),
  treeOnly(str('ieee1905.ap_metrics.est_param_be', 'Estimated service parameters AC=BE', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.ap_extended_metrics.bssid', label: 'BSSID', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.ap_extended_metrics.unicast_bytes_sent', 'UnicastBytesSent', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_extended_metrics.unicast_bytes_received', 'UnicastBytesReceived', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_extended_metrics.multicast_bytes_sent', 'MulticastBytesSent', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_extended_metrics.multicast_bytes_received', 'MulticastBytesReceived', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_extended_metrics.Broadcast_bytes_sent', 'BroadcastBytesSent', 'ieee1905')),
  treeOnly(uint('ieee1905.ap_extended_metrics.broadcast_bytes_received', 'BroadcastBytesReceived', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.radio_metrics.radio_id', label: 'Radio unique ID', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.radio_metrics.noise', 'Noise', 'ieee1905')),
  treeOnly(uint('ieee1905.radio_metrics.transmit', 'Transmit', 'ieee1905')),
  treeOnly(uint('ieee1905.radio_metrics.receive_self', 'ReceiveSelf', 'ieee1905')),
  treeOnly(uint('ieee1905.radio_metrics.receive_other', 'ReceiveOther', 'ieee1905')),

  // Per-station metrics: the mesh's own view of every client on it.
  treeOnly({ abbrev: 'ieee1905.assoc_sta_link_metrics.mac_addr', label: 'MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_sta_link_metrics.bssid_count', 'Number of BSSIDs for STA', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_sta_link_metrics.bssid', label: 'STA BSSID', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_sta_link_metrics.time_delta', 'Measurement time delta', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_link_metrics.down_rate', 'Downlink data rate', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_link_metrics.up_rate', 'Uplink data rate', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_link_metrics.rcpi', 'Measured uplink RCPI for STA', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_sta_extended_link_metrics.mac_addr', label: 'Associated STA MAC Address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_sta_extended_link_metrics.count', 'BSSID count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_sta_extended_link_metrics.bssid', label: 'BSSID', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_sta_extended_link_metrics.lddlr', 'Last Data Downlink Rate', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_extended_link_metrics.ldulr', 'Last Data Uplink Rate', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_extended_link_metrics.ur', 'Utilization Receive', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_extended_link_metrics.ut', 'Utilization Transmit', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_sta_traffic_stats.mac_addr', label: 'Associated STA MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.bytes_sent', 'Bytes Sent', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.bytes_rcvd', 'Bytes Received', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.packets_sent', 'Packets Sent', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.packets_rcvd', 'Packets Received', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.tx_pkt_errs', 'Tx Packet Errors', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.rx_packet_errs', 'Rx Packet Errors', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_sta_traffic_stats.retrans_count', 'Retransmission Count', 'ieee1905')),
  treeOnly({ abbrev: 'ieee1905.assoc_wf6_sta_status_report.mac_addr', label: 'MAC address', type: 'mac', layer: 'ieee1905' }),
  treeOnly(uint('ieee1905.assoc_wf6_sta_status_report.tid_count', 'Number of Wi-Fi 6 TIDs', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_wf6_sta_status_report.tid', 'TID', 'ieee1905')),
  treeOnly(uint('ieee1905.assoc_wf6_sta_status_report.queue_size', 'Queue Size', 'ieee1905')),
];

export const FIELD_BY_ABBREV: ReadonlyMap<string, FieldDef> = new Map(FIELDS.map((f) => [f.abbrev, f]));

/** Every filter name a dissector publishes, for the engine's typo check. */
export const FIELD_ABBREVS: ReadonlySet<string> = new Set(FIELDS.map((f) => f.abbrev));

export function fieldDef(abbrev: string): FieldDef | undefined {
  return FIELD_BY_ABBREV.get(abbrev);
}

/** The fields "Apply as column" offers, in registry order. */
export function columnFields(): readonly FieldDef[] {
  return FIELDS.filter((f) => f.column !== undefined);
}
