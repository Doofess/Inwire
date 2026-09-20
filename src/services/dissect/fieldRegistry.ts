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
  // IPv6 extension headers are their own filter tokens, as in Wireshark:
  // `ipv6.hopopts`, `ipv6.fragment`. They appear in frameProtocols rather
  // than as field prefixes, so they own no fields of their own.
  'ipv6.hopopts', 'ipv6.dstopts', 'ipv6.routing', 'ipv6.fragment', 'ipv6.ext', 'ah',
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

  // --- TLS -------------------------------------------------------------------
  uint('tls.record.content_type', 'Content Type', 'tls'),
  uint('tls.record.version', 'Version', 'tls'),
  uint('tls.record.length', 'Length', 'tls'),
  uint('tls.handshake.type', 'Handshake Type', 'tls'),
  uint('tls.handshake.version', 'Version', 'tls'),
  uint('tls.handshake.ciphersuite', 'Cipher Suite', 'tls'),
  str('tls.handshake.extensions_server_name', 'Server Name', 'tls', { label: 'SNI', align: 'left' }),
  str('tls.handshake.extensions_alpn_str', 'ALPN Next Protocol', 'tls', { label: 'ALPN', align: 'left' }),
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
  bool('tls.reassembled', 'Reassembled record', 'tls'),
  bool('inwire.tls.decrypted', 'Decrypted with a key log secret', 'tls'),

  // --- HTTP ------------------------------------------------------------------
  // Cleartext, and the plaintext of a TLS conversation a key log opened - the
  // same dissector reads both, so one set of names covers both.
  str('http.request.method', 'Request Method', 'http', { label: 'Method', align: 'left' }),
  str('http.request.uri', 'Request URI', 'http', { label: 'URI', align: 'left' }),
  str('http.host', 'Host', 'http'),
  str('http.user_agent', 'User-Agent', 'http'),
  uint('http.response.code', 'Status Code', 'http', { label: 'Status', align: 'right' }),
  str('http.content_type', 'Content-Type', 'http'),

  // --- HTTP/2 ----------------------------------------------------------------
  uint('http2.type', 'Type', 'http2'),
  uint('http2.streamid', 'Stream Identifier', 'http2'),
  str('http2.headers.method', 'Method', 'http2', { label: 'Method', align: 'left' }),
  str('http2.headers.path', 'Path', 'http2', { label: 'Path', align: 'left' }),
  str('http2.headers.authority', 'Authority', 'http2'),
  uint('http2.headers.status', 'Status', 'http2', { label: 'Status', align: 'right' }),
  str('http2.headers.user_agent', 'User-Agent', 'http2'),
  str('http2.headers.content_type', 'Content-Type', 'http2'),

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
