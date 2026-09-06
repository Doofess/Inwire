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
  'frame', 'eth', 'vlan', 'llc', 'sll', 'null', 'arp', 'stp', 'lldp', 'ieee1905',
  'ip', 'ipv6', 'icmp', 'icmpv6', 'igmp', 'tcp', 'udp',
  'dns', 'nbns', 'tls', 'quic', 'ssdp', 'dhcp', 'dhcpv6', 'ntp', 'stun',
  'syslog', 'radius', 'snmp', 'http', 'http2', 'http3',
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

export const FIELDS: readonly FieldDef[] = [
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
  str('ip.reassembled', 'Reassembled IPv4 fragments', 'ip'),
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
  uint('tcp.window_size', 'Calculated window size', 'tcp', { label: 'Window', align: 'right' }),
  uint('tcp.len', 'TCP Segment Len', 'tcp', { label: 'TCP len', align: 'right' }),
  uint('tcp.seq', 'Sequence Number', 'tcp'),
  uint('tcp.seq_raw', 'Sequence Number (raw)', 'tcp'),
  uint('tcp.ack', 'Acknowledgment Number', 'tcp'),
  uint('tcp.ack_raw', 'Acknowledgment Number (raw)', 'tcp'),
  uint('tcp.checksum', 'Checksum', 'tcp'),
  str('tcp.checksum.status', 'Checksum Status', 'tcp'),
  uint('tcp.options.mss', 'MSS Value', 'tcp'),
  uint('tcp.options.wscale.shift', 'Window Scale Shift', 'tcp'),
  bool('tcp.options.sack_perm', 'SACK Permitted', 'tcp'),
  uint('tcp.options.timestamp.tsval', 'Timestamp value', 'tcp'),
  { abbrev: 'tcp.analysis.ack_rtt', label: 'The RTT to ACK the segment was', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.initial_rtt', label: 'iRTT', type: 'time', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.bytes_in_flight', label: 'Bytes in flight', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.duplicate_ack_num', label: 'Duplicate ACK #', type: 'uint', layer: 'tcp', generated: true },
  { abbrev: 'tcp.analysis.duplicate_ack_frame', label: 'Duplicate to the ACK in frame', type: 'uint', layer: 'tcp', generated: true },
  uint('udp.srcport', 'Source Port', 'udp', { label: 'Src port', align: 'right' }),
  uint('udp.dstport', 'Destination Port', 'udp', { label: 'Dst port', align: 'right' }),
  uint('udp.length', 'Length', 'udp'),
  uint('udp.checksum', 'Checksum', 'udp'),
  str('udp.checksum.status', 'Checksum Status', 'udp'),

  // --- ICMP ------------------------------------------------------------------
  uint('icmp.type', 'Type', 'icmp'),
  uint('icmp.code', 'Code', 'icmp'),
  uint('icmpv6.type', 'Type', 'icmpv6'),
  uint('icmpv6.code', 'Code', 'icmpv6'),
  // Router Advertisement. How a passive observer learns an IPv6 network's
  // shape - the prefix hosts autoconfigure from, the resolvers they were
  // handed, and whether they were also told to use DHCPv6 - none of which is
  // recorded anywhere on the machine as having come from the router.
  uint('icmpv6.nd.ra.cur_hop_limit', 'Cur hop limit', 'icmpv6'),
  uint('icmpv6.nd.ra.flag.m', 'Managed address configuration', 'icmpv6'),
  uint('icmpv6.nd.ra.flag.o', 'Other configuration', 'icmpv6'),
  uint('icmpv6.nd.ra.router_lifetime', 'Router lifetime', 'icmpv6'),
  str('icmpv6.opt.prefix', 'Prefix', 'icmpv6'),
  uint('icmpv6.opt.prefix.valid_lifetime', 'Prefix valid lifetime', 'icmpv6'),
  uint('icmpv6.opt.prefix.preferred_lifetime', 'Prefix preferred lifetime', 'icmpv6'),
  str('icmpv6.opt.rdnss', 'Recursive DNS server', 'icmpv6'),

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
  str('lldp.tlv.system.cap', 'Capabilities', 'lldp'),
  str('lldp.mgn.addr', 'Management Address', 'lldp'),

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
  uint('http3.stream_id', 'Stream ID', 'http3'),
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
  str('snmp.value', 'Value', 'snmp'),
  str('snmp.enterprise', 'Enterprise', 'snmp'),

  // --- RADIUS ----------------------------------------------------------------
  uint('radius.code', 'Code', 'radius'),
  uint('radius.id', 'Packet identifier', 'radius'),
  uint('radius.length', 'Length', 'radius'),
  { abbrev: 'radius.authenticator', label: 'Authenticator', type: 'bytes', layer: 'radius' },
  str('radius.username', 'User-Name', 'radius', { label: 'RADIUS user', align: 'left' }),
  uint('radius.avp.type', 'AVP Type', 'radius'),
  uint('radius.avp.length', 'AVP Length', 'radius'),

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
  uint('nbns.type', 'Type', 'nbns'),
  uint('nbns.class', 'Class', 'nbns'),
  uint('nbns.ttl', 'Time to live', 'nbns'),
  uint('nbns.data_length', 'Data length', 'nbns'),
  str('nbns.nb_flags', 'Name flags', 'nbns'),
  { abbrev: 'nbns.addr', label: 'Addr', type: 'ipv4', layer: 'nbns' },

  // --- DNS -------------------------------------------------------------------
  uint('dns.id', 'Transaction ID', 'dns'),
  uint('dns.flags', 'Flags', 'dns'),
  bool('dns.flags.response', 'Response', 'dns'),
  uint('dns.flags.opcode', 'Opcode', 'dns'),
  bool('dns.flags.authoritative', 'Authoritative', 'dns'),
  bool('dns.flags.truncated', 'Truncated', 'dns'),
  bool('dns.flags.recdesired', 'Recursion desired', 'dns'),
  uint('dns.flags.rcode', 'Reply code', 'dns'),
  uint('dns.count.queries', 'Questions', 'dns'),
  uint('dns.count.answers', 'Answer RRs', 'dns'),
  str('dns.qry.name', 'Name', 'dns', { label: 'DNS name', align: 'left' }),
  uint('dns.qry.type', 'Type', 'dns'),
  str('dns.resp.name', 'Name', 'dns'),
  uint('dns.resp.type', 'Type', 'dns'),
  uint('dns.resp.ttl', 'Time to live', 'dns'),
  { abbrev: 'dns.a', label: 'Address', type: 'ipv4', layer: 'dns' },
  { abbrev: 'dns.aaaa', label: 'AAAA Address', type: 'ipv6', layer: 'dns' },
  str('dns.cname', 'CNAME', 'dns'),
  str('dns.ns', 'Name Server', 'dns'),
  str('dns.ptr.domain_name', 'Domain Name', 'dns'),
  str('dns.txt', 'TXT', 'dns'),
  uint('dns.srv.port', 'Port', 'dns'),
  str('dns.srv.target', 'Target', 'dns'),
  uint('dns.svcb.priority', 'SvcPriority', 'dns'),
  str('dns.svcb.alpn', 'SvcParam alpn', 'dns'),
  uint('dns.rr.udp_payload_size', 'UDP payload size', 'dns'),
  bool('dns.resp.z.do', 'DO bit', 'dns'),
  { abbrev: 'dns.response_to', label: 'Request In', type: 'uint', layer: 'dns', generated: true },
  { abbrev: 'dns.response_in', label: 'Response In', type: 'uint', layer: 'dns', generated: true },

  // --- DHCP ------------------------------------------------------------------
  uint('dhcp.type', 'Message type', 'dhcp'),
  uint('dhcp.id', 'Transaction ID', 'dhcp'),
  uint('dhcp.option.dhcp', 'DHCP Message Type', 'dhcp'),
  str('dhcp.option.hostname', 'Host Name', 'dhcp', { label: 'Hostname', align: 'left' }),
  str('dhcp.option.vendor_class_id', 'Vendor class identifier', 'dhcp'),
  str('dhcp.option.domain_name', 'Domain Name', 'dhcp'),
  str('dhcp.option.request_list', 'Parameter Request List', 'dhcp'),
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
  uint('ipv6.fragment.offset', 'Fragment Offset', 'ipv6'),
  bool('ipv6.fragment.more', 'More Fragments', 'ipv6'),
  str('ipv6.opt.router_alert', 'Router Alert', 'ipv6'),

  // --- Inwire's own ----------------------------------------------------------
  // Wireshark has no single field for "the worst thing any dissector said about
  // this frame" - its expert info is a per-item list, not a frame property. It
  // is one here because a colour rule and a display filter both want to ask the
  // question, and neither can walk a tree.
  str('inwire.expert.category', 'Expert category', 'frame', { label: 'Expert', align: 'left' }),

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
  uint('ieee1905.message.type', 'Message type', 'ieee1905'),
  uint('ieee1905.message.id', 'Message id', 'ieee1905'),
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
