/**
 * What an IP protocol number is called, in the tree: IPv4's Protocol, IPv6's
 * Next Header, and every IPv6 extension header's Next Header.
 *
 * **The names are the reference's own**, taken from `tshark -G values` for
 * `ip.proto` (Wireshark 4.6.8), so a row reads `ICMP (1)` or `Generic Routing
 * Encapsulation (47)` exactly as Wireshark draws it. The IPv4 row used to name
 * TCP and UDP and print every other protocol as a bare number, so an ICMP
 * frame's IPv4 header said `Protocol: 1` - the first thing a network engineer
 * looks at, and the one row that could not be read without a table to hand.
 *
 * Not the Protocol column's names. That column carries the short labels in
 * `networkLayer.ts`'s `IP_PROTOCOL_NAMES` ("GRE", "ESP"), because Wireshark's
 * column does; the tree spells them out. `scripts/parity/header-names.ts`
 * builds a frame for every number and holds each row to tshark's.
 */

/** IANA protocol numbers, named as `ip.proto`'s value table names them. */
const IP_PROTOCOL_VALUE_NAMES: Record<number, string> = {
  0: 'IPv6 Hop-by-Hop Option', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IPIP', 5: 'Stream', 6: 'TCP',
  7: 'CBT', 8: 'EGP', 9: 'IGRP', 10: 'BBN RCC', 11: 'Network Voice', 12: 'PUP', 13: 'ARGUS',
  14: 'EMCON', 15: 'XNET', 16: 'CHAOS', 17: 'UDP', 18: 'Multiplex', 19: 'DCN Measurement',
  20: 'Host Monitoring', 21: 'Packet radio', 22: 'IDP', 23: 'Trunk-1', 24: 'Trunk-2', 25: 'Leaf-1',
  26: 'Leaf-2', 27: 'Reliable Data', 28: 'IRT', 29: 'ISO TP4', 30: 'Bulk Data', 31: 'MFE NSP',
  32: 'Merit Internodal', 33: 'Datagram Congestion Control Protocol', 34: '3rd Party Connect',
  35: 'Inter-Domain Policy Routing Protocol', 36: 'XTP', 37: 'Datagram delivery',
  38: 'Control Message', 39: 'TP++', 40: 'IL', 41: 'IPv6', 42: 'Source demand routing',
  43: 'Routing Header for IPv6', 44: 'Fragment Header for IPv6',
  45: 'Inter-Domain Routing Protocol', 46: 'Reservation Protocol',
  47: 'Generic Routing Encapsulation', 48: 'Dynamic source routing', 49: 'BNA',
  50: 'Encap Security Payload', 51: 'Authentication Header', 52: 'INSLP', 53: 'SWIPE',
  54: 'NBMA ARP', 55: 'IP Mobility', 56: 'TLSP Kryptonet', 57: 'SKIP', 58: 'ICMPv6',
  59: 'No Next Header for IPv6', 60: 'Destination Options for IPv6',
  61: 'any host internal protocol', 62: 'Mobile IPv6 (old)', 63: 'any local network',
  64: 'SATNET EXPAK', 65: 'Kryptolan', 66: 'Remote Virtual Disk', 67: 'IPPC',
  68: 'any distributed file system', 69: 'SATNET Monitoring', 70: 'VISA', 71: 'IPCV', 72: 'CPNX',
  73: 'CPHB', 74: 'Wang Span', 75: 'Packet Video', 76: 'Backroom SATNET Mon',
  77: 'Sun ND Protocol', 78: 'Wideband Mon', 79: 'Wideband Expak', 80: 'ISO Internet Protocol',
  81: 'VMTP', 82: 'Secure VMTP', 83: 'VINES', 84: 'TTP', 85: 'NSFNET IGP',
  86: 'Dissimilar Gateway', 87: 'TCF', 88: 'EIGRP', 89: 'OSPF IGP', 90: 'Sprite RPC',
  91: 'Locus ARP', 92: 'Multicast Transport', 93: 'AX.25 Frames', 94: 'IP in IP', 95: 'MICP',
  96: 'Semaphore', 97: 'Ether in IP', 98: 'ENCAP', 99: 'any private encryption scheme',
  100: 'GMTP', 101: 'Ipsilon Flow', 102: 'PNNI over IP', 103: 'PIM', 104: 'ARIS', 105: 'SCPS',
  106: 'QNX', 107: 'Active Networks', 108: 'IPComp', 109: 'Sitara Networks', 110: 'Compaq Peer',
  111: 'IPX IN IP', 112: 'VRRP', 113: 'PGM', 114: 'any 0-hop protocol', 115: 'Layer 2 Tunneling',
  116: 'DDX', 117: 'IATP', 118: 'STP', 119: 'SpectraLink', 120: 'UTI', 121: 'SMP', 122: 'SM',
  123: 'PTP', 124: 'ISIS over IP', 125: 'FIRE', 126: 'CRTP', 127: 'CRUDP', 128: 'SSCOPMCE',
  129: 'IPLT', 130: 'Secure Packet', 131: 'PIPE', 132: 'SCTP', 133: 'Fibre Channel',
  134: 'RSVP E2EI', 135: 'Mobile IPv6', 136: 'UDPLite', 137: 'MPLS in IP', 138: 'MANET',
  139: 'HIP', 140: 'Shim6 header', 141: 'WESP', 142: 'ROHC', 143: 'Ethernet', 144: 'AGGFRAG',
  145: 'NSH', 146: 'Homa', 147: 'Bit-stream Emulation', 148: 'Unassigned', 149: 'Unassigned',
  150: 'Unassigned', 151: 'Unassigned', 152: 'Unassigned', 153: 'Unassigned', 154: 'Unassigned',
  155: 'Unassigned', 156: 'Unassigned', 157: 'Unassigned', 158: 'Unassigned', 159: 'Unassigned',
  160: 'Unassigned', 161: 'Unassigned', 162: 'Unassigned', 163: 'Unassigned', 164: 'Unassigned',
  165: 'Unassigned', 166: 'Unassigned', 167: 'Unassigned', 168: 'Unassigned', 169: 'Unassigned',
  170: 'Unassigned', 171: 'Unassigned', 172: 'Unassigned', 173: 'AX/4000 Testframe',
  174: 'Unassigned', 175: 'Unassigned', 176: 'Unassigned', 177: 'Unassigned', 178: 'Unassigned',
  179: 'Unassigned', 180: 'Unassigned', 181: 'Unassigned', 182: 'Unassigned', 183: 'Unassigned',
  184: 'Unassigned', 185: 'Unassigned', 186: 'Unassigned', 187: 'Unassigned', 188: 'Unassigned',
  189: 'Unassigned', 190: 'Unassigned', 191: 'Unassigned', 192: 'Unassigned', 193: 'Unassigned',
  194: 'Unassigned', 195: 'Unassigned', 196: 'Unassigned', 197: 'Unassigned', 198: 'Unassigned',
  199: 'Unassigned', 200: 'Unassigned', 201: 'Unassigned', 202: 'Unassigned', 203: 'Unassigned',
  204: 'Unassigned', 205: 'Unassigned', 206: 'Unassigned', 207: 'Unassigned', 208: 'Unassigned',
  209: 'Unassigned', 210: 'Unassigned', 211: 'Unassigned', 212: 'Unassigned', 213: 'Unassigned',
  214: 'Unassigned', 215: 'Unassigned', 216: 'Unassigned', 217: 'Unassigned', 218: 'Unassigned',
  219: 'Unassigned', 220: 'Unassigned', 221: 'Unassigned', 222: 'Unassigned', 223: 'Unassigned',
  224: 'Novell NCS Heartbeat',
};

/** `ICMP (1)`, `Generic Routing Encapsulation (47)`; `Unknown (n)` past the table. */
export function describeIpProtocol(n: number): string {
  return `${IP_PROTOCOL_VALUE_NAMES[n] ?? 'Unknown'} (${n})`;
}
