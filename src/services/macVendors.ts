/**
 * MAC address name resolution, matching what Wireshark shows in the Source and
 * Destination columns for frames that have no network-layer address (ARP, STP,
 * and other pure-L2 traffic).
 *
 * Two independent mechanisms, in priority order:
 *
 *   1. Reserved group addresses - "Broadcast", "Nearest-Customer-Bridge",
 *      "IPv6mcast_ff:8c:e5:bf". These are protocol constants assigned by IEEE
 *      802.1/IANA, not vendor data, so they resolve for everyone.
 *   2. OUI (Organizationally Unique Identifier) lookup - the first 3 bytes of a
 *      MAC identify the manufacturer that was assigned that block.
 *
 * The OUI table below is a hand-curated subset of IEEE's public assignment
 * data, independently compiled (not copied from any third-party project's
 * manuf database). Short names follow the conventional <=12-character
 * abbreviation style used across packet analyzers so the column stays narrow.
 * Run `npx tsx scripts/gen-oui.ts` to regenerate it with full coverage from
 * IEEE's published registry - see that script for why the table is partial.
 */

/**
 * Exact group/reserved addresses. IEEE 802.1D reserves 01:80:c2:00:00:00-0f
 * for bridge control traffic, and each address in that range has its own name
 * because they are forwarded (or not) differently by bridges.
 */
const RESERVED_MAC_NAMES: Record<string, string> = {
  'ff:ff:ff:ff:ff:ff': 'Broadcast',
  '01:80:c2:00:00:00': 'Nearest-Customer-Bridge',
  '01:80:c2:00:00:01': 'Pause_flow_control',
  '01:80:c2:00:00:02': 'Slow-Protocols',
  // These two were the wrong way round. 0e is the Nearest Bridge group - the
  // address essentially every LLDP agent sends to - and 03 is the non-TPMR
  // group, per IEEE 802.1AB Table 7-1 and `tshark -e eth.dst_resolved`, which
  // was used to check every entry in this block rather than just these two.
  '01:80:c2:00:00:03': 'Nearest-non-TPMR-Bridge',
  '01:80:c2:00:00:0d': 'Provider-Bridge-MVRP',
  '01:80:c2:00:00:0e': 'Nearest-Bridge',
  '01:00:0c:cc:cc:cc': 'CDP/VTP/DTP/PAgP/UDLD',
  '01:00:0c:cc:cc:cd': 'PVST+',
};

/**
 * Multicast ranges whose *prefix* names the address family and whose remaining
 * bytes carry the group. IPv6 multicast (33:33) keeps 4 bytes because the
 * solicited-node group needs them; IPv4 multicast (01:00:5e) keeps 3, since
 * only the low 23 bits of the group address are mapped into the MAC.
 */
const MULTICAST_PREFIXES: { prefix: string; label: string; keepBytes: number }[] = [
  { prefix: '33:33', label: 'IPv6mcast', keepBytes: 4 },
  { prefix: '01:00:5e', label: 'IPv4mcast', keepBytes: 3 },
];

const OUI_VENDOR_MAP: Record<string, string> = {
  // Vendors observed in real captures on this project
  '44:15:24': 'SagemcomBroa',
  '04:7C:16': 'MicroStarINT',
  '74:56:3C': 'GigaByteTech',
  // Cloud / virtualization
  '00:50:56': 'VMware',
  '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',
  '08:00:27': 'PCSSystemtec',
  '52:54:00': 'RealtekU',
  '00:15:5D': 'Microsoft',
  '00:16:3E': 'Xensource',
  '02:42:AC': 'Docker',
  // Silicon / NIC vendors
  '00:1B:21': 'Intel',
  '00:1C:C0': 'Intel',
  '3C:97:0E': 'Intel',
  '8C:16:45': 'IntelCorpora',
  '00:E0:4C': 'RealtekSemic',
  '00:1F:29': 'HewlettPacka',
  '00:26:55': 'HewlettPacka',
  // Consumer OEMs
  '00:1B:63': 'Apple',
  '3C:07:54': 'Apple',
  'A4:83:E7': 'Apple',
  'F0:18:98': 'Apple',
  'AC:BC:32': 'Apple',
  '00:1A:11': 'Google',
  '3C:5A:B4': 'Google',
  'F4:F5:D8': 'Google',
  '00:1D:0F': 'SamsungElect',
  'BC:14:85': 'SamsungElect',
  '00:16:6F': 'Sony',
  '00:1A:80': 'Sony',
  'DC:A6:32': 'RaspberryPiT',
  'B8:27:EB': 'RaspberryPiF',
  'E4:5F:01': 'RaspberryPiT',
  // Networking gear
  '00:1A:64': 'IbmCorp',
  '00:0F:34': 'Cisco',
  '00:1E:13': 'Cisco',
  '00:50:BA': 'DLink',
  'C8:D3:A3': 'DLink',
  '00:14:78': 'TpLinkTechno',
  '50:C7:BF': 'TpLinkTechno',
  'AC:84:C6': 'TpLinkTechno',
  '00:1F:33': 'NetgearInc',
  'A0:40:A0': 'NetgearInc',
  '3C:37:86': 'NetgearInc',
  '00:E0:FC': 'HuaweiTechno',
  '00:1E:C2': 'Dell',
  '18:03:73': 'Dell',
  'B0:83:FE': 'Dell',
  '00:1D:D8': 'Microsoft',
  '00:03:FF': 'Microsoft',
  '00:0D:3A': 'Microsoft',
};

/**
 * Splits a lowercase "aa:bb:cc:dd:ee:ff" into its octet strings.
 */
function octets(mac: string): string[] {
  return mac.split(':');
}

/**
 * Resolves a MAC to the short display name Wireshark shows in the packet-list
 * address columns: "SagemcomBroa_5d:cc:62", "Broadcast",
 * "IPv6mcast_ff:8c:e5:bf". Falls back to the raw MAC when the OUI is unknown,
 * which is also what Wireshark does.
 *
 * Deliberately distinct from resolveMacVendor() below: the columns want the
 * bare name, while the detail tree wants the name *and* the literal address.
 */
export function resolveMacName(mac: string): string {
  const lower = mac.toLowerCase();

  const reserved = RESERVED_MAC_NAMES[lower];
  if (reserved) return reserved;

  for (const { prefix, label, keepBytes } of MULTICAST_PREFIXES) {
    if (lower.startsWith(`${prefix}:`)) {
      return `${label}_${octets(lower).slice(6 - keepBytes).join(':')}`;
    }
  }

  const vendor = OUI_VENDOR_MAP[lower.slice(0, 8).toUpperCase()];
  if (!vendor) return lower;

  return `${vendor}_${octets(lower).slice(3).join(':')}`;
}

/**
 * Formats a MAC address with its resolved name for the protocol detail tree,
 * Wireshark-style ("SagemcomBroa_5d:cc:62 (44:15:24:5d:cc:62)"), falling back
 * to the raw MAC unchanged when nothing resolves.
 */
export function resolveMacVendor(mac: string): string {
  const name = resolveMacName(mac);
  return name === mac.toLowerCase() ? mac : `${name} (${mac.toLowerCase()})`;
}
