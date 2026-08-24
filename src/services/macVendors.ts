/**
 * A small, hand-curated subset of IEEE's public OUI (Organizationally Unique
 * Identifier) registry - the first 3 bytes of a MAC address map to the
 * manufacturer that was assigned that block. This is independently compiled
 * from IEEE's public assignment data (not copied from any third-party
 * project's manuf database) and intentionally covers only common,
 * easily-recognized vendors rather than IEEE's full multi-thousand-entry
 * list - full coverage isn't worth the maintenance burden for a UI nicety.
 */
const OUI_VENDOR_MAP: Record<string, string> = {
  '00:1A:11': 'Google',
  '3C:5A:B4': 'Google',
  'F4:F5:D8': 'Google',
  '00:50:56': 'VMware',
  '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',
  '08:00:27': 'Oracle_VirtualBox',
  '52:54:00': 'QEMU_KVM',
  '00:15:5D': 'Microsoft_Hyper-V',
  '00:1B:63': 'Apple',
  '3C:07:54': 'Apple',
  'A4:83:E7': 'Apple',
  'F0:18:98': 'Apple',
  'DC:A6:32': 'Raspberry_Pi_Foundation',
  'B8:27:EB': 'Raspberry_Pi_Foundation',
  'E4:5F:01': 'Raspberry_Pi_Foundation',
  '00:1D:D8': 'Microsoft',
  '00:03:FF': 'Microsoft',
  '00:0D:3A': 'Microsoft',
  '00:1B:21': 'Intel',
  '00:1C:C0': 'Intel',
  '3C:97:0E': 'Intel',
  '00:1E:C2': 'Dell',
  '18:03:73': 'Dell',
  'B0:83:FE': 'Dell',
  '00:1A:64': 'Cisco',
  '00:0F:34': 'Cisco',
  '00:50:BA': 'D-Link',
  'C8:D3:A3': 'D-Link',
  '00:14:78': 'TP-Link',
  '50:C7:BF': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  '00:1F:33': 'Netgear',
  'A0:40:A0': 'Netgear',
  '3C:37:86': 'Huawei',
  '00:E0:FC': 'Huawei',
  '00:1D:0F': 'Samsung',
  'BC:14:85': 'Samsung',
  '00:16:6F': 'Sony',
  '00:1A:80': 'Sony',
};

/**
 * Formats a MAC address with its resolved vendor name, Wireshark-style
 * ("Vendor_xx:xx:xx (aa:bb:cc:dd:ee:ff)"), falling back to the raw MAC
 * unchanged when the OUI isn't in the table.
 */
export function resolveMacVendor(mac: string): string {
  const oui = mac.slice(0, 8).toUpperCase();
  const vendor = OUI_VENDOR_MAP[oui];
  if (!vendor) return mac;
  return `${vendor}_${mac.slice(9).toUpperCase()} (${mac})`;
}
