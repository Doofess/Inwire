/**
 * How each surveyed exporter is pointed at a collector, in its vendor's own words (Task 10).
 *
 * Every line is taken from the page cited beside it, read on `readOn`; a page that could not be read
 * gives no lines rather than guessed ones. `{ADDRESS}` and `{PORT}` are where Inwire listens;
 * `{INTERFACE}`, `{RATE}` and `{SOURCE_ADDRESS}` are the reader's to fill. Pure data, beside the
 * component, so `scripts/monitoring/sheet-source.ts` can hold it under plain tsx.
 */

export interface SnippetSource { title: string; url: string }

export interface OnboardingSnippet {
  id: string;
  /** The survey's vendor, as `docs/monitoring-v5-measurements.md` names it. */
  vendor: string;
  product: string;
  /** What it sends; "NetFlow" when the pages read do not name a version. */
  protocol: 'NetFlow v5' | 'NetFlow v9' | 'IPFIX' | 'NetFlow';
  /** `cli`: commands to type; `gui`: steps to follow. */
  kind: 'cli' | 'gui';
  lines: string[];
  sources: SnippetSource[];
  readOn: string;
  /** False when the vendor's page refused to be read, so the survey's row is unverified. */
  verified: boolean;
  notes?: string[];
}

export const SNIPPET_CAVEAT = 'From vendor documentation; not tested on this hardware.';
export const UNVERIFIED_CAVEAT = 'Unverified: the vendor’s page refused to be read, so no lines are shown rather than guessed ones.';

const READ_ON = '2026-10-23';

const FILL: Record<string, string> = {
  '{INTERFACE}': '<interface>',
  '{RATE}': '<sampling rate>',
  '{SOURCE_ADDRESS}': '<this device’s address>',
};

/** The snippet's lines with the listener's address and port in, and the reader's own values marked. */
export function fillSnippet(s: OnboardingSnippet, address: string, port: number): string {
  if (s.lines.length === 0) return '';
  return s.lines.join('\n')
    .replaceAll('{ADDRESS}', address)
    .replaceAll('{PORT}', String(port))
    .replace(/\{[A-Z_]+\}/g, (m) => FILL[m] ?? m);
}

export function snippetLabel(s: OnboardingSnippet): string {
  return `${s.vendor} ${s.product} (${s.protocol})`;
}

export const ONBOARDING_SNIPPETS: OnboardingSnippet[] = [
  {
    id: 'cisco-fnf',
    vendor: 'Cisco',
    product: 'IOS XE Flexible NetFlow',
    protocol: 'NetFlow v9',
    kind: 'cli',
    lines: [
      'flow exporter INWIRE',
      ' destination {ADDRESS}',
      ' transport udp {PORT}',
      ' export-protocol netflow-v9',
      'flow monitor INWIRE',
      ' record netflow ipv4 original-input',
      ' exporter INWIRE',
      'interface {INTERFACE}',
      ' ip flow monitor INWIRE input',
    ],
    sources: [
      { title: 'Cisco IOS XE 17 Flexible NetFlow guide', url: 'https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fnf-fnetflow.html' },
      { title: 'Cisco Flexible NetFlow command reference', url: 'https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/command/fnf-cr-book.pdf' },
    ],
    readOn: READ_ON,
    verified: true,
    notes: [
      'Flow exporters use UDP port 9995 unless told otherwise, so the transport line matters.',
      'Apply the monitor to every interface to be reported; IPv6 uses ipv6 flow monitor.',
      'On Catalyst switches running IOS XE 3.2SE the reference allows only a named record, so the predefined record may be refused.',
    ],
  },
  {
    id: 'meraki-mx',
    vendor: 'Cisco Meraki',
    product: 'MX and Z-Series',
    protocol: 'NetFlow v9',
    kind: 'gui',
    lines: [
      'Network-wide > Configure > General, under Reporting:',
      '  NetFlow traffic reporting: Enabled: send netflow traffic statistics',
      '  NetFlow collector IP: {ADDRESS}',
      '  NetFlow collector port: {PORT}',
    ],
    sources: [{ title: 'Meraki NetFlow overview', url: 'https://documentation.meraki.com/SASE_and_SD-WAN/MX/Operate_and_Maintain/Monitoring_and_Reporting/NetFlow_Overview' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'One collector, IPv4 only.',
      'The MX exports only traffic that hits its CPU: traffic it NATs or routes.',
    ],
  },
  {
    id: 'fortigate',
    vendor: 'Fortinet',
    product: 'FortiGate 7.6',
    protocol: 'NetFlow',
    kind: 'cli',
    lines: [
      'config system netflow',
      '    config collectors',
      '        edit 1',
      '            set collector-ip {ADDRESS}',
      '            set collector-port {PORT}',
      '        next',
      '    end',
      'end',
      'config system interface',
      '    edit {INTERFACE}',
      '        set netflow-sampler both',
      '    next',
      'end',
    ],
    sources: [
      { title: 'FortiGate 7.6.0 CLI reference, config system netflow', url: 'https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/105185180/config-system-netflow' },
      { title: 'FortiGate 7.6.3 administration guide, NetFlow', url: 'https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/998643/netflow' },
      { title: 'FortiGate 7.6.3 administration guide, NetFlow sampling', url: 'https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/667577/netflow-sampling' },
    ],
    readOn: READ_ON,
    verified: true,
    notes: [
      'The pages do not name the NetFlow version; Inwire reads v5, v9 and IPFIX alike.',
      'Two Fortinet pages give different default ports (2055 and 6343), so set the port.',
      'NetFlow is off on every interface until netflow-sampler is set; it is configured in the CLI only.',
      'Non-management VDOMs use config system vdom-netflow instead.',
    ],
  },
  {
    id: 'aruba-aoscx',
    vendor: 'HPE Aruba',
    product: 'AOS-CX 10.15',
    protocol: 'IPFIX',
    kind: 'cli',
    lines: [],
    sources: [{ title: 'AOS-CX 10.15 IPFIX configuration', url: 'https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/monitoring_8100-83xx-9300-10000/Content/Chp_flow/conf-ipfix.htm' }],
    readOn: READ_ON,
    verified: false,
  },
  {
    id: 'juniper-srx',
    vendor: 'Juniper',
    product: 'SRX',
    protocol: 'IPFIX',
    kind: 'cli',
    lines: [
      'set services flow-monitoring version-ipfix template ipfix-ipv4 ipv4-template',
      'set forwarding-options sampling instance instance1 input rate {RATE}',
      'set forwarding-options sampling instance instance1 family inet output flow-server {ADDRESS} port {PORT}',
      'set forwarding-options sampling instance instance1 family inet output flow-server {ADDRESS} version-ipfix template ipfix-ipv4',
      'set forwarding-options sampling instance instance1 family inet output inline-jflow source-address {SOURCE_ADDRESS}',
    ],
    sources: [{ title: 'Juniper IPFIX formatting for SRX J-Flow', url: 'https://www.juniper.net/documentation/en_US/junos/topics/topic-map/ipfix-formatting-for-srx-jflow.html' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'The export side only: the page does not show turning sampling on for an interface, which the SRX also needs.',
      'The rate is 1 to 16,000,000; the page names no default port. IPv6 uses ipv6-template.',
    ],
  },
  {
    id: 'mikrotik',
    vendor: 'MikroTik',
    product: 'RouterOS 7',
    protocol: 'IPFIX',
    kind: 'cli',
    lines: [
      '/ip traffic-flow set enabled=yes interfaces=all',
      '/ip traffic-flow target add dst-address={ADDRESS} port={PORT} version=IPFIX',
    ],
    sources: [{ title: 'MikroTik Traffic Flow', url: 'https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic+Flow' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'version has no default and must be given; version=9 sends NetFlow v9.',
      'Hardware-offloaded traffic is not seen in Traffic Flow.',
    ],
  },
  {
    id: 'opnsense',
    vendor: 'OPNsense',
    product: 'NetFlow',
    protocol: 'NetFlow v9',
    kind: 'gui',
    lines: [
      'Reporting > NetFlow:',
      '  Interfaces: every interface to export from',
      '  Version: 9',
      '  Destinations: {ADDRESS}:{PORT}, then Enter',
    ],
    sources: [{ title: 'OPNsense, Configure Netflow Exporter', url: 'https://docs.opnsense.org/manual/how-tos/netflow_exporter.html' }],
    readOn: READ_ON,
    verified: true,
    notes: ['Add the interfaces to Egress only as well to avoid counting the firewall’s own traffic twice.'],
  },
  {
    id: 'panos',
    vendor: 'Palo Alto Networks',
    product: 'PAN-OS',
    protocol: 'NetFlow v9',
    kind: 'gui',
    lines: [
      'Device > Server Profiles > NetFlow, Add:',
      '  Name: Inwire',
      '  Add a collector: NetFlow Server {ADDRESS}, Access Port {PORT}',
      '  OK',
      'Network > Interfaces > Ethernet, edit {INTERFACE}:',
      '  NetFlow Profile: Inwire, OK',
      'Commit',
    ],
    sources: [
      { title: 'PAN-OS, Configure NetFlow Exports', url: 'https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring/configure-netflow-exports' },
      { title: 'PAN-OS, NetFlow Monitoring', url: 'https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring' },
    ],
    readOn: READ_ON,
    verified: true,
    notes: [
      'Set the profile on each interface where the traffic comes in. Sampled NetFlow is not supported.',
      'PA-7000, PA-7500, PA-5500, PA-5450 and PA-5200 need a service route: the management interface cannot send NetFlow.',
    ],
  },
  {
    id: 'pfsense-pflow',
    vendor: 'Netgate',
    product: 'pfSense Plus 24.03+ pflow',
    protocol: 'IPFIX',
    kind: 'gui',
    lines: [
      'Firewall > Packet Flow Data:',
      '  Enable Packet Flow Data Tracking and Exporting: checked',
      '  Enable Packet Flow tracking on all rules by default: checked',
      '  Save',
      'Add an exporter:',
      '  Enable: checked',
      '  Destination IP Address: {ADDRESS}',
      '  Destination Port: {PORT}',
      '  Flow Protocol: IPFIX',
      '  Save, then Apply Changes',
    ],
    sources: [{ title: 'pfSense, Packet Flow Data', url: 'https://docs.netgate.com/pfsense/en/latest/firewall/pflow.html' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'pfSense Plus only, not pfSense CE.',
      'Only states created after it is turned on are exported.',
    ],
  },
  {
    id: 'pfsense-softflowd',
    vendor: 'Netgate',
    product: 'pfSense CE softflowd package',
    protocol: 'NetFlow v9',
    kind: 'gui',
    lines: [
      'System > Packages, Available Packages: install softflowd',
      'Services > softflowd:',
      '  Interface: {INTERFACE}',
      '  Host: {ADDRESS}',
      '  Port: {PORT}',
      '  NetFlow Version: 9',
    ],
    sources: [{ title: 'pfSense, NetFlow with softflowd', url: 'https://docs.netgate.com/pfsense/en/latest/recipes/netflow-with-softflowd.html' }],
    readOn: READ_ON,
    verified: true,
    notes: ['The page does not list the versions the NetFlow Version list offers; softflowd itself sends version 5 unless told otherwise.'],
  },
  {
    id: 'softflowd',
    vendor: 'softflowd',
    product: 'on Linux or WSL',
    protocol: 'NetFlow v9',
    kind: 'cli',
    lines: ['softflowd -v 9 -i {INTERFACE} -n {ADDRESS}:{PORT}'],
    sources: [{ title: 'softflowd wiki', url: 'https://github.com/irino/softflowd/wiki/softflowd' }],
    readOn: READ_ON,
    verified: true,
    notes: ['-v 10 sends IPFIX; with no -v it sends NetFlow v5.'],
  },
  {
    id: 'sophos',
    vendor: 'Sophos',
    product: 'Firewall SFOS 21.5',
    protocol: 'NetFlow v5',
    kind: 'gui',
    lines: [
      'Netflow configuration:',
      '  Name: Inwire',
      '  IP/domain: {ADDRESS}',
      '  Port: {PORT}',
    ],
    sources: [{ title: 'Sophos Firewall 21.5, NetFlow configuration', url: 'https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/NetflowConfiguration/index.html' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'Sophos sends NetFlow v5 only.',
      'Only traffic of firewall rules with Log firewall traffic turned on is sent.',
    ],
  },
  {
    id: 'unifi',
    vendor: 'Ubiquiti',
    product: 'UniFi',
    protocol: 'IPFIX',
    kind: 'gui',
    lines: [
      'Settings > CyberSecure > Traffic Logging: enable NetFlow (IPFIX)',
      'Collector: {ADDRESS}, port {PORT}',
    ],
    sources: [{ title: 'UniFi, Traffic Flows and Traffic Logging', url: 'https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network' }],
    readOn: READ_ON,
    verified: true,
    notes: [
      'The page does not say where the collector’s address and port are entered; the second line is Inwire’s, not Ubiquiti’s.',
      'The export is sampled at a rate the page does not state. Not on UDR, UDR7, UDR 5G Max, Express, Express 7, UDM, UCG-Ultra or UXG-Lite.',
    ],
  },
];
