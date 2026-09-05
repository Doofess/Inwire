/**
 * Port numbers to service names, for transport-layer name resolution.
 *
 * IANA's registry has some 14,000 entries and most of them are noise - a port
 * assigned in 1996 to something nobody has run since. This is the working set:
 * the ports a capture from a modern network actually contains, plus the ones
 * whose absence would be conspicuous. Held here rather than generated because
 * generating it would mean shipping a megabyte to name `443`.
 *
 * This is display only. The Info column's text is built by the dissectors and
 * compared against tshark by the parity harness, so nothing here may reach it;
 * these names appear in the Statistics tables and the Resolved Addresses view,
 * where they answer "what is this conversation" rather than "what did the
 * frame say".
 */

/** Ports whose service differs by transport (`tcp/53` vs `udp/53` agree; `tcp/1900` does not exist). */
type Transport = 'tcp' | 'udp';

const COMMON: Record<number, string> = {
  7: 'echo', 19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
  25: 'smtp', 37: 'time', 42: 'nameserver', 43: 'whois', 49: 'tacacs',
  53: 'domain', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 70: 'gopher',
  79: 'finger', 80: 'http', 88: 'kerberos', 102: 'iso-tsap', 110: 'pop3',
  111: 'sunrpc', 113: 'ident', 119: 'nntp', 123: 'ntp',
  135: 'epmap', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn',
  143: 'imap', 161: 'snmp', 162: 'snmptrap', 179: 'bgp', 194: 'irc',
  389: 'ldap', 427: 'svrloc', 443: 'https', 445: 'microsoft-ds',
  464: 'kpasswd', 465: 'submissions', 500: 'isakmp', 502: 'modbus',
  514: 'syslog', 515: 'printer', 520: 'router', 521: 'ripng', 546: 'dhcpv6-client',
  547: 'dhcpv6-server', 548: 'afp', 554: 'rtsp', 563: 'nntps', 587: 'submission',
  593: 'http-rpc-epmap', 623: 'asf-rmcp', 631: 'ipp', 636: 'ldaps',
  873: 'rsync', 902: 'vmware-auth', 989: 'ftps-data', 990: 'ftps',
  993: 'imaps', 995: 'pop3s',
  1080: 'socks', 1194: 'openvpn', 1234: 'search-agent', 1433: 'ms-sql-s',
  1434: 'ms-sql-m', 1521: 'oracle', 1701: 'l2tp', 1723: 'pptp', 1812: 'radius',
  1813: 'radius-acct', 1883: 'mqtt', 1900: 'ssdp', 1935: 'rtmp',
  2049: 'nfs', 2082: 'cpanel', 2083: 'cpanel-ssl', 2181: 'zookeeper',
  2375: 'docker', 2376: 'docker-s', 2483: 'oracle-db', 2967: 'symantec-av',
  3000: 'ppp', 3128: 'squid-http', 3260: 'iscsi', 3268: 'globalcatLDAP',
  3283: 'net-assistant', 3306: 'mysql', 3389: 'ms-wbt-server', 3478: 'stun',
  3479: 'stun-alt', 3702: 'ws-discovery', 4070: 'spotify',
  4433: 'https-alt', 4500: 'ipsec-nat-t', 5000: 'upnp', 5001: 'commplex-link',
  5060: 'sip', 5061: 'sips', 5222: 'xmpp-client', 5228: 'hpvroom',
  5269: 'xmpp-server', 5298: 'presence', 5353: 'mdns', 5355: 'llmnr',
  5432: 'postgresql', 5555: 'freeciv', 5672: 'amqp', 5683: 'coap',
  5684: 'coaps', 5900: 'vnc', 5938: 'teamviewer', 6000: 'x11',
  6379: 'redis', 6443: 'kubernetes', 6666: 'irc-alt', 6667: 'irc',
  6881: 'bittorrent', 7000: 'afs3-fileserver', 7680: 'delivery-optimization',
  8000: 'http-alt', 8006: 'proxmox', 8008: 'http-alt', 8009: 'ajp13',
  8080: 'http-proxy', 8081: 'http-alt', 8086: 'influxdb', 8443: 'https-alt',
  8883: 'secure-mqtt', 8888: 'http-alt', 9000: 'cslistener', 9090: 'websm',
  9092: 'kafka', 9100: 'jetdirect', 9200: 'elasticsearch', 9418: 'git',
  11211: 'memcached', 15672: 'rabbitmq-mgmt', 27017: 'mongodb',
  32400: 'plex', 51820: 'wireguard',
};

/** Ports that mean something different, or only exist, on one transport. */
const BY_TRANSPORT: Record<Transport, Record<number, string>> = {
  tcp: {
    3478: 'stun-tcp',
    8999: 'inwire-agent',
  },
  udp: {
    80: 'http-udp',
    443: 'https-quic',
    4433: 'quic-alt',
  },
};

/**
 * A service name for a port, or undefined when this table does not know it.
 *
 * Undefined rather than the number back again, so a caller can decide whether
 * an unnamed port shows as blank or as the number - the two views want
 * different answers.
 */
export function serviceName(port: number, transport: Transport): string | undefined {
  return BY_TRANSPORT[transport][port] ?? COMMON[port];
}

/**
 * How a port reads with resolution on: `443 (https)`, or just the number.
 *
 * Wireshark writes the name alone; the number is kept because a filter is
 * written against the number and losing it would mean looking the port back up
 * to act on what the table just showed.
 */
export function portLabel(port: number, transport: Transport, resolve: boolean): string {
  if (!resolve) return String(port);
  const name = serviceName(port, transport);
  return name ? `${port} (${name})` : String(port);
}

/**
 * True for a port that is well known enough that a service on it is probably
 * the service the port names. Used by the conversation table to label a flow
 * by its server end rather than by whichever end happens to be lower.
 */
export function isWellKnownPort(port: number): boolean {
  return port < 1024 || port in COMMON;
}
