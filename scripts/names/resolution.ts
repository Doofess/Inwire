/**
 * Assertion tests for the passive name map.
 *
 *   npx tsx scripts/names/resolution.ts
 *
 * Every name this map holds was carried by a frame that was on the wire, so
 * the risk is not that it looks up the wrong thing - it looks nothing up - but
 * that it BELIEVES the wrong thing. A CDN address serves thousands of names,
 * so an SNI is weak evidence about an address and a DNS answer is strong; a
 * real ECH ClientHello's outer name is genuinely carried and genuinely wrong.
 * The checks below are almost all about which claim wins.
 */
import { NameResolutionMap, buildNameMap } from '../../src/services/nameResolution';
import type { Packet, ProtocolType } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

let nextId = 1;
function packet(over: Partial<Packet>): Packet {
  return {
    id: nextId++,
    tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP' as ProtocolType,
    length: 100, info: '', status: 'ok',
    layers: [], rawBytes: new Uint8Array(0), interfaceName: 'test',
    ...over,
  };
}

// --- what each source teaches ------------------------------------------------

{
  nextId = 1;
  const dns = packet({
    protocol: 'DNS', protocolLabel: 'DNS',
    resolved: [{ name: 'example.com', addresses: ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'] }],
  });
  const map = new NameResolutionMap();
  map.learnFromPacket(dns);
  check('a DNS answer names every address it returned', map.hostName('93.184.216.34'), 'example.com');
  check('...including the AAAA', map.hostName('2606:2800:220:1:248:1893:25c8:1946'), 'example.com');
  check('an address the capture never named has no name', map.hostName('1.1.1.1'), undefined);
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  map.learnFromPacket(packet({
    protocol: 'DNS', protocolLabel: 'MDNS',
    resolved: [{ name: 'printer.local', addresses: ['10.0.0.9'] }],
  }));
  check('an mDNS answer is recorded as mDNS', map.entries()[0].source, 'mdns');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  // An SNI names the host the frame was SENT TO - the client is the one asking.
  map.learnFromPacket(packet({
    source: '10.0.0.1', destination: '93.184.216.34',
    fields: { 'tls.handshake.extensions_server_name': 'www.example.com' },
  }));
  check('an SNI names the destination', map.hostName('93.184.216.34'), 'www.example.com');
  check('...and not the client', map.hostName('10.0.0.1'), undefined);
  check('...recorded as a TLS SNI', map.entries()[0].source, 'sni');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  map.learnFromPacket(packet({
    protocol: 'QUIC', source: '10.0.0.1', destination: '142.250.185.78',
    fields: { 'tls.handshake.extensions_server_name': 'www.google.com' },
  }));
  check('a QUIC hello is recorded as a QUIC SNI', map.entries()[0].source, 'quic-sni');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  map.learnFromPacket(packet({
    fields: {
      'dhcp.option.hostname': 'laptop',
      'dhcp.ip.your': '10.0.0.42',
      'dhcp.hw.mac_addr': 'aa:bb:cc:dd:ee:ff',
    },
  }));
  check('DHCP names the address being offered', map.hostName('10.0.0.42'), 'laptop');
  check('...and the MAC that will hold it', map.macName('aa:bb:cc:dd:ee:ff'), 'laptop');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  // A request has no address yet, so the requested one carries the name.
  map.learnFromPacket(packet({
    fields: { 'dhcp.option.hostname': 'laptop', 'dhcp.ip.your': '0.0.0.0', 'dhcp.option.requested_ip_address': '10.0.0.42' },
  }));
  check('a DHCP request names the address it asked for', map.hostName('10.0.0.42'), 'laptop');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  map.learnFromPacket(packet({
    fields: { 'lldp.tlv.system.name': 'sw-core-1', 'lldp.mgn.addr': '10.0.0.1', 'lldp.chassis.id': '00:11:22:33:44:55' },
  }));
  check('LLDP names its management address', map.hostName('10.0.0.1'), 'sw-core-1');
  check('...and its chassis MAC', map.macName('00:11:22:33:44:55'), 'sw-core-1');
}

{
  nextId = 1;
  const map = new NameResolutionMap();
  // ARP carries no name; it joins a MAC already named to the address it is using.
  map.learnFromPacket(packet({
    fields: { 'dhcp.option.hostname': 'laptop', 'dhcp.hw.mac_addr': 'aa:bb:cc:dd:ee:ff', 'dhcp.ip.your': '0.0.0.0' },
  }));
  map.learnFromPacket(packet({
    fields: { 'arp.src.hw_mac': 'aa:bb:cc:dd:ee:ff', 'arp.src.proto_ipv4': '10.0.0.7' },
  }));
  check('ARP carries a known MAC\'s name onto the address it is using', map.hostName('10.0.0.7'), 'laptop');
  check('an unknown MAC in ARP teaches nothing', map.hostName('10.0.0.8'), undefined);
}

// --- which claim wins --------------------------------------------------------

{
  const map = new NameResolutionMap();
  map.learn('10.0.0.5', 'from-sni', 'sni', 1);
  map.learn('10.0.0.5', 'from-dns', 'dns', 2);
  check('a DNS answer outranks an SNI', map.hostName('10.0.0.5'), 'from-dns');
  map.learn('10.0.0.5', 'from-sni-again', 'sni', 3);
  check('...and is not displaced by a later one', map.hostName('10.0.0.5'), 'from-dns');
  map.learn('10.0.0.5', 'from-dhcp', 'dhcp', 4);
  check('a host naming itself outranks a DNS answer', map.hostName('10.0.0.5'), 'from-dhcp');
  map.learn('10.0.0.5', 'second-dhcp', 'dhcp', 5);
  check('within a rank the first name is kept, so the list does not relabel',
    map.hostName('10.0.0.5'), 'from-dhcp');
}

// --- what must NOT be learned ------------------------------------------------

{
  const map = new NameResolutionMap();
  // Chrome and Firefox add a GREASE ECH extension to every hello, but a REAL
  // ECH hello's outer SNI is the provider's public name. Learning it would
  // label every address behind that provider with the same wrong name, and it
  // would look trustworthy because the traffic really carried it.
  map.learn('104.16.0.1', 'cloudflare-ech.com', 'sni', 1);
  check('an ECH public name is not learned from an SNI', map.hostName('104.16.0.1'), undefined);
  map.learn('104.16.0.1', 'cloudflare-ech.com', 'dns', 2);
  check('...but a DNS answer for it is a real answer', map.hostName('104.16.0.1'), 'cloudflare-ech.com');

  map.learn('10.0.0.9', '10.0.0.9', 'dns', 3);
  check('a "name" that is the address back again teaches nothing', map.hostName('10.0.0.9'), undefined);
  map.learn('10.0.0.9', '   ', 'dns', 4);
  check('an empty name teaches nothing', map.hostName('10.0.0.9'), undefined);
  map.learn('10.0.0.9', 'host.example.com.', 'dns', 5);
  check('a trailing root dot is trimmed', map.hostName('10.0.0.9'), 'host.example.com');
}

// --- built from a buffer -----------------------------------------------------

{
  nextId = 1;
  const packets = [
    packet({ protocol: 'DNS', resolved: [{ name: 'a.example', addresses: ['1.2.3.4'] }] }),
    packet({ destination: '5.6.7.8', fields: { 'tls.handshake.extensions_server_name': 'b.example' } }),
    packet({}),
  ];
  const map = buildNameMap(packets);
  check('a whole buffer resolves in one pass', [map.hostName('1.2.3.4'), map.hostName('5.6.7.8')],
    ['a.example', 'b.example']);
  check('the entry remembers the frame that taught it',
    map.entries().find(e => e.address === '1.2.3.4')?.frame, 1);
  check('size counts what was learned', map.size, 2);
  map.reset();
  check('reset empties it', map.size, 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All name resolution checks passed.');
process.exit(0);
