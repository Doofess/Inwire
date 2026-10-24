/**
 * The terms the packet list's row menu offers for "Filter on this packet".
 *
 * Synthetic frames only. Review Focus 4 of the copy-and-menus plan: an IPv6 row
 * must get `ipv6.src`, a non-IP row `eth.src`, a row with no address nothing,
 * and a protocol that is not a filter name must fall back to `proto == "..."`
 * rather than a bareword the engine would call a typo.
 */
import type { Packet } from '../../src/types/packet';
import { rowFilterTerms } from '../../src/services/filter/fromField';
import { FilterEngine } from '../../src/services/filterEngine';

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

function packet(over: Partial<Packet>): Packet {
  return {
    id: 1,
    tsUs: 1_700_000_000_000_000,
    relativeTime: 0,
    timeDelta: 0,
    source: '',
    destination: '',
    protocol: 'TCP',
    length: 60,
    info: '',
    status: 'ok',
    layers: [],
    rawBytes: new Uint8Array(0),
    interfaceName: 'test',
    ...over,
  } as Packet;
}

const tcp4 = packet({
  source: '10.0.0.1', destination: '10.0.0.2', protocol: 'TCP',
  frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'],
  fields: { 'eth.src': 'aa:bb:cc:00:00:01', 'eth.dst': 'aa:bb:cc:00:00:02', 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.2' },
});
check('ipv4 source', rowFilterTerms(tcp4).source, 'ip.src == "10.0.0.1"');
check('ipv4 destination', rowFilterTerms(tcp4).destination, 'ip.dst == "10.0.0.2"');
check('ipv4 tcp protocol', rowFilterTerms(tcp4).protocol, 'tcp');

const tls4 = packet({ ...tcp4, protocolLabel: 'TLSv1.3', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp', 'tls'] });
check('top protocol above tcp', rowFilterTerms(tls4).protocol, 'tls');

const trailingData = packet({ ...tcp4, frameProtocols: ['eth', 'ethertype', 'ip', 'tcp', 'data'] });
check('trailing data layer skipped', rowFilterTerms(trailingData).protocol, 'tcp');

const v6 = packet({
  source: 'fe80::1', destination: 'ff02::1', protocol: 'ICMP', protocolLabel: 'ICMPv6',
  frameProtocols: ['eth', 'ethertype', 'ipv6', 'icmpv6'],
  fields: { 'eth.src': 'aa:bb:cc:00:00:01', 'eth.dst': '33:33:00:00:00:01', 'ipv6.src': 'fe80::1', 'ipv6.dst': 'ff02::1' },
});
check('ipv6 source', rowFilterTerms(v6).source, 'ipv6.src == "fe80::1"');
check('ipv6 destination', rowFilterTerms(v6).destination, 'ipv6.dst == "ff02::1"');

const arp = packet({
  source: 'aa:bb:cc:00:00:01', destination: 'ff:ff:ff:ff:ff:ff', protocol: 'ARP',
  frameProtocols: ['eth', 'arp'],
  fields: { 'eth.src': 'aa:bb:cc:00:00:01', 'eth.dst': 'ff:ff:ff:ff:ff:ff' },
});
check('arp source is the MAC', rowFilterTerms(arp).source, 'eth.src == "aa:bb:cc:00:00:01"');
check('arp destination is the MAC', rowFilterTerms(arp).destination, 'eth.dst == "ff:ff:ff:ff:ff:ff"');
check('arp protocol', rowFilterTerms(arp).protocol, 'arp');

const bare = packet({ source: 'x', destination: 'y', protocol: 'TCP', frameProtocols: ['tcp'] });
check('no addresses: source null', rowFilterTerms(bare).source, null);
check('no addresses: destination null', rowFilterTerms(bare).destination, null);

const odd = packet({
  protocol: 'UDP', protocolLabel: 'Zorp', frameProtocols: ['eth', 'ip', 'udp', 'zorp'],
  fields: { 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.2' },
});
check('unknown top protocol falls back to proto ==', rowFilterTerms(odd).protocol, 'proto == "Zorp"');

const noLayers = packet({ protocol: 'UDP' });
check('no frameProtocols falls back to the coarse protocol', rowFilterTerms(noLayers).protocol, 'proto == "UDP"');

// The fallback and the bare names must be accepted by the real validator, or
// the menu would offer a filter the bar then rejects.
for (const term of ['tcp', 'tls', 'arp', 'proto == "UDP"', 'ip.src == "10.0.0.1"', 'ipv6.src == "fe80::1"', 'eth.src == "aa:bb:cc:00:00:01"']) {
  check(`strict validator accepts ${term}`, FilterEngine.validateFilter(term, { strict: true }).isValid, true);
}

if (failures > 0) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nrow-terms: all passed');
