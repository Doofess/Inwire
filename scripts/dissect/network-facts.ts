/**
 * Assertion tests for what a capture reveals about its own network.
 *
 *   npx tsx scripts/dissect/network-facts.ts
 *
 * `services/networkFacts.ts` is the "observed" half of the Network panel: the
 * resolver that was really asked, the MAC that really forwards, the router
 * that really advertised. It sits beside the OS's own answer, and the value of
 * the pairing is entirely in the cases where the two disagree - so a fact
 * collected wrongly here does not read as a bug, it reads as a finding.
 * "Your machine is querying a resolver it is not configured with" is an alarm,
 * and raising it falsely is worse than not raising it.
 *
 * That is what most of these hold: not that a fact is found, but that the
 * things which merely resemble it are not.
 *
 *   - A neighbour's DNS query, visible in promiscuous mode, is not our
 *     resolver.
 *   - Multicast DNS is not a resolver at all.
 *   - An LLDP frame is not necessarily a switch - Windows advertises itself,
 *     and the capture this was built against contains exactly one LLDP frame
 *     which is the host's own.
 *   - One stray frame to an odd MAC does not rename the gateway.
 */
import { NetworkFactsCollector, emptyNetworkFacts } from '../../src/services/networkFacts';
import type { HostIdentity } from '../../src/services/direction';
import type { Packet } from '../../src/types/packet';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const OURS = '04:7c:16:52:db:17';
const GATEWAY = '44:15:24:aa:bb:cc';
const STRANGER = '74:56:3c:c5:e3:7d';

const host: HostIdentity = {
  macs: new Set([OURS]), addresses: new Set(['10.0.0.4']),
  inferred: false, confidence: 1,
};

function frame(protocols: string[], fields: Record<string, string | number>): Packet {
  return {
    id: 1, length: 200, source: String(fields['ip.src'] ?? fields['ipv6.src'] ?? ''),
    destination: '', frameProtocols: protocols, fields,
  } as unknown as Packet;
}

const collect = (packets: Packet[]) => {
  const collector = new NetworkFactsCollector();
  for (const packet of packets) collector.observe(packet, host);
  return collector;
};

// --- Nothing observed is nothing claimed -----------------------------------------
{
  const empty = emptyNetworkFacts();
  check('an empty capture claims no gateway', empty.gatewayMac, null);
  check('...no resolvers', empty.dnsServers, []);
  check('...no router', empty.router, null);
  check('...and no neighbour', empty.neighbour, null);
}

// --- The gateway is whoever carries our off-link traffic ---------------------------
{
  const offLink = () => frame(['eth', 'ip', 'tcp'], {
    'eth.src': OURS, 'eth.dst': GATEWAY, 'ip.src': '10.0.0.4', 'ip.dst': '142.250.185.14',
  });
  check('the MAC our off-link traffic goes to is the gateway',
    collect(Array.from({ length: 10 }, offLink)).snapshot().gatewayMac, GATEWAY);

  // One frame is not a gateway. A probe, a misdirected packet or a moment of
  // failover would otherwise rename it, and the snapshot is posted on change.
  check('a single frame does not name a gateway',
    collect([offLink()]).snapshot().gatewayMac, null);

  // Traffic that never left the segment says nothing about who forwards.
  check('local traffic names no gateway',
    collect(Array.from({ length: 20 }, () => frame(['eth', 'ip', 'tcp'], {
      'eth.src': OURS, 'eth.dst': GATEWAY, 'ip.src': '10.0.0.4', 'ip.dst': '10.0.0.9',
    }))).snapshot().gatewayMac, null);

  // Somebody else's off-link traffic names THEIR gateway, not ours - and on a
  // mirror port or a hub there is plenty of it.
  check('a neighbour\'s traffic names no gateway for us',
    collect(Array.from({ length: 20 }, () => frame(['eth', 'ip', 'tcp'], {
      'eth.src': STRANGER, 'eth.dst': GATEWAY, 'ip.src': '10.0.0.9', 'ip.dst': '1.1.1.1',
    }))).snapshot().gatewayMac, null);

  // The ARP reply that names the gateway's address almost always arrives
  // BEFORE enough traffic has flowed to identify which MAC is the gateway -
  // a machine ARPs for its router when it joins the network. Matching only in
  // the moment lost the address on every capture that opened that way.
  const arpFirst = [
    frame(['eth', 'arp'], {
      'eth.src': GATEWAY, 'arp.opcode': 2,
      'arp.src.proto_ipv4': '10.0.0.138', 'arp.src.hw_mac': GATEWAY,
    }),
    ...Array.from({ length: 10 }, offLink),
  ];
  check('an ARP reply seen before the gateway was known still names its address',
    collect(arpFirst).snapshot().gatewayAddresses, ['10.0.0.138']);

  // Every host on a segment answers ARP. Collecting all of them would make
  // this a neighbour table rather than a statement about the gateway.
  const others = [
    frame(['eth', 'arp'], {
      'eth.src': STRANGER, 'arp.opcode': 2,
      'arp.src.proto_ipv4': '10.0.0.55', 'arp.src.hw_mac': STRANGER,
    }),
    ...arpFirst,
  ];
  check('other hosts answering ARP are not recorded as gateways',
    collect(others).snapshot().gatewayAddresses, ['10.0.0.138']);
}

// --- Resolvers: what was asked, and by us -----------------------------------------
{
  const query = (dst: string, src = OURS) => frame(['eth', 'ip', 'udp', 'dns'], {
    'eth.src': src, 'ip.src': '10.0.0.4', 'ip.dst': dst, 'udp.dstport': 53,
  });
  check('a resolver we queried is recorded',
    collect([query('10.0.0.138')]).snapshot().dnsServers, ['10.0.0.138']);

  // In promiscuous mode a neighbour's queries are visible, and their resolver
  // is not ours - listing it beside the OS's configured list would read as
  // "your machine is querying somewhere it should not be".
  check('a neighbour\'s query does not add their resolver',
    collect([query('9.9.9.9', STRANGER)]).snapshot().dnsServers, []);

  // mDNS and LLMNR are the segment shouting, not a resolver. 224.0.0.251
  // listed as a DNS server would be actively misleading.
  check('multicast DNS is not a resolver',
    collect([query('224.0.0.251')]).snapshot().dnsServers, []);
  check('IPv6 multicast DNS is not either',
    collect([frame(['eth', 'ipv6', 'udp', 'dns'], {
      'eth.src': OURS, 'ipv6.dst': 'ff02::fb', 'udp.dstport': 53,
    })]).snapshot().dnsServers, []);

  // The question names the server; the answer's source is the server too, but
  // recording that would add our own address every time we answered an mDNS
  // query on the segment.
  check('a DNS response is not read as a query',
    collect([frame(['eth', 'ip', 'udp', 'dns'], {
      'eth.src': OURS, 'ip.src': '10.0.0.4', 'ip.dst': '10.0.0.138', 'udp.srcport': 53,
    })]).snapshot().dnsServers, []);
}

// --- Encrypted DNS ------------------------------------------------------------------
{
  check('a DoH endpoint is recognised by name',
    collect([frame(['eth', 'ip', 'tcp', 'tls'], {
      'eth.src': OURS, 'tcp.dstport': 443,
      'tls.handshake.extensions_server_name': 'cloudflare-dns.com',
    })]).snapshot().encryptedDns, ['cloudflare-dns.com (DoH)']);

  // DoT has a port of its own, which matters because a resumed session sends
  // no server name at all.
  check('DoT is recognised by port, with no name needed',
    collect([frame(['eth', 'ip', 'tcp', 'tls'], {
      'eth.src': OURS, 'tcp.dstport': 853, 'ip.dst': '9.9.9.9',
    })]).snapshot().encryptedDns, ['9.9.9.9 (DoT)']);

  // A name list rather than a heuristic. "Contains dns" would catch every host
  // on dnsimple.com, and a false entry here reads as an alarm.
  check('an ordinary host that merely mentions dns is not DoH',
    collect([frame(['eth', 'ip', 'tcp', 'tls'], {
      'eth.src': OURS, 'tcp.dstport': 443,
      'tls.handshake.extensions_server_name': 'api.dnsimple.com',
    })]).snapshot().encryptedDns, []);
}

// --- LLDP: a machine introducing itself is not a neighbour ---------------------------
//
// The correction this whole feature turned up. Windows runs an LLDP agent, so
// an LLDP frame in a capture is as likely to be the capturing host as a switch.
{
  const self = collect([frame(['eth', 'lldp'], {
    'eth.src': OURS, 'lldp.port.id': OURS, 'lldp.chassis.id': 'ROTEM',
  })]).snapshot();
  check('our own LLDP advertisement is not a neighbour', self.neighbour, null);
  check('...it is recorded as our own name', self.selfAdvertisedName, 'ROTEM');

  const switchAd = collect([frame(['eth', 'lldp'], {
    'eth.src': STRANGER, 'lldp.port.id': 'GigabitEthernet0/1',
    'lldp.tlv.system.name': 'sw-core-01', 'lldp.mgn.addr': '10.0.0.2',
  })]).snapshot();
  check('a real switch is a neighbour', switchAd.neighbour?.systemName, 'sw-core-01');
  check('...with the port it told us', switchAd.neighbour?.portId, 'GigabitEthernet0/1');
  check('...and is not mistaken for us', switchAd.selfAdvertisedName, null);
}

// --- The router, from its advertisement -----------------------------------------------
{
  const facts = collect([frame(['eth', 'ipv6', 'icmpv6'], {
    'eth.src': GATEWAY, 'ipv6.src': 'fe80::4615:24ff:feaa:bbcc', 'icmpv6.type': 134,
    'icmpv6.opt.prefix': '2001:db8:422c:9100::/64',
    'icmpv6.opt.rdnss': '2001:db8:ffff::1,2001:db8:ffff::2',
    'icmpv6.nd.ra.router_lifetime': 300,
    'icmpv6.nd.ra.flag.m': 0, 'icmpv6.nd.ra.flag.o': 1,
  })]).snapshot();
  check('the advertising router is recorded', facts.router?.address, 'fe80::4615:24ff:feaa:bbcc');
  check('...with its prefix', facts.router?.prefixes, ['2001:db8:422c:9100::/64']);
  check('...and both resolvers it handed out', facts.router?.rdnss.length, 2);
  check('...and the flags, which say SLAAC plus DHCPv6 for everything else',
    [facts.router?.managed, facts.router?.other], [false, true]);
  // A router that advertises is on the segment, whatever else we know.
  checkTrue('...and it counts as a gateway address',
    facts.gatewayAddresses.includes('fe80::4615:24ff:feaa:bbcc'));

  // A neighbour advertisement, a solicitation, an echo - none of them is an RA.
  check('other ICMPv6 types announce no router',
    collect([frame(['eth', 'ipv6', 'icmpv6'], {
      'eth.src': GATEWAY, 'ipv6.src': 'fe80::1', 'icmpv6.type': 136,
    })]).snapshot().router, null);
}

// --- It speaks only when it learns something --------------------------------------------
//
// The snapshot is posted to the main thread on change. A collector that
// reported "changed" every frame would push a message ten times a second for
// facts that move once an hour.
{
  const collector = new NetworkFactsCollector();
  const dhcp = frame(['eth', 'ip', 'udp', 'dhcp'], {
    'eth.src': OURS, 'dhcp.option.dhcp_server_id': '10.0.0.138',
  });
  collector.observe(dhcp, host);
  checkTrue('learning something sets changed', collector.takeChanged());
  check('...and reading it clears the flag', collector.takeChanged(), false);
  collector.observe(dhcp, host);
  check('the same fact again changes nothing', collector.takeChanged(), false);
  check('...and the fact is still held', collector.snapshot().dhcpServer, '10.0.0.138');

  // A frame that carries nothing this cares about - which is almost all of
  // them - must not mark the snapshot dirty.
  collector.observe(frame(['eth', 'ip', 'tcp'], { 'eth.src': OURS }), host);
  check('an ordinary frame changes nothing', collector.takeChanged(), false);

  collector.reset();
  check('a reset forgets what the capture taught', collector.snapshot().dhcpServer, null);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All network-facts checks passed.');
process.exit(0);
