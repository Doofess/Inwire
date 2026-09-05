/**
 * Assertion tests for the conversation, endpoint and protocol-hierarchy tables.
 *
 *   npx tsx scripts/statistics/tables.ts
 *
 * These three tables are the reason a capture gets opened, and every way they
 * can be wrong looks exactly like a way they can be right: a pair counted as
 * two rows because the second frame came back the other way, a direction
 * attributed to the wrong end, a hierarchy that hangs QUIC underneath the TLS
 * it actually carries. So the checks below are mostly about identity and
 * direction rather than about arithmetic.
 *
 * Frames are hand-built. The point is what the aggregation does with a layer
 * list and a field bag, not how those were filled.
 */
import {
  conversations, endpoints, protocolHierarchy, devices, processes, processFilter,
  conversationFilter, endpointFilter, deviceFilter,
  type HierarchyNode, type ProcessGroup,
} from '../../src/services/statistics';
import { FilterEngine } from '../../src/services/filterEngine';
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
interface Spec {
  src: string; dst: string;
  sport?: number; dport?: number;
  layers: string[];
  length?: number;
  at?: number;
  protocol?: ProtocolType;
  protocolLabel?: string;
  streamId?: number;
}

function packet(s: Spec): Packet {
  const v6 = s.src.includes(':');
  const transport = s.layers.includes('tcp') ? 'tcp' : s.layers.includes('udp') ? 'udp' : null;
  const fields: Record<string, string | number> = {
    'eth.src': '00:11:22:33:44:55',
    'eth.dst': '66:77:88:99:aa:bb',
  };
  if (s.layers.includes('ip')) { fields['ip.src'] = s.src; fields['ip.dst'] = s.dst; }
  if (s.layers.includes('ipv6')) { fields['ipv6.src'] = s.src; fields['ipv6.dst'] = s.dst; }
  if (transport && s.sport !== undefined) {
    fields[`${transport}.srcport`] = s.sport;
    fields[`${transport}.dstport`] = s.dport!;
  }
  void v6;
  return {
    id: nextId++,
    tsUs: 1_700_000_000_000_000,
    relativeTime: s.at ?? 0,
    timeDelta: 0,
    source: s.src,
    destination: s.dst,
    sourcePort: s.sport,
    destPort: s.dport,
    protocol: s.protocol ?? 'TCP',
    protocolLabel: s.protocolLabel,
    length: s.length ?? 100,
    info: '',
    status: 'ok',
    frameProtocols: ['frame', 'eth', ...s.layers],
    fields,
    streamId: s.streamId,
    layers: [],
    rawBytes: new Uint8Array(0),
    interfaceName: 'test',
  };
}

// --- one pair is one row, whichever way the frame went ----------------------

{
  nextId = 1;
  const ps = [
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp'], length: 74, at: 0 }),
    packet({ src: '10.0.0.2', dst: '10.0.0.1', sport: 443, dport: 5000, layers: ['ip', 'tcp'], length: 60, at: 0.1 }),
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp'], length: 500, at: 0.2,
             protocol: 'TLS', protocolLabel: 'TLSv1.3' }),
  ];

  const [c] = conversations(ps, 'ipv4');
  check('a pair in both directions is one conversation', conversations(ps, 'ipv4').length, 1);
  check('the first frame decides which end is A', [c.addressA, c.addressB], ['10.0.0.1', '10.0.0.2']);
  check('the two directions are counted apart', [c.packetsAtoB, c.packetsBtoA], [2, 1]);
  check('...and so are their bytes', [c.bytesAtoB, c.bytesBtoA], [574, 60]);
  check('totals are the sum', [c.packets, c.bytes], [3, 634]);
  check('duration spans the pair', Number(c.duration.toFixed(3)), 0.2);
  check('the label is the most specific one seen, not the commonest', c.protocol, 'TLSv1.3');
  check('the row remembers the frame it started at', c.firstFrame, 1);
}

// --- a different port is a different TCP conversation, one IP conversation --

{
  nextId = 1;
  const ps = [
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp'] }),
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5001, dport: 443, layers: ['ip', 'tcp'] }),
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5002, dport: 80, layers: ['ip', 'tcp'] }),
  ];
  check('the IP tab collapses the ports', conversations(ps, 'ipv4').length, 1);
  check('the TCP tab keeps them apart', conversations(ps, 'tcp').length, 3);
  check('an endpoint on the IP tab has no port', endpoints(ps, 'ipv4').map(e => e.port), [undefined, undefined]);
  check('an endpoint on the TCP tab is address plus port',
    endpoints(ps, 'tcp').map(e => `${e.address}:${e.port}`).sort(),
    ['10.0.0.1:5000', '10.0.0.1:5001', '10.0.0.1:5002', '10.0.0.2:443', '10.0.0.2:80'].sort());
  check('...and 10.0.0.2:443 saw two of the three',
    endpoints(ps, 'tcp').find(e => e.port === 443)?.packets, 2);
}

// --- which tab a frame belongs on is decided by its layers ------------------

{
  nextId = 1;
  const ps = [
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp', 'tls'],
             protocol: 'TLS', protocolLabel: 'TLSv1.2' }),
    packet({ src: 'fe80::1', dst: 'fe80::2', sport: 5353, dport: 5353, layers: ['ipv6', 'udp', 'dns'],
             protocol: 'DNS', protocolLabel: 'MDNS' }),
    packet({ src: 'aa:bb:cc:dd:ee:ff', dst: 'ff:ff:ff:ff:ff:ff', layers: ['arp'], protocol: 'ARP' }),
  ];
  check('a TLS frame is a TCP frame', conversations(ps, 'tcp').length, 1);
  check('...and does not appear on the UDP tab', conversations(ps, 'udp').length, 1);
  check('an IPv6 frame is not on the IPv4 tab', conversations(ps, 'ipv4').length, 1);
  check('an ARP frame is on neither', conversations(ps, 'ipv4').length + conversations(ps, 'ipv6').length, 2);
  check('every frame is on the Ethernet tab', conversations(ps, 'eth')[0].packets, 3);
}

// --- the hierarchy is nesting, not a flat count ------------------------------

{
  nextId = 1;
  const ps = [
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp', 'tls'], length: 100 }),
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp'], length: 60 }),
    packet({ src: 'fe80::1', dst: 'fe80::2', sport: 443, dport: 5000, layers: ['ipv6', 'udp', 'quic', 'tls'], length: 1200 }),
  ];
  const h = protocolHierarchy(ps);
  const find = (nodes: HierarchyNode[], token: string): HierarchyNode | undefined => {
    for (const n of nodes) {
      if (n.token === token) return n;
      const hit = find(n.children, token);
      if (hit) return hit;
    }
    return undefined;
  };

  check('every frame is counted at the link layer', find(h.roots, 'eth')?.packets, 3);
  check('a frame counts at every level it passed', find(h.roots, 'tcp')?.packets, 2);
  check('TLS over TCP hangs off TCP', find(find(h.roots, 'tcp')!.children, 'tls')?.packets, 1);
  check('TLS over QUIC hangs off QUIC, not the other way round',
    find(find(h.roots, 'quic')!.children, 'tls')?.packets, 1);
  check('bytes come with it', find(h.roots, 'quic')?.bytes, 1200);
  check('totals cover every frame', [h.packets, h.bytes], [3, 1360]);
  check('siblings are ordered by weight',
    find(h.roots, 'eth')!.children.map(c => c.token), ['ip', 'ipv6']);
}

// --- a table row's filter selects that row's frames --------------------------

{
  nextId = 1;
  const ps = [
    packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 443, layers: ['ip', 'tcp'] }),
    packet({ src: '10.0.0.2', dst: '10.0.0.1', sport: 443, dport: 5000, layers: ['ip', 'tcp'] }),
    packet({ src: '10.0.0.1', dst: '10.0.0.3', sport: 5001, dport: 443, layers: ['ip', 'tcp'] }),
    packet({ src: 'fe80::1', dst: 'fe80::2', sport: 5000, dport: 53, layers: ['ipv6', 'udp'] }),
  ];

  const ip = conversations(ps, 'ipv4').find(c => c.addressB === '10.0.0.2')!;
  const ipFilter = conversationFilter(ip, 'ipv4');
  check('an IPv4 conversation filter is valid', FilterEngine.validateFilter(ipFilter).isValid, true);
  check('...and selects exactly that pair, both directions',
    FilterEngine.filterPackets(ps, ipFilter).map(p => p.id), [1, 2]);

  const tcp = conversations(ps, 'tcp').find(c => c.portA === 5001)!;
  check('a TCP conversation filter selects the one flow',
    FilterEngine.filterPackets(ps, conversationFilter(tcp, 'tcp')).map(p => p.id), [3]);

  const v6 = conversations(ps, 'ipv6')[0];
  check('an IPv6 conversation filter works too',
    FilterEngine.filterPackets(ps, conversationFilter(v6, 'ipv6')).map(p => p.id), [4]);

  const e = endpoints(ps, 'ipv4').find(x => x.address === '10.0.0.1')!;
  check('an endpoint filter selects everything to or from it',
    FilterEngine.filterPackets(ps, endpointFilter(e, 'ipv4')).map(p => p.id), [1, 2, 3]);
  check('...split by direction: 10.0.0.1 sent two of those and received one',
    [e.packetsTx, e.packetsRx], [2, 1]);
}

// --- the device inventory ---------------------------------------------------

{
  nextId = 1;
  const withMac = (mac: string, spec: Spec): Packet => {
    const p = packet(spec);
    p.fields!['eth.src'] = mac;
    return p;
  };
  const ps = [
    withMac('aa:bb:cc:dd:ee:01', { src: '10.0.0.1', dst: '10.0.0.2', layers: ['ip', 'tcp'], sport: 1, dport: 2, at: 0, length: 100 }),
    // The same machine, later, on its IPv6 address. One device, two addresses.
    withMac('aa:bb:cc:dd:ee:01', { src: 'fe80::1', dst: 'fe80::2', layers: ['ipv6', 'udp'], sport: 1, dport: 2, at: 5, length: 200 }),
    withMac('aa:bb:cc:dd:ee:02', { src: '10.0.0.2', dst: '10.0.0.1', layers: ['ip', 'tcp'], sport: 2, dport: 1, at: 1, length: 60 }),
    // Sent from a group address, which never happens on the wire.
    withMac('01:00:5e:00:00:fb', { src: '10.0.0.9', dst: '224.0.0.251', layers: ['ip', 'udp'], sport: 5353, dport: 5353, at: 2 }),
    withMac('ff:ff:ff:ff:ff:ff', { src: '10.0.0.9', dst: '10.0.0.255', layers: ['ip', 'udp'], sport: 1, dport: 2, at: 3 }),
    withMac('00:00:00:00:00:00', { src: '0.0.0.0', dst: '255.255.255.255', layers: ['ip', 'udp'], sport: 68, dport: 67, at: 4 }),
  ];

  const list = devices(ps);
  check('one row per machine, not per address', list.length, 2);
  check('a dual-stack host keeps both of its addresses',
    list.find(d => d.mac === 'aa:bb:cc:dd:ee:01')?.addresses, ['10.0.0.1', 'fe80::1']);
  check('...with its traffic summed', 
    [list.find(d => d.mac === 'aa:bb:cc:dd:ee:01')?.packets, list.find(d => d.mac === 'aa:bb:cc:dd:ee:01')?.bytes],
    [2, 300]);
  check('first and last seen span the frames', 
    [list.find(d => d.mac === 'aa:bb:cc:dd:ee:01')?.firstSeen, list.find(d => d.mac === 'aa:bb:cc:dd:ee:01')?.lastSeen],
    [0, 5]);
  check('a multicast source is not a device', list.some(d => d.mac.startsWith('01:00:5e')), false);
  check('...nor is broadcast or the unset address',
    list.some(d => d.mac === 'ff:ff:ff:ff:ff:ff' || d.mac === '00:00:00:00:00:00'), false);
  check('a device filter selects both directions of its traffic',
    FilterEngine.filterPackets(ps, deviceFilter(list[0])).length > 0, true);
  check('no Ethernet header, no devices', devices([packet({ src: 'a', dst: 'b', layers: ['ip'] })]).length, 1);
}

// --- nothing to count ---------------------------------------------------------

{
  check('an empty buffer yields no rows', conversations([], 'ipv4').length, 0);
  check('...no endpoints', endpoints([], 'tcp').length, 0);
  check('...and an empty hierarchy', protocolHierarchy([]), { roots: [], packets: 0, bytes: 0 });
  const bare: Packet = {
    id: 1, tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2', protocol: 'TCP',
    length: 60, info: '', status: 'ok', layers: [], rawBytes: new Uint8Array(0), interfaceName: 'x',
  };
  check('a frame that recorded no layers is on no tab', conversations([bare], 'ipv4').length, 0);
  check('...and not in the hierarchy either', protocolHierarchy([bare]).packets, 0);
}

// --- Processes ------------------------------------------------------------------
//
// The grouping no analyzer reading a file alone can produce, so nothing about
// it can be checked against tshark. What CAN be checked is that it says only
// what it was told: a pid it never saw gets no row, and two processes sharing a
// name stay two rows.
{
  const attributed = (spec: Parameters<typeof packet>[0], name: string, pid: number, exe = '') => {
    const p = packet(spec);
    p.fields = {
      ...p.fields,
      'inwire.process.name': name,
      'inwire.process.pid': pid,
      ...(exe ? { 'inwire.process.path': exe } : {}),
    };
    return p;
  };

  const local = new Set(['10.0.0.4']);
  const isLocal = (a: string) => local.has(a);

  const rows = processes([
    attributed({ src: '10.0.0.4', dst: '1.1.1.1', sport: 5001, dport: 443, layers: ['ip', 'tcp'], length: 100 }, 'chrome.exe', 100, 'C:/chrome.exe'),
    attributed({ src: '1.1.1.1', dst: '10.0.0.4', sport: 443, dport: 5001, layers: ['ip', 'tcp'], length: 200 }, 'chrome.exe', 100, 'C:/chrome.exe'),
    // Same NAME, different process. A browser's renderers are not one thing.
    attributed({ src: '10.0.0.4', dst: '9.9.9.9', sport: 5002, dport: 443, layers: ['ip', 'tcp'], length: 50 }, 'chrome.exe', 200, 'C:/chrome.exe'),
    attributed({ src: '10.0.0.4', dst: '8.8.8.8', sport: 5003, dport: 53, layers: ['ip', 'udp'], length: 70 }, 'curl.exe', 300),
    // No attribution at all - must not become an "unknown" row.
    packet({ src: '10.0.0.4', dst: '4.4.4.4', sport: 5004, dport: 443, layers: ['ip', 'tcp'] }),
  ], isLocal);

  check('one row per process id, not per name', rows.length, 3);
  check('...so two processes sharing a name stay two rows',
    rows.filter((r) => r.name === 'chrome.exe').map((r) => r.pid).sort(), [100, 200]);

  const chrome = rows.find((r) => r.pid === 100)!;
  check('both directions of a flow count toward its process', chrome.packets, 2);
  check('...and its bytes', chrome.bytes, 300);
  check('the peer is the far end, never this machine', chrome.peers, ['1.1.1.1']);
  check('the path is carried when the OS gave one', chrome.exe, 'C:/chrome.exe');
  check('...and is empty, not invented, when it did not',
    rows.find((r) => r.pid === 300)!.exe, '');

  check('an unattributed frame is absent rather than gathered into "unknown"',
    rows.reduce((n, r) => n + r.packets, 0), 4);

  // The filter is on the pid, because that is what the row is. On the name it
  // would select every renderer a browser has, which is not the row clicked.
  check('the row filters on its process id', processFilter(chrome), 'inwire.process.pid == 100');
  check('...and that filter is valid',
    FilterEngine.validateFilter(processFilter(chrome)).isValid, true);

  // And selects exactly the frames it claims to. This is the property that
  // would break silently if the field were registered under a layer the frames
  // do not carry: the table would still look right and the click would select
  // nothing.
  const chromeFrames = [
    attributed({ src: '10.0.0.4', dst: '1.1.1.1', sport: 5001, dport: 443, layers: ['ip', 'tcp'] }, 'chrome.exe', 100),
    attributed({ src: '10.0.0.4', dst: '9.9.9.9', sport: 5002, dport: 443, layers: ['ip', 'tcp'] }, 'chrome.exe', 200),
    packet({ src: '10.0.0.4', dst: '4.4.4.4', sport: 5004, dport: 443, layers: ['ip', 'tcp'] }),
  ];
  check('...and selects that process and no other',
    FilterEngine.filterPackets(chromeFrames, processFilter(chrome)).map((p) => p.id),
    [chromeFrames[0].id]);

  // Without a way to tell which end is local, the column stays empty rather
  // than naming this machine as its own peer.
  const noLocal = processes([
    attributed({ src: '10.0.0.4', dst: '1.1.1.1', sport: 5001, dport: 443, layers: ['ip', 'tcp'] }, 'chrome.exe', 100),
  ]);
  check('with no local set, no peer is guessed at', noLocal[0].peers, []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All statistics checks passed.');
process.exit(0);
