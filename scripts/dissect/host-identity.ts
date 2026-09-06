/**
 * Assertion tests for working out which machine a capture was taken on.
 *
 *   npx tsx scripts/dissect/host-identity.ts
 *
 * A live capture is told who it is by the agent. An imported one has only the
 * frames, so `services/hostIdentity.ts` scores the MACs in it and nominates
 * one - and that nomination becomes an arrow in a column that a user reads as
 * fact, so it is worth holding to more than "it worked on the file I had".
 *
 * Two halves, and they check different things.
 *
 * **Synthetic frames** drive each signal in isolation, which a real capture
 * cannot: in a real file every signal agrees, so a scorer that had three of
 * them wired backwards would still pick the right host. The synthetic cases
 * are built to disagree - a gateway that sends far more traffic than the host,
 * a host whose only distinguishing mark is its TTLs - because that is where a
 * weighting is actually load-bearing.
 *
 * **The fixture**, when it is present, checks the whole thing against a
 * capture nobody constructed for it. The expected answer is not a guess: it
 * was established independently with tshark before any of this was written,
 * and cross-checked three further ways - the Router Advertisement source is
 * the gateway's MAC in EUI-64 form, the DHCP ACK names the same router, and
 * this machine's own OS neighbour table agrees. See
 * `docs/decisions/0019-packet-direction.md`.
 *
 * Skips cleanly without the fixture (test/fixtures/README.md); the synthetic
 * half always runs.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { inferHostIdentity, CONFIDENT_AT } from '../../src/services/hostIdentity';
import type { Packet } from '../../src/types/packet';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';

/** Established with tshark before this code existed. See the header. */
const FIXTURE_HOST = '04:7c:16:52:db:17';
const FIXTURE_GATEWAY = '44:15:24:aa:bb:cc';

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

/**
 * A frame carrying only what the scorer reads.
 *
 * Built as a bare object rather than by dissecting bytes, because what is
 * under test is the scoring rather than the dissection - and a synthetic case
 * has to be able to state "this MAC sent 400 frames with routed TTLs", which
 * would be a packet capture to construct.
 */
function frame(over: {
  src: string; ip?: string; ttl?: number; len?: number;
  protocols?: string[]; fields?: Record<string, string | number>;
}): Packet {
  return {
    id: 1, length: over.len ?? 200, source: over.ip ?? '', destination: '',
    frameProtocols: over.protocols ?? ['eth', 'ip'],
    fields: {
      'eth.src': over.src, 'eth.dst': 'ff:ff:ff:ff:ff:ff',
      ...(over.ip !== undefined ? { 'ip.src': over.ip } : {}),
      ...(over.ttl !== undefined ? { 'ip.ttl': over.ttl } : {}),
      ...over.fields,
    },
  } as unknown as Packet;
}

const HOST = 'aa:bb:cc:00:00:01';
const ROUTER = 'aa:bb:cc:00:00:02';
const repeat = (n: number, make: () => Packet) => Array.from({ length: n }, make);

// --- Nothing to go on produces nothing, not a default ---------------------------
//
// The answer that costs the most to get wrong. A capture from a span port has
// no capturing host in it at all, and nominating whichever MAC sent the most
// frames would put confident arrows on a file where none of them mean anything.
{
  check('an empty capture nominates nobody', inferHostIdentity([]), null);
  check('a capture of one unremarkable frame nominates nobody',
    inferHostIdentity([frame({ src: HOST })]), null);
}

// --- TTL alone, against a much busier router --------------------------------------
//
// The case a naive "whoever sent the most" would fail. The router sends four
// times the traffic; every one of its frames has been decremented.
{
  const packets = [
    ...repeat(100, () => frame({ src: HOST, ip: '10.0.0.4', ttl: 128 })),
    ...repeat(400, () => frame({ src: ROUTER, ip: '1.1.1.1', ttl: 54 })),
  ];
  const id = inferHostIdentity(packets);
  check('initial TTLs beat volume', id ? [...id.macs] : null, [HOST]);
  checkTrue('...and it says so in the basis',
    (id?.basis ?? '').includes('initial TTL'));
  checkTrue('...and it is marked inferred rather than known', id?.inferred === true);
  check('...and the host\'s address is learned with it',
    id ? [...id.addresses] : null, ['10.0.0.4']);
}

// --- Many source addresses is what a router looks like -----------------------------
{
  const packets = [
    ...repeat(60, () => frame({ src: HOST, ip: '10.0.0.4', ttl: 64 })),
    ...repeat(60, (() => { let n = 0; return () =>
      frame({ src: ROUTER, ip: `1.1.1.${n++}`, ttl: 64 }); })()),
  ];
  // Both have initial TTLs here, so the source count is the only thing left
  // to separate them - which is exactly the isolation this file exists for.
  check('one source address beats many', inferHostIdentity(packets)?.macs.has(HOST), true);
}

// --- Self-LLDP outweighs everything -------------------------------------------------
//
// A machine advertising its own port MAC is as close to being told as an
// imported capture gets. It has to win even when every other signal is against
// it, because every other signal is a heuristic and this one is a statement.
{
  const packets = [
    frame({ src: HOST, protocols: ['eth', 'lldp'], fields: { 'lldp.port.id': HOST } }),
    ...repeat(500, () => frame({ src: ROUTER, ip: '10.0.0.9', ttl: 64, len: 3000 })),
  ];
  const id = inferHostIdentity(packets);
  check('self-LLDP wins against every other signal', id ? [...id.macs] : null, [HOST]);
  checkTrue('...and says why', (id?.basis ?? '').includes('LLDP'));
}

// --- An LLDP frame is not automatically a neighbour -----------------------------------
//
// The assumption this corrects. Windows runs an LLDP agent, so an LLDP frame
// in a capture is as likely to be the capturing host introducing itself as it
// is to be a switch. A switch's LLDPDU names the switch's own port, which is
// not the MAC the frame arrived from on this segment - so matching the port id
// against the source MAC is what tells the two apart.
{
  const packets = [
    frame({ src: ROUTER, protocols: ['eth', 'lldp'], fields: { 'lldp.port.id': 'GigabitEthernet0/1' } }),
    ...repeat(40, () => frame({ src: HOST, ip: '10.0.0.4', ttl: 128 })),
  ];
  check('a switch advertising a port that is not its sending MAC is not the host',
    inferHostIdentity(packets)?.macs.has(HOST), true);
}

// --- A DHCP client is an endpoint; a DHCP server is not --------------------------------
{
  const client = frame({
    src: HOST, ip: '0.0.0.0', ttl: 128, protocols: ['eth', 'ip', 'udp', 'dhcp'],
    fields: { 'dhcp.hw.mac_addr': HOST },
  });
  // The server's ACK carries the CLIENT's hardware address too. Matching on
  // the field alone rather than on "it equals my own source MAC" would
  // nominate the DHCP server as the capturing host.
  const server = frame({
    src: ROUTER, ip: '10.0.0.138', ttl: 64, protocols: ['eth', 'ip', 'udp', 'dhcp'],
    fields: { 'dhcp.hw.mac_addr': HOST },
  });
  const packets = [client, server, ...repeat(30, () => frame({ src: ROUTER, ip: '1.1.1.1', ttl: 54 }))];
  const id = inferHostIdentity(packets);
  check('the DHCP client is the host, not the server that named it',
    id ? [...id.macs] : null, [HOST]);
}

// --- Two lookalikes produce a low confidence rather than a coin toss ----------------
//
// A capture from a bridge, or one holding two of a machine's own adapters.
// Both score well; neither deserves a confident arrow. The margin is what
// expresses that, and without it the winner's own score would still read high.
{
  const packets = [
    ...repeat(50, () => frame({ src: HOST, ip: '10.0.0.4', ttl: 128 })),
    ...repeat(50, () => frame({ src: ROUTER, ip: '10.0.0.9', ttl: 128 })),
  ];
  const id = inferHostIdentity(packets);
  checkTrue('two lookalikes still nominate somebody', id !== null);
  checkTrue('...but not confidently', (id?.confidence ?? 1) < CONFIDENT_AT);
}

// --- The fixture ----------------------------------------------------------------------
if (!existsSync(FIXTURE)) {
  console.log();
  console.log(`SKIP  ${FIXTURE} (see test/fixtures/README.md)`);
} else {
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(readFileSync(FIXTURE))], 'fixture.pcap'), 1_000_000,
  );
  const id = inferHostIdentity(parsed.packets);
  console.log();
  console.log(`  ${parsed.packets.length.toLocaleString()} frames`);
  console.log(`  host       ${id ? [...id.macs].join(', ') : '(none)'}`);
  console.log(`  confidence ${id ? id.confidence.toFixed(3) : '-'}`);
  console.log(`  basis      ${id?.basis ?? '-'}`);
  console.log();

  check('the fixture\'s capturing host is identified', id ? [...id.macs] : null, [FIXTURE_HOST]);
  checkTrue('...and the gateway is not mistaken for it', !id?.macs.has(FIXTURE_GATEWAY));
  // Every signal agrees on this file, so anything less than a clear answer
  // means the scoring is not combining them.
  checkTrue('...confidently, since every signal agrees on this capture',
    (id?.confidence ?? 0) >= CONFIDENT_AT);
  checkTrue('...and its own address was learned alongside it',
    id?.addresses.has('10.0.0.4') === true);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All host-identity checks passed.');
process.exit(0);
