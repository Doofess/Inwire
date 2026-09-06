/**
 * NBNS, against tshark.
 *
 *   npx tsx scripts/nbns/dissect.ts
 *
 * Neither parity fixture contains a single NetBIOS frame - they are personal
 * desktop captures - so there is no ground truth to compare against and no
 * `--write-floors` number this can move. The frames are therefore built here
 * from RFC 1001/1002's own layouts and handed to **tshark**, which is the same
 * oracle `scripts/parity/parity-check.ts` uses; only the provenance of the
 * bytes differs. See `scripts/parity/synthetic.ts`.
 *
 * What this is really guarding is the encoding. NBNS shares DNS's message
 * structure and almost nothing else, and reading it as DNS is not obviously
 * wrong on screen - it produces a plausible-looking
 * `Standard query 0x8f8e TYPE32 FHEPFCELEHFCEPFFFACACACACACACAAA`, which is a
 * real name with RFC 1001 first-level encoding still on it. A test that only
 * checked "did we produce something" would have passed on that for years.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { decodeNetbiosName, looksLikeNbns } from '../../src/services/dissectors/nbns';
import type { ProtocolField } from '../../src/types/packet';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

/**
 * RFC 1001 §14.1 first-level encoding: sixteen bytes become thirty-two
 * letters, each nibble added to `A`. Written out here rather than imported
 * from the dissector, so the test encodes independently of what it checks.
 */
function nbName(name: string, suffix: number, scope?: string): number[] {
  const raw = [...name.toUpperCase().padEnd(15, ' ')].map((c) => c.charCodeAt(0)).concat(suffix);
  const out: number[] = [32];
  for (const b of raw) out.push(0x41 + (b >> 4), 0x41 + (b & 0x0f));
  if (scope) for (const label of scope.split('.')) out.push(label.length, ...[...label].map((c) => c.charCodeAt(0)));
  out.push(0);
  return out;
}

const NB = 0x0020, NBSTAT = 0x0021, IN = 0x0001;

const query = (name: string, suffix: number, flags = 0x0110) => new Bytes()
  .u16(0x8f8e).u16(flags).u16(1, 0, 0, 0)
  .u8(...nbName(name, suffix)).u16(NB, IN).build();

const response = (name: string, suffix: number, address: string, flags = 0x8500) => new Bytes()
  .u16(0x8f8e).u16(flags).u16(0, 1, 0, 0)
  .u8(...nbName(name, suffix)).u16(NB, IN)
  .u32(0x000493e0).u16(6).u16(0x6000).ipv4(address).build();

const cases: SyntheticCase[] = [
  { name: 'a name query', frame: udpFrame(137, 137, query('WORKGROUP', 0x00)) },
  { name: 'a name query response', frame: udpFrame(137, 137, response('WORKGROUP', 0x00, '192.0.2.10')) },

  // The four opcodes DNS has nothing at, which is why reading NBNS as DNS
  // printed "Dynamic update" for a registration.
  { name: 'a registration', frame: udpFrame(137, 137, new Bytes()
      .u16(0x1234).u16(0x2910).u16(1, 0, 0, 1)
      .u8(...nbName('MYPC', 0x20)).u16(NB, IN)
      .u8(0xc0, 0x0c).u16(NB, IN).u32(0x000493e0).u16(6).u16(0x6000).ipv4('192.0.2.11')
      .build()) },
  { name: 'a release', frame: udpFrame(137, 137, new Bytes()
      .u16(0x2345).u16(0x3010).u16(1, 0, 0, 1)
      .u8(...nbName('MYPC', 0x20)).u16(NB, IN)
      .u8(0xc0, 0x0c).u16(NB, IN).u32(0).u16(6).u16(0x0000).ipv4('192.0.2.11')
      .build()) },
  { name: 'a refresh', frame: udpFrame(137, 137, new Bytes()
      .u16(0x3456).u16(0x4010).u16(1, 0, 0, 1)
      .u8(...nbName('MYPC', 0x20)).u16(NB, IN)
      .u8(0xc0, 0x0c).u16(NB, IN).u32(0x000493e0).u16(6).u16(0x6000).ipv4('192.0.2.11')
      .build()) },

  // A group name, whose flags word has the top bit set - the difference
  // between "this machine" and "anyone in this workgroup".
  { name: 'a group-name response', frame: udpFrame(137, 137, new Bytes()
      .u16(0x4567).u16(0x8500).u16(0, 1, 0, 0)
      .u8(...nbName('WORKGROUP', 0x1e)).u16(NB, IN)
      .u32(0x000493e0).u16(6).u16(0xe000).ipv4('192.0.2.255')
      .build()) },

  // Two addresses in one NB record: the RDATA repeats, and a dissector that
  // read only the first would look right on every single-homed host.
  { name: 'a multi-homed response', frame: udpFrame(137, 137, new Bytes()
      .u16(0x5678).u16(0x8500).u16(0, 1, 0, 0)
      .u8(...nbName('DUALNIC', 0x00)).u16(NB, IN)
      .u32(0x000493e0).u16(12)
      .u16(0x6000).ipv4('192.0.2.20')
      .u16(0x6000).ipv4('192.0.2.21')
      .build()) },

  { name: 'a name-in-use error', frame: udpFrame(137, 137, new Bytes()
      .u16(0x6789).u16(0x8506).u16(0, 1, 0, 0)
      .u8(...nbName('TAKEN', 0x00)).u16(NB, IN)
      .u32(0).u16(6).u16(0x6000).ipv4('192.0.2.30')
      .build()) },

  { name: 'a node status query', frame: udpFrame(137, 137, new Bytes()
      .u16(0x789a).u16(0x0000).u16(1, 0, 0, 0)
      .u8(...nbName('*', 0x00)).u16(NBSTAT, IN).build()) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the encoding, on its own ---------------------------------------------
  //
  // Unit-level, because the round trip through tshark cannot distinguish "we
  // decoded it" from "we happened to print the same thing".
  check('a padded name loses its padding, not its suffix',
    decodeNetbiosName('FHEPFCELEHFCEPFFFACACACACACACAAA'),
    { name: 'WORKGROUP', suffix: 0x00, display: 'WORKGROUP<00>' });
  check('the sixteenth byte is the suffix and never part of the name',
    decodeNetbiosName('ENFJFAEDCACACACACACACACACACACACA')?.display, 'MYPC<20>');
  check('a wildcard name survives the padding trim',
    decodeNetbiosName('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')?.name, '*');
  // Padding is spaces, but some stacks pad with NUL; both must trim or the
  // name grows invisible trailing characters that break every comparison.
  // Encoded here rather than written out, because a hand-typed 32-character
  // vector is exactly the thing this test exists to catch being wrong.
  const nulPadded = [...'MYPC'].map((c) => c.charCodeAt(0))
    .concat(new Array(11).fill(0x00)).concat(0x20);
  check('NUL padding trims too',
    decodeNetbiosName(nulPadded.map((b) => String.fromCharCode(0x41 + (b >> 4), 0x41 + (b & 0x0f))).join(''))?.display,
    'MYPC<20>');

  check('a label that is not 32 characters is not a NetBIOS name',
    decodeNetbiosName('EXAMPLE'), null);
  check('...nor is one with a character outside A-P',
    decodeNetbiosName('ZHEPFCELEHFCEPFFFACACACACACACAAA'), null);

  // --- the detector -----------------------------------------------------------
  //
  // `looksLikeNbns` exists so a heuristic path can claim NBNS on a port that is
  // not 137. It must reject ordinary DNS, whose names are not encoded.
  const dnsQuery = new Bytes().u16(0x1234).u16(0x0100).u16(1, 0, 0, 0)
    .u8(7).ascii('example').u8(3).ascii('com').u8(0).u16(1, 1).build();
  check('the detector accepts NBNS', looksLikeNbns(query('WORKGROUP', 0x00), 0, 50), true);
  check('...and rejects a DNS query for example.com', looksLikeNbns(dnsQuery, 0, dnsQuery.length), false);
  check('...and rejects bytes that are not a message at all',
    looksLikeNbns(Uint8Array.from([1, 2, 3]), 0, 3), false);

  // --- what reaches the rest of the app ---------------------------------------
  const frame = udpFrame(137, 137, response('WORKGROUP', 0x00, '192.0.2.10'));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);

  check('the protocol hierarchy sees nbns, not dns',
    packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'nbns']);
  check('the decoded name is published as a field', packet.fields?.['nbns.name'], 'WORKGROUP<00>');
  check('...and the address', packet.fields?.['nbns.addr'], '192.0.2.10');

  // The whole reason this dissector pays for itself twice: `nbns` has been a
  // declared NameSource with rank 30 in services/nameResolution.ts since long
  // before today, and nothing produced one.
  check('a name query response feeds passive name resolution',
    packet.resolved, [{ name: 'WORKGROUP', addresses: ['192.0.2.10'] }]);

  const nbnsLayer = packet.layers.find((l) => l.name === 'NetBIOS Name Service');
  check('the tree carries a NetBIOS Name Service layer', nbnsLayer !== undefined, true);

  // Every row that publishes a field must carry its filter name, or the tree's
  // "Apply as Filter" and "Apply as Column" items are greyed out on it.
  const abbrevs: string[] = [];
  const walk = (fields: ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev) abbrevs.push(f.abbrev);
      if (f.children) walk(f.children);
    }
  };
  walk(nbnsLayer?.fields ?? []);
  for (const required of ['nbns.id', 'nbns.flags', 'nbns.name', 'nbns.type', 'nbns.addr']) {
    check(`the tree row for ${required} carries its filter name`, abbrevs.includes(required), true);
  }

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All NBNS checks passed.');
  process.exit(0);
}

main();
