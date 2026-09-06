/**
 * RIP and RIPng, against tshark.
 *
 *   npx tsx scripts/rip/dissect.ts
 *
 * The point of this one is the pair of Info lines, which are gratuitously
 * different and which no amount of reading RFC 2453 and RFC 2080 would
 * predict:
 *
 *     RIPv2   `Response`
 *     RIPng   ` Command Response, Version 1`
 *
 * A leading space, a different word order, and the version spelled out. The
 * temptation is to share one formatter and normalise them; doing that breaks
 * agreement with the reference analyzer on every RIPng frame, and the leading
 * space is exactly the kind of thing a `trim()` "tidies" away. Both spellings
 * are asserted here so neither can be quietly unified.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectRip, dissectRipng } from '../../src/services/dissectors/rip';
import {
  Bytes, check, failureCount, runCases, udp6Frame, udpFrameTo, type SyntheticCase,
} from '../parity/synthetic';

/** RIPv2's own multicast group; RIPv1 broadcast instead. */
const RIP_GROUP = '224.0.0.9';

interface Route { address: string; mask: string; metric: number }

function rip(command: number, version: number, routes: Route[]): Uint8Array {
  const b = new Bytes().u8(command, version).u16(0);
  for (const route of routes) {
    b.u16(2, 0).ipv4(route.address).ipv4(route.mask).ipv4('0.0.0.0').u32(route.metric);
  }
  return b.build();
}

function ripng(command: number, prefixes: { prefix: number[]; length: number; metric: number }[]):
  Uint8Array {
  const b = new Bytes().u8(command, 1).u16(0);
  for (const entry of prefixes) b.raw(entry.prefix).u16(0).u8(entry.length, entry.metric);
  return b.build();
}

const DOC_PREFIX = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const oneRoute: Route[] = [{ address: '192.0.2.0', mask: '255.255.255.0', metric: 1 }];
const threeRoutes: Route[] = [
  { address: '192.0.2.0', mask: '255.255.255.0', metric: 1 },
  { address: '198.51.100.0', mask: '255.255.255.0', metric: 2 },
  // Metric 16 is RIP's infinity - a route being withdrawn, which is the entry
  // worth finding when something has just gone unreachable.
  { address: '203.0.113.0', mask: '255.255.255.0', metric: 16 },
];

const toGroup = (payload: Uint8Array) =>
  udpFrameTo('192.0.2.1', RIP_GROUP, 520, 520, payload);

const cases: SyntheticCase[] = [
  { name: 'a RIPv2 response', frame: toGroup(rip(2, 2, oneRoute)) },
  { name: 'a RIPv2 response carrying three routes', frame: toGroup(rip(2, 2, threeRoutes)) },
  { name: 'a RIPv2 request', frame: toGroup(rip(1, 2, oneRoute)) },
  { name: 'a RIPv1 response', frame: toGroup(rip(2, 1, oneRoute)) },
  // RIPng, whose Info line is spelt differently for no reason anybody records.
  { name: 'a RIPng response', frame: udp6Frame(521, 521,
      ripng(2, [{ prefix: DOC_PREFIX, length: 32, metric: 1 }])) },
  { name: 'a RIPng request', frame: udp6Frame(521, 521,
      ripng(1, [{ prefix: DOC_PREFIX, length: 32, metric: 1 }])) },
  { name: 'a RIPng response carrying two prefixes', frame: udp6Frame(521, 521,
      ripng(2, [
        { prefix: DOC_PREFIX, length: 32, metric: 1 },
        { prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          length: 48, metric: 16 },
      ])) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the two Info spellings, stated so neither can be unified -------------------
  const v2 = rip(2, 2, oneRoute);
  check('RIP writes the bare command', dissectRip(v2, 0, v2.length)?.info, 'Response');
  const ng = ripng(2, [{ prefix: DOC_PREFIX, length: 32, metric: 1 }]);
  check('RIPng writes a longer line, opening with a space',
    dissectRipng(ng, 0, ng.length)?.info, ' Command Response, Version 1');
  // Stated separately, because a `trimStart()` anywhere in the chain would
  // pass the check above only if it were written as `endsWith`.
  check('...and that leading space is real',
    dissectRipng(ng, 0, ng.length)?.info.startsWith(' '), true);

  // --- routes -------------------------------------------------------------------------
  const three = rip(2, 2, threeRoutes);
  const read = dissectRip(three, 0, three.length);
  check('every route is counted', read?.fields['rip.route_count'], 3);
  check('the first route is published', read?.fields['rip.ip'], '192.0.2.0');
  const rows = (read?.layer.fields ?? []).filter((f) => f.name === 'IP Address');
  check('...and each is a row', rows.length, 3);
  // Metric 16 is unreachable, and reads as a bare number unless it is named.
  const withdrawn = rows[2]?.children?.find((f) => f.name === 'Metric');
  check('an infinite metric is named as unreachable', withdrawn?.value, '16 (unreachable)');

  // --- what is not RIP -------------------------------------------------------------------
  //
  // The header is four bytes, two of which are "must be zero" - and those two
  // are the whole fingerprint. Without enforcing them this claims anything on
  // the port.
  const nonZero = rip(2, 2, oneRoute);
  nonZero[2] = 0x01;
  check('a non-zero reserved word is declined', dissectRip(nonZero, 0, nonZero.length), null);
  const version3 = rip(2, 3, oneRoute);
  check('version 3 is declined', dissectRip(version3, 0, version3.length), null);
  const command9 = rip(9, 2, oneRoute);
  check('an unknown command is declined', dissectRip(command9, 0, command9.length), null);
  // RIPng is version 1 over IPv6; a RIPng datagram claiming version 2 is not one.
  const ngV2 = ripng(2, [{ prefix: DOC_PREFIX, length: 32, metric: 1 }]);
  ngV2[1] = 2;
  check('RIPng at version 2 is declined', dissectRipng(ngV2, 0, ngV2.length), null);

  // --- what reaches the rest of the app ------------------------------------------------
  const frame = toGroup(rip(2, 2, threeRoutes));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the RIP protocol chain is right', packet.frameProtocols,
    ['frame', 'eth', 'ip', 'udp', 'rip']);
  check('the command is published', packet.fields?.['rip.command'], 2);

  const ngFrame = udp6Frame(521, 521, ripng(2, [{ prefix: DOC_PREFIX, length: 32, metric: 1 }]));
  const ngPacket = decodeRawEthernetPacket(
    ngFrame, 2, 1_700_000_000_000_000, 0, 1, ngFrame.length).packet;
  // A distinct token, so a filter naming `ripng` does not match a RIPv2 frame.
  check('the RIPng protocol chain is right', ngPacket.frameProtocols,
    ['frame', 'eth', 'ipv6', 'udp', 'ripng']);
  check('the prefix is published', ngPacket.fields?.['rip.ip'], '2001:db8::');

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All RIP checks passed.');
  process.exit(0);
}

main();
