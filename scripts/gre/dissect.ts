/**
 * GRE, held to tshark on frames built from RFC 2784 and RFC 2890.
 *
 *   npx tsx scripts/gre/dissect.ts
 *
 * The first tunnel here, and the thing it tests is not the header format. It is
 * that `decodeNetworkLayer` can be **called again with a different offset** -
 * the claim `docs/decisions/0023` made and did not check, in the same shape as
 * the claim `0020` made about stream protocols and got wrong.
 *
 * **Every rule below came from asking tshark**, and the first one is why a
 * half-tunnel is worse than no tunnel:
 *
 * - A GRE frame carrying something readable reports the **inner** packet in
 *   Protocol, Info, Source *and* Destination. The outer addresses do not appear
 *   anywhere. Naming such a frame `GRE` and stopping would be wrong on four
 *   columns at once, two of which this build holds at 100%.
 * - The word `GRE` appears **only** when nothing inside could be read, and then
 *   the Info is `Encapsulated <name>` - `IP` rather than `IPv4`, `Transparent
 *   Ethernet bridging` spelt exactly so, and an unknown type as
 *   `Encapsulated 0x1234 (unknown)`.
 * - The optional key, sequence and checksum words change the header's length
 *   and nothing in the columns, which is the point of testing them: get the
 *   length wrong and the inner packet is read at the wrong offset, which shows
 *   up as a plausible wrong answer rather than as a failure.
 */
import {
  Bytes, ethernet, ipv4, ipFrame, internetChecksum, runCases, finish, failureCount,
  type SyntheticCase,
} from '../parity/synthetic';

/** An ICMPv4 echo request with a correct checksum. */
function icmpEcho(id: number, seq: number): Uint8Array {
  const b = new Bytes().u8(8, 0).u16(0).u16(id, seq).ascii('abcdefgh').build();
  const sum = internetChecksum(b);
  b[2] = (sum >> 8) & 0xff;
  b[3] = sum & 0xff;
  return b;
}

/** A TCP SYN - enough for the inner packet to be recognisably TCP. */
const tcpSyn = new Bytes()
  .u16(51000, 443).u32(0).u32(0).u8(0x50, 0x02).u16(64240, 0, 0).build();

/**
 * A GRE header, written out rather than helper-ised: flags and version, the
 * protocol type, then whichever optional words the flags claim.
 */
function gre(protocolType: number, opts: { checksum?: boolean; key?: number; seq?: number } = {}): number[] {
  let flags = 0;
  if (opts.checksum) flags |= 0x8000;           // C
  if (opts.key !== undefined) flags |= 0x2000;  // K
  if (opts.seq !== undefined) flags |= 0x1000;  // S
  const out = new Bytes().u16(flags, protocolType);
  if (opts.checksum) out.u16(0, 0);             // checksum word, then reserved1
  if (opts.key !== undefined) out.u32(opts.key);
  if (opts.seq !== undefined) out.u32(opts.seq);
  return Array.from(out.build());
}

const innerIcmp = ipv4(1, icmpEcho(0x1234, 1), '10.1.1.1', '10.2.2.2');
const innerTcp = ipv4(6, tcpSyn, '10.1.1.1', '10.2.2.2');
/** Transparent Ethernet Bridging: a whole Ethernet frame inside the tunnel. */
const innerEthernet = Uint8Array.from([
  ...ethernet(0x0800).build(),
  ...ipv4(1, icmpEcho(0x5678, 2), '10.3.3.3', '10.4.4.4'),
]);

const greFrame = (header: number[], payload: Uint8Array = new Uint8Array(0)): Uint8Array =>
  ipFrame(47, Uint8Array.from([...header, ...payload]));

const cases: SyntheticCase[] = [
  // The four that matter: the inner packet owns every column.
  { name: 'a tunnelled ICMP echo reports the inner packet', frame: greFrame(gre(0x0800), innerIcmp) },
  { name: 'a tunnelled TCP SYN reports the inner packet', frame: greFrame(gre(0x0800), innerTcp) },
  // Each optional word moves the payload; a wrong header length reads the inner
  // packet at the wrong offset, which looks plausible rather than broken.
  { name: '...with a key in front of it', frame: greFrame(gre(0x0800, { key: 0xdeadbeef }), innerIcmp) },
  { name: '...with a key and a sequence number', frame: greFrame(gre(0x0800, { key: 1, seq: 7 }), innerIcmp) },
  { name: '...with a checksum, which carries a reserved word too', frame: greFrame(gre(0x0800, { checksum: true }), innerIcmp) },
  // Transparent Ethernet Bridging: an inner Ethernet header before the inner IP.
  { name: 'NVGRE looks through the bridged Ethernet frame as well', frame: greFrame(gre(0x6558), innerEthernet) },

  // The only cases where the word GRE appears at all.
  { name: 'an empty tunnel names what it would have carried', frame: greFrame(gre(0x0800)) },
  { name: '...and says IPv6 when that is what it claims', frame: greFrame(gre(0x86dd)) },
  { name: '...and spells transparent Ethernet bridging out', frame: greFrame(gre(0x6558)) },
  { name: 'an unreadable payload type is named in hex', frame: greFrame(gre(0x1234), Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])) },
];

async function main(): Promise<void> {
  await runCases(cases, { compareAddresses: true });
  if (failureCount() > 0) process.exit(1);
  finish('GRE');
}

main();
