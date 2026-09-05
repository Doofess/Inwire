/**
 * Assertion tests for the IPv6 extension-header chain and the DHCP dissector.
 *
 *   npx tsx scripts/ipv6/extensions.ts
 *
 * The chain is not an optional nicety: every MLDv2 report a device sends
 * carries a Hop-by-Hop header, so a dissector that assumes the transport
 * starts at byte 40 reads the option bytes as an ICMPv6 header and reports a
 * message nobody sent. Five frames in one fixture did exactly that. The
 * lengths are the other trap - three different rules, one of which (the
 * Authentication Header's) is in units of four bytes rather than eight.
 *
 * Frames here are synthesised so the test needs no fixture and holds no real
 * traffic; the MLDv2 case mirrors the shape of the real ones.
 */
import { walkIpv6Extensions, NO_NEXT_HEADER } from '../../src/services/dissectors/ipv6Ext';
import { dissectDhcp } from '../../src/services/dissectors/dhcp';

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

const bytes = (...xs: number[]) => Uint8Array.from(xs);

// --- Hop-by-Hop with a Router Alert, then ICMPv6 (an MLDv2 report) ----------

{
  // Next Header = ICMPv6, Hdr Ext Len = 0 (8 bytes), Router Alert (MLD), PadN.
  const b = bytes(58, 0, 5, 2, 0, 0, 1, 0, /* ICMPv6 */ 143, 0, 0, 0);
  const chain = walkIpv6Extensions(b, 0, 0, b.length);
  check('the chain ends at ICMPv6', chain.finalNextHeader, 58);
  check('...with the transport 8 bytes in', chain.transportOffset, 8);
  check('...and does not stop the dissection', chain.stopsHere, false);
  check('one Hop-by-Hop layer', chain.layers.map((l) => l.name), ['IPv6 Hop-by-Hop Options']);
  check('...naming what follows', chain.layers[0].fields[0].value, 'ICMPv6 (58)');
  check('...and decoding the Router Alert', chain.layers[0].fields.map((f) => f.name).includes('IPv6 Option (Router Alert)'), true);
  check('the Router Alert names its value', chain.layers[0].fields.find((f) => f.name.includes('Router Alert'))?.value, 'MLD (0)');
  check('the filter token is the header, not a field', chain.protocolTokens, ['ipv6.hopopts']);
}

// --- two headers in a row -----------------------------------------------------

{
  // Hop-by-Hop (8 bytes) -> Destination Options (16 bytes) -> TCP.
  const b = new Uint8Array(8 + 16 + 20);
  b.set([60, 0, 1, 4, 0, 0, 0, 0], 0);            // hop-by-hop, next = dest opts
  b.set([6, 1, 1, 12, ...new Array(12).fill(0)], 8); // dest opts len 1 => 16 bytes, next = TCP
  const chain = walkIpv6Extensions(b, 0, 0, b.length);
  check('both headers are walked', chain.layers.map((l) => l.name), ['IPv6 Hop-by-Hop Options', 'IPv6 Destination Options']);
  check('...to the transport at 24', chain.transportOffset, 24);
  check('...ending at TCP', chain.finalNextHeader, 6);
  check('...with both tokens', chain.protocolTokens, ['ipv6.hopopts', 'ipv6.dstopts']);
}

// --- lengths follow three different rules -------------------------------------

{
  // Authentication Header: (len + 2) * 4, NOT (len + 1) * 8.
  const b = new Uint8Array(24 + 8);
  b.set([6, 4, 0, 0, 0, 0, 0, 0], 0); // len 4 => (4 + 2) * 4 = 24 bytes
  const chain = walkIpv6Extensions(b, 0, 51, b.length);
  check('the Authentication Header is measured in 4-byte units', chain.transportOffset, 24);

  // Fragment header is a fixed 8 bytes whatever the length byte says.
  const frag = new Uint8Array(8 + 20);
  frag.set([6, 0xff, 0, 0, 0, 0, 0, 1], 0);
  const fragChain = walkIpv6Extensions(frag, 0, 44, frag.length);
  check('the Fragment header is always 8 bytes', fragChain.transportOffset, 8);
  check('...and the first fragment continues to the transport', fragChain.stopsHere, false);
}

{
  // A non-first fragment carries payload, not a transport header.
  const b = new Uint8Array(8 + 100);
  b.set([6, 0, 0x00, 0xb9, 0, 0, 0, 1], 0); // offset 23 (184 bytes), more=1
  const chain = walkIpv6Extensions(b, 0, 44, b.length);
  // In bytes, not the wire's 8-byte units: every caller wants a byte offset,
  // and converting in one place beats converting in each of them.
  check('a later fragment reports its offset in bytes', chain.fragmentOffset, 184);
  check('...and that more follow', chain.moreFragments, true);
  check('...and stops the dissection', chain.stopsHere, true);
}

// --- the ends of a chain --------------------------------------------------------

{
  const none = walkIpv6Extensions(bytes(NO_NEXT_HEADER, 0, 0, 0, 0, 0, 0, 0), 0, 0, 8);
  check('"No Next Header" stops the chain', none.stopsHere, true);
  check('...and is reported as such', none.finalNextHeader, NO_NEXT_HEADER);

  const esp = walkIpv6Extensions(new Uint8Array(24), 0, 50, 24);
  check('ESP stops the chain - everything after it is encrypted', esp.stopsHere, true);
  check('...and claims no bytes', esp.transportOffset, 0);

  const plain = walkIpv6Extensions(new Uint8Array(20), 0, 6, 20);
  check('a frame with no extension headers is untouched', [plain.layers.length, plain.transportOffset, plain.finalNextHeader], [0, 0, 6]);

  // A truncated header must not read past the end.
  const short = walkIpv6Extensions(bytes(58, 5), 0, 0, 2);
  check('a header longer than the frame is skipped, not misread', short.layers.length, 0);
}

// --- DHCP ------------------------------------------------------------------------

{
  // A minimal DHCP Request: BOOTP header, magic cookie, options 53, 12, 55, 255.
  const b = new Uint8Array(240 + 20);
  b.set([1, 1, 6, 0, 0xa3, 0xb5, 0x90, 0xd4], 0);           // op, htype, hlen, hops, xid
  b.set([192, 0, 2, 44], 16);                                // yiaddr
  b.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x2c], 28);           // chaddr
  b.set([0x63, 0x82, 0x53, 0x63], 236);                      // magic cookie
  let p = 240;
  b.set([53, 1, 3], p); p += 3;                              // DHCP Request
  b.set([12, 6, 0x6c, 0x61, 0x70, 0x74, 0x6f, 0x70], p); p += 8; // Host Name "laptop"
  b.set([55, 3, 1, 3, 6], p); p += 5;                        // Parameter Request List
  b[p] = 255;

  const dhcp = dissectDhcp(b, 0, b.length)!;
  check('DHCP parses', !!dhcp, true);
  check('...with Wireshark\'s padded Info line', dhcp.info, 'DHCP Request  - Transaction ID 0xa3b590d4');
  check('...the hostname, which is what names the device', dhcp.hostname, 'laptop');
  check('...the client MAC', dhcp.clientMac, '02:00:00:00:00:2c');
  check('...the offered address', dhcp.yourIp, '192.0.2.44');
  check('...and the parameter list that fingerprints the OS', dhcp.parameterRequestList, [1, 3, 6]);
  check('the hostname is filterable', dhcp.fields['dhcp.option.hostname'], 'laptop');
  check('an ACK pads to the same width', (() => {
    const ack = b.slice();
    ack[242] = 5;
    return dissectDhcp(ack, 0, ack.length)!.info;
  })(), 'DHCP ACK      - Transaction ID 0xa3b590d4');
  check('a datagram with no magic cookie is not DHCP', dissectDhcp(new Uint8Array(300), 0, 300), null);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All IPv6 extension and DHCP checks passed.');
process.exit(0);
