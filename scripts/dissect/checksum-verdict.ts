/**
 * When may the app say a checksum is BAD?
 *
 *   npx tsx scripts/dissect/checksum-verdict.ts
 *
 * ## Why this exists
 *
 * `dissect/transportShared.ts` carries this app's answer to the problem
 * Wireshark solves by shipping TCP/UDP validation off by default: a frame
 * captured on the sending host, before the NIC filled its checksum in, is
 * `Unverified` rather than `Bad`. Knowing the direction is what lets this app
 * be more precise than a global switch - and that knowledge comes from the
 * agent's `adapter_config`, which is the part that can be absent.
 *
 * **When it is absent, every frame this machine sends reads as corrupt.**
 * `directionFromMacs` answers `Unknown` the moment `host.macs` is empty
 * (`services/direction.ts`), `sentByUs` collapsed that to `false`, and the
 * verdict then validated bytes the NIC had not finished writing. Measured in
 * `pcapParser.ts`'s own header: 3,891 and 3,594 "Bad checksum" findings, 30.3%
 * and 24.4% of the list painted `Broken`.
 *
 * ## The distinction this file defends
 *
 * "Not sent by us" and "we cannot tell" are different facts, and only the
 * first licenses a `Bad`. But the second must not be stretched to excuse
 * everything: a frame between two other machines on a mirror port is
 * `Transit`, which IS known, and its checksum must still be checked. That pair
 * is why this is a file rather than a line - the fix and its over-correction
 * fail in opposite directions and only one of them is loud.
 *
 * No fixtures: the frames are built here, byte by byte, so the whole thing
 * runs under plain `tsx` in the ordinary suite.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { NO_HOST, type HostIdentity } from '../../src/services/direction';

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

const US = 'aa:bb:cc:dd:ee:02';
const THEM = 'aa:bb:cc:dd:ee:01';
const STRANGER = '99:99:99:99:99:99';

const hostWith = (...macs: string[]): HostIdentity => ({
  macs: new Set(macs), addresses: new Set(['10.0.0.2']), inferred: false, confidence: 1,
});

/** One's-complement sum, for the IPv4 header so the L3 verdict stays out of this. */
function ones(b: Uint8Array, start: number, end: number): number {
  let sum = 0;
  for (let i = start; i + 1 < end; i += 2) sum += (b[i] << 8) | b[i + 1];
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/**
 * A 54-byte TCP SYN from 10.0.0.2 to 10.0.0.1, with a correct IPv4 header
 * checksum and a **deliberately wrong** TCP one.
 *
 * The TCP value is non-zero on purpose: a stored zero is `Unverified` by a
 * different rule, and a test that tripped that rule would pass for the wrong
 * reason no matter what the direction logic did.
 */
function badTcpFrame(): Uint8Array {
  const f = new Uint8Array(54);
  f.set(THEM.split(':').map((h) => parseInt(h, 16)), 0);
  f.set(US.split(':').map((h) => parseInt(h, 16)), 6);
  f[12] = 0x08; f[13] = 0x00;

  const ip = 14;
  f[ip] = 0x45;
  f[ip + 2] = 0x00; f[ip + 3] = 0x28;   // total length 40 = 20 IP + 20 TCP
  f[ip + 5] = 1;
  f[ip + 6] = 0x40;
  f[ip + 8] = 64; f[ip + 9] = 6;
  f.set([10, 0, 0, 2], ip + 12);
  f.set([10, 0, 0, 1], ip + 16);
  const ipc = ones(f, ip, ip + 20);
  f[ip + 10] = ipc >> 8; f[ip + 11] = ipc & 0xff;

  const t = 34;
  f[t] = 0x30; f[t + 1] = 0x39;          // sport 12345
  f[t + 3] = 0x50;                       // dport 80
  f[t + 7] = 1;                          // seq
  f[t + 12] = 0x50; f[t + 13] = 0x02;    // data offset 5, SYN
  f[t + 14] = 0xff; f[t + 15] = 0xff;
  f[t + 16] = 0x12; f[t + 17] = 0x34;    // wrong, and not zero
  return f;
}

function statusWith(host: HostIdentity | undefined): unknown {
  const f = badTcpFrame();
  const { packet } = decodeRawEthernetPacket(
    f, 1, 1_000_000, 0, 0, f.length,
    undefined, undefined, undefined, undefined, undefined, undefined, undefined, host,
  );
  return (packet.fields as Record<string, unknown> | undefined)?.['tcp.checksum.status'];
}

console.log('\n--- a known direction decides the verdict ---\n');

// The control. Our MAC is the destination, so the frame arrived; its checksum
// really is wrong and saying so is the whole point of the check.
check('a frame we received with a wrong checksum is Bad',
  statusWith(hostWith(THEM)), 'Bad');

// The offload exemption, which already worked.
check('a frame we sent is Unverified, not Bad',
  statusWith(hostWith(US)), 'Unverified');

console.log('\n--- an UNKNOWN direction is not an inbound one ---\n');

// The regression. With no host identity every frame this machine sends was
// validated against bytes the NIC had not finished writing.
check('with no host identity at all, the verdict is Unverified',
  statusWith(undefined), 'Unverified');

check('with a host carrying no MACs, the verdict is Unverified',
  statusWith(NO_HOST), 'Unverified');

console.log('\n--- and the over-correction is refused ---\n');

// The other way this can be got wrong: excusing everything whose direction is
// not `Out`. Transit is a KNOWN direction - somebody else's conversation on a
// mirror port or through promiscuous mode - and nothing about it says a NIC
// was mid-write, so its checksum is still checkable.
check('a transit frame between two other machines is still Bad',
  statusWith(hostWith(STRANGER)), 'Bad');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checksum verdict checks passed.');
process.exit(0);
