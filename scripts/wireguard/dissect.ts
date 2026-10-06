/**
 * WireGuard against the reference, row for row, sessions included.
 *
 *   npx tsx scripts/wireguard/dissect.ts
 *
 * The VPN under Mullvad, NordLynx, Cloudflare WARP and Tailscale, found by
 * content on whatever port it runs. Built here from the protocol's own message
 * layouts - neither fixture holds any - as a conversation: two handshakes, a
 * response to each, data both ways, a keepalive and a cookie reply, so the
 * session numbering and the response link are tested as the reference keeps
 * them across frames, not just each message's rows.
 */
import { Bytes, udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { looksLikeWireGuard } from '../../src/services/dissectors/wireguard';

const fill = (n: number, v: number) => new Array(n).fill(v);
/** Indices are little-endian on the wire. */
const le = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
const initiation = (sender: number, reserved = [0, 0, 0]) => new Bytes().u8(1, ...reserved).raw(le(sender))
  .raw(fill(32, 0xa1)).raw(fill(48, 0xa2)).raw(fill(28, 0xa3)).raw(fill(16, 0xa4)).raw(fill(16, 0)).build();
const response = (sender: number, receiver: number) => new Bytes().u8(2, 0, 0, 0).raw(le(sender)).raw(le(receiver))
  .raw(fill(32, 0xb1)).raw(fill(16, 0xb2)).raw(fill(16, 0xb3)).raw(fill(16, 0)).build();
const cookie = (receiver: number) => new Bytes().u8(3, 0, 0, 0).raw(le(receiver)).raw(fill(24, 0xc1)).raw(fill(32, 0xc2)).build();
const data = (receiver: number, counter: number, plaintext: number) => new Bytes().u8(4, 0, 0, 0).raw(le(receiver))
  .raw(le(counter)).raw(le(0)).raw(fill(plaintext + 16, 0xd1)).build();

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const up = (port: number, payload: Uint8Array) => udpFrameTo(CLIENT, SERVER, port, 51820, payload);
const down = (port: number, payload: Uint8Array) => udpFrameTo(SERVER, CLIENT, 51820, port, payload);

const cases: OracleCase[] = [
  { label: 'a handshake initiation', frame: up(50000, initiation(0x11223344)) },
  { label: 'its response', frame: down(50000, response(0x55667788, 0x11223344)) },
  { label: 'data from the initiator', frame: up(50000, data(0x55667788, 0, 96)) },
  { label: 'data from the responder', frame: down(50000, data(0x11223344, 0, 1280)) },
  { label: 'a keepalive', frame: up(50000, data(0x55667788, 1, 0)) },
  // A second session from another port: a stream of its own.
  { label: 'a second initiation', frame: up(50001, initiation(0x01020304)) },
  { label: 'a cookie reply to it, under load', frame: down(50001, cookie(0x01020304)) },
  { label: 'the first session carries on', frame: up(50000, data(0x55667788, 2, 48)) },
  // Cloudflare's implementation sets the reserved bytes during the handshake.
  { label: 'an initiation with load-balancing bits', frame: up(50002, initiation(0x0a0b0c0d, [0x12, 0x34, 0x56])) },
  // Data from a handshake before the capture began: no session to name.
  { label: 'data with no handshake seen', frame: udpFrameTo(CLIENT, SERVER, 40000, 443, data(0xdeadbeef, 900, 64)) },
];

const packets = await compareWithReference(cases, { rows: /^wg\./ });
await checkRevisit(cases);

check('the response links to its initiation', packets[1]?.fields?.['wg.response_to'] === 1);
check('`wg.stream == 0` is the first session, both ways',
  [0, 1, 2, 3, 4, 7].every((i) => packets[i]?.fields?.['wg.stream'] === 0));
check('the second session is stream 1', packets[5]?.fields?.['wg.stream'] === 1);
check('data on port 443 is still WireGuard', packets[9]?.protocolLabel === 'WireGuard');

// --- what is not WireGuard -----------------------------------------------------
const rejects = (name: string, bytes: number[]) =>
  check(`${name} is not WireGuard`, !looksLikeWireGuard(Uint8Array.from(bytes), 0, bytes.length));
rejects('an initiation one byte short', [1, 0, 0, 0, ...fill(143, 1)]);
rejects('data with reserved bits set', [4, 0, 1, 0, ...fill(60, 1)]);
rejects('data shorter than its tag', [4, 0, 0, 0, ...fill(20, 1)]);
rejects('a type 5', [5, 0, 0, 0, ...fill(60, 1)]);

finish('WireGuard');
