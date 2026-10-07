/**
 * Steam In-Home Streaming discovery against the reference, row for row.
 *
 *   npx tsx scripts/steam/dissect.ts
 *
 * Every Steam client on a LAN broadcasts on UDP 27036 to find the others, and
 * each answers with its host name, OS, users and MAC addresses - so a capture
 * on any network with a gaming PC on it carries them. Neither fixture holds
 * one, so the messages are built here from Steam's own protobuf definitions
 * (`steammessages_remoteclient_discovery.proto`): all eleven types, each body
 * field the reference names, the fields a newer client sends that it does
 * not, and the empty bodies whose Info falls back to the bare type.
 *
 * Not built: an unknown fixed 32-bit field, which the reference misreads (see
 * `dissectors/steamIhs.ts`). Not compared: the Status timestamp, a local time
 * whose zone the reference names from Windows ("Jerusalem Standard Time") and
 * this build from the browser's locale data ("Israel Standard Time"), as
 * `scripts/openvpn/dissect.ts` found; its value is checked here instead.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const varint = (n: bigint | number): number[] => {
  let v = BigInt.asUintN(64, BigInt(n));
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return out;
};
const key = (field: number, wire: number) => varint((field << 3) | wire);
const vi = (field: number, n: bigint | number) => [...key(field, 0), ...varint(n)];
const ld = (field: number, bytes: number[]) => [...key(field, 2), ...varint(bytes.length), ...bytes];
const str = (field: number, s: string) => ld(field, [...new TextEncoder().encode(s)]);
const fixed64 = (field: number, n: bigint) => [...key(field, 1), ...Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn))];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];

const SIGNATURE = [0xff, 0xff, 0xff, 0xff, 0x21, 0x4c, 0x5f, 0xa0];
const message = (header: number[], body: number[]) =>
  Uint8Array.from([...SIGNATURE, ...le32(header.length), ...header, ...le32(body.length), ...body]);
const header = (type: number) => [...vi(1, 0x1122334455667788n), ...vi(2, type), ...vi(3, 0x0102030405060708n)];

const PHONE = '192.168.1.20';
const PC = '192.168.1.30';
const BROADCAST = '192.168.1.255';
const broadcast = (from: string, header: number[], body: number[]) => udpFrameTo(from, BROADCAST, 27036, 27036, message(header, body));
const toPc = (type: number, body: number[]) => udpFrameTo(PHONE, PC, 50000, 27036, message(header(type), body));
const toPhone = (type: number, body: number[]) => udpFrameTo(PC, PHONE, 27036, 50000, message(header(type), body));

const cases: OracleCase[] = [
  { label: 'a discovery broadcast', frame: broadcast(PHONE, header(0), vi(1, 7)) },
  { label: 'a discovery naming known clients', frame: broadcast(PHONE, header(0), [...vi(1, 8), ...vi(2, 0x1122334455667788n), ...vi(2, 99)]) },
  {
    label: 'a status answer, with the fields a newer client adds',
    frame: broadcast(PC, header(1), [
      ...vi(1, 8), ...vi(2, 6), ...vi(3, 27036), ...str(4, 'GAMING-PC'), ...vi(6, 1), ...vi(7, -500), ...vi(8, 1),
      ...ld(9, [...fixed64(1, 76561197960287930n), ...vi(2, 12345)]),
      ...vi(11, 1), ...vi(12, 1700000000), ...vi(13, 0), ...vi(14, 1),
      ...str(15, '00:11:22:33:44:55'), ...str(15, '66:77:88:99:aa:bb'),
      ...vi(16, 5), ...vi(17, 0), ...vi(18, 0), ...vi(19, 0), ...vi(20, 1), ...ld(22, [1, 2, 3]),
    ]),
  },
  { label: 'a client going offline', frame: broadcast(PC, header(2), []) },
  { label: 'an authorization request', frame: toPc(3, [...ld(1, [1, 2, 3, 4]), ...str(2, 'Phone'), ...ld(3, [9, 9])]) },
  { label: 'an authorization denied', frame: toPhone(4, vi(1, 1)) },
  {
    label: 'a streaming request',
    frame: toPc(5, [...vi(1, 3), ...vi(2, 1920), ...vi(3, 1080), ...vi(4, 2), ...str(5, '1.0'), ...vi(6, 1),
      ...ld(7, [5]), ...ld(8, [0x31, 0x32]), ...vi(9, 1), ...vi(10, 1), ...vi(11, 0)]),
  },
  { label: 'a streaming response asking for a PIN', frame: toPhone(6, [...vi(1, 3), ...vi(2, 11), ...vi(3, 27031), ...ld(4, [7, 7]), ...vi(5, 2)]) },
  { label: 'a proof request', frame: toPc(7, ld(1, [1, 1, 1])) },
  { label: 'a proof response', frame: toPhone(8, ld(1, [2, 2])) },
  { label: 'an authorization cancelled', frame: toPc(9, []) },
  { label: 'a streaming request cancelled', frame: toPc(10, vi(1, 3)) },
  { label: 'a message type nobody names', frame: toPc(42, vi(1, 3)) },
  // Empty bodies: the Info column is the bare type.
  { label: 'an empty discovery', frame: broadcast(PHONE, header(0), []) },
  { label: 'an empty status', frame: broadcast(PC, header(1), []) },
  { label: 'an empty authorization request', frame: toPc(3, []) },
  { label: 'an empty authorization response', frame: toPhone(4, []) },
  { label: 'an authorization result nobody names', frame: toPhone(4, vi(1, 99)) },
  { label: 'an empty streaming request', frame: toPc(5, []) },
  { label: 'an empty streaming response', frame: toPhone(6, []) },
  { label: 'a streaming result nobody names', frame: toPhone(6, vi(2, 99)) },
  { label: 'an empty streaming cancel', frame: toPc(10, []) },
  // A header missing fields, or carrying one it should not.
  { label: 'a header with an extra field and no IDs', frame: broadcast(PHONE, [...vi(2, 0), ...vi(7, 5)], vi(1, 1)) },
  { label: 'a header with no message type', frame: broadcast(PHONE, vi(1, 1), vi(1, 1)) },
  { label: 'two users, each with one field', frame: broadcast(PC, header(1), [...ld(9, vi(2, 5)), ...ld(9, fixed64(1, 5n))]) },
  // No signature: plain UDP, here and in the reference.
  { label: 'a datagram on 27036 without the signature', frame: udpFrameTo(PHONE, BROADCAST, 27036, 27036, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])) },
];

const packets = await compareWithReference(cases, { rows: /^steam_ihs_discovery\.(?!body_status_timestamp)/ });
await checkRevisit(cases);
check('a discovery is the `steam_ihs_discovery` layer over UDP',
  packets[0]?.frameProtocols?.slice(-2).join(':') === 'udp:steam_ihs_discovery', packets[0]?.frameProtocols?.join(':'));
check('the answering host is a field', packets[2]?.fields?.['steam_ihs_discovery.body_status_hostname'] === 'GAMING-PC');
check('a negative OS type reads as one', packets[2]?.fields?.['steam_ihs_discovery.body_status_ostype'] === -500);
const timestamp = packets[2]?.layers.at(-1)?.fields.find((f) => f.abbrev === 'steam_ihs_discovery.body_status_timestamp')?.value;
check('the status timestamp is drawn as a date, in November 2023', /^Nov 1[45], 2023 /.test(String(timestamp)), String(timestamp));
finish('steam');
