/**
 * OpenVPN against the reference, row for row.
 *
 *   npx tsx scripts/openvpn/dissect.ts
 *
 * A session's handshake and its data channel, built from the protocol's
 * packet layout - neither fixture holds OpenVPN: both hard resets, an
 * acknowledgement naming the peer's session, the same with tls-auth's HMAC,
 * replay ID and timestamp in front, and P_DATA in both versions.
 *
 * Two things are deliberately not compared. A control packet's TLS fragment
 * is drawn as bytes, where the reference reassembles and dissects the TLS -
 * so no case carries one. And tls-auth's Net Time is a local time whose zone
 * the reference names from Windows ("Jerusalem Daylight Time") and this build
 * from the browser's locale data ("Israel Daylight Time"); its rows are left
 * out of the comparison and its value is checked here instead.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const session = (v: number) => new Array(8).fill(v);
const up = (bytes: number[]) => udpFrameTo(CLIENT, SERVER, 50000, 1194, Uint8Array.from(bytes));
const down = (bytes: number[]) => udpFrameTo(SERVER, CLIENT, 1194, 50000, Uint8Array.from(bytes));
const hmac = new Array(20).fill(0x4d);
const tlsAuth = [...hmac, 0, 0, 0, 1, 0x65, 0x2a, 0, 0];

const cases: OracleCase[] = [
  { label: 'client hard reset', frame: up([7 << 3, ...session(0xa1), 0, 0, 0, 0, 0]) },
  { label: 'server hard reset, acknowledging it', frame: down([8 << 3, ...session(0xb2), 1, 0, 0, 0, 0, ...session(0xa1), 0, 0, 0, 0]) },
  { label: 'an acknowledgement', frame: up([5 << 3, ...session(0xa1), 1, 0, 0, 0, 0, ...session(0xb2)]) },
  { label: 'client hard reset with tls-auth', frame: up([7 << 3, ...session(0xc3), ...tlsAuth, 0, 0, 0, 0, 0]) },
  { label: 'an acknowledgement with tls-auth', frame: down([5 << 3, ...session(0xd4), ...tlsAuth, 1, 0, 0, 0, 0, ...session(0xc3)]) },
  { label: 'P_DATA_V2', frame: up([(9 << 3) | 0, 0, 0, 1, ...new Array(40).fill(0xdd)]) },
  { label: 'P_DATA_V2 under the next key', frame: down([(9 << 3) | 1, 0, 0, 7, ...new Array(72).fill(0xde)]) },
  { label: 'P_DATA_V1', frame: up([(6 << 3) | 0, ...new Array(36).fill(0xdf)]) },
];

const packets = await compareWithReference(cases, { rows: /^openvpn\.(?!net_time)/ });
await checkRevisit(cases);

const netTime = (field: { abbrev?: string; value: unknown; children?: unknown[] }[]): string | undefined =>
  field.find((f) => f.abbrev === 'openvpn.net_time')?.value as string | undefined;
check('tls-auth\'s timestamp is drawn as a date, in 2023', /Oct 14, 2023/.test(netTime(packets[3]?.layers.at(-1)?.fields ?? []) ?? ''));
check('a data packet names its peer', packets[5]?.fields?.['openvpn.peerid'] === 1);

finish('OpenVPN');
