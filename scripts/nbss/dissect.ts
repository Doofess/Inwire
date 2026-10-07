/**
 * The NetBIOS Session Service - and the SMB1 Negotiate a client still opens
 * with - against the reference, row for row.
 *
 *   npx tsx scripts/nbss/dissect.ts
 *
 * On TCP 139 a client must ask for a session by the server's NetBIOS name
 * before it may speak SMB, and the answer - yes, no and why, or "try that
 * address" - is the first thing to read when a connection to an old file
 * server fails. On 445 the same framing is only a length in front of each SMB
 * message, SMB2's included. And the first SMB message on many connections is
 * still an SMB1 Negotiate listing every dialect the client knows, `SMB 2.???`
 * among them. Built from RFC 1002 and MS-CIFS, one connection each, and
 * compared with tshark's reading of the same file.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const le16 = (n: number) => [n & 255, (n >> 8) & 255];
const ascii = (text: string) => [...new TextEncoder().encode(text)];

function netbiosName(name: string, suffix: number): number[] {
  const raw = [...ascii(name.padEnd(15, ' ')).slice(0, 15), suffix];
  return [32, ...raw.flatMap((c) => [0x41 + (c >> 4), 0x41 + (c & 15)]), 0];
}

/** A TCP connection to `port` whose segments carry consistent sequence numbers. */
let nextClientPort = 50000;
function connection(port: number) {
  const clientPort = nextClientPort++;
  let clientSeq = 1000;
  let serverSeq = 5000;
  return (fromClient: boolean, payload: number[]): Uint8Array => {
    const body = Uint8Array.from(payload);
    const segment = fromClient
      ? tcp(clientPort, port, clientSeq, serverSeq, body)
      : tcp(port, clientPort, serverSeq, clientSeq, body);
    const frame = Uint8Array.from([...ethernet(0x0800).build(),
      ...ipv4(6, segment, fromClient ? CLIENT : SERVER, fromClient ? SERVER : CLIENT)]);
    if (fromClient) clientSeq += body.length; else serverSeq += body.length;
    return frame;
  };
}

/** An NBSS message as 139 frames it: type, the 17th length bit, sixteen more. */
const session = (type: number, body: number[]) => [type, body.length >> 16, (body.length >> 8) & 255, body.length & 255, ...body];
/** As 445 frames it: type and a 24-bit length. */
const direct = (body: number[]) => [0, (body.length >> 16) & 255, (body.length >> 8) & 255, body.length & 255, ...body];

const smbHeader = (cmd: number) => [0xff, 0x53, 0x4d, 0x42, cmd, 0, 0, 0, 0, 0x18, ...le16(0xc853), 0, 0,
  ...new Array(8).fill(0), 0, 0, ...le16(0xffff), ...le16(0xfeff), ...le16(0), ...le16(0)];
const DIALECTS = ['PC NETWORK PROGRAM 1.0', 'LANMAN1.0', 'Windows for Workgroups 3.1a', 'LM1.2X002', 'LANMAN2.1',
  'NT LM 0.12', 'SMB 2.002', 'SMB 2.???'];
const dialectBytes = DIALECTS.flatMap((d) => [0x02, ...ascii(d), 0]);
const negotiate = [...smbHeader(0x72), 0, ...le16(dialectBytes.length), ...dialectBytes];

/** SMB2's NEGOTIATE response, header and fixed part, no security blob. */
const smb2Negotiate = [
  0xfe, 0x53, 0x4d, 0x42, ...le16(64), 0, 0, 0, 0, 0, 0, ...le16(0), ...le16(1), 1, 0, 0, 0, 0, 0, 0, 0,
  ...new Array(8).fill(0), 0, 0, 0, 0, 0, 0, 0, 0, ...new Array(8).fill(0), ...new Array(16).fill(0),
  ...le16(65), 1, 0, ...le16(0x02ff), 0, 0, ...new Array(16).fill(0x11), 7, 0, 0, 0,
  0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, ...new Array(16).fill(0), ...le16(128), ...le16(0), 0, 0, 0, 0,
];

const cases: OracleCase[] = [];
{
  const c = connection(139);
  cases.push(
    { label: 'a session request', frame: c(true, session(0x81, [...netbiosName('SERVER', 0x20), ...netbiosName('LAPTOP1', 0x00)])) },
    { label: 'a positive session response', frame: c(false, session(0x82, [])) },
    { label: 'SMB1 Negotiate on 139', frame: c(true, session(0x00, negotiate)) },
    { label: 'a session keep-alive', frame: c(true, session(0x85, [])) },
  );
}
for (const code of [0x80, 0x81, 0x82, 0x83, 0x8f]) {
  const c = connection(139);
  cases.push(
    { label: `a session request to *SMBSERVER (${code})`, frame: c(true, session(0x81, [...netbiosName('*SMBSERVER', 0x20), ...netbiosName('LAPTOP1', 0x00)])) },
    { label: `a negative session response ${code}`, frame: c(false, session(0x83, [code])) },
  );
}
{
  const c = connection(139);
  cases.push(
    { label: 'a session request to be retargeted', frame: c(true, session(0x81, [...netbiosName('SERVER', 0x20), ...netbiosName('LAPTOP1', 0x00)])) },
    { label: 'a retarget response', frame: c(false, session(0x84, [192, 0, 2, 9, 0, 139])) },
  );
}
{
  const c = connection(445);
  cases.push(
    { label: 'SMB1 Negotiate on 445', frame: c(true, direct(negotiate)) },
    { label: 'the SMB2 answer, framed', frame: c(false, direct(smb2Negotiate)) },
  );
}

const packets = await compareWithReference(cases, { rows: /^(nbss|smb)\./ });
await checkRevisit(cases);
const chain = (i: number) => packets[i]?.frameProtocols?.slice(-2).join(':');
check('a session request is the `nbss` layer', packets[0]?.frameProtocols?.at(-1) === 'nbss', chain(0));
check('SMB1 rides on it', chain(2) === 'nbss:smb', chain(2));
check('and so does SMB2', chain(cases.length - 1) === 'nbss:smb2', chain(cases.length - 1));
check('the server asked for is a field', packets[0]?.fields?.['nbss.called_name'] === 'SERVER<20>');
finish('NBSS');
