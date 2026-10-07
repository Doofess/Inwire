/**
 * NTLMSSP, and the GSS-API / SPNEGO envelope it travels in, against the
 * reference, row for row.
 *
 *   npx tsx scripts/ntlmssp/dissect.ts
 *
 * How a Windows machine signs in where Kerberos is not on offer - a
 * workgroup, a server reached by address, a proxy - and what a work network
 * carries on every new SMB connection. Neither fixture holds one, so the
 * messages are built from MS-NLMP, RFC 4178 and MS-SMB2 (`frames.ts`): a
 * whole SMB2 sign-in from the server's first offer to its acceptance, the
 * forms a real client sends that the first one does not (OEM strings, NTLMv1,
 * anonymous, no Version, no MIC), a message type nobody names and one cut
 * short; then the same sign-in in a DCE/RPC Bind, Bind_ack and AUTH3 with a
 * signed call after it, and in HTTP's NTLM and Negotiate headers.
 *
 * Not compared: the two AV-pair Timestamps, local times whose zone the
 * reference names from Windows ("Jerusalem Daylight Time") and this build
 * from the browser's locale data ("Israel Daylight Time"), as
 * `scripts/openvpn/dissect.ts` found; their dates are checked here instead.
 */
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import * as F from './frames';

const ROWS = /^(gss-api|spnego|ntlmssp)\.(?!challenge\.target_info\.timestamp|ntlmv2_response\.timestamp)/;

const NEGOTIATE_FLAGS = 0xe2088297;
const CHALLENGE_FLAGS = 0xe28a8215;
const AUTH_FLAGS = 0xe2888215;
const targetInfo = [
  F.avText(2, 'CORP'), F.avText(1, 'FILESRV'), F.avText(4, 'corp.example'), F.avText(3, 'filesrv.corp.example'),
  F.avText(5, 'corp.example'), F.av(7, F.le64(F.FILETIME)),
];
const responseInfo = [
  ...targetInfo, F.av(6, F.le32(2)), F.av(8, [48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, ...new Array(32).fill(0x99)]),
  F.av(10, new Array(16).fill(0)), F.avText(9, 'cifs/filesrv'),
];
const v2Auth = (user: string, lm = new Array(24).fill(0)) =>
  F.authenticate(AUTH_FLAGS, 'CORP', user, 'LAPTOP', lm, F.ntlmv2Response(responseInfo), new Array(16).fill(0x5a));
const verifier = (fill: number) => [1, 0, 0, 0, ...new Array(12).fill(fill)];

// --- one SMB2 sign-in, from the server's offer to its acceptance --------------
const smb = new F.Connection('192.0.2.1', '192.0.2.2', 50000, 445);
const MORE_PROCESSING = 0xc0000016;
const cases: OracleCase[] = [
  { label: 'the mechanisms a server offers', frame: smb.segment(false, F.negotiateResponse(0, F.negTokenInit(
    [[0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 0x1e], F.MSKRB5_OID, F.KRB5_OID, [...F.KRB5_OID, 3], F.NTLMSSP_OID], undefined, true))) },
  { label: 'NEGOTIATE in a negTokenInit', frame: smb.segment(true, F.sessionSetupRequest(1, 0n, F.negTokenInit([F.NTLMSSP_OID], F.negotiate(NEGOTIATE_FLAGS)))) },
  { label: 'CHALLENGE in a negTokenTarg', frame: smb.segment(false, F.sessionSetupResponse(1, 0x1000n, MORE_PROCESSING,
    F.negTokenResp({ state: 1, mech: F.NTLMSSP_OID, token: F.challenge(CHALLENGE_FLAGS, 'CORP', targetInfo) }))) },
  { label: 'AUTHENTICATE, NTLMv2, with a MIC and a mechListMIC', frame: smb.segment(true, F.sessionSetupRequest(2, 0x1000n,
    F.negTokenResp({ token: v2Auth('alice'), mic: verifier(0x77) }))) },
  { label: 'the server accepting', frame: smb.segment(false, F.sessionSetupResponse(2, 0x1000n, 0, F.negTokenResp({ state: 0, mic: verifier(0x66) }))) },
  // The forms a real client sends that the one above does not.
  { label: 'NEGOTIATE naming its domain and host, no Version', frame: smb.segment(true, F.sessionSetupRequest(3, 0n,
    F.negTokenInit([F.NTLMSSP_OID], F.negotiate(0x3207, 'CORP', 'LAPTOP', false)))) },
  { label: 'a raw NTLMSSP blob, no SPNEGO', frame: smb.segment(true, F.sessionSetupRequest(4, 0n, F.negotiate(NEGOTIATE_FLAGS))) },
  { label: 'NTLMSSP straight under GSS-API', frame: smb.segment(true, F.sessionSetupRequest(5, 0n,
    F.tlv(0x60, [...F.tlv(0x06, F.NTLMSSP_OID), ...F.negotiate(NEGOTIATE_FLAGS)]))) },
  { label: 'a CHALLENGE with an unknown and a short AV pair', frame: smb.segment(false, F.sessionSetupResponse(5, 0x1001n, MORE_PROCESSING,
    F.negTokenResp({ state: 1, mech: F.NTLMSSP_OID, token: F.challenge(0x00028233, 'SRV', [F.av(6, F.le32(1)), F.av(0x55, [1, 2, 3]), F.av(8, [1, 2])]) }))) },
  { label: 'AUTHENTICATE, NTLMv1, no Version or MIC', frame: smb.segment(true, F.sessionSetupRequest(6, 0x1001n, F.negTokenResp({
    token: F.authenticate(0x8205, 'CORP', 'bob', 'PC1', new Array(24).fill(0x11), new Array(24).fill(0x22), [], false) }))) },
  { label: 'AUTHENTICATE, anonymous', frame: smb.segment(true, F.sessionSetupRequest(7, 0x1001n, F.negTokenResp({
    token: F.authenticate(0x0a05, '', '', '', [0], [], [], true) }))) },
  { label: 'AUTHENTICATE, NTLM2 session response, Version but no MIC', frame: smb.segment(true, F.sessionSetupRequest(8, 0x1001n, F.negTokenResp({
    token: F.authenticate(AUTH_FLAGS, 'CORP', 'carol', 'PC2', [1, 2, 3, 4, 5, 6, 7, 8, ...new Array(16).fill(0)],
      F.ntlmv2Response([F.avText(2, 'CORP')]), new Array(16).fill(1), false) }))) },
  { label: 'AUTHENTICATE with OEM strings', frame: smb.segment(true, F.sessionSetupRequest(9, 0x1001n, F.negTokenResp({
    token: F.authenticate(0x0206, 'CORP', 'dave', 'PC3', new Array(24).fill(0x33), new Array(24).fill(0x44), [], false, true) }))) },
  { label: 'NTLMSSP_UNKNOWN', frame: smb.segment(true, F.sessionSetupRequest(10, 0x1001n, F.negTokenResp({ token: [...F.ascii('NTLMSSP\0'), ...F.le32(4), 1, 2, 3, 4] }))) },
  { label: 'a message type nobody names', frame: smb.segment(true, F.sessionSetupRequest(11, 0x1001n, F.negTokenResp({ token: [...F.ascii('NTLMSSP\0'), ...F.le32(9), 1, 2, 3, 4] }))) },
  { label: 'a CHALLENGE cut short', frame: smb.segment(false, F.sessionSetupResponse(11, 0x1001n, MORE_PROCESSING, F.negTokenResp({
    token: F.challenge(CHALLENGE_FLAGS, 'CORP', [F.avText(2, 'CORP')]).slice(0, 30) }))) },
  { label: 'a GSS-API token for a mechanism nobody names', frame: smb.segment(true, F.sessionSetupRequest(12, 0n,
    F.tlv(0x60, [...F.tlv(0x06, [0x2a, 3, 4]), 1, 2, 3]))) },
  { label: 'the server refusing', frame: smb.segment(false, F.sessionSetupResponse(12, 0x1001n, 0xc000006d, F.negTokenResp({ state: 2 }))) },
];

// --- DCE/RPC: the sign-in in the auth verifier, then each PDU's signature -----
const uuid = (text: string) => {
  const b = text.replace(/-/g, '').match(/../g)!.map((x) => parseInt(x, 16));
  return [...b.slice(0, 4).reverse(), ...b.slice(4, 6).reverse(), ...b.slice(6, 8).reverse(), ...b.slice(8)];
};
const SRVSVC = '4b324fc8-1670-01d3-1278-5a47bf6ee188';
const NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860';
/** A PDU whose body is padded to four, then its sec_trailer (NTLMSSP, `level`, context 79231) and verifier. */
const rpcPdu = (type: number, callId: number, body: number[], auth: number[], level = 6) => {
  const pad = (4 - (body.length % 4)) % 4;
  const rest = [...body, ...new Array(pad).fill(0), 10, level, pad, 0, ...F.le32(79231), ...auth];
  return [5, 0, type, 3, 0x10, 0, 0, 0, ...F.le16(16 + rest.length), ...F.le16(auth.length), ...F.le32(callId), ...rest];
};
const bind = [...F.le16(5840), ...F.le16(5840), ...F.le32(0), 1, 0, 0, 0,
  ...F.le16(0), 1, 0, ...uuid(SRVSVC), ...F.le16(3), ...F.le16(0), ...uuid(NDR), ...F.le32(2)];
const port = [...'49670'].map((c) => c.charCodeAt(0)).concat(0);
const bindAckHead = [...F.le16(5840), ...F.le16(5840), ...F.le32(0x1234), ...F.le16(port.length), ...port];
const bindAck = [...bindAckHead, ...new Array((4 - ((16 + bindAckHead.length) % 4)) % 4).fill(0),
  1, 0, 0, 0, ...F.le16(0), ...F.le16(0), ...uuid(NDR), ...F.le32(2)];
const request = (stub: number[]) => [...F.le32(stub.length), ...F.le16(0), ...F.le16(21), ...stub];
const rpc = new F.Connection('192.0.2.1', '192.0.2.2', 50001, 49670);
cases.push(
  { label: 'an RPC Bind carrying NEGOTIATE', frame: rpc.segment(true, rpcPdu(11, 1, bind, F.negotiate(NEGOTIATE_FLAGS))) },
  { label: 'its Bind_ack carrying CHALLENGE', frame: rpc.segment(false, rpcPdu(12, 1, bindAck, F.challenge(CHALLENGE_FLAGS, 'CORP', targetInfo))) },
  { label: 'AUTH3 carrying AUTHENTICATE', frame: rpc.segment(true, rpcPdu(16, 1, [0, 0, 0, 0], v2Auth('alice'))) },
  { label: 'a signed request', frame: rpc.segment(true, rpcPdu(0, 2, request([...F.le32(0), ...F.le32(101)]), verifier(0x55), 5)) },
);

// --- HTTP: NTLM, and NTLM inside Negotiate ------------------------------------
const http = (connection: F.Connection, fromClient: boolean, lines: string[]) =>
  connection.segment(fromClient, F.ascii(`${lines.join('\r\n')}\r\n\r\n`));
const web = new F.Connection('192.0.2.1', '192.0.2.2', 50002, 80);
const proxy = new F.Connection('192.0.2.1', '192.0.2.3', 50003, 80);
cases.push(
  { label: 'HTTP Authorization: NTLM, NEGOTIATE', frame: http(web, true, ['GET /a HTTP/1.1', 'Host: srv', `Authorization: NTLM ${F.base64(F.negotiate(NEGOTIATE_FLAGS))}`]) },
  { label: 'WWW-Authenticate: NTLM, CHALLENGE', frame: http(web, false, ['HTTP/1.1 401 Unauthorized',
    `WWW-Authenticate: NTLM ${F.base64(F.challenge(CHALLENGE_FLAGS, 'CORP', targetInfo))}`, 'Content-Length: 0']) },
  { label: 'Authorization: NTLM, AUTHENTICATE', frame: http(web, true, ['GET /a HTTP/1.1', 'Host: srv', `Authorization: NTLM ${F.base64(v2Auth('alice'))}`]) },
  { label: 'a 401 offering both schemes', frame: http(proxy, false, ['HTTP/1.1 401 Unauthorized', 'WWW-Authenticate: Negotiate', 'WWW-Authenticate: NTLM', 'Content-Length: 0']) },
  { label: 'Authorization: Negotiate, NEGOTIATE in a negTokenInit', frame: http(proxy, true, ['GET /b HTTP/1.1', 'Host: srv',
    `Authorization: Negotiate ${F.base64(F.negTokenInit([F.NTLMSSP_OID], F.negotiate(NEGOTIATE_FLAGS)))}`]) },
  { label: 'WWW-Authenticate: Negotiate, CHALLENGE in a negTokenTarg', frame: http(proxy, false, ['HTTP/1.1 401 Unauthorized',
    `WWW-Authenticate: Negotiate ${F.base64(F.negTokenResp({ state: 1, mech: F.NTLMSSP_OID, token: F.challenge(CHALLENGE_FLAGS, 'CORP', targetInfo) }))}`, 'Content-Length: 0']) },
  { label: 'Authorization: Negotiate, AUTHENTICATE in a negTokenTarg', frame: http(proxy, true, ['GET /b HTTP/1.1', 'Host: srv',
    `Authorization: Negotiate ${F.base64(F.negTokenResp({ token: v2Auth('alice'), mic: verifier(0x77) }))}`]) },
);

const packets = await compareWithReference(cases, { rows: ROWS });
await checkRevisit(cases);

const at = (label: string) => cases.findIndex((c) => c.label === label);
const chain = (label: string) => packets[at(label)]?.frameProtocols?.join(':');
const endsWith = (label: string, tail: string) => check(`${label} reads ...${tail}`, chain(label)?.endsWith(tail) === true, chain(label));
endsWith('NEGOTIATE in a negTokenInit', 'nbss:smb2:gss-api:spnego:ntlmssp');
endsWith('a raw NTLMSSP blob, no SPNEGO', 'smb2:ntlmssp');
endsWith('NTLMSSP straight under GSS-API', 'smb2:gss-api:ntlmssp');
endsWith('HTTP Authorization: NTLM, NEGOTIATE', 'tcp:http:ntlmssp');
endsWith('Authorization: Negotiate, NEGOTIATE in a negTokenInit', 'tcp:http:gss-api:spnego:ntlmssp');
// The reference's chain stops at `dcerpc` here, as it does for every RPC
// interface this build names as a layer; the bareword `ntlmssp` matches the
// frame in both, which is what the token is for.
endsWith('AUTH3 carrying AUTHENTICATE', 'tcp:dcerpc:ntlmssp');
const auth3 = packets[at('AUTH3 carrying AUTHENTICATE')];
check('the RPC sign-in is drawn inside Auth Info', auth3?.layers.at(-1)?.name.startsWith('Distributed Computing Environment') === true
  && JSON.stringify(auth3?.layers.at(-1)?.fields.find((f) => f.abbrev === 'dcerpc.auth_info')?.children?.at(-1)?.name) === '"NTLM Secure Service Provider"',
  auth3?.layers.map((l) => l.name).join(' / '));
check('who signed in is a field', packets[3]?.fields?.['ntlmssp.auth.username'] === 'alice'
  && packets[3]?.fields?.['ntlmssp.auth.domain'] === 'CORP', JSON.stringify(packets[3]?.fields));
check('NTLMSSP is drawn inside SPNEGO, not after it',
  packets[3]?.layers.every((l) => l.name !== 'NTLM Secure Service Provider' && l.name !== 'Simple Protected Negotiation') === true,
  packets[3]?.layers.map((l) => l.name).join(' / '));
const find = (i: number, abbrev: string) => {
  let found: unknown;
  const walk = (rows: readonly { abbrev?: string; value: unknown; children?: unknown[] }[]) => {
    for (const r of rows) {
      if (r.abbrev === abbrev && found === undefined) found = r.value;
      if (r.children) walk(r.children as typeof rows);
    }
  };
  for (const layer of packets[i]?.layers ?? []) walk(layer.fields);
  return String(found);
};
check('the target info timestamp is a date, on 20 or 21 June 2023', /^Jun 2[01], 2023 /.test(find(2, 'ntlmssp.challenge.target_info.timestamp')),
  find(2, 'ntlmssp.challenge.target_info.timestamp'));
check('...and so is the response\'s', /^Jun 2[01], 2023 /.test(find(3, 'ntlmssp.ntlmv2_response.timestamp')), find(3, 'ntlmssp.ntlmv2_response.timestamp'));

finish('ntlmssp');
