/**
 * Remote Desktop's connection setup against the reference, row for row.
 *
 *   npx tsx scripts/rdp/dissect.ts
 *
 * The two segments of every Remote Desktop connection that a capture can
 * still read: the client's X.224 Connect Request with its user cookie and the
 * security it offers, and the server's Connect Confirm with what it chose -
 * or a Negotiation Failure saying why it will not. Then a disconnect. Built
 * from MS-RDPBCGR 2.2.1.1-2 and ISO 8073, one connection each.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const C = '192.0.2.1', S = '192.0.2.2';
let cs = 1000, ss = 5000, port = 50000;
const fresh = () => { cs = 1000; ss = 5000; port++; };
const seg = (up: boolean, p: number[]) => { const b = Uint8Array.from(p); const f = Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, tcp(up ? port : 3389, up ? 3389 : port, up ? cs : ss, up ? ss : cs, b), up ? C : S, up ? S : C)]); if (up) cs += b.length; else ss += b.length; return f; };
const tpkt = (body: number[]) => [3, 0, (4 + body.length) >> 8, (4 + body.length) & 255, ...body];
const ascii = (t: string) => [...new TextEncoder().encode(t)];
const cookie = ascii('Cookie: mstshash=alice\r\n');
const negReq = [1, 0, 8, 0, 0x0b, 0, 0, 0];   // RDP_NEG_REQ: TLS, CredSSP, CredSSP+EUA
const cr = (extra: number[]) => { const vari = [...cookie, ...extra]; return [6 + vari.length, 0xe0, 0, 0, 0, 0, 0, ...vari]; };
const ccBody = (neg: number[]) => [6 + neg.length, 0xd0, 0, 0, 0x12, 0x34, 0, ...neg];
const negResp = [2, 0x1f, 8, 0, 2, 0, 0, 0];  // RDP_NEG_RSP: selected CredSSP
const negFail = [3, 0, 8, 0, 5, 0, 0, 0];      // RDP_NEG_FAILURE: CredSSP required
const frames: Uint8Array[] = [];
frames.push(seg(true, tpkt(cr(negReq))), seg(false, tpkt(ccBody(negResp)))); fresh();
frames.push(seg(true, tpkt(cr([1, 0x03, 8, 0, 0x0f, 0, 0, 0]))), seg(false, tpkt(ccBody(negFail)))); fresh();
frames.push(seg(true, tpkt(cr([]))), seg(false, tpkt(ccBody([])))); fresh();
frames.push(seg(true, tpkt([6, 0x80, 0, 0, 0x12, 0x34, 0])));


const labels = [
  'a request offering TLS and CredSSP, with its cookie', 'the server chooses CredSSP',
  'a request with both admin flags set', 'the server refuses: CredSSP required',
  'a cookie and nothing else', 'a confirm with no negotiation', 'a disconnect',
];
const cases: OracleCase[] = frames.map((frame, i) => ({ label: labels[i], frame }));
const packets = await compareWithReference(cases, { rows: /^(tpkt|cotp|rdp)\./, twoPass: true });
await checkRevisit(cases);
check('the cookie is filterable', packets[0]?.fields?.['rdp.rt_cookie'] === 'Cookie: mstshash=alice');
check('the refusal is filterable', packets[3]?.fields?.['rdp.negFailure.failureCode'] === 5);
finish('RDP');
