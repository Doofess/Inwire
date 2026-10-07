/**
 * DCE/RPC over TCP, and the endpoint mapper's Map, against the reference.
 *
 *   npx tsx scripts/dcerpc/dissect.ts
 *
 * A Windows client asks the endpoint mapper on 135 where an interface lives,
 * then binds to it on the port it was given and calls it. What the reference
 * shows for those calls is the connection's state, not the frame: the Bind
 * names the interface, each request names its context by number, a response
 * names its request by call id - and the Protocol and Info columns are the
 * interface's and the operation's names (`SRVSVC`, `NetShareEnumAll
 * request`), from tables generated out of tshark itself. Built from C706 and
 * MS-RPCE, one connection per conversation, and compared with tshark's
 * reading of the same file.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const le16 = (n: number) => [n & 255, (n >> 8) & 255];
const be16 = (n: number) => [(n >> 8) & 255, n & 255];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
/** A UUID as DCE writes it: the first three fields little-endian. */
function uuid(text: string): number[] {
  const b = text.replace(/-/g, '').match(/../g)!.map((x) => parseInt(x, 16));
  return [...b.slice(0, 4).reverse(), ...b.slice(4, 6).reverse(), ...b.slice(6, 8).reverse(), ...b.slice(8)];
}

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

const EPM = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa';
const SRVSVC = '4b324fc8-1670-01d3-1278-5a47bf6ee188';
const DRSUAPI = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2';
const UNKNOWN = '12345678-1234-5678-9abc-def012345678';
const NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860';
const NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36';
const BTFN = '6cb71c2c-9812-4540-0300-000000000000';
const NULL_UUID = '00000000-0000-0000-0000-000000000000';

/** A connection-oriented PDU: the sixteen-byte header, then `body`. */
const pdu = (type: number, flags: number, callId: number, body: number[], authLength = 0) =>
  [5, 0, type, flags, 0x10, 0, 0, 0, ...le16(16 + body.length), ...le16(authLength), ...le32(callId), ...body];
const contextItem = (id: number, iface: string, major: number, minor: number, syntax: string, version: number) =>
  [...le16(id), 1, 0, ...uuid(iface), ...le16(major), ...le16(minor), ...uuid(syntax), ...le32(version)];
const bindBody = (items: number[][]) => [...le16(5840), ...le16(5840), ...le32(0), items.length, 0, 0, 0, ...items.flat()];
const result = (outcome: number, reason: number, syntax: string, version: number) =>
  [...le16(outcome), ...le16(reason), ...uuid(syntax), ...le32(version)];
/** Bind_ack's body: the secondary address, padded to four from the PDU start, then the results. */
function ackBody(address: string, results: number[][]): number[] {
  const addr = [...address].map((c) => c.charCodeAt(0)).concat(0);
  const head = [...le16(5840), ...le16(5840), ...le32(0x1234), ...le16(addr.length), ...addr];
  const pad = (4 - ((16 + head.length) % 4)) % 4;
  return [...head, ...new Array(pad).fill(0), results.length, 0, 0, 0, ...results.flat()];
}
const request = (callId: number, ctx: number, opnum: number, stub: number[], flags = 3, object?: string) =>
  pdu(0, flags, callId, [...le32(stub.length), ...le16(ctx), ...le16(opnum), ...(object !== undefined ? uuid(object) : []), ...stub]);
const response = (callId: number, ctx: number, stub: number[]) => pdu(2, 3, callId, [...le32(stub.length), ...le16(ctx), 0, 0, ...stub]);

/** A protocol tower: the interface, NDR, connection-oriented RPC, a TCP port and an address. */
function tower(iface: string, major: number, port: number, address: number[]): number[] {
  const floor = (lhs: number[], rhs: number[]) => [...le16(lhs.length), ...lhs, ...le16(rhs.length), ...rhs];
  const floors = [
    floor([0x0d, ...uuid(iface), ...le16(major)], le16(0)),
    floor([0x0d, ...uuid(NDR), ...le16(2)], le16(0)),
    floor([0x0b], le16(0)),
    floor([0x07], be16(port)),
    floor([0x09], address),
  ];
  return [...le16(floors.length), ...floors.flat()];
}
const pad4 = (bytes: number[]) => [...bytes, ...new Array((4 - (bytes.length % 4)) % 4).fill(0)];
const asked = tower(DRSUAPI, 4, 0, [0, 0, 0, 0]);
const mapRequest = [
  ...pad4([...le32(1), ...uuid(NULL_UUID), ...le32(2), ...le32(asked.length), ...le32(asked.length), ...asked]),
  ...new Array(20).fill(0), ...le32(4),
];
const given = tower(DRSUAPI, 4, 49667, [192, 0, 2, 2]);
const mapResponse = [
  ...pad4([...new Array(20).fill(0), ...le32(1), ...le32(4), ...le32(0), ...le32(1), ...le32(3),
    ...le32(given.length), ...le32(given.length), ...given]),
  ...le32(0),
];

const cases: OracleCase[] = [];
{
  const epm = connection(135);
  cases.push(
    { label: 'a bind offering NDR, NDR64 and feature negotiation', frame: epm(true, pdu(11, 3, 2, bindBody([
      contextItem(0, EPM, 3, 0, NDR, 2), contextItem(1, EPM, 3, 0, NDR64, 1), contextItem(2, EPM, 3, 0, BTFN, 1)]))) },
    { label: 'the bind_ack: accepted, rejected, negotiated', frame: epm(false, pdu(12, 3, 2, ackBody('135', [
      result(0, 0, NDR, 2), result(2, 2, NULL_UUID, 0), result(3, 3, NULL_UUID, 0)]))) },
    { label: 'Map, asking where DRSUAPI is', frame: epm(true, request(2, 0, 3, mapRequest)) },
    { label: 'Map, answering with its port', frame: epm(false, response(2, 0, mapResponse)) },
  );
}
{
  const rpc = connection(49667);
  cases.push(
    { label: 'a bind to an unnamed interface and SRVSVC', frame: rpc(true, pdu(11, 3, 1, bindBody([
      contextItem(0, UNKNOWN, 1, 2, NDR, 2), contextItem(1, SRVSVC, 3, 0, NDR, 2)]))) },
    { label: 'its bind_ack', frame: rpc(false, pdu(12, 3, 1, ackBody('49667', [result(0, 0, NDR, 2), result(0, 0, NDR, 2)]))) },
    { label: 'a call to the unnamed interface', frame: rpc(true, request(2, 0, 7, new Array(16).fill(0x41))) },
    { label: 'its answer, with the time it took', frame: rpc(false, response(2, 0, [1, 2, 3, 4])) },
    { label: 'a call naming an object', frame: rpc(true, request(3, 0, 9, [9, 9, 9, 9], 0x83, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')) },
    { label: 'a fault: access denied', frame: rpc(false, pdu(3, 3, 3, [...le32(32), ...le16(0), 0, 1, ...le32(5), ...le32(0)])) },
    { label: 'an alter_context', frame: rpc(true, pdu(14, 3, 4, bindBody([contextItem(2, UNKNOWN, 1, 0, NDR, 2)]))) },
    { label: 'its answer', frame: rpc(false, pdu(15, 3, 4, ackBody('', [result(0, 0, NDR, 2)]))) },
    { label: 'a fault: unknown interface', frame: rpc(false, pdu(3, 3, 5, [...le32(32), ...le16(2), 0, 0, ...le32(0x1c010003), ...le32(0)])) },
  );
}
{
  const nak = connection(49668);
  cases.push(
    { label: 'a bind', frame: nak(true, pdu(11, 3, 1, bindBody([contextItem(0, UNKNOWN, 1, 0, NDR, 2)]))) },
    { label: 'refused', frame: nak(false, pdu(13, 3, 1, [...le16(4), 1, 5, 0, 0])) },
  );
}

const packets = await compareWithReference(cases, { rows: /^(dcerpc\.(?!response_in)|epm\.)/ });
await checkRevisit(cases);

// A named interface whose stub is not read: the Protocol and Info columns are
// the interface's and the operation's, its layer names the call - and the
// reference's NDR rows under it are not compared, nor is its second Auth Info
// row, an empty one this tree does not repeat.
const utf16z = (text: string) => [...text].flatMap((c) => le16(c.charCodeAt(0))).concat(0, 0);
const UNC = '\\\\SERVER';
const shareEnum = [
  ...pad4([...le32(0x00020000), ...le32(UNC.length + 1), ...le32(0), ...le32(UNC.length + 1), ...utf16z(UNC)]),
  ...le32(1), ...le32(1), ...le32(0x00020004), ...le32(0), ...le32(0), ...le32(0xffffffff), ...le32(0),
];
const shareEnumAnswer = [...le32(1), ...le32(1), ...le32(0x00020000), ...le32(0), ...le32(0), ...le32(0), ...le32(0), ...le32(0)];
/** sec_trailer: NTLMSSP, packet integrity, context 79231 - then a 16-byte verifier. */
const verifier = [10, 5, 0, 0, ...le32(79231), 1, 0, 0, 0, ...new Array(12).fill(0x55)];
const named: OracleCase[] = [];
{
  const rpc = connection(49670);
  named.push(
    { label: 'a bind to SRVSVC', frame: rpc(true, pdu(11, 3, 1, bindBody([contextItem(0, SRVSVC, 3, 0, NDR, 2)]))) },
    { label: 'NetShareEnumAll', frame: rpc(true, request(2, 0, 15, shareEnum)) },
    { label: 'its answer', frame: rpc(false, response(2, 0, shareEnumAnswer)) },
    { label: 'an authenticated NetSrvGetInfo', frame: rpc(true, pdu(0, 3, 3,
      [...le32(8), ...le16(0), ...le16(21), ...le32(0), ...le32(101), ...verifier], 16)) },
  );
}
const namedPackets = await compareWithReference(named, {
  rows: /^(dcerpc\.(?!response_in|referent_id|null_pointer|array\.|auth_info)|srvsvc\.opnum)/,
});
await checkRevisit(named);
check('a SRVSVC call is the `srvsvc` layer over `dcerpc`', namedPackets[1]?.frameProtocols?.slice(-2).join(':') === 'dcerpc:srvsvc',
  namedPackets[1]?.frameProtocols?.join(':'));

// The request learns which frame answered it only when the answer arrives;
// the link is written onto it then, where the reference draws it.
const responseIn = (i: number) => packets[i]?.fields?.['dcerpc.response_in'];
check('the Map request names the frame that answered it', responseIn(2) === 4, String(responseIn(2)));
check('...and so does the call to the unnamed interface', responseIn(6) === 8, String(responseIn(6)));
const row = packets[2]?.layers.find((l) => l.name.startsWith('Distributed'))?.fields;
const opnumAt = row?.findIndex((f) => f.abbrev === 'dcerpc.opnum') ?? -1;
check('...drawn right after the opnum', opnumAt >= 0 && row?.[opnumAt + 1]?.abbrev === 'dcerpc.response_in');
check('the Map request is the `epm` layer over `dcerpc`', packets[2]?.frameProtocols?.slice(-2).join(':') === 'dcerpc:epm',
  packets[2]?.frameProtocols?.join(':'));
finish('DCE/RPC');
