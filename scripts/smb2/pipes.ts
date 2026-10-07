/**
 * SMB2's open files, and DCE/RPC over its named pipes, against the reference.
 *
 *   npx tsx scripts/smb2/pipes.ts
 *
 * Two things a Create teaches a connection. The FileId the server answers
 * with is what every later Read, Write, Close or Find names, and the
 * reference appends the file's name to each of their Info lines - `Read
 * Request Len:1024 Off:0, File: docs\a.txt` - until a Close forgets it. And
 * on the IPC$ share that file is a pipe, whose writes and reads are DCE/RPC:
 * listing a server's shares is a Bind on `srvsvc` and a NetShareEnumAll
 * through an Ioctl, and the columns are then the RPC's. Built from MS-SMB2,
 * one connection, and compared with tshark's reading of the same file.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const le16 = (n: number) => [n & 255, (n >> 8) & 255];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
const le64 = (n: number) => [...le32(n), 0, 0, 0, 0];
const utf16 = (text: string) => [...text].flatMap((c) => le16(c.charCodeAt(0)));
function uuid(text: string): number[] {
  const b = text.replace(/-/g, '').match(/../g)!.map((x) => parseInt(x, 16));
  return [...b.slice(0, 4).reverse(), ...b.slice(4, 6).reverse(), ...b.slice(6, 8).reverse(), ...b.slice(8)];
}

let clientSeq = 1000;
let serverSeq = 5000;
/** One SMB2 message in its NBSS framing, on the one connection. */
function segment(fromClient: boolean, message: number[]): Uint8Array {
  const body = Uint8Array.from([0, (message.length >> 16) & 255, (message.length >> 8) & 255, message.length & 255, ...message]);
  const seg = fromClient ? tcp(50000, 445, clientSeq, serverSeq, body) : tcp(445, 50000, serverSeq, clientSeq, body);
  if (fromClient) clientSeq += body.length; else serverSeq += body.length;
  return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, seg, fromClient ? CLIENT : SERVER, fromClient ? SERVER : CLIENT)]);
}
/** The 64-byte header. */
const header = (command: number, messageId: number, response: boolean, treeId: number, status = 0) => [
  0xfe, 0x53, 0x4d, 0x42, ...le16(64), ...le16(1), ...le32(status), ...le16(command), ...le16(1), ...le32(response ? 1 : 0), ...le32(0),
  ...le64(messageId), ...le32(0xfeff), ...le32(treeId), ...le64(0x1000), ...new Array(16).fill(0),
];

const SHARE_TREE = 1;
const IPC_TREE = 2;
const treeConnect = (messageId: number, path: string, treeId: number): number[][] => {
  const name = utf16(path);
  return [
    [...header(3, messageId, false, 0), ...le16(9), 0, 0, ...le16(72), ...le16(name.length), ...name],
    [...header(3, messageId, true, treeId), ...le16(16), path.endsWith('IPC$') ? 2 : 1, 0, ...le32(0), ...le32(0), ...le32(0x1f01ff)],
  ];
};
const create = (messageId: number, treeId: number, path: string, fid: number[]): number[][] => {
  const name = utf16(path);
  return [
    [...header(5, messageId, false, treeId), ...le16(57), 0, 0, ...le32(2), ...le64(0), ...le64(0), ...le32(0x0012019f), ...le32(0),
      ...le32(7), ...le32(1), ...le32(0), ...le16(120), ...le16(name.length), ...le32(0), ...le32(0), ...name],
    [...header(5, messageId, true, treeId), ...le16(89), 0, 0, ...le32(1), ...le64(0), ...le64(0), ...le64(0), ...le64(0), ...le64(4096),
      ...le64(5), ...le32(0x20), ...le32(0), ...fid, ...le32(0), ...le32(0)],
  ];
};

// --- an ordinary file, from Create to Close -----------------------------------
const FILE = [7, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0];
const data = [1, 2, 3, 4, 5];
const fileMessages: [string, number[]][] = [];
let id = 10;
const exchange = (label: string, request: number[], response: number[]) => {
  fileMessages.push([`${label} request`, request], [`${label} response`, response]);
  id++;
};
for (const [i, m] of treeConnect(id, '\\\\SERVER\\docs', SHARE_TREE).entries()) fileMessages.push([`tree connect ${i}`, m]);
id++;
for (const [i, m] of create(id, SHARE_TREE, 'docs\\a.txt', FILE).entries()) fileMessages.push([`create ${i}`, m]);
id++;
exchange('write', [...header(9, id, false, SHARE_TREE), ...le16(49), ...le16(112), ...le32(data.length), ...le64(0), ...FILE, ...le32(0), ...le32(0), ...le16(0), ...le16(0), ...le32(0), ...data],
  [...header(9, id, true, SHARE_TREE), ...le16(17), 0, 0, ...le32(data.length), ...le32(0), ...le16(0), ...le16(0)]);
exchange('read', [...header(8, id, false, SHARE_TREE), ...le16(49), 0, 0, ...le32(1024), ...le64(0), ...FILE, ...le32(0), ...le32(0), ...le32(0), ...le16(0), ...le16(0), 0],
  [...header(8, id, true, SHARE_TREE), ...le16(17), 80, 0, ...le32(data.length), ...le32(0), ...le32(0), ...data]);
exchange('read past the end', [...header(8, id, false, SHARE_TREE), ...le16(49), 0, 0, ...le32(1024), ...le64(5), ...FILE, ...le32(0), ...le32(0), ...le32(0), ...le16(0), ...le16(0), 0],
  [...header(8, id, true, SHARE_TREE, 0xc0000011), ...le16(9), 0, 0, ...le32(0), 0]);
exchange('getinfo', [...header(16, id, false, SHARE_TREE), ...le16(41), 1, 5, ...le32(4096), ...le16(0), ...le16(0), ...le32(0), ...le32(0), ...le32(0), ...FILE],
  [...header(16, id, true, SHARE_TREE), ...le16(9), ...le16(72), ...le32(4), 1, 2, 3, 4]);
exchange('flush', [...header(7, id, false, SHARE_TREE), ...le16(24), 0, 0, ...le32(0), ...FILE],
  [...header(7, id, true, SHARE_TREE), ...le16(4), 0, 0]);
exchange('notify', [...header(15, id, false, SHARE_TREE), ...le16(32), 1, 0, ...le32(4096), ...FILE, ...le32(0x17), ...le32(0)],
  [...header(15, id, true, SHARE_TREE, 0x103), ...le16(9), 0, 0, ...le32(0), 0]);
exchange('find', [...header(14, id, false, SHARE_TREE), ...le16(33), 0x25, 0, ...le32(0), ...FILE, ...le16(96), ...le16(2), ...le32(65536), ...utf16('*')],
  [...header(14, id, true, SHARE_TREE, 0x80000006), ...le16(9), 0, 0, ...le32(0), 0]);
exchange('lock', [...header(10, id, false, SHARE_TREE), ...le16(48), ...le16(1), ...le32(0), ...FILE, ...le64(0), ...le64(10), ...le32(1), ...le32(0)],
  [...header(10, id, true, SHARE_TREE), ...le16(4), 0, 0]);
exchange('ioctl', [...header(11, id, false, SHARE_TREE), ...le16(57), 0, 0, ...le32(0x00090078), ...FILE, ...le32(0), ...le32(0), ...le32(0), ...le32(0), ...le32(0), ...le32(0), ...le32(1), ...le32(0)],
  [...header(11, id, true, SHARE_TREE, 0xc0000010), ...le16(9), 0, 0, ...le32(0), 0]);
exchange('close', [...header(6, id, false, SHARE_TREE), ...le16(24), 0, 0, ...le32(0), ...FILE],
  [...header(6, id, true, SHARE_TREE), ...le16(60), 0, 0, ...le32(0), ...new Array(56).fill(0)]);
exchange('getinfo after the close', [...header(16, id, false, SHARE_TREE), ...le16(41), 1, 5, ...le32(4096), ...le16(0), ...le16(0), ...le32(0), ...le32(0), ...le32(0), ...FILE],
  [...header(16, id, true, SHARE_TREE, 0xc0000128), ...le16(9), 0, 0, ...le32(0), 0]);

// --- srvsvc on IPC$: Bind by Write and Read, NetShareEnumAll by Ioctl -----------
const PIPE = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
const NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860';
const SRVSVC = '4b324fc8-1670-01d3-1278-5a47bf6ee188';
const pdu = (type: number, callId: number, body: number[]) => [5, 0, type, 3, 0x10, 0, 0, 0, ...le16(16 + body.length), 0, 0, ...le32(callId), ...body];
const bind = pdu(11, 2, [...le16(4280), ...le16(4280), ...le32(0), 1, 0, 0, 0, ...le16(0), 1, 0, ...uuid(SRVSVC), ...le16(3), ...le16(0), ...uuid(NDR), ...le32(2)]);
const address = [...'\\PIPE\\srvsvc'].map((c) => c.charCodeAt(0)).concat(0);
const ackHead = [...le16(4280), ...le16(4280), ...le32(0x5678), ...le16(address.length), ...address];
const bindAck = pdu(12, 2, [...ackHead, ...new Array((4 - ((16 + ackHead.length) % 4)) % 4).fill(0), 1, 0, 0, 0, ...le16(0), ...le16(0), ...uuid(NDR), ...le32(2)]);
const pad4 = (a: number[]) => [...a, ...new Array((4 - (a.length % 4)) % 4).fill(0)];
const UNC = '\\\\SERVER';
const enumStub = [...pad4([...le32(0x00020000), ...le32(UNC.length + 1), ...le32(0), ...le32(UNC.length + 1), ...utf16(UNC), 0, 0]),
  ...le32(1), ...le32(1), ...le32(0x00020004), ...le32(0), ...le32(0), ...le32(0xffffffff), ...le32(0)];
const call = pdu(0, 3, [...le32(enumStub.length), ...le16(0), ...le16(15), ...enumStub]);
const answerStub = [...le32(1), ...le32(1), ...le32(0x00020000), ...le32(0), ...le32(0), ...le32(0), ...le32(0), ...le32(0)];
const answer = pdu(2, 3, [...le32(answerStub.length), ...le16(0), 0, 0, ...answerStub]);
const pipeMessages: [string, number[]][] = [];
for (const [i, m] of treeConnect(id, '\\\\SERVER\\IPC$', IPC_TREE).entries()) pipeMessages.push([`IPC$ tree connect ${i}`, m]);
id++;
for (const [i, m] of create(id, IPC_TREE, 'srvsvc', PIPE).entries()) pipeMessages.push([`create srvsvc ${i}`, m]);
id++;
pipeMessages.push(
  ['the bind, written', [...header(9, id, false, IPC_TREE), ...le16(49), ...le16(112), ...le32(bind.length), ...le64(0), ...PIPE, ...le32(0), ...le32(0), ...le16(0), ...le16(0), ...le32(0), ...bind]],
  ['the write answered', [...header(9, id, true, IPC_TREE), ...le16(17), 0, 0, ...le32(bind.length), ...le32(0), ...le16(0), ...le16(0)]],
);
id++;
pipeMessages.push(
  ['a read for the bind_ack', [...header(8, id, false, IPC_TREE), ...le16(49), 0, 0, ...le32(1024), ...le64(0), ...PIPE, ...le32(0), ...le32(0), ...le32(0), ...le16(0), ...le16(0), 0]],
  ['the bind_ack, read', [...header(8, id, true, IPC_TREE), ...le16(17), 80, 0, ...le32(bindAck.length), ...le32(0), ...le32(0), ...bindAck]],
);
id++;
pipeMessages.push(
  ['NetShareEnumAll through FSCTL_PIPE_TRANSCEIVE', [...header(11, id, false, IPC_TREE), ...le16(57), 0, 0, ...le32(0x0011c017), ...PIPE, ...le32(120), ...le32(call.length),
    ...le32(0), ...le32(0), ...le32(0), ...le32(1024), ...le32(1), ...le32(0), ...call]],
  ['and its answer', [...header(11, id, true, IPC_TREE), ...le16(49), 0, 0, ...le32(0x0011c017), ...PIPE, ...le32(112), ...le32(0), ...le32(112), ...le32(answer.length),
    ...le32(0), ...le32(0), ...answer]],
);

const all = [...fileMessages, ...pipeMessages];
const cases: OracleCase[] = all.map(([label, message], i) => ({ label, frame: segment(i % 2 === 0, message) }));
const packets = await compareWithReference(cases, {
  rows: /^(dcerpc\.(?!response_in|referent_id|null_pointer|array\.|nt\.)|srvsvc\.opnum)/,
  // What the packet list shows: a response names its file, which the
  // reference's single pass does not yet know.
  twoPass: true,
});
await checkRevisit(cases);
const enumAt = all.findIndex(([label]) => label.startsWith('NetShareEnumAll'));
check('the RPC call names the frame that answered it', packets[enumAt]?.fields?.['dcerpc.response_in'] === enumAt + 2,
  String(packets[enumAt]?.fields?.['dcerpc.response_in']));
check('NetShareEnumAll is `smb2:dcerpc:srvsvc`', packets[enumAt]?.frameProtocols?.slice(-3).join(':') === 'smb2:dcerpc:srvsvc',
  packets[enumAt]?.frameProtocols?.join(':'));
finish('SMB2 pipes');
