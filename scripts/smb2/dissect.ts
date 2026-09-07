/**
 * SMB2, held to tshark on frames built from MS-SMB2's own layouts.
 *
 *   npx tsx scripts/smb2/dissect.ts
 *
 * Neither fixture contains SMB2 - they are desktop captures and SMB2 is what a
 * corporate network is made of - so `scripts/parity/synthetic.ts` is the oracle.
 *
 * **Eight of the nineteen command names are not the ones MS-SMB2 uses**, which
 * is the single most valuable thing here: a dissector written from the
 * specification prints `Echo Request` where every reference, tutorial and saved
 * filter says `KeepAlive Request`. NEGOTIATE reads `Negotiate Protocol`, LOGOFF
 * `Session Logoff`, QUERY_DIRECTORY `Find`, CHANGE_NOTIFY `Notify`, QUERY_INFO
 * `GetInfo`, SET_INFO `SetInfo`, OPLOCK_BREAK `Break`.
 *
 * The rest of the format is just as unguessable, and every rule below cost one
 * round-trip to the oracle to establish:
 *
 * - `, Tree: '\server\share'` is single-quoted; `, File: dirile.txt` is not;
 * - Read and Write use ` Len:N Off:N` - **no comma**, no space after the colon;
 * - an Ioctl's function name has no comma before it either;
 * - a non-zero status appends `, Error: STATUS_...` BEFORE the detail, and
 *   `STATUS_PENDING` counts as an error even though it is a success code;
 * - compounded PDUs join with `"; "`;
 * - an unnamed Ioctl code is decoded rather than printed: device from bits
 *   16-31, function from bits 2-13, giving `NETWORK Function:0x0d15`.
 */
import {
  tcpFrame, runCases, finish, failureCount, type SyntheticCase,
} from '../parity/synthetic';

const le16 = (n: number): number[] => [n & 0xff, (n >> 8) & 0xff];
const le32 = (n: number): number[] => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
const le64 = (n: number): number[] => [...le32(n), 0, 0, 0, 0];
/** UTF-16LE, which is how SMB2 carries every path. */
const utf16 = (s: string): number[] => [...s].flatMap((c) => le16(c.charCodeAt(0)));

/** SMB2_FLAGS_SERVER_TO_REDIR. */
const RESPONSE = 0x00000001;   // SMB2_FLAGS_SERVER_TO_REDIR

/** The 64-byte synchronous SMB2 header. */
function header(command: number, opts: {
  flags?: number; messageId?: number; treeId?: number; sessionId?: number; status?: number;
  credits?: number;
} = {}): number[] {
  return [
    0xfe, 0x53, 0x4d, 0x42,             // ProtocolId "\xFESMB"
    ...le16(64),                        // StructureSize
    ...le16(0),                         // CreditCharge
    ...le32(opts.status ?? 0),          // Status (response) / ChannelSequence (request)
    ...le16(command),
    ...le16(opts.credits ?? 1),
    ...le32(opts.flags ?? 0),
    ...le32(0),                         // NextCommand
    ...le64(opts.messageId ?? 0),
    ...le32(0),                         // Reserved / ProcessId
    ...le32(opts.treeId ?? 0),
    ...le64(opts.sessionId ?? 0),
    ...new Array(16).fill(0),           // Signature
  ];
}

/** NetBIOS Session Service: type 0, then a 3-byte big-endian length. */
function nbss(payload: number[]): Uint8Array {
  const n = payload.length;
  return Uint8Array.from([0x00, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff, ...payload]);
}

// --- command bodies, minimal but structurally real ---------------------------

const negotiateRequest = [
  ...le16(36), ...le16(1),              // StructureSize, DialectCount
  ...le16(1), ...le16(0),               // SecurityMode, Reserved
  ...le32(0),                           // Capabilities
  ...new Array(16).fill(0x11),          // ClientGuid
  ...le64(0),                           // ClientStartTime
  ...le16(0x0202),                      // Dialects[0] = SMB 2.0.2
];
const negotiateResponse = [
  ...le16(65), ...le16(1),              // StructureSize, SecurityMode
  ...le16(0x0202), ...le16(0),          // DialectRevision, NegotiateContextCount
  ...new Array(16).fill(0x22),          // ServerGuid
  ...le32(0), ...le32(0x00800000), ...le32(0x00800000), ...le32(0x00800000),
  ...le64(0), ...le64(0),               // SystemTime, ServerStartTime
  ...le16(128), ...le16(0),             // SecurityBufferOffset, SecurityBufferLength
  ...le32(0),                           // NegotiateContextOffset
];
const sessionSetupRequest = [
  ...le16(25), 0x00, 0x01,              // StructureSize, Flags, SecurityMode
  ...le32(0), ...le32(0),               // Capabilities, Channel
  ...le16(88), ...le16(0),              // SecurityBufferOffset, Length
  ...le64(0),                           // PreviousSessionId
];
const treeConnectRequest = (path: string) => [
  ...le16(9), ...le16(0),               // StructureSize, Reserved
  ...le16(72), ...le16(path.length * 2),// PathOffset, PathLength
  ...utf16(path),
];
const createRequest = (name: string) => [
  ...le16(57), 0x00, 0x00,              // StructureSize, SecurityFlags, RequestedOplockLevel
  ...le32(0),                           // ImpersonationLevel
  ...le64(0), ...le64(0),               // SmbCreateFlags, Reserved
  ...le32(0x00100081),                  // DesiredAccess
  ...le32(0x80),                        // FileAttributes
  ...le32(3),                           // ShareAccess
  ...le32(1),                           // CreateDisposition
  ...le32(0x40),                        // CreateOptions
  ...le16(120), ...le16(name.length * 2), // NameOffset, NameLength
  ...le32(0), ...le32(0),               // CreateContextsOffset, Length
  ...utf16(name),
];
const readRequest = [
  ...le16(49), 0x00, 0x00,              // StructureSize, Padding, Flags
  ...le32(65536),                       // Length
  ...le64(0),                           // Offset
  ...new Array(16).fill(0xaa),          // FileId
  ...le32(0), ...le32(0),               // MinimumCount, Channel
  ...le32(0), ...le16(0), ...le16(0),   // RemainingBytes, ReadChannelInfoOffset/Length
  0x00,
];
const closeRequest = [
  ...le16(24), ...le16(0), ...le32(0),  // StructureSize, Flags, Reserved
  ...new Array(16).fill(0xaa),          // FileId
];
const echoRequest = [...le16(4), ...le16(0)];
const treeDisconnect = [...le16(4), ...le16(0)];

const createResponse = [
  ...le16(89), 0x00, 0x00,              // StructureSize, OplockLevel, Flags
  ...le32(1),                           // CreateAction = FILE_OPENED
  ...le64(0), ...le64(0), ...le64(0), ...le64(0),   // the four times
  ...le64(0), ...le64(1024),            // AllocationSize, EndOfFile
  ...le32(0x80), ...le32(0),            // FileAttributes, Reserved2
  ...new Array(16).fill(0xbb),          // FileId
  ...le32(0), ...le32(0),               // CreateContextsOffset, Length
];
const writeRequest = [
  ...le16(49), ...le16(112),            // StructureSize, DataOffset
  ...le32(4096),                        // Length
  ...le64(8192),                        // Offset
  ...new Array(16).fill(0xaa),          // FileId
  ...le32(0), ...le32(0),               // Channel, RemainingBytes
  ...le16(0), ...le16(0),               // WriteChannelInfo Offset/Length
  ...le32(0),
];
const queryDirectory = (pattern: string) => [
  ...le16(33), 0x25, 0x00,              // StructureSize, FileInformationClass, Flags
  ...le32(0),                           // FileIndex
  ...new Array(16).fill(0xaa),          // FileId
  ...le16(96), ...le16(pattern.length * 2),
  ...le32(65536),                       // OutputBufferLength
  ...utf16(pattern),
];
const ioctlRequest = (ctlCode: number) => [
  ...le16(57), ...le16(0),              // StructureSize, Reserved
  ...le32(ctlCode),
  ...new Array(16).fill(0xaa),          // FileId
  ...le32(120), ...le32(0), ...le32(0),
  ...le32(120), ...le32(0), ...le32(65536),
  ...le32(1), ...le32(0),
];
/** Two PDUs chained by NextCommand, which is how SMB2 compounds. */
function compound(): number[] {
  const first = [...header(0x03, { messageId: 10, sessionId: 0x99 }), ...treeConnectRequest('\\srv\ipc$')];
  const padded = [...first, ...new Array((8 - first.length % 8) % 8).fill(0)];
  // NextCommand is at offset 20 of the header, and counts from the header start.
  padded[20] = padded.length & 0xff;
  padded[21] = (padded.length >> 8) & 0xff;
  return [...padded, ...header(0x05, { messageId: 11, treeId: 1, sessionId: 0x99 }), ...createRequest('x.txt')];
}


// --- the conversation ---------------------------------------------------------
//
// One connection in order, so the Create response can find the request's file
// name - the cross-frame state this protocol needs and LDAP's entry counter
// established the pattern for.

const CLIENT = 50000;
let cSeq = 1;
let sSeq = 1;
const toServer = (payload: Uint8Array): Uint8Array => {
  const frame = tcpFrame(CLIENT, 445, cSeq, sSeq, payload);
  cSeq += payload.length;
  return frame;
};
const toClient = (payload: Uint8Array): Uint8Array => {
  const frame = tcpFrame(445, CLIENT, sSeq, cSeq, payload);
  sSeq += payload.length;
  return frame;
};


const cases: SyntheticCase[] = [
  { name: 'a negotiate names the protocol, not the command',
    frame: toServer(nbss([...header(0x00, { messageId: 0 }), ...negotiateRequest])) },
  { name: '...and its response says so too',
    frame: toClient(nbss([...header(0x00, { flags: RESPONSE, messageId: 0 }), ...negotiateResponse])) },
  { name: 'a session setup',
    frame: toServer(nbss([...header(0x01, { messageId: 1 }), ...sessionSetupRequest])) },
  { name: 'a tree connect quotes its share',
    frame: toServer(nbss([...header(0x03, { messageId: 2, sessionId: 0x99 }), ...treeConnectRequest(String.raw`\\server\share`)])) },
  { name: 'a create names its file, unquoted',
    frame: toServer(nbss([...header(0x05, { messageId: 3, treeId: 1, sessionId: 0x99 }), ...createRequest(String.raw`dir\file.txt`)])) },
  // The cross-frame case: the response carries no name, only the message id.
  { name: '...and the response finds that name from the request',
    frame: toClient(nbss([...header(0x05, { flags: RESPONSE, messageId: 3 }), ...createResponse])) },
  { name: 'a read uses Len/Off with no comma',
    frame: toServer(nbss([...header(0x08, { messageId: 4, treeId: 1, sessionId: 0x99 }), ...readRequest])) },
  { name: 'a write uses the same shape',
    frame: toServer(nbss([...header(0x09, { messageId: 5, treeId: 1, sessionId: 0x99 }), ...writeRequest, ...new Array(64).fill(0x41)])) },
  { name: 'a close', frame: toServer(nbss([...header(0x06, { messageId: 6, treeId: 1, sessionId: 0x99 }), ...closeRequest])) },
  { name: 'ECHO is called KeepAlive', frame: toServer(nbss([...header(0x0d, { messageId: 7 }), ...echoRequest])) },
  { name: 'a tree disconnect', frame: toServer(nbss([...header(0x04, { messageId: 8, treeId: 1, sessionId: 0x99 }), ...treeDisconnect])) },
  { name: 'QUERY_DIRECTORY is called Find, and names its class',
    frame: toServer(nbss([...header(0x0e, { messageId: 9, treeId: 1, sessionId: 0x99 }), ...queryDirectory('*')])) },
  { name: 'a known ioctl is named, with no comma in front of it',
    frame: toServer(nbss([...header(0x0b, { messageId: 12, treeId: 1 }), ...ioctlRequest(0x00140204)])) },
  // Decoded rather than printed: device 0x12 is NETWORK, function 0x0d15.
  { name: '...and an unknown one is decoded, not printed as hex',
    frame: toServer(nbss([...header(0x0b, { messageId: 13, treeId: 1 }), ...ioctlRequest(0x00123456)])) },
  { name: 'compounded PDUs join with a semicolon', frame: toServer(nbss(compound())) },
  { name: 'an error status is named',
    frame: toClient(nbss([...header(0x05, { flags: RESPONSE, messageId: 20, status: 0xc0000022 }), ...createResponse])) },
  // STATUS_PENDING is a success code and still reads as an error, before the file.
  { name: 'STATUS_PENDING reads as an error, and still names the file',
    frame: toClient(nbss([...header(0x05, { flags: RESPONSE, messageId: 21, status: 0x00000103 }), ...createResponse])) },
];

async function main(): Promise<void> {
  await runCases(cases, { statefulTcp: true });
  if (failureCount() > 0) process.exit(1);
  finish('SMB2');
}

main();
