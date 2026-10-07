/**
 * SMB2 (MS-SMB2), behind the NetBIOS Session Service framing it always uses.
 *
 * The protocol a corporate network is actually made of, and the second non-leaf
 * dissector here after LDAP - a Create response names the file the *request*
 * asked for, which no single frame contains.
 *
 * **The whole Info format came from asking tshark, and eight of the nineteen
 * command names are not the ones MS-SMB2 uses.** That is not a detail: a
 * dissector written from the specification would have printed `Echo Request`
 * where every reference, tutorial and saved filter says `KeepAlive Request`.
 * The full set of differences, each verified:
 *
 * | code | MS-SMB2 | what the column says |
 * |---|---|---|
 * | 0x00 | NEGOTIATE | `Negotiate Protocol` |
 * | 0x02 | LOGOFF | `Session Logoff` |
 * | 0x0d | ECHO | `KeepAlive` |
 * | 0x0e | QUERY_DIRECTORY | `Find` |
 * | 0x0f | CHANGE_NOTIFY | `Notify` |
 * | 0x10 | QUERY_INFO | `GetInfo` |
 * | 0x11 | SET_INFO | `SetInfo` |
 * | 0x12 | OPLOCK_BREAK | `Break` |
 *
 * The rest of the format, also from the oracle and also not derivable:
 *
 * - `Tree Connect Request, Tree: '\\server\share'` - single-quoted, unlike
 *   `Create Request, File: dir\file.txt`, which is not quoted at all;
 * - `Read Request Len:65536 Off:0` - **no comma**, and no space after a colon,
 *   where every other detail is introduced by `, `;
 * - a response carrying a non-zero status appends `, Error: STATUS_...`, and
 *   `STATUS_PENDING` counts as one even though it is a success code;
 * - several PDUs compounded in one message join with `"; "`;
 * - an unknown Ioctl code is not printed as hex but **decoded**: device from
 *   bits 16-31 and function from bits 2-13, rendered `NETWORK Function:0x0d15`.
 *
 * Pinned in `scripts/smb2/dissect.ts`.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';
import { dissectDcerpc, freshDcerpcConversation, looksLikeDcerpc, type DcerpcConversationState, type DcerpcFrame, type DcerpcResult } from './dcerpc';
import { dissectSecurityBlob, type GssResult } from './gssapi';

/** SMB over TCP. 139 is the older NetBIOS session service, which SMB1 used. */
export const SMB2_PORT = 445;

/**
 * `þSMB`, the SMB2 protocol id, compared as BYTES.
 *
 * Not as a number, and the distinction cost a debugging round: every other
 * field in SMB2 is little-endian, so reading this one with the same helper
 * yields 0x424d53fe and the check silently never matches. The symptom was every
 * frame reading as plain TCP, which looks like an unwired dispatch rather than
 * like a byte-order slip. SMB1's id is `ÿSMB`.
 */
function hasSmb2Magic(bytes: Uint8Array, p: number): boolean {
  return bytes[p] === 0xfe && bytes[p + 1] === 0x53
    && bytes[p + 2] === 0x4d && bytes[p + 3] === 0x42;
}
const HEADER_SIZE = 64;
/** SMB2_FLAGS_SERVER_TO_REDIR: this message is a response. */
const FLAG_RESPONSE = 0x00000001;

/**
 * The command names the reference analyzer prints.
 *
 * Eight differ from MS-SMB2's own names - see the table above. Copied from the
 * oracle one command at a time, not transcribed from the specification.
 */
const COMMAND_NAMES: Record<number, string> = {
  0x00: 'Negotiate Protocol',
  0x01: 'Session Setup',
  0x02: 'Session Logoff',
  0x03: 'Tree Connect',
  0x04: 'Tree Disconnect',
  0x05: 'Create',
  0x06: 'Close',
  0x07: 'Flush',
  0x08: 'Read',
  0x09: 'Write',
  0x0a: 'Lock',
  0x0b: 'Ioctl',
  0x0c: 'Cancel',
  0x0d: 'KeepAlive',
  0x0e: 'Find',
  0x0f: 'Notify',
  0x10: 'GetInfo',
  0x11: 'SetInfo',
  0x12: 'Break',
};

/**
 * NTSTATUS codes by the name the column prints.
 *
 * Every one verified against the oracle rather than copied from a header, which
 * matters because the reference does not spell them all as Microsoft does.
 * An unlisted code falls back to its hex value.
 */
export const STATUS_NAMES: Record<number, string> = {
  0x00000103: 'STATUS_PENDING',
  0x80000005: 'STATUS_BUFFER_OVERFLOW',
  0x80000006: 'STATUS_NO_MORE_FILES',
  0xc000000d: 'STATUS_INVALID_PARAMETER',
  0xc0000010: 'STATUS_INVALID_DEVICE_REQUEST',
  0xc0000011: 'STATUS_END_OF_FILE',
  0xc0000016: 'STATUS_MORE_PROCESSING_REQUIRED',
  0xc0000022: 'STATUS_ACCESS_DENIED',
  0xc0000034: 'STATUS_OBJECT_NAME_NOT_FOUND',
  0xc0000035: 'STATUS_OBJECT_NAME_COLLISION',
  0xc000003a: 'STATUS_OBJECT_PATH_NOT_FOUND',
  0xc0000043: 'STATUS_SHARING_VIOLATION',
  0xc000006a: 'STATUS_WRONG_PASSWORD',
  0xc000006d: 'STATUS_LOGON_FAILURE',
  0xc00000bb: 'STATUS_NOT_SUPPORTED',
  0xc00000cc: 'STATUS_BAD_NETWORK_NAME',
  0xc0000128: 'STATUS_FILE_CLOSED',
  0xc0000203: 'STATUS_USER_SESSION_DELETED',
  0xc0000225: 'STATUS_NOT_FOUND',
};

/** Verified FSCTL codes. An unknown one is decoded instead - see `nameIoctl`. */
const FSCTL_NAMES: Record<number, string> = {
  0x00060194: 'FSCTL_DFS_GET_REFERRALS',
  0x00090000: 'FSCTL_REQUEST_OPLOCK_LEVEL_1',
  0x00090078: 'FSCTL_IS_VOLUME_DIRTY',
  0x0011400c: 'FSCTL_PIPE_PEEK',
  0x0011c017: 'FSCTL_PIPE_TRANSCEIVE',
  0x001401d4: 'FSCTL_LMR_REQUEST_RESILIENCY',
  0x00140204: 'FSCTL_VALIDATE_NEGOTIATE_INFO',
};

/**
 * Windows device types, for an Ioctl code with no name.
 *
 * Only `NETWORK` is verified against the oracle; the others are the documented
 * `FILE_DEVICE_*` values and are here so an unnamed code from a different
 * device reads as something rather than as a number. An unlisted device falls
 * back to its own value, which is the honest answer when this table is wrong.
 */
const DEVICE_NAMES: Record<number, string> = {
  0x0009: 'DFS',
  0x0012: 'NETWORK',
  0x0014: 'NAMED_PIPE',
  0x0019: 'FILE_SYSTEM',
};

/** The `Find` information classes, by the name the column prints. */
const FIND_CLASS_NAMES: Record<number, string> = {
  0x01: 'SMB2_FIND_DIRECTORY_INFO',
  0x02: 'SMB2_FIND_FULL_DIRECTORY_INFO',
  0x03: 'SMB2_FIND_BOTH_DIRECTORY_INFO',
  0x0c: 'SMB2_FIND_NAME_INFO',
  0x25: 'SMB2_FIND_ID_BOTH_DIRECTORY_INFO',
  0x26: 'SMB2_FIND_ID_FULL_DIRECTORY_INFO',
};

/** GetInfo/SetInfo classes, and the levels named under the ones verified. */
const INFO_CLASS_NAMES: Record<number, string> = {
  0x01: 'FILE_INFO',
  0x02: 'FS_INFO',
  0x03: 'SEC_INFO',
  0x04: 'QUOTA_INFO',
};
const FILE_INFO_LEVELS: Record<number, string> = {
  0x05: 'SMB2_FILE_STANDARD_INFO',
};

// --- per-connection state -----------------------------------------------------

/**
 * How many outstanding message ids to remember.
 *
 * Bounded like every tracker here (`docs/decisions/0014`). SMB2 message ids
 * climb for the life of a connection, so the map would otherwise grow with it.
 * Losing an old one makes a response read `File: [unknown]`, which is exactly
 * what the reference prints when it has no matching request either.
 */
const MAX_TRACKED_MESSAGES = 512;

export interface Smb2ConversationState {
  /** File name by the message id of the Create request that asked for it. */
  createdFiles: Map<number, string>;
  /** Share path by the message id of the Tree Connect that asked for it, then by tree id. */
  treeRequests: Map<number, string>;
  trees: Map<number, string>;
  /** An open file's name by its FileId, from the Create response that opened it to the Close. */
  files: Map<string, string>;
  /**
   * A request's file, by message id, for its response - which carries no
   * FileId of its own - and a Find's whole detail, which its response repeats.
   */
  requests: Map<number, { fid: string; name?: string; detail?: string }>;
  /** DCE/RPC on each named pipe, by FileId. */
  pipes: Map<string, DcerpcConversationState>;
}

export function freshSmb2Conversation(): Smb2ConversationState {
  return { createdFiles: new Map(), treeRequests: new Map(), trees: new Map(), files: new Map(), requests: new Map(), pipes: new Map() };
}

/** Bounded like `createdFiles`: drop the oldest past the limit. */
function bounded<K, V>(map: Map<K, V>, key: K, value: V): void {
  map.set(key, value);
  if (map.size > MAX_TRACKED_MESSAGES) {
    const oldest = map.keys().next();
    if (!oldest.done) map.delete(oldest.value);
  }
}

/** A FileId as a key: its sixteen bytes in hex. */
const fileIdAt = (b: Uint8Array, at: number): string =>
  Array.from(b.subarray(at, at + 16), (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * Where each request carries its FileId, from the start of its body - for
 * the commands whose Info names the file, which the reference appends once it
 * has seen the Create that opened it. Ioctl carries one too and is never
 * named; it is here for its pipe.
 */
const FILE_ID_AT: Record<number, number> = {
  0x06: 8, 0x07: 8, 0x08: 16, 0x09: 16, 0x0a: 8, 0x0b: 8, 0x0e: 8, 0x0f: 8, 0x10: 24, 0x11: 16,
};
const FSCTL_PIPE_TRANSCEIVE = 0x0011c017;

function rememberFile(state: Smb2ConversationState, messageId: number, name: string): void {
  state.createdFiles.set(messageId, name);
  if (state.createdFiles.size > MAX_TRACKED_MESSAGES) {
    const oldest = state.createdFiles.keys().next();
    if (!oldest.done) state.createdFiles.delete(oldest.value);
  }
}

// --- reading ------------------------------------------------------------------

const u16 = (b: Uint8Array, p: number): number => b[p] | (b[p + 1] << 8);
const u32 = (b: Uint8Array, p: number): number =>
  (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
/** Message ids are 64-bit; the low half is what identifies one in practice. */
const u64Low = (b: Uint8Array, p: number): number => u32(b, p);

/** A UTF-16LE string, which is how SMB2 carries every path. */
function utf16(bytes: Uint8Array, start: number, length: number): string {
  let out = '';
  for (let p = start; p + 1 < start + length && p + 1 < bytes.length; p += 2) {
    out += String.fromCharCode(u16(bytes, p));
  }
  return out;
}

/**
 * A string as the Info column shows it, with every backslash doubled.
 *
 * Wireshark passes these through `format_text()` before the column sees them,
 * so `\server\share` is printed `\\server\share`. It looks like a bug in the
 * test until you notice every path is affected and no other detail is - and it
 * matters most for exactly the protocol where every string is a UNC path.
 *
 * The FIELD keeps the real value: `smb2.tree` is what a filter compares, and a
 * filter should not have to know about a display convention.
 */
function forColumn(text: string): string {
  return text.split('\\').join('\\\\');
}

/**
 * An Ioctl code by name, or decoded the way the reference decodes an unknown
 * one: the device from bits 16-31 and the function from bits 2-13.
 */
function nameIoctl(code: number): string {
  const known = FSCTL_NAMES[code];
  if (known !== undefined) return known;
  const device = (code >>> 16) & 0xffff;
  const fn = (code >>> 2) & 0xfff;
  return `${DEVICE_NAMES[device] ?? device} Function:0x${fn.toString(16).padStart(4, '0')}`;
}

export interface Smb2Result {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /** DCE/RPC's layers, when a named pipe carried it - after SMB2's. */
  innerLayers?: ProtocolLayer[];
  /** A DCE/RPC request this frame's response answered. */
  answered?: DcerpcResult['answered'];
}

interface OneMessage {
  info: string;
  rows: ProtocolField[];
  fields: Record<string, string | number>;
  /** DCE/RPC carried in a named pipe's data. */
  rpc?: DcerpcResult;
  /** The sign-in a Negotiate response or a Session Setup carries. */
  auth?: GssResult;
}

/**
 * Reads one SMB2 message - a header and its body - starting at `start`.
 *
 * `end` is the end of the whole NBSS message, not of this PDU: a compounded
 * chain shares one, and `NextCommand` says where the next begins.
 */
function readMessage(
  bytes: Uint8Array, start: number, end: number, state: Smb2ConversationState, frame?: DcerpcFrame,
): { message: OneMessage; nextCommand: number } | null {
  if (end - start < HEADER_SIZE) return null;
  if (!hasSmb2Magic(bytes, start)) return null;
  if (u16(bytes, start + 4) !== HEADER_SIZE) return null;

  const status = u32(bytes, start + 8);
  const command = u16(bytes, start + 12);
  const flags = u32(bytes, start + 16);
  const nextCommand = u32(bytes, start + 20);
  const messageId = u64Low(bytes, start + 24);
  const treeId = u32(bytes, start + 36);
  const sessionId = u64Low(bytes, start + 40);
  const isResponse = (flags & FLAG_RESPONSE) !== 0;
  const name = COMMAND_NAMES[command];
  if (name === undefined) return null;

  const body = start + HEADER_SIZE;
  const fields: Record<string, string | number> = {
    'smb2.cmd': command,
    'smb2.msg_id': messageId,
    'smb2.flags': flags,
    'smb2.tid': treeId,
    'smb2.sesid': sessionId,
  };
  const rows: ProtocolField[] = [
    { name: 'Command', value: `${name} (${command})`, abbrev: 'smb2.cmd' },
    { name: 'Message ID', value: messageId, abbrev: 'smb2.msg_id' },
    { name: 'Flags', value: `0x${flags.toString(8).padStart(8, '0')}`, abbrev: 'smb2.flags' },
    { name: 'Tree Id', value: `0x${treeId.toString(16).padStart(8, '0')}`, abbrev: 'smb2.tid' },
    { name: 'Session Id', value: `0x${sessionId.toString(16).padStart(8, '0')}`, abbrev: 'smb2.sesid' },
  ];
  if (isResponse) {
    fields['smb2.nt_status'] = status;
    rows.push({
      name: 'NT Status', abbrev: 'smb2.nt_status',
      value: STATUS_NAMES[status] ?? `0x${status.toString(16).padStart(8, '0')}`,
    });
  }

  // The detail after the command name. Every separator here is deliberate: a
  // comma before most of them, a bare space before Read/Write's Len, and
  // nothing at all before an Ioctl's function name.
  let detail = '';
  // The file this message is about, when its Create was seen: a request names
  // its FileId, a response is matched to its request.
  const fidAt = FILE_ID_AT[command];
  let fid: string | undefined;
  let fileName: string | undefined;
  const asked = isResponse ? state.requests.get(messageId) : undefined;
  if (!isResponse && fidAt !== undefined && body + fidAt + 16 <= end) {
    fid = fileIdAt(bytes, body + fidAt);
    fileName = state.files.get(fid);
  } else if (asked !== undefined) {
    fid = asked.fid;
    fileName = asked.name;
  }
  const fileSuffix = fileName !== undefined && command !== 0x0b ? `, File: ${forColumn(fileName)}` : '';
  let rpc: DcerpcResult | null = null;
  /** DCE/RPC in a pipe's data, when the tree is IPC$ - or, with the tree unseen, when it reads as one. */
  const pipeRpc = (from: number, length: number): void => {
    if (fid === undefined || length <= 0) return;
    const tree = state.trees.get(treeId);
    if (tree !== undefined && !/\\IPC\$$/i.test(tree)) return;
    const dataEnd = Math.min(end, from + length);
    if (from < start || !looksLikeDcerpc(bytes, from, dataEnd)) return;
    let pipe = state.pipes.get(fid);
    if (pipe === undefined) {
      pipe = freshDcerpcConversation();
      bounded(state.pipes, fid, pipe);
    }
    rpc = dissectDcerpc(bytes, from, dataEnd, pipe, frame);
  };
  let auth: GssResult | null = null;
  /** The security blob at a (offset from the header, length) pair. */
  const securityBlob = (offsetAt: number): void => {
    if (body + offsetAt + 4 > end) return;
    const from = start + u16(bytes, body + offsetAt);
    const length = u16(bytes, body + offsetAt + 2);
    if (length === 0 || from < body || from + length > end) return;
    auth = dissectSecurityBlob(bytes, from, from + length);
  };
  switch (command) {
    case 0x00:                                          // Negotiate Protocol
      if (isResponse) securityBlob(56);
      break;
    case 0x01:                                          // Session Setup
      securityBlob(isResponse ? 4 : 12);
      break;
    case 0x03: {                                        // Tree Connect
      if (!isResponse && end - body >= 8) {
        const offset = u16(bytes, body + 4);
        const length = u16(bytes, body + 6);
        const tree = utf16(bytes, start + offset, length);
        fields['smb2.tree'] = tree;
        rows.push({ name: 'Tree', value: tree, abbrev: 'smb2.tree' });
        bounded(state.treeRequests, messageId, tree);
        detail = `, Tree: '${forColumn(tree)}'`;
      } else if (isResponse) {
        // The response names the request's tree, as the packet list shows it.
        const tree = state.treeRequests.get(messageId);
        if (tree !== undefined) {
          if (status === 0) bounded(state.trees, treeId, tree);
          detail = `, Tree: '${forColumn(tree)}'`;
        }
      }
      break;
    }
    case 0x05: {                                        // Create
      if (!isResponse && end - body >= 56) {
        const offset = u16(bytes, body + 44);
        const length = u16(bytes, body + 46);
        const file = utf16(bytes, start + offset, length);
        fields['smb2.filename'] = file;
        rows.push({ name: 'Filename', value: file, abbrev: 'smb2.filename' });
        rememberFile(state, messageId, file);
        detail = `, File: ${forColumn(file)}`;
      } else if (isResponse) {
        // The name is the request's, which this frame does not carry. The
        // reference prints `[unknown]` when it cannot match one either.
        const file = state.createdFiles.get(messageId);
        if (file !== undefined) fields['smb2.filename'] = file;
        detail = `, File: ${file === undefined ? '[unknown]' : forColumn(file)}`;
        // The FileId the server gave it, which every later request names.
        if (file !== undefined && status === 0 && body + 80 <= end) bounded(state.files, fileIdAt(bytes, body + 64), file);
      }
      break;
    }
    case 0x08:                                          // Read
    case 0x09: {                                        // Write
      if (!isResponse && end - body >= 24) {
        const isRead = command === 0x08;
        const length = u32(bytes, body + 4);
        const offset = u32(bytes, body + 8);
        fields[isRead ? 'smb2.read_length' : 'smb2.write_length'] = length;
        fields['smb2.file_offset'] = offset;
        rows.push({ name: 'Length', value: length, abbrev: isRead ? 'smb2.read_length' : 'smb2.write_length' });
        rows.push({ name: 'File Offset', value: offset, abbrev: 'smb2.file_offset' });
        // No comma, and no space after the colons - the one detail formatted
        // differently from every other, and only the oracle says so.
        detail = ` Len:${length} Off:${offset}`;
        if (!isRead) pipeRpc(start + u16(bytes, body + 2), length);
      } else if (isResponse && command === 0x08 && status === 0 && end - body >= 8) {
        pipeRpc(start + bytes[body + 2], u32(bytes, body + 4));
      }
      break;
    }
    case 0x0b: {                                        // Ioctl
      if (!isResponse && end - body >= 8) {
        const code = u32(bytes, body + 4);
        fields['smb2.ioctl.function'] = code;
        rows.push({ name: 'Function', value: nameIoctl(code), abbrev: 'smb2.ioctl.function' });
        detail = ` ${nameIoctl(code)}`;
        if (code === FSCTL_PIPE_TRANSCEIVE && end - body >= 32) pipeRpc(start + u32(bytes, body + 24), u32(bytes, body + 28));
      } else if (isResponse && status === 0 && end - body >= 40 && u32(bytes, body + 4) === FSCTL_PIPE_TRANSCEIVE) {
        fid = fileIdAt(bytes, body + 8);
        pipeRpc(start + u32(bytes, body + 32), u32(bytes, body + 36));
      }
      break;
    }
    case 0x0e: {                                        // Find
      if (!isResponse && end - body >= 32) {
        const infoClass = bytes[body + 2];
        const offset = u16(bytes, body + 24);
        const length = u16(bytes, body + 26);
        const pattern = utf16(bytes, start + offset, length);
        fields['smb2.find.pattern'] = pattern;
        rows.push({ name: 'Search Pattern', value: pattern, abbrev: 'smb2.find.pattern' });
        // The file goes before the class here, not after the detail.
        detail = `${fileSuffix}, ${FIND_CLASS_NAMES[infoClass] ?? `(Class:0x${infoClass.toString(16).padStart(2, '0')})`}`
          + `, Pattern: ${forColumn(pattern)}`;
      } else if (isResponse) {
        // The request's whole detail, error or not.
        detail = asked?.detail ?? '';
      }
      break;
    }
    case 0x10:                                          // GetInfo
    case 0x11: {                                        // SetInfo
      if (!isResponse && end - body >= 4) {
        const infoClass = bytes[body + 2];
        const level = bytes[body + 3];
        const className = INFO_CLASS_NAMES[infoClass];
        const levelName = infoClass === 0x01 ? FILE_INFO_LEVELS[level] : undefined;
        detail = ` ${className ?? `(Class:0x${infoClass.toString(16).padStart(2, '0')})`}`
          + `/${levelName ?? `(Level:0x${level.toString(16).padStart(2, '0')})`}`;
      }
      break;
    }
    default:
      detail = '';
  }

  // An error is announced before the detail, not after: a pending Create reads
  // `Create Response, Error: STATUS_PENDING, File: [unknown]`.
  const error = isResponse && status !== 0
    ? `, Error: ${STATUS_NAMES[status] ?? `0x${status.toString(16).padStart(8, '0')}`}`
    : '';
  // The file closes the Info line - on a request, and on a response that
  // succeeded. Find placed it already; Create names its own.
  if (command !== 0x0e && command !== 0x05 && (!isResponse || status === 0)) detail += fileSuffix;
  if (!isResponse && fid !== undefined) {
    bounded(state.requests, messageId, { fid, ...(fileName !== undefined ? { name: fileName } : {}), ...(command === 0x0e ? { detail } : {}) });
    // A Close forgets the file: what follows on that FileId is unnamed.
    if (command === 0x06) state.files.delete(fid);
  }
  if (fileName !== undefined) fields['smb2.filename'] = fileName;
  // Set inside `securityBlob`, which narrowing does not see: without the
  // cast, `auth` reads as the `null` it was declared with.
  const signIn = auth as GssResult | null;
  if (signIn !== null) Object.assign(fields, signIn.fields);
  return {
    message: {
      info: `${name} ${isResponse ? 'Response' : 'Request'}${error}${detail}${signIn?.info ?? ''}`,
      rows, fields,
      ...(rpc !== null ? { rpc } : {}),
      ...(signIn !== null ? { auth: signIn } : {}),
    },
    nextCommand,
  };
}

/** Whether these bytes open a NetBIOS-framed SMB2 message. */
export function looksLikeSmb2(bytes: Uint8Array, start: number, end: number): boolean {
  return end - start >= 4 + HEADER_SIZE
    && bytes[start] === 0x00
    && hasSmb2Magic(bytes, start + 4);
}

/**
 * Every SMB2 message in one segment.
 *
 * Two nestings, and they are different things. **Compounding** chains PDUs
 * inside one NBSS message through `NextCommand`, and the reference joins those
 * with `"; "`. **Several NBSS messages** in one segment is the ordinary case of
 * a TCP segment holding more than one PDU.
 *
 * A message whose declared length runs past the captured bytes is declined
 * rather than half-read, the rule DNS-over-TCP and LDAP both follow.
 */
export function dissectSmb2(
  bytes: Uint8Array, start: number, end: number, state: Smb2ConversationState, frame?: DcerpcFrame,
): Smb2Result | null {
  const messages: OneMessage[] = [];
  let offset = start;

  while (offset + 4 <= end) {
    if (bytes[offset] !== 0x00) break;                  // not a session message
    const declared = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const messageEnd = offset + 4 + declared;
    if (declared <= 0 || messageEnd > end) break;       // split across segments

    // The compound chain inside this NBSS message.
    let pdu = offset + 4;
    for (;;) {
      const read = readMessage(bytes, pdu, messageEnd, state, frame);
      if (read === null) break;
      messages.push(read.message);
      if (read.nextCommand === 0 || pdu + read.nextCommand >= messageEnd) break;
      pdu += read.nextCommand;
    }
    offset = messageEnd;
  }

  if (messages.length === 0) return null;
  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  for (const [index, message] of messages.entries()) {
    Object.assign(fields, message.fields);
    rows.push({
      name: messages.length === 1 ? 'SMB2 Header' : `SMB2 Header ${index + 1}`,
      value: '', children: message.rows,
    });
  }
  // DCE/RPC in a pipe takes the columns over, as the reference has it.
  const rpc = messages.find((m) => m.rpc !== undefined)?.rpc;
  if (rpc !== undefined) Object.assign(fields, rpc.fields);
  // The sign-in's protocols, then a pipe's RPC, each after SMB2's own layer.
  const innerLayers = [...messages.flatMap((m) => m.auth?.layers ?? []), ...(rpc?.layers ?? [])];
  return {
    protocolLabel: rpc?.protocolLabel ?? 'SMB2',
    info: rpc?.info ?? messages.map((m) => m.info).join('; '),
    fields,
    ...(innerLayers.length > 0 ? { innerLayers } : {}),
    ...(rpc?.answered !== undefined ? { answered: rpc.answered } : {}),
    layer: {
      name: 'SMB2',
      summary: messages.length === 1
        ? 'SMB2 (Server Message Block Protocol version 2)'
        : `SMB2 (${messages.length} messages)`,
      fields: rows,
    },
  };
}
