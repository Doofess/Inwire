/**
 * SMB1 (MS-CIFS) - the header every SMB1 message carries, and the one command
 * a network still sends in volume: the Transaction written to a mailslot,
 * which is how every Windows browser announcement travels.
 *
 *   Trans Request
 *   Negotiate Protocol Request
 *
 * SMB1 is a different wire format from SMB2 (`ÿSMB` against `þSMB`), not the
 * same protocol with a smaller number, and `dissectors/smb2.ts` is the one a
 * file share speaks. What reaches a capture of SMB1 today is the NetBIOS
 * datagram traffic of `dissectors/nbds.ts` - a Trans request to
 * `\MAILSLOT\BROWSE` - so that command is read whole and handed to
 * `dissectors/browser.ts`; every other command draws its header, its word and
 * byte counts, and its name in the reference's words.
 *
 * Every name, true/false sentence and timeout wording is tshark's, read one
 * flag at a time.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { BROWSE_MAILSLOT, dissectBrowser, flagsRow, mailslotLayer, msecsText, type Bit } from './browser';
import { STATUS_NAMES } from './smb2';

const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const le16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const hexColons = (b: Uint8Array, from: number, to: number) =>
  Array.from(b.subarray(from, to), (x) => x.toString(16).padStart(2, '0')).join(':');
const LATIN1 = new TextDecoder('latin1');
const UTF16 = new TextDecoder('utf-16le');

const HEADER_SIZE = 32;

/** `ÿSMB`, compared as bytes - see `hasSmb2Magic` for why not as a number. */
export function hasSmbMagic(b: Uint8Array, at: number): boolean {
  return b[at] === 0xff && b[at + 1] === 0x53 && b[at + 2] === 0x4d && b[at + 3] === 0x42;
}

/** The reference's name for every command it knows; the gaps print as `Unknown`. */
const COMMANDS: Record<number, string> = {
  0x00: 'Create Directory', 0x01: 'Delete Directory', 0x02: 'Open', 0x03: 'Create', 0x04: 'Close', 0x05: 'Flush',
  0x06: 'Delete', 0x07: 'Rename', 0x08: 'Query Information', 0x09: 'Set Information', 0x0a: 'Read', 0x0b: 'Write',
  0x0c: 'Lock Byte Range', 0x0d: 'Unlock Byte Range', 0x0e: 'Create Temp', 0x0f: 'Create New', 0x10: 'Check Directory',
  0x11: 'Process Exit', 0x12: 'Seek', 0x13: 'Lock And Read', 0x14: 'Write And Unlock', 0x15: 'unknown-0x15',
  0x16: 'unknown-0x16', 0x17: 'unknown-0x17', 0x18: 'unknown-0x18', 0x19: 'unknown-0x19', 0x1a: 'Read Raw',
  0x1b: 'Read MPX', 0x1c: 'Read MPX Secondary', 0x1d: 'Write Raw', 0x1e: 'Write MPX', 0x1f: 'Write MPX Secondary',
  0x20: 'Write Complete', 0x21: 'Query Server (reserved)', 0x22: 'Set Information2', 0x23: 'Query Information2',
  0x24: 'Locking AndX', 0x25: 'Trans', 0x26: 'Trans Secondary', 0x27: 'IOCTL', 0x28: 'IOCTL Secondary', 0x29: 'Copy',
  0x2a: 'Move', 0x2b: 'Echo', 0x2c: 'Write And Close', 0x2d: 'Open AndX', 0x2e: 'Read AndX', 0x2f: 'Write AndX',
  0x30: 'New File Size (reserved)', 0x31: 'Close And Tree Disconnect', 0x32: 'Trans2', 0x33: 'Trans2 Secondary',
  0x34: 'Find Close2', 0x35: 'Find Notify Close', 0x70: 'Tree Connect', 0x71: 'Tree Disconnect',
  0x72: 'Negotiate Protocol', 0x73: 'Session Setup AndX', 0x74: 'Logoff AndX', 0x75: 'Tree Connect AndX',
  0x80: 'Query Information Disk', 0x81: 'Search', 0x82: 'Find', 0x83: 'Find Unique', 0x84: 'Find Close',
  0xa0: 'NT Trans', 0xa1: 'NT Trans Secondary', 0xa2: 'NT Create AndX', 0xa3: 'unknown-0xA3', 0xa4: 'NT Cancel',
  0xa5: 'NT Rename', 0xc0: 'Open Print File', 0xc1: 'Write Print File', 0xc2: 'Close Print File',
  0xc3: 'Get Print Queue', 0xd0: 'Send Single Block Message', 0xd1: 'Send Broadcast Message',
  0xd2: 'Forward User Name', 0xd3: 'Cancel Forward', 0xd4: 'Get Machine Name',
  0xd5: 'Send Start of Multi-block Message', 0xd6: 'Send End of Multi-block Message',
  0xd7: 'Send Text of Multi-block Message', 0xd8: 'SMBreadbulk', 0xd9: 'SMBwritebulk', 0xda: 'SMBwritebulkdata',
  0xfe: 'SMBinvalid',
};
const commandName = (cmd: number) => COMMANDS[cmd] ?? `Unknown (${hex(cmd, 2)})`;

const ERROR_CLASSES: Record<number, string> = { 0: 'Success', 1: 'DOS Error', 2: 'Server Error', 3: 'Hardware Error' };
/** DOS error codes, only those read from the reference. */
const DOS_ERRORS: Record<number, string> = { 0: 'No Error', 5: 'Access denied' };

const FLAGS: Bit[] = [
  [0x80, 'smb.flags.response', 'Request/Response', 'Message is a response to the client/redirector', 'Message is a request to the server'],
  [0x40, 'smb.flags.notify', 'Notify', 'Notify client on all modifications', 'Notify client only on open'],
  [0x20, 'smb.flags.oplock', 'Oplocks', 'OpLock requested/granted', 'OpLock not requested/granted'],
  [0x10, 'smb.flags.canon', 'Canonicalized Pathnames', 'Pathnames are canonicalized', 'Pathnames are not canonicalized'],
  [0x08, 'smb.flags.caseless', 'Case Sensitivity', 'Path names are caseless', 'Path names are case sensitive'],
  [0x02, 'smb.flags.receive_buffer', 'Receive Buffer Posted', 'Receive buffer has been posted', 'Receive buffer has not been posted'],
  [0x01, 'smb.flags.lock', 'Lock and Read', 'Lock&Read, Write&Unlock are supported', 'Lock&Read, Write&Unlock are not supported'],
];
const FLAG_RESPONSE = 0x80;
const FLAGS2: Bit[] = [
  [0x8000, 'smb.flags2.string', 'Unicode Strings', 'Strings are Unicode', 'Strings are ASCII'],
  [0x4000, 'smb.flags2.nt_error', 'Error Code Type', 'Error codes are NT error codes', 'Error codes are DOS error codes'],
  [0x2000, 'smb.flags2.roe', 'Execute-only Reads', 'Permit reads if execute-only', "Don't permit reads if execute-only"],
  [0x1000, 'smb.flags2.dfs', 'Dfs', 'Resolve pathnames with Dfs', "Don't resolve pathnames with Dfs"],
  [0x0800, 'smb.flags2.esn', 'Extended Security Negotiation', 'Extended security negotiation is supported', 'Extended security negotiation is not supported'],
  [0x0400, 'smb.flags2.reparse_path', 'Reparse Path', 'The request uses a @GMT reparse path', 'The request does not use a @GMT reparse path'],
  [0x0040, 'smb.flags2.long_names_used', 'Long Names Used', 'Path names in request are long file names', 'Path names in request are not long file names'],
  [0x0010, 'smb.flags2.sec_sig_required', 'Security Signatures Required', 'Security signatures are required', 'Security signatures are not required'],
  [0x0008, 'smb.flags2.compressed', 'Compressed', 'Compression is requested', 'Compression is not requested'],
  [0x0004, 'smb.flags2.sec_sig', 'Security Signatures', 'Security signatures are supported', 'Security signatures are not supported'],
  [0x0002, 'smb.flags2.ea', 'Extended Attributes', 'Extended attributes are supported', 'Extended attributes are not supported'],
  [0x0001, 'smb.flags2.long_names_allowed', 'Long Names Allowed', 'Long file names are allowed in the response', 'Long file names are not allowed in the response'],
];
const FLAGS2_UNICODE = 0x8000;
const FLAGS2_NT_ERROR = 0x4000;

const TRANS_FLAGS: Bit[] = [
  [0x0002, 'smb.transaction.flags.owt', 'One Way Transaction', 'One Way Transaction (NO RESPONSE)', 'Two way transaction'],
  [0x0001, 'smb.transaction.flags.dtid', 'Disconnect TID', 'Also DISCONNECT TID', 'Do NOT disconnect TID'],
];

/** A Trans request's timeout, in milliseconds, with its three reserved values named. */
function timeoutText(ms: number): string {
  if (ms === 0) return 'Return immediately (0)';
  if (ms === 0xffffffff) return 'Wait indefinitely (-1)';
  if (ms === 0xfffffffe) return 'Use default timeout (-2)';
  return msecsText(ms);
}

export interface SmbResult {
  protocolLabel: string;
  info: string;
  /** SMB, and the mailslot and browser layers a Trans request carries. */
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
}

/** A string in the byte area: UTF-16 aligned to the message when the header says Unicode, else ASCII. */
function smbString(b: Uint8Array, smbStart: number, at: number, end: number, unicode: boolean): { text: string; from: number; after: number } {
  if (unicode) {
    const from = (at - smbStart) % 2 === 1 ? at + 1 : at;
    let p = from;
    while (p + 1 < end && (b[p] !== 0 || b[p + 1] !== 0)) p += 2;
    return { text: UTF16.decode(b.subarray(from, p)), from, after: Math.min(end, p + 2) };
  }
  let p = at;
  while (p < end && b[p] !== 0) p++;
  return { text: LATIN1.decode(b.subarray(at, p)), from: at, after: Math.min(end, p + 1) };
}

/** One SMB1 message, `start` at its `ÿSMB`. */
export function dissectSmb(b: Uint8Array, start: number, end: number): SmbResult | null {
  if (end - start < HEADER_SIZE + 3 || !hasSmbMagic(b, start)) return null;
  const cmd = b[start + 4];
  const flags = b[start + 9];
  const flags2 = le16(b, start + 10);
  const isResponse = (flags & FLAG_RESPONSE) !== 0;
  const unicode = (flags2 & FLAGS2_UNICODE) !== 0;
  const name = commandName(cmd);
  const fields: Record<string, string | number> = {
    'smb.cmd': cmd, 'smb.tid': le16(b, start + 24), 'smb.pid': le16(b, start + 26),
    'smb.uid': le16(b, start + 28), 'smb.mid': le16(b, start + 30),
  };

  const header: ProtocolField[] = [
    { name: 'Server Component', value: 'SMB', abbrev: 'smb.server_component', rawBytesRange: [start, start + 3] },
    { name: 'SMB Command', value: `${name} (${hex(cmd, 2)})`, abbrev: 'smb.cmd', rawBytesRange: [start + 4, start + 4] },
  ];
  if ((flags2 & FLAGS2_NT_ERROR) !== 0) {
    const status = le32(b, start + 5);
    fields['smb.nt_status'] = status;
    header.push({ name: 'NT Status', value: `${status === 0 ? 'STATUS_SUCCESS' : STATUS_NAMES[status] ?? 'Unknown'} (${hex(status, 8)})`,
      abbrev: 'smb.nt_status', rawBytesRange: [start + 5, start + 8] });
  } else {
    const cls = b[start + 5];
    const code = le16(b, start + 7);
    header.push(
      { name: 'Error Class', value: `${ERROR_CLASSES[cls] ?? 'Unknown'} (${hex(cls, 2)})`, abbrev: 'smb.error_class', rawBytesRange: [start + 5, start + 5] },
      { name: 'Reserved', value: hexColons(b, start + 6, start + 7), abbrev: 'smb.reserved', rawBytesRange: [start + 6, start + 6] },
      { name: 'Error Code', value: DOS_ERRORS[code] ?? `Unknown (${hex(code, 4)})`, abbrev: 'smb.error_code', rawBytesRange: [start + 7, start + 8] },
    );
  }
  header.push(
    flagsRow('Flags', 'smb.flags', flags, 1, start + 9, FLAGS),
    flagsRow('Flags2', 'smb.flags2', flags2, 2, start + 10, FLAGS2),
    { name: 'Process ID High', value: le16(b, start + 12), abbrev: 'smb.pid.high', rawBytesRange: [start + 12, start + 13] },
    { name: 'Signature', value: hexColons(b, start + 14, start + 22), abbrev: 'smb.signature', rawBytesRange: [start + 14, start + 21] },
    { name: 'Reserved', value: hexColons(b, start + 22, start + 24), abbrev: 'smb.reserved', rawBytesRange: [start + 22, start + 23] },
    { name: 'Tree ID', value: le16(b, start + 24), abbrev: 'smb.tid', rawBytesRange: [start + 24, start + 25] },
    { name: 'Process ID', value: le16(b, start + 26), abbrev: 'smb.pid', rawBytesRange: [start + 26, start + 27] },
    { name: 'User ID', value: le16(b, start + 28), abbrev: 'smb.uid', rawBytesRange: [start + 28, start + 29] },
    { name: 'Multiplex ID', value: le16(b, start + 30), abbrev: 'smb.mid', rawBytesRange: [start + 30, start + 31] },
  );

  const w = start + HEADER_SIZE + 1;
  const wct = b[start + HEADER_SIZE];
  const bccAt = w + wct * 2;
  const body: ProtocolField[] = [
    { name: 'Word Count (WCT)', value: wct, abbrev: 'smb.wct', rawBytesRange: [start + HEADER_SIZE, start + HEADER_SIZE] },
  ];
  const direction = isResponse ? 'Response' : 'Request';
  let protocolLabel = 'SMB';
  let info = `${name} ${direction}`;
  const extra: ProtocolLayer[] = [];

  if (bccAt + 2 > end) return null;
  const bcc = le16(b, bccAt);

  if (cmd === 0x25 && !isResponse && wct >= 14) {
    // SMB_COM_TRANSACTION's request (MS-CIFS 2.2.4.33.1).
    const sc = b[w + 26];
    const tdc = le16(b, w + 2);
    const dc = le16(b, w + 22);
    const dataOffset = le16(b, w + 24);
    body.push(
      { name: 'Total Parameter Count', value: le16(b, w), abbrev: 'smb.tpc', rawBytesRange: [w, w + 1] },
      { name: 'Total Data Count', value: tdc, abbrev: 'smb.tdc', rawBytesRange: [w + 2, w + 3] },
      { name: 'Max Parameter Count', value: le16(b, w + 4), abbrev: 'smb.mpc', rawBytesRange: [w + 4, w + 5] },
      { name: 'Max Data Count', value: le16(b, w + 6), abbrev: 'smb.mdc', rawBytesRange: [w + 6, w + 7] },
      { name: 'Max Setup Count', value: b[w + 8], abbrev: 'smb.msc', rawBytesRange: [w + 8, w + 8] },
      { name: 'Reserved', value: hexColons(b, w + 9, w + 10), abbrev: 'smb.reserved', rawBytesRange: [w + 9, w + 9] },
      flagsRow('Flags', 'smb.transaction.flags', le16(b, w + 10), 2, w + 10, TRANS_FLAGS),
      { name: 'Timeout', value: timeoutText(le32(b, w + 12)), abbrev: 'smb.timeout', rawBytesRange: [w + 12, w + 15] },
      { name: 'Reserved', value: hexColons(b, w + 16, w + 18), abbrev: 'smb.reserved', rawBytesRange: [w + 16, w + 17] },
      { name: 'Parameter Count', value: le16(b, w + 18), abbrev: 'smb.pc', rawBytesRange: [w + 18, w + 19] },
      { name: 'Parameter Offset', value: le16(b, w + 20), abbrev: 'smb.po', rawBytesRange: [w + 20, w + 21] },
      { name: 'Data Count', value: dc, abbrev: 'smb.dc', rawBytesRange: [w + 22, w + 23] },
      { name: 'Bytes remaining until TDC', value: Math.max(0, tdc - dc), abbrev: 'smb.bytes_until_tdc' },
      { name: 'Data Offset', value: dataOffset, abbrev: 'smb.data_offset', rawBytesRange: [w + 24, w + 25] },
      { name: 'Setup Count', value: sc, abbrev: 'smb.sc', rawBytesRange: [w + 26, w + 26] },
      { name: 'Reserved', value: hexColons(b, w + 27, w + 28), abbrev: 'smb.reserved', rawBytesRange: [w + 27, w + 27] },
      { name: 'Byte Count (BCC)', value: bcc, abbrev: 'smb.bcc', rawBytesRange: [bccAt, bccAt + 1] },
    );
    const transName = smbString(b, start, bccAt + 2, Math.min(end, bccAt + 2 + bcc), unicode);
    body.push({ name: 'Transaction Name', value: transName.text, abbrev: 'smb.trans_name',
      rawBytesRange: [transName.from, Math.max(transName.from, transName.after - 1)] });
    fields['smb.trans_name'] = transName.text;

    const upper = transName.text.toUpperCase();
    if (upper.startsWith('\\MAILSLOT\\') && sc >= 3 && w + 28 + 6 <= end) {
      // The mailslot layer reads its name as ASCII wherever the name begins,
      // as the reference does: a Unicode name preceded by its alignment byte
      // reads as empty there.
      const slotName = smbString(b, start, bccAt + 2, Math.min(end, bccAt + 2 + bcc), false);
      extra.push(mailslotLayer(b, w + 28, bcc, bccAt, slotName.text,
        [slotName.from, Math.max(slotName.from, slotName.after - 1)]));
      const dataStart = start + dataOffset;
      const dataEnd = Math.min(end, dataStart + dc);
      if (upper === BROWSE_MAILSLOT && dataStart < dataEnd) {
        const browser = dissectBrowser(b, dataStart, dataEnd);
        if (browser !== null) {
          extra.push(browser.layer);
          Object.assign(fields, browser.fields);
          protocolLabel = 'BROWSER';
          info = browser.info;
        }
      }
    }
  } else {
    body.push({ name: 'Byte Count (BCC)', value: bcc, abbrev: 'smb.bcc', rawBytesRange: [bccAt, bccAt + 1] });
  }

  return {
    protocolLabel,
    info,
    fields,
    layers: [
      {
        name: 'SMB (Server Message Block Protocol)',
        summary: `SMB (Server Message Block Protocol), ${name} ${direction} (${hex(cmd, 2)})`,
        rawBytesRange: [start, Math.max(start, end - 1)],
        fields: [
          { name: 'SMB Header', value: '', rawBytesRange: [start, start + HEADER_SIZE - 1], children: header },
          { name: `${name} ${direction} (${hex(cmd, 2)})`, value: '', children: body },
        ],
      },
      ...extra,
    ],
  };
}
