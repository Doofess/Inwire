/**
 * TFTP (RFC 1350), UDP 69 - the protocol a machine boots over.
 *
 *   Read Request, File: boot.bin, Transfer type: octet
 *   Data Packet, Block: 1
 *
 * Small, old and still everywhere: PXE boot, switch firmware, IP phone
 * provisioning. A capture containing TFTP is nearly always a capture of
 * something starting up, which is when things go wrong.
 *
 * **Only the first leg is read here, and that is a real limit rather than an
 * omission.** RFC 1350 §4 has the server answer a request from a *fresh*
 * ephemeral port, and the rest of the transfer runs between two ports nobody
 * could have predicted - so following it means remembering the request and
 * matching the reply, which is conversation state. Wireshark does that. Port
 * dispatch reaches the RRQ/WRQ and any implementation that keeps talking on
 * 69, and stops there. The transfer is not misread, it is unread, and a wrong
 * label would be the worse outcome.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface TftpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

const RRQ = 1, WRQ = 2, DATA = 3, ACK = 4, ERROR = 5, OACK = 6;

/** Wireshark's own wording for the opcode, which is what the Info line uses. */
const OPCODE_NAMES: Record<number, string> = {
  [RRQ]: 'Read Request',
  [WRQ]: 'Write Request',
  [DATA]: 'Data Packet',
  [ACK]: 'Acknowledgement',
  [ERROR]: 'Error Code',
  [OACK]: 'Option Acknowledgement',
};

/** RFC 1350 §5, plus RFC 2347's option-negotiation failure. */
const ERROR_NAMES: Record<number, string> = {
  0: 'Not defined',
  1: 'File not found',
  2: 'Access violation',
  3: 'Disk full or allocation exceeded',
  4: 'Illegal TFTP operation',
  5: 'Unknown transfer ID',
  6: 'File already exists',
  7: 'No such user',
  8: 'Option negotiation failed',
};

/** RFC 1350's fixed block size, and the default when none was negotiated. */
const BLOCK_BYTES = 512;

const utf8 = new TextDecoder('utf-8', { fatal: false });

/**
 * A NUL-terminated string, and where the next one starts.
 *
 * Every string field in TFTP is one of these - the format has no lengths at
 * all - so a datagram that runs out before the NUL is truncated rather than
 * empty, and says so by returning null.
 */
function netascii(bytes: Uint8Array, start: number, end: number): { text: string; after: number } | null {
  for (let p = start; p < end; p++) {
    if (bytes[p] === 0) return { text: utf8.decode(bytes.subarray(start, p)), after: p + 1 };
  }
  return null;
}

export function dissectTftp(bytes: Uint8Array, start: number, end: number): TftpResult | null {
  if (start + 2 > end) return null;
  const opcode = (bytes[start] << 8) | bytes[start + 1];
  const name = OPCODE_NAMES[opcode];
  if (name === undefined) return null;

  const fields: Record<string, string | number> = { 'tftp.opcode': opcode };
  const rows: ProtocolField[] = [
    { name: 'Opcode', value: `${name} (${opcode})`, abbrev: 'tftp.opcode',
      rawBytesRange: [start, start + 1] },
  ];
  let info = name;

  if (opcode === RRQ || opcode === WRQ) {
    const file = netascii(bytes, start + 2, end);
    if (file === null) return null;
    const mode = netascii(bytes, file.after, end);
    if (mode === null) return null;
    fields['tftp.source_file'] = file.text;
    fields['tftp.type'] = mode.text;
    rows.push(
      { name: opcode === RRQ ? 'Source File' : 'Destination File', value: file.text,
        abbrev: 'tftp.source_file', rawBytesRange: [start + 2, file.after - 1] },
      { name: 'Type', value: mode.text, abbrev: 'tftp.type',
        rawBytesRange: [file.after, mode.after - 1] },
    );
    // Anything after the mode is RFC 2347 option negotiation, which is the
    // same NUL-separated name/value pairs the acknowledgement carries - and
    // which joins the Info line the same way, so a capture shows what block
    // size was asked for without opening the frame.
    const options = appendOptions(bytes, mode.after, end, rows, fields);
    info = `${name}, File: ${file.text}, Transfer type: ${mode.text}`
      + (options.length > 0 ? `, ${options.join(', ')}` : '');
  } else if (opcode === DATA) {
    if (start + 4 > end) return null;
    const block = (bytes[start + 2] << 8) | bytes[start + 3];
    const dataLength = end - (start + 4);
    fields['tftp.block'] = block;
    fields['tftp.data_length'] = dataLength;
    // A block shorter than the block size IS the end of the transfer - that is
    // the whole of TFTP's termination, there is no FIN and no final flag. So
    // the Info line says so, which is what lets a reader find where a transfer
    // finished by scanning the column.
    //
    // BLOCK_BYTES is the RFC 1350 default. A transfer that negotiated a
    // different size with RFC 2347 `blksize` would need the request remembered
    // to know it, and that is conversation state this does not keep - so a
    // negotiated transfer marks its last block one block early or not at all.
    // Wrong in a way that under-claims, which is the right direction.
    const last = dataLength < BLOCK_BYTES;
    if (last) fields['tftp.last_block'] = 1;
    rows.push(
      { name: 'Block', value: block, abbrev: 'tftp.block', rawBytesRange: [start + 2, start + 3] },
      { name: 'Data', value: `${dataLength} bytes`,
        rawBytesRange: [start + 4, Math.max(start + 4, end - 1)] },
    );
    info = `${name}, Block: ${block}${last ? ' (last)' : ''}`;
  } else if (opcode === ACK) {
    if (start + 4 > end) return null;
    const block = (bytes[start + 2] << 8) | bytes[start + 3];
    fields['tftp.block'] = block;
    rows.push({ name: 'Block', value: block, abbrev: 'tftp.block',
      rawBytesRange: [start + 2, start + 3] });
    info = `${name}, Block: ${block}`;
  } else if (opcode === ERROR) {
    if (start + 4 > end) return null;
    const code = (bytes[start + 2] << 8) | bytes[start + 3];
    const message = netascii(bytes, start + 4, end);
    if (message === null) return null;
    const codeName = ERROR_NAMES[code] ?? `Unknown (${code})`;
    fields['tftp.error.code'] = code;
    fields['tftp.error.message'] = message.text;
    rows.push(
      { name: 'Error code', value: `${codeName} (${code})`, abbrev: 'tftp.error.code',
        rawBytesRange: [start + 2, start + 3] },
      { name: 'Error message', value: message.text, abbrev: 'tftp.error.message',
        rawBytesRange: [start + 4, message.after - 1] },
    );
    // Wireshark names the CODE and then prints the server's own message, which
    // are usually but not always the same words.
    info = `${name}, Code: ${codeName}, Message: ${message.text}`;
  } else {
    // OACK: nothing but options.
    const options = appendOptions(bytes, start + 2, end, rows, fields);
    if (options.length === 0) return null;
    info = `${name}, ${options.join(', ')}`;
  }

  return {
    protocolLabel: 'TFTP',
    info,
    fields,
    layer: {
      name: 'Trivial File Transfer Protocol',
      summary: `Trivial File Transfer Protocol (${name})`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}

/** RFC 2347 option pairs, appended as rows; returns them as `name=value`. */
function appendOptions(
  bytes: Uint8Array, start: number, end: number,
  rows: ProtocolField[], fields: Record<string, string | number>,
): string[] {
  const pairs: string[] = [];
  let p = start;
  while (p < end) {
    const name = netascii(bytes, p, end);
    if (name === null || name.text.length === 0) break;
    const value = netascii(bytes, name.after, end);
    if (value === null) break;
    rows.push({ name: name.text, value: value.text, rawBytesRange: [p, value.after - 1] });
    fields[`tftp.option.${name.text.toLowerCase()}`] = value.text;
    pairs.push(`${name.text}=${value.text}`);
    p = value.after;
  }
  return pairs;
}
