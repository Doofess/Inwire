/**
 * DCE/RPC over TCP, connection-oriented (C706 chapter 12, MS-RPCE) - what
 * Windows administration, Active Directory replication and the endpoint
 * mapper speak.
 *
 *   Bind: call_id: 2, Fragment: Single, 1 context items: EPMv4 V3.0 (32bit NDR)
 *   Bind_ack: call_id: 2, Fragment: Single, max_xmit: 5840 max_recv: 5840, 1 results: Acceptance
 *   Map request, DRSUAPI, 32bit NDR
 *   NetShareEnumAll request
 *
 * A connection binds presentation contexts - an interface by UUID and the
 * transfer syntax to speak it in - and every later call names its context by
 * number, so which interface a request is for, and what its operation number
 * means, is the connection's state (`DcerpcConversationState`), as is which
 * request a response answers. The interface and operation names are the
 * reference's own, generated into `dcerpcNames.ts`; the endpoint mapper's
 * Map is read whole (`dissectors/epm.ts`), every other interface's stub is
 * drawn as bytes.
 *
 * Not read: a call fragmented across several PDUs is shown one PDU at a time,
 * where the reference reassembles it; and an authentication verifier other
 * than NTLMSSP's is drawn as its trailer and bytes, not decoded as Kerberos.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { INTERFACES, SYNTAXES } from './dcerpcNames';
import { dissectEpm, EPM_UUID, readUuid, uuidName } from './epm';
import { elapsedText } from './ldap';
import { dissectNtlmssp, ntlmsspVerifier } from './ntlmssp';
import { headingFor } from '../dissect/nestedLayers';

export const EPM_PORT = 135;

const TYPES: Record<number, string> = {
  0: 'Request', 1: 'Ping', 2: 'Response', 3: 'Fault', 4: 'Working', 5: 'Nocall', 6: 'Reject', 7: 'Ack',
  8: 'Cl_cancel', 9: 'Fack', 10: 'Cancel_ack', 11: 'Bind', 12: 'Bind_ack', 13: 'Bind_nak', 14: 'Alter_context',
  15: 'Alter_context_resp', 16: 'AUTH3', 17: 'Shutdown', 18: 'Co_cancel', 19: 'Orphaned', 20: 'RPC-over-HTTP RTS',
};
const ACK_RESULTS: Record<number, string> = { 0: 'Acceptance', 1: 'User rejection', 2: 'Provider rejection', 3: 'Negotiate ACK' };
const ACK_REASONS: Record<number, string> = {
  0: 'Reason not specified', 1: 'Abstract syntax not supported', 2: 'Proposed transfer syntaxes not supported', 3: 'Local limit exceeded',
};
const REJECT_REASONS: Record<number, string> = {
  0: 'Reason not specified', 1: 'Temporary congestion', 2: 'Local limit exceeded', 3: 'Called paddr unknown',
  4: 'Protocol version not supported', 5: 'Default context not supported', 6: 'User data not readable',
  7: 'No PSAP available', 8: 'Authentication type not recognized', 9: 'Invalid checksum',
};
const AUTH_TYPES: Record<number, string> = {
  0: 'None', 1: 'Kerberos 5', 9: 'SPNEGO', 10: 'NTLMSSP', 14: 'SCHANNEL SSP', 16: 'Kerberos SSP',
  17: 'Distributed Password Authentication SSP', 18: 'MSN SSP', 21: 'Digest SSP', 68: 'NETLOGON Secure Channel', 100: 'MSMQ SSP',
};
const AUTH_NTLMSSP = 10;
const AUTH_LEVELS: Record<number, string> = {
  1: 'None', 2: 'Connect', 3: 'Call', 4: 'Packet', 5: 'Packet integrity', 6: 'Packet privacy',
};
/** `dcerpc.cn_status`, the reference's names - a fault's reason. */
const STATUSES: Record<number, string> = {
  0x0: 'Stub-defined exception', 0x1: 'nca_s_fault_other', 0x5: 'nca_s_fault_access_denied', 0x6f7: 'nca_s_fault_ndr',
  0x6d8: 'nca_s_fault_cant_perform', 0x721: 'nca_s_fault_sec_pkg_error', 0x1c000001: 'nca_s_fault_int_div_by_zero',
  0x1c000002: 'nca_s_fault_addr_error', 0x1c000003: 'nca_s_fault_fp_div_zero', 0x1c000004: 'nca_s_fault_fp_underflow',
  0x1c000005: 'nca_s_fault_fp_overflow', 0x1c000006: 'nca_s_fault_invalid_tag', 0x1c000007: 'nca_s_fault_invalid_bound',
  0x1c000008: 'nca_rpc_version_mismatch', 0x1c000009: 'nca_unspec_reject', 0x1c00000a: 'nca_s_bad_actid',
  0x1c00000b: 'nca_who_are_you_failed', 0x1c00000c: 'nca_manager_not_entered', 0x1c00000d: 'nca_s_fault_cancel',
  0x1c00000e: 'nca_s_fault_ill_inst', 0x1c00000f: 'nca_s_fault_fp_error', 0x1c000010: 'nca_s_fault_int_overflow',
  0x1c000014: 'nca_s_fault_pipe_empty', 0x1c000015: 'nca_s_fault_pipe_closed', 0x1c000016: 'nca_s_fault_pipe_order',
  0x1c000017: 'nca_s_fault_pipe_discipline', 0x1c000018: 'nca_s_fault_pipe_comm_error', 0x1c000019: 'nca_s_fault_pipe_memory',
  0x1c00001a: 'nca_s_fault_context_mismatch', 0x1c00001b: 'nca_s_fault_remote_no_memory', 0x1c00001c: 'nca_invalid_pres_context_id',
  0x1c00001d: 'nca_unsupported_authn_level', 0x1c00001f: 'nca_invalid_checksum', 0x1c000020: 'nca_invalid_crc',
  0x1c000021: 'ncs_s_fault_user_defined', 0x1c000022: 'nca_s_fault_tx_open_failed', 0x1c000023: 'nca_s_fault_codeset_conv_error',
  0x1c000024: 'nca_s_fault_object_not_found', 0x1c000025: 'nca_s_fault_no_client_stub', 0x1c010002: 'nca_op_rng_error',
  0x1c010003: 'nca_unk_if', 0x1c010006: 'nca_wrong_boot_time', 0x1c010009: 'nca_s_you_crashed', 0x1c01000b: 'nca_proto_error',
  0x1c010013: 'nca_out_args_too_big', 0x1c010014: 'nca_server_too_busy', 0x1c010017: 'nca_unsupported_type',
  0x80004001: 'E_NOTIMPL', 0x80004003: 'E_POINTER', 0x80004004: 'E_ABORT', 0x8000ffff: 'E_UNEXPECTED',
  0x80010105: 'RPC_E_SERVERFAULT', 0x80010108: 'RPC_E_DISCONNECTED', 0x80010113: 'RPC_E_INVALID_IPID', 0x8001011f: 'RPC_E_TIMEOUT',
  0x80020003: 'DISP_E_MEMBERNOTFOUND', 0x80020006: 'DISP_E_UNKNOWNNAME', 0x8002000e: 'DISP_E_BADPARAMCOUNT',
  0x8007000e: 'E_OUTOFMEMORY', 0x80070057: 'E_INVALIDARG', 0x800706d1: 'RPC_S_PROCNUM_OUT_OF_RANGE', 0x80070776: 'OR_INVALID_OXID',
};
/** The bind-time feature negotiation "syntax", whose UUID carries a bitmask. */
const BTFN_PREFIX = '6cb71c2c-9812-4540-';

type Bit = [mask: number, abbrev: string, name: string];
const PACKET_FLAGS: Bit[] = [
  [0x80, 'dcerpc.cn_flags.object', 'Object'], [0x40, 'dcerpc.cn_flags.maybe', 'Maybe'],
  [0x20, 'dcerpc.cn_flags.dne', 'Did Not Execute'], [0x10, 'dcerpc.cn_flags.mpx', 'Multiplex'],
  [0x08, 'dcerpc.cn_flags.reserved', 'Reserved'], [0x04, 'dcerpc.cn_flags.cancel_pending', 'Cancel Pending'],
  [0x02, 'dcerpc.cn_flags.last_frag', 'Last Frag'], [0x01, 'dcerpc.cn_flags.first_frag', 'First Frag'],
];
const FLAG_OBJECT = 0x80;
const BTFN_BITS: Bit[] = [
  [0x01, 'dcerpc.cn_bind_trans_btfn.01', 'Security Context Multiplexing Supported'],
  [0x02, 'dcerpc.cn_bind_trans_btfn.02', 'Keep Connection On Orphan Supported'],
];

const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const hexColons = (b: Uint8Array, from: number, to: number) =>
  Array.from(b.subarray(from, to), (x) => x.toString(16).padStart(2, '0')).join(':');
const LATIN1 = new TextDecoder('latin1');

/** A bound presentation context. */
interface BoundContext { uuid: string; major: number; minor: number }

/** One connection's contexts and its calls awaiting an answer. */
export interface DcerpcConversationState {
  contexts: Map<number, BoundContext>;
  calls: Map<number, { frame: number; tsUs: number; opnum: number }>;
}
export const freshDcerpcConversation = (): DcerpcConversationState => ({ contexts: new Map(), calls: new Map() });
const MAX_CALLS = 1024;

/**
 * Whether a segment opens with a connection-oriented PDU: version 5.0 or 5.1,
 * a known type, a data representation the reference accepts, and a fragment
 * that fits.
 */
export function looksLikeDcerpc(b: Uint8Array, start: number, end: number): boolean {
  if (end - start < 16) return false;
  if (b[start] !== 5 || b[start + 1] > 1 || b[start + 2] > 20) return false;
  if ((b[start + 4] & 0xee) !== 0 || b[start + 5] > 3 || b[start + 6] !== 0 || b[start + 7] !== 0) return false;
  const little = (b[start + 4] & 0x10) !== 0;
  const fragLen = little ? b[start + 8] | (b[start + 9] << 8) : (b[start + 8] << 8) | b[start + 9];
  const authLen = little ? b[start + 10] | (b[start + 11] << 8) : (b[start + 10] << 8) | b[start + 11];
  return fragLen >= 16 && start + fragLen <= end && authLen + 16 <= fragLen;
}

const fragmentName = (flags: number) =>
  (flags & 3) === 3 ? 'Single' : (flags & 1) !== 0 ? '1st' : (flags & 2) !== 0 ? 'Last' : 'Mid';

export interface DcerpcResult {
  protocolLabel: string;
  info: string;
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
  /** The request a response answered, which learns of it only now. */
  answered?: { requestFrame: number; responseFrame: number };
}

export interface DcerpcFrame { id: number; tsUs: number }

/** One PDU at `start`. Callers check `looksLikeDcerpc` first. */
export function dissectDcerpc(b: Uint8Array, start: number, end: number, state: DcerpcConversationState,
  frame?: DcerpcFrame): DcerpcResult | null {
  const little = (b[start + 4] & 0x10) !== 0;
  const u16 = (at: number) => (little ? b[at] | (b[at + 1] << 8) : (b[at] << 8) | b[at + 1]);
  const u32 = (at: number) => (little
    ? (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0
    : ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0);
  const type = b[start + 2];
  const flags = b[start + 3];
  const fragLen = u16(start + 8);
  const authLen = u16(start + 10);
  const callId = u32(start + 12);
  const pduEnd = Math.min(end, start + fragLen);
  // The authentication verifier and its eight-byte trailer close the PDU.
  const bodyEnd = authLen > 0 ? pduEnd - authLen - 8 : pduEnd;
  const typeName = TYPES[type] ?? 'Unknown';
  const fragment = fragmentName(flags);

  const byteOrder = b[start + 4] >> 4;
  const character = b[start + 4] & 0x0f;
  const fp = b[start + 5];
  const drepText = `${hexColons(b, start + 4, start + 8).replace(/:/g, '')} (Order: ${byteOrder === 1 ? 'Little-endian' : 'Big-endian'}, Char: ${character === 0 ? 'ASCII' : 'EBCDIC'}, Float: ${['IEEE', 'VAX', 'Cray', 'IBM'][fp] ?? 'Unknown'})`;
  const rows: ProtocolField[] = [
    { name: 'Version', value: b[start], abbrev: 'dcerpc.ver', rawBytesRange: [start, start] },
    { name: 'Version (minor)', value: b[start + 1], abbrev: 'dcerpc.ver_minor', rawBytesRange: [start + 1, start + 1] },
    { name: 'Packet type', value: `${typeName} (${type})`, abbrev: 'dcerpc.pkt_type', rawBytesRange: [start + 2, start + 2] },
    ...(type === 13 ? [{ name: 'Bind not acknowledged', value: '', abbrev: 'dcerpc.bind_not_acknowledged', generated: true,
      expertInfo: { category: 'Note' as const, message: 'Bind not acknowledged' } }] : []),
    {
      name: 'Packet Flags', value: hex(flags, 2), abbrev: 'dcerpc.cn_flags', rawBytesRange: [start + 3, start + 3],
      children: PACKET_FLAGS.map(([mask, abbrev, name]): ProtocolField => ({
        name, value: (flags & mask) !== 0 ? 'Set' : 'Not set', abbrev, rawBytesRange: [start + 3, start + 3],
        bitfield: { bitOffset: 7 - Math.log2(mask), bitLength: 1, totalBits: 8 },
      })),
    },
    {
      name: 'Data Representation', value: drepText, abbrev: 'dcerpc.drep', rawBytesRange: [start + 4, start + 7],
      children: [
        { name: 'Byte order', value: `${byteOrder === 1 ? 'Little-endian' : 'Big-endian'} (${byteOrder})`, abbrev: 'dcerpc.drep.byteorder', rawBytesRange: [start + 4, start + 4] },
        { name: 'Character', value: `${character === 0 ? 'ASCII' : 'EBCDIC'} (${character})`, abbrev: 'dcerpc.drep.character', rawBytesRange: [start + 4, start + 4] },
        { name: 'Floating-point', value: `${['IEEE', 'VAX', 'Cray', 'IBM'][fp] ?? 'Unknown'} (${fp})`, abbrev: 'dcerpc.drep.fp', rawBytesRange: [start + 5, start + 5] },
      ],
    },
    { name: 'Frag Length', value: fragLen, abbrev: 'dcerpc.cn_frag_len', rawBytesRange: [start + 8, start + 9] },
    { name: 'Auth Length', value: authLen, abbrev: 'dcerpc.cn_auth_len', rawBytesRange: [start + 10, start + 11] },
    { name: 'Call ID', value: callId, abbrev: 'dcerpc.cn_call_id', rawBytesRange: [start + 12, start + 15] },
  ];
  const fields: Record<string, string | number> = { 'dcerpc.pkt_type': type, 'dcerpc.cn_call_id': callId };
  const extra: ProtocolLayer[] = [];
  let protocolLabel = 'DCERPC';
  let info = `${typeName}: call_id: ${callId}, Fragment: ${fragment}`;
  let answered: DcerpcResult['answered'];
  const p = start + 16;

  /** A context's interface as the column writes it: `EPMv4 V3.0`, or the bare UUID. */
  const interfaceText = (uuid: string, major: number, minor: number) => `${uuidName(uuid) ?? uuid} V${major}.${minor}`;

  if ((type === 11 || type === 14) && p + 8 <= bodyEnd) {
    // Bind and Alter_context: the contexts the client proposes.
    const count = b[p + 8];
    rows.push(
      { name: 'Max Xmit Frag', value: u16(p), abbrev: 'dcerpc.cn_max_xmit', rawBytesRange: [p, p + 1] },
      { name: 'Max Recv Frag', value: u16(p + 2), abbrev: 'dcerpc.cn_max_recv', rawBytesRange: [p + 2, p + 3] },
      { name: 'Assoc Group', value: hex(u32(p + 4), 8), abbrev: 'dcerpc.cn_assoc_group', rawBytesRange: [p + 4, p + 7] },
      { name: 'Num Ctx Items', value: count, abbrev: 'dcerpc.cn_num_ctx_items', rawBytesRange: [p + 8, p + 8] },
    );
    const offered: string[] = [];
    let q = p + 12;
    for (let i = 1; i <= count && q + 24 <= bodyEnd; i++) {
      const ctxId = u16(q);
      const transCount = b[q + 2];
      const uuid = readUuid(b, q + 4);
      const major = u16(q + 20);
      const minor = u16(q + 22);
      state.contexts.set(ctxId, { uuid, major, minor });
      const ifName = uuidName(uuid);
      const children: ProtocolField[] = [
        { name: 'Context ID', value: ctxId, abbrev: 'dcerpc.cn_ctx_id', rawBytesRange: [q, q + 1] },
        { name: 'Num Trans Items', value: transCount, abbrev: 'dcerpc.cn_num_trans_items', rawBytesRange: [q + 2, q + 2] },
        {
          name: 'Abstract Syntax', value: interfaceText(uuid, major, minor), abbrev: 'dcerpc.cn_bind_abstract_syntax', rawBytesRange: [q + 4, q + 23],
          children: [
            ifName !== undefined
              ? { name: 'Interface', value: `${ifName} UUID: ${uuid}`, abbrev: 'dcerpc.cn_bind_to_uuid', rawBytesRange: [q + 4, q + 19] }
              : { name: 'Interface UUID', value: uuid, abbrev: 'dcerpc.cn_bind_to_uuid', rawBytesRange: [q + 4, q + 19] },
            { name: 'Interface Ver', value: major, abbrev: 'dcerpc.cn_bind_if_ver', rawBytesRange: [q + 20, q + 21] },
            { name: 'Interface Ver Minor', value: minor, abbrev: 'dcerpc.cn_bind_if_ver_minor', rawBytesRange: [q + 22, q + 23] },
          ],
        },
      ];
      let r = q + 24;
      const syntaxNames: string[] = [];
      for (let t = 1; t <= transCount && r + 20 <= bodyEnd; t++, r += 20) {
        const syntax = readUuid(b, r);
        const version = u32(r + 16);
        const btfn = syntax.startsWith(BTFN_PREFIX);
        const syntaxName = SYNTAXES[syntax] ?? (btfn ? 'Bind Time Feature Negotiation' : undefined);
        syntaxNames.push(syntaxName ?? syntax);
        if (t === 1) offered.push(`${interfaceText(uuid, major, minor)} (${SYNTAXES[syntax] ?? syntax})`);
        const transfer: ProtocolField[] = [
          { name: 'Transfer Syntax', value: syntaxName !== undefined ? `${syntaxName} UUID:${syntax}` : syntax, abbrev: 'dcerpc.cn_bind_trans_id', rawBytesRange: [r, r + 15] },
        ];
        if (btfn) transfer.push(btfnRow(b[r + 8] | (b[r + 9] << 8), r + 8));
        transfer.push({ name: 'ver', value: version, abbrev: 'dcerpc.cn_bind_trans_ver', rawBytesRange: [r + 16, r + 19] });
        children.push({ name: `Transfer Syntax[${t}]`, value: `${syntaxName ?? syntax} V${version}`, abbrev: 'dcerpc.cn_bind_trans', rawBytesRange: [r, r + 19], children: transfer });
      }
      rows.push({
        name: `Ctx Item[${i}]`, value: `Context ID:${ctxId}, ${ifName ?? uuid}, ${syntaxNames.join(', ')}`,
        abbrev: 'dcerpc.cn_ctx_item', rawBytesRange: [q, r - 1], children,
      });
      q = r;
    }
    info += `, ${count} context items: ${offered.join(', ')}`;
  } else if ((type === 12 || type === 15) && p + 10 <= bodyEnd) {
    // Bind_ack and Alter_context_resp: the server's answer to each context.
    const secLen = u16(p + 8);
    let q = p + 10 + secLen;
    q += (4 - ((q - start) % 4)) % 4;
    rows.push(
      { name: 'Max Xmit Frag', value: u16(p), abbrev: 'dcerpc.cn_max_xmit', rawBytesRange: [p, p + 1] },
      { name: 'Max Recv Frag', value: u16(p + 2), abbrev: 'dcerpc.cn_max_recv', rawBytesRange: [p + 2, p + 3] },
      { name: 'Assoc Group', value: hex(u32(p + 4), 8), abbrev: 'dcerpc.cn_assoc_group', rawBytesRange: [p + 4, p + 7] },
      { name: 'Scndry Addr len', value: secLen, abbrev: 'dcerpc.cn_sec_addr_len', rawBytesRange: [p + 8, p + 9] },
    );
    if (secLen > 0) {
      let stop = p + 10;
      while (stop < p + 10 + secLen && b[stop] !== 0) stop++;
      rows.push({ name: 'Scndry Addr', value: LATIN1.decode(b.subarray(p + 10, stop)), abbrev: 'dcerpc.cn_sec_addr', rawBytesRange: [p + 10, p + 9 + secLen] });
    }
    const count = q < bodyEnd ? b[q] : 0;
    rows.push({ name: 'Num results', value: count, abbrev: 'dcerpc.cn_num_results', rawBytesRange: [q, q] });
    const results: string[] = [];
    let r = q + 4;
    for (let i = 1; i <= count && r + 24 <= bodyEnd; i++, r += 24) {
      const result = u16(r);
      const reason = u16(r + 2);
      const syntax = readUuid(b, r + 4);
      results.push(ACK_RESULTS[result] ?? 'Unknown');
      const children: ProtocolField[] = [
        { name: 'Ack result', value: `${ACK_RESULTS[result] ?? 'Unknown'} (${result})`, abbrev: 'dcerpc.cn_ack_result', rawBytesRange: [r, r + 1] },
      ];
      // A negotiate ACK's reason is the bind-time feature bitmask.
      if (result === 3) children.push(btfnRow(reason, r + 2));
      else if (result !== 0) children.push({ name: 'Ack reason', value: `${ACK_REASONS[reason] ?? 'Unknown'} (${reason})`, abbrev: 'dcerpc.cn_ack_reason', rawBytesRange: [r + 2, r + 3] });
      children.push(
        // The null UUID is, to the reference, PROFINET's implicit AR.
        { name: 'Transfer Syntax', value: syntax === '00000000-0000-0000-0000-000000000000' ? 'PNIO (Implicit Ar)' : uuidName(syntax) ?? syntax, abbrev: 'dcerpc.cn_ack_trans_id', rawBytesRange: [r + 4, r + 19] },
        { name: 'Syntax ver', value: u32(r + 20), abbrev: 'dcerpc.cn_ack_trans_ver', rawBytesRange: [r + 20, r + 23] },
      );
      rows.push({ name: `Ctx Item[${i}]`, value: ACK_RESULTS[result] ?? 'Unknown', rawBytesRange: [r, r + 23], children });
    }
    info += `, max_xmit: ${u16(p)} max_recv: ${u16(p + 2)}, ${count} results: ${results.join(', ')}`;
  } else if (type === 13 && p + 2 <= bodyEnd) {
    // Bind_nak: why, and the protocol versions the server would speak.
    const reason = u16(p);
    const count = p + 2 < bodyEnd ? b[p + 2] : 0;
    rows.push(
      { name: 'Reject reason', value: `${REJECT_REASONS[reason] ?? 'Unknown'} (${reason})`, abbrev: 'dcerpc.cn_reject_reason', rawBytesRange: [p, p + 1] },
      { name: 'Number of protocols', value: count, abbrev: 'dcerpc.cn_num_protocols', rawBytesRange: [p + 2, p + 2] },
    );
    for (let i = 0, q = p + 3; i < count && q + 2 <= bodyEnd; i++, q += 2) {
      rows.push(
        { name: 'Protocol major version', value: b[q], abbrev: 'dcerpc.cn_protocol_ver_major', rawBytesRange: [q, q] },
        { name: 'Protocol minor version', value: b[q + 1], abbrev: 'dcerpc.cn_protocol_ver_minor', rawBytesRange: [q + 1, q + 1] },
      );
    }
    info += ` reason: ${REJECT_REASONS[reason] ?? 'Unknown'}`;
  } else if ((type === 0 || type === 2 || type === 3) && p + 8 <= bodyEnd) {
    const ctxId = u16(p + 4);
    const context = state.contexts.get(ctxId);
    rows.push(
      { name: 'Alloc hint', value: u32(p), abbrev: 'dcerpc.cn_alloc_hint', rawBytesRange: [p, p + 3] },
      { name: 'Context ID', value: ctxId, abbrev: 'dcerpc.cn_ctx_id', rawBytesRange: [p + 4, p + 5] },
    );
    fields['dcerpc.cn_ctx_id'] = ctxId;
    let stubStart = p + 8;
    let opnum: number | undefined;
    let link: ProtocolField | null = null;
    const answerRows: ProtocolField[] = [];
    if (type === 0) {
      opnum = u16(p + 6);
      rows.push({ name: 'Opnum', value: opnum, abbrev: 'dcerpc.opnum', rawBytesRange: [p + 6, p + 7] });
      if ((flags & FLAG_OBJECT) !== 0 && stubStart + 16 <= bodyEnd) {
        rows.push({ name: 'Object UUID', value: readUuid(b, stubStart), abbrev: 'dcerpc.obj_id', rawBytesRange: [stubStart, stubStart + 15] });
        stubStart += 16;
      }
      if (frame !== undefined) {
        state.calls.set(callId, { frame: frame.id, tsUs: frame.tsUs, opnum });
        if (state.calls.size > MAX_CALLS) {
          const oldest = state.calls.keys().next();
          if (!oldest.done) state.calls.delete(oldest.value);
        }
      }
    } else {
      rows.push({ name: 'Cancel count', value: b[p + 6], abbrev: 'dcerpc.cn_cancel_count', rawBytesRange: [p + 6, p + 6] });
      const asked = state.calls.get(callId);
      if (asked !== undefined && frame !== undefined && asked.frame !== frame.id) {
        opnum = asked.opnum;
        link = { name: 'Request in frame', value: asked.frame, abbrev: 'dcerpc.request_in', generated: true, linkToFrame: asked.frame };
        answerRows.push(
          { name: 'Opnum', value: opnum, abbrev: 'dcerpc.opnum', generated: true },
          link,
          { name: 'Time from request', value: elapsedText(frame.tsUs - asked.tsUs), abbrev: 'dcerpc.time', generated: true },
        );
        answered = { requestFrame: asked.frame, responseFrame: frame.id };
      }
      // A response draws them before its stub; a fault after its status.
      if (type === 2) rows.push(...answerRows);
    }
    if (opnum !== undefined) fields['dcerpc.opnum'] = opnum;

    if (type === 3) {
      const faultFlags = b[p + 7];
      const status = u32(p + 8);
      const statusName = STATUSES[status] ?? 'Unknown';
      rows.push(
        {
          name: 'Fault flags', value: `${hex(faultFlags, 2)}${(faultFlags & 1) !== 0 ? ', Extended error information present' : ''}`,
          abbrev: 'dcerpc.cn_fault_flags', rawBytesRange: [p + 7, p + 7],
          children: [{ name: 'Extended error information present', value: (faultFlags & 1) !== 0 ? 'True' : 'False',
            abbrev: 'dcerpc.cn_fault_flags.extended_error', rawBytesRange: [p + 7, p + 7], bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } }],
        },
        {
          name: 'Status', value: `${statusName} (${hex(status, 8)})`, abbrev: 'dcerpc.cn_status', rawBytesRange: [p + 8, p + 11],
          children: [{ name: 'Fault', value: statusName, abbrev: 'dcerpc.cn_status.expert', generated: true,
            expertInfo: { category: 'Note', message: `Fault: ${statusName}` } }],
        },
        { name: 'Reserved', value: hexColons(b, p + 12, Math.min(bodyEnd, p + 16)), abbrev: 'dcerpc.reserved', rawBytesRange: [p + 12, p + 15] },
        ...answerRows,
      );
      fields['dcerpc.cn_status'] = status;
      info += `, Ctx: ${ctxId}, status: ${statusName}`;
    } else {
      const known = context !== undefined ? INTERFACES[context.uuid] : undefined;
      const stubLength = Math.max(0, bodyEnd - stubStart);
      if (known === undefined) {
        rows.push({ name: 'Stub data', value: hexColons(b, stubStart, bodyEnd), abbrev: 'dcerpc.stub_data', rawBytesRange: [stubStart, Math.max(stubStart, bodyEnd - 1)] });
        info += `${type === 0 ? `, opnum: ${opnum}` : ''}, Ctx: ${ctxId}${context !== undefined ? ` ${context.uuid} V${context.major}` : ''}`;
      } else {
        rows.push({ name: `Payload stub data (${stubLength} bytes)`, value: '', abbrev: 'dcerpc.payload_stub_data', rawBytesRange: [stubStart, Math.max(stubStart, bodyEnd - 1)] });
        protocolLabel = known.protocol;
        const isResponse = type === 2;
        if (context?.uuid === EPM_UUID && opnum !== undefined) {
          const epm = dissectEpm(b, stubStart, bodyEnd, opnum, isResponse, link === null ? null : { ...link });
          extra.push(epm.layer);
          info = epm.info;
        } else {
          // Any other named interface: its own layer, naming the operation,
          // over a stub drawn as the bytes it is.
          const opName = opnum !== undefined ? known.operations[opnum] ?? `Unknown operation ${opnum}` : 'Unknown operation';
          info = `${opName} ${isResponse ? 'response' : 'request'}`;
          const callRows: ProtocolField[] = [];
          if (known.opnumField !== null && opnum !== undefined) {
            callRows.push({ name: 'Operation', value: `${opName} (${opnum})`, abbrev: known.opnumField });
          }
          if (link !== null) callRows.push({ ...link });
          callRows.push({ name: 'Stub', value: `${stubLength} bytes`, rawBytesRange: [stubStart, Math.max(stubStart, bodyEnd - 1)] });
          extra.push({ name: known.layer, summary: `${known.layer}, ${opName}`, rawBytesRange: [stubStart, Math.max(stubStart, bodyEnd - 1)], fields: callRows });
        }
      }
    }
  }

  /**
   * The verifier itself. NTLMSSP's is read: a Bind, Bind_ack or AUTH3 carries
   * a whole message, which names the sign-in on the Info line and is drawn
   * inside Auth Info; every later PDU carries its signature. Any other
   * mechanism's is its bytes.
   */
  const authData = (from: number): ProtocolField => {
    if (b[bodyEnd] === AUTH_NTLMSSP) {
      const ntlm = dissectNtlmssp(b, from, pduEnd);
      if (ntlm !== null) {
        extra.push(ntlm.layer);
        Object.assign(fields, ntlm.fields);
        info += `, ${ntlm.info}`;
        return headingFor(ntlm.layer);
      }
      const verifier = ntlmsspVerifier(b, from, pduEnd);
      if (verifier !== null) return verifier;
    }
    return { name: 'Auth Data', value: `${authLen} bytes`, rawBytesRange: [from, pduEnd - 1] };
  };
  if (authLen > 0 && bodyEnd >= p) {
    const at = bodyEnd;
    const authType = b[at];
    const authLevel = b[at + 1];
    rows.push({
      name: 'Auth Info', value: `${AUTH_TYPES[authType] ?? 'Unknown'}, ${AUTH_LEVELS[authLevel] ?? 'Unknown'}, AuthContextId(${u32(at + 4)})`,
      abbrev: 'dcerpc.auth_info', rawBytesRange: [at, pduEnd - 1],
      children: [
        { name: 'Auth type', value: `${AUTH_TYPES[authType] ?? 'Unknown'} (${authType})`, abbrev: 'dcerpc.auth_type', rawBytesRange: [at, at] },
        { name: 'Auth level', value: `${AUTH_LEVELS[authLevel] ?? 'Unknown'} (${authLevel})`, abbrev: 'dcerpc.auth_level', rawBytesRange: [at + 1, at + 1] },
        { name: 'Auth pad len', value: b[at + 2], abbrev: 'dcerpc.auth_pad_len', rawBytesRange: [at + 2, at + 2] },
        { name: 'Auth Rsrvd', value: b[at + 3], abbrev: 'dcerpc.auth_rsrvd', rawBytesRange: [at + 3, at + 3] },
        { name: 'Auth Context ID', value: u32(at + 4), abbrev: 'dcerpc.auth_ctx_id', rawBytesRange: [at + 4, at + 7] },
        authData(at + 8),
      ],
    });
    fields['dcerpc.auth_type'] = authType;
  }

  return {
    protocolLabel,
    info,
    fields,
    ...(answered !== undefined ? { answered } : {}),
    layers: [
      {
        name: 'Distributed Computing Environment / Remote Procedure Call (DCE/RPC)',
        summary: `Distributed Computing Environment / Remote Procedure Call (DCE/RPC) ${typeName}, Fragment: ${fragment}, FragLen: ${fragLen}, Call: ${callId}`,
        rawBytesRange: [start, Math.max(start, pduEnd - 1)],
        fields: rows,
      },
      ...extra,
    ],
  };
}

function btfnRow(bits: number, at: number): ProtocolField {
  const set = BTFN_BITS.filter(([mask]) => (bits & mask) !== 0).map(([, , name]) => `, ${name}`).join('');
  return {
    name: 'Bind Time Features', value: `${hex(bits, 4)}${set}`, abbrev: 'dcerpc.cn_bind_trans_btfn', rawBytesRange: [at, at + 1],
    children: BTFN_BITS.map(([mask, abbrev, name]): ProtocolField => ({
      name, value: (bits & mask) !== 0 ? 'True' : 'False', abbrev, rawBytesRange: [at, at + 1],
      bitfield: { bitOffset: 15 - Math.log2(mask), bitLength: 1, totalBits: 16 },
    })),
  };
}
