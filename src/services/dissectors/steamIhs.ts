/**
 * Steam In-Home Streaming discovery (UDP 27036): how every Steam client on a
 * LAN finds the others to stream games to and from. A running client
 * broadcasts a Client Discovery, and each other one answers with a Client
 * Status naming its host, its OS, its signed-in users and its MAC addresses -
 * which is why a capture on any network with a gaming PC on it carries them.
 *
 * An eight-byte signature, then a length-prefixed protobuf header (who sent
 * it, and the message type) and a length-prefixed protobuf body, whose fields
 * depend on the type. Field names and formats are the reference's, checked
 * against `tshark -T pdml` by `scripts/steam/dissect.ts`; a field the
 * reference does not know is drawn as it draws one, an unknown number or an
 * unknown length-delimited value with an Undecoded note under it.
 *
 * One deliberate difference: the reference reads an unknown fixed 32-bit
 * field's value from the four bytes AFTER it, and shows the next field's key
 * as its number. This reads the four bytes the field holds.
 */
import type { ProtocolField } from '../../types/packet';
import { formatArrivalTime } from '../dissect/arrivalTime';
import { hexColons } from '../dissect/hexBytes';
import type { LeafResult } from './dispatch';

export const STEAM_IHS_PORT = 27036;
const SIGNATURE = [0xff, 0xff, 0xff, 0xff, 0x21, 0x4c, 0x5f, 0xa0];

const MESSAGE_TYPES = [
  'Client Discovery', 'Client Status', 'Client Offline', 'Device Authorization Request',
  'Device Authorization Response', 'Device Streaming Request', 'Device Streaming Response',
  'Device Proof Request', 'Device Proof Response', 'Device Authorization Cancel Request',
  'Device Streaming Cancel Request',
];
const AUTH_RESULTS = ['Success', 'Denied', 'Not Logged In', 'Offline', 'Busy', 'In Progress', 'TimedOut', 'Failed', 'Canceled'];
const STREAMING_RESULTS = [
  'Success', 'Unauthorized', 'Screen Locked', 'Failed', 'Busy', 'In Progress', 'Canceled',
  'Drivers Not Installed', 'Disabled', 'Broadcasting Active', 'VR Active', 'PIN Required',
];

/**
 * How a field's value is shown. `id` is a 64-bit number with its hex beside
 * it, `hex32`/`hex64` hex alone, `nobytes` a byte string whose row is only
 * its name (the reference's "Encrypted Request").
 */
type Kind = 'u32' | 'i32' | 'hex32' | 'hex64' | 'id' | 'u64' | 'bool' | 'string' | 'bytes' | 'nobytes' | 'time' | 'user'
  | readonly string[];
interface Spec { abbrev: string; name: string; kind: Kind }
const spec = (abbrev: string, name: string, kind: Kind): Spec => ({ abbrev, name, kind });

const HEADER: Record<number, Spec> = {
  1: spec('steam_ihs_discovery.header_client_id', 'Client ID', 'id'),
  2: spec('steam_ihs_discovery.header_msg_type', 'Message Type', MESSAGE_TYPES),
  3: spec('steam_ihs_discovery.header_instance_id', 'Instance ID', 'id'),
};
const USER: Record<number, Spec> = {
  1: spec('steam_ihs_discovery.body_status_user_steamid', 'Steam ID', 'u64'),
  2: spec('steam_ihs_discovery.body_status_user_authkeyid', 'Auth Key ID', 'u32'),
};
const BODIES: Record<number, Record<number, Spec>> = {
  0: {
    1: spec('steam_ihs_discovery.body_discovery_seqnum', 'Sequence Number', 'u32'),
    2: spec('steam_ihs_discovery.body_discovery_clientids', 'Client IDs', 'hex64'),
  },
  1: {
    1: spec('steam_ihs_discovery.body_status_version', 'Version', 'i32'),
    2: spec('steam_ihs_discovery.body_status_minversion', 'Minimum Version', 'i32'),
    3: spec('steam_ihs_discovery.body_status_connectport', 'Connect Port', 'u32'),
    4: spec('steam_ihs_discovery.body_status_hostname', 'Hostname', 'string'),
    6: spec('steam_ihs_discovery.body_status_enabledservices', 'Enabled Services', 'hex32'),
    7: spec('steam_ihs_discovery.body_status_ostype', 'OS Type', 'i32'),
    8: spec('steam_ihs_discovery.body_status_is64bit', 'Is 64 Bit', 'bool'),
    // A submessage with no field name of its own: its row is `User, ...`.
    9: spec('', 'User', 'user'),
    11: spec('steam_ihs_discovery.body_status_euniverse', 'EUniverse', 'i32'),
    12: spec('steam_ihs_discovery.body_status_timestamp', 'Timestamp', 'time'),
    13: spec('steam_ihs_discovery.body_status_screenlocked', 'Screen Locked', 'bool'),
    14: spec('steam_ihs_discovery.body_status_gamesrunning', 'Games Running', 'bool'),
    15: spec('steam_ihs_discovery.body_status_macaddresses', 'MAC Addresses', 'string'),
  },
  2: {},
  3: {
    1: spec('steam_ihs_discovery.body_authrequest_devicetoken', 'Device Token', 'bytes'),
    2: spec('steam_ihs_discovery.body_authrequest_devicename', 'Device Name', 'string'),
    3: spec('steam_ihs_discovery.body_authrequest_encryptedrequest', 'Encrypted Request', 'nobytes'),
  },
  4: { 1: spec('steam_ihs_discovery.body_authresponse_authresult', 'Result', AUTH_RESULTS) },
  5: {
    1: spec('steam_ihs_discovery.body_streamingrequest_requestid', 'Request ID', 'hex32'),
    2: spec('steam_ihs_discovery.body_streamingrequest_maximumresolutionx', 'Maximum Resolution X', 'i32'),
    3: spec('steam_ihs_discovery.body_streamingrequest_maximumresolutiony', 'Maximum Resolution Y', 'i32'),
    4: spec('steam_ihs_discovery.body_streamingrequest_audiochannelcount', 'Audio Channel Count', 'i32'),
    5: spec('steam_ihs_discovery.body_streamingrequest_deviceversion', 'Device Version', 'string'),
    6: spec('steam_ihs_discovery.body_streamingrequest_streamdesktop', 'Stream Desktop', 'bool'),
    7: spec('steam_ihs_discovery.body_streamingrequest_devicetoken', 'Device Token', 'bytes'),
    8: spec('steam_ihs_discovery.body_streamingrequest_pin', 'PIN', 'bytes'),
    9: spec('steam_ihs_discovery.body_streamingrequest_enablevideostreaming', 'Enable Video Streaming', 'bool'),
    10: spec('steam_ihs_discovery.body_streamingrequest_enableaudiostreaming', 'Enable Audio Streaming', 'bool'),
    11: spec('steam_ihs_discovery.body_streamingrequest_enableinputstreaming', 'Enable Input Streaming', 'bool'),
  },
  6: {
    1: spec('steam_ihs_discovery.body_streamingresponse_requestid', 'Request ID', 'hex32'),
    2: spec('steam_ihs_discovery.body_streamingresponse_result', 'Result', STREAMING_RESULTS),
    3: spec('steam_ihs_discovery.body_streamingresponse_port', 'Port', 'u32'),
    4: spec('steam_ihs_discovery.body_streamingresponse_encryptedsessionkey', 'Encrypted Session Key', 'bytes'),
    5: spec('steam_ihs_discovery.body_streamingresponse_virtualherelicenseddevicecount', 'VirtualHere Licensed Device Count', 'i32'),
  },
  7: { 1: spec('steam_ihs_discovery.body_proofrequest_challenge', 'Challenge', 'bytes') },
  8: { 1: spec('steam_ihs_discovery.body_proofresponse_response', 'Response', 'bytes') },
  9: {},
  10: { 1: spec('steam_ihs_discovery.body_streamingcancelrequest_requestid', 'Request ID', 'hex32') },
};

const u32le = (b: Uint8Array, p: number) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
const hex = (v: bigint, digits: number) => `0x${v.toString(16).padStart(digits, '0')}`;
const plainHex = (b: Uint8Array, from: number, to: number) => hexColons(b, from, to).replace(/:/g, '');
const decoder = new TextDecoder();

/** One protobuf field: its number, wire type, and where its value lies. */
interface Wire { field: number; wire: number; value: bigint; from: number; to: number }

function varint(b: Uint8Array, p: number, end: number): [bigint, number] | null {
  let value = 0n;
  for (let shift = 0n; p < end && shift < 70n; shift += 7n) {
    const byte = b[p++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [BigInt.asUintN(64, value), p];
  }
  return null;
}

/** The fields of one message, stopping at the first it cannot read. */
function fieldsOf(b: Uint8Array, p: number, end: number): Wire[] {
  const out: Wire[] = [];
  while (p < end) {
    const key = varint(b, p, end);
    if (key === null) break;
    const field = Number(key[0] >> 3n);
    const wire = Number(key[0] & 7n);
    p = key[1];
    if (wire === 0) {
      const v = varint(b, p, end);
      if (v === null) break;
      out.push({ field, wire, value: v[0], from: p, to: v[1] });
      p = v[1];
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4;
      if (p + size > end) break;
      let value = 0n;
      for (let i = size - 1; i >= 0; i--) value = (value << 8n) | BigInt(b[p + i]);
      out.push({ field, wire, value, from: p, to: p + size });
      p += size;
    } else if (wire === 2) {
      const length = varint(b, p, end);
      if (length === null || length[1] + Number(length[0]) > end) break;
      out.push({ field, wire, value: length[0], from: length[1], to: length[1] + Number(length[0]) });
      p = length[1] + Number(length[0]);
    } else {
      break;
    }
  }
  return out;
}

const WIRE_NAMES: Record<number, string> = { 0: 'VarInt', 1: '64-bit', 5: '32-bit' };

/** A field the message's table does not know, drawn as the reference draws one. */
function unknownRow(b: Uint8Array, w: Wire): ProtocolField {
  const delimited = w.wire === 2;
  const note = delimited ? 'Unknown length-delimited protobuf field' : `Unknown numeric protobuf field (wire type ${w.wire} = ${WIRE_NAMES[w.wire]})`;
  return {
    name: delimited ? 'Unknown Data' : 'Unknown Number',
    value: delimited ? plainHex(b, w.from, w.to) : `${w.value} (${hex(w.value, 16)})`,
    abbrev: delimited ? 'steam_ihs_discovery.unknown_data' : 'steam_ihs_discovery.unknown_number',
    rawBytesRange: [w.from, Math.max(w.from, w.to - 1)],
    children: [{
      name: note, value: '', abbrev: delimited ? 'steam_ihs_discovery.unknownlengthdelimited' : 'steam_ihs_discovery.unknownnumber', generated: true,
      expertInfo: { category: 'Note', message: note },
    }],
  };
}

/** Rows for one message's fields; `known` collects each field's value for the Info column. */
function rowsOf(
  b: Uint8Array, from: number, to: number, table: Record<number, Spec> | undefined,
  fields: Record<string, string | number>, known: Map<string, bigint | string>,
): ProtocolField[] {
  const rows: ProtocolField[] = [];
  for (const w of fieldsOf(b, from, to)) {
    const s = table?.[w.field];
    const kind = s?.kind;
    const varintKind = kind === 'u32' || kind === 'i32' || kind === 'hex32' || kind === 'hex64' || kind === 'id' || kind === 'bool'
      || kind === 'time' || Array.isArray(kind);
    const lengthKind = kind === 'string' || kind === 'bytes' || kind === 'nobytes' || kind === 'user';
    const fits = s !== undefined && ((varintKind && w.wire === 0) || (lengthKind && w.wire === 2) || (kind === 'u64' && (w.wire === 1 || w.wire === 0)));
    if (!fits || s === undefined || kind === undefined) { rows.push(unknownRow(b, w)); continue; }
    const abbrev = s.abbrev;
    const range: [number, number] = [w.from, Math.max(w.from, w.to - 1)];
    if (kind === 'user') {
      const children = rowsOf(b, w.from, w.to, USER, fields, new Map());
      const summary = children.filter((c) => Object.values(USER).some((u) => u.abbrev === c.abbrev)).map((c) => `${c.name}: ${c.value}`);
      rows.push({ name: 'User', value: summary.join(', '), rawBytesRange: range, children });
      continue;
    }
    let value: string | number | boolean;
    let filterValue: string | number | undefined;
    if (kind === 'string') {
      value = decoder.decode(b.subarray(w.from, w.to));
      filterValue = value;
      known.set(abbrev, value);
    } else if (kind === 'bytes' || kind === 'nobytes') {
      value = kind === 'bytes' ? plainHex(b, w.from, w.to) : '';
    } else if (kind === 'bool') {
      value = w.value !== 0n;
      filterValue = value ? 1 : 0;
    } else if (kind === 'time') {
      value = formatArrivalTime(Number(w.value) * 1_000_000);
    } else if (kind === 'id') {
      value = `${w.value} (${hex(w.value, 16)})`;
    } else if (kind === 'u64') {
      value = String(w.value);
    } else if (kind === 'hex64') {
      value = hex(w.value, 16);
    } else {
      const n = kind === 'i32' ? Number(BigInt.asIntN(32, w.value)) : Number(BigInt.asUintN(32, w.value));
      filterValue = n;
      known.set(abbrev, BigInt(n));
      value = kind === 'hex32' ? hex(BigInt(n), 8) : Array.isArray(kind) ? `${kind[n] ?? 'Unknown'} (${n})` : n;
    }
    if (filterValue !== undefined && !(abbrev in fields)) fields[abbrev] = filterValue;
    rows.push({ name: s.name, value, abbrev, rawBytesRange: range });
  }
  return rows;
}

/** The Info column, built up from the fields present as the reference builds it. */
function infoOf(type: number, known: Map<string, bigint | string>): string {
  const name = MESSAGE_TYPES[type];
  if (name === undefined) return 'Unknown Message';
  const n = (abbrev: string) => known.get(abbrev);
  const id = (abbrev: string) => { const v = n(abbrev); return v === undefined ? undefined : v.toString(16).padStart(8, '0'); };
  const result = (abbrev: string, names: readonly string[]) => {
    const v = n(abbrev);
    return v === undefined ? '' : ` Result=${v}(${names[Number(v)] ?? 'Unknown'})`;
  };
  switch (type) {
    case 0: return n('steam_ihs_discovery.body_discovery_seqnum') === undefined ? name : `${name} Seq=${n('steam_ihs_discovery.body_discovery_seqnum')}`;
    case 1: return n('steam_ihs_discovery.body_status_hostname') === undefined ? name : `${name} from ${n('steam_ihs_discovery.body_status_hostname')}`;
    case 3: return n('steam_ihs_discovery.body_authrequest_devicename') === undefined ? name : `${name} from ${n('steam_ihs_discovery.body_authrequest_devicename')}`;
    case 4: return `${name}${result('steam_ihs_discovery.body_authresponse_authresult', AUTH_RESULTS)}`;
    case 5: return id('steam_ihs_discovery.body_streamingrequest_requestid') === undefined ? name : `${name} ID=${id('steam_ihs_discovery.body_streamingrequest_requestid')}`;
    case 6: {
      const request = id('steam_ihs_discovery.body_streamingresponse_requestid');
      const port = n('steam_ihs_discovery.body_streamingresponse_port');
      return `${name}${request === undefined ? '' : ` ID=${request}`}${result('steam_ihs_discovery.body_streamingresponse_result', STREAMING_RESULTS)}${port === undefined ? '' : ` Port=${port}`}`;
    }
    case 10: return id('steam_ihs_discovery.body_streamingcancelrequest_requestid') === undefined ? name : `${name}, ID=${id('steam_ihs_discovery.body_streamingcancelrequest_requestid')}`;
    default: return name;
  }
}

export function dissectSteamIhs(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start + 12 > end) return null;
  for (let i = 0; i < SIGNATURE.length; i++) if (b[start + i] !== SIGNATURE[i]) return null;
  const headerLength = u32le(b, start + 8);
  const headerFrom = start + 12;
  const headerTo = headerFrom + headerLength;
  if (headerTo + 4 > end) return null;
  const bodyLength = u32le(b, headerTo);
  const bodyFrom = headerTo + 4;
  const bodyTo = Math.min(end, bodyFrom + bodyLength);

  const fields: Record<string, string | number> = { 'steam_ihs_discovery.header_length': headerLength, 'steam_ihs_discovery.body_length': bodyLength };
  const known = new Map<string, bigint | string>();
  const headerRows = rowsOf(b, headerFrom, headerTo, HEADER, fields, known);
  const typeValue = known.get('steam_ihs_discovery.header_msg_type');
  const type = typeValue === undefined ? -1 : Number(typeValue);
  const bodyRows = rowsOf(b, bodyFrom, bodyTo, BODIES[type], fields, known);
  const info = infoOf(type, known);

  const rows: ProtocolField[] = [
    { name: 'Signature', value: `0x${plainHex(b, start, start + 8).match(/../g)!.reverse().join('')}`, abbrev: 'steam_ihs_discovery.signature', rawBytesRange: [start, start + 7] },
    { name: 'Header Length', value: headerLength, abbrev: 'steam_ihs_discovery.header_length', rawBytesRange: [start + 8, start + 11] },
    ...headerRows,
    { name: 'Body Length', value: bodyLength, abbrev: 'steam_ihs_discovery.body_length', rawBytesRange: [headerTo, headerTo + 3] },
    ...bodyRows,
  ];
  return {
    protocolLabel: 'STEAMDISCOVER',
    info,
    layer: { name: 'Steam In-Home Streaming Discovery Protocol', summary: info, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
  };
}
