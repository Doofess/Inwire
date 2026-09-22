import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';

/**
 * IGMP (IP protocol 2) - the multicast group membership chatter every LAN
 * carries. Without this, IGMP frames reached the transport decoder's "protocol
 * not recognized" return, and inherited the parser's TCP/`Frame (N bytes)`
 * defaults: the router's periodic query to 224.0.0.1 showed up in the packet
 * list as a TCP frame with no Info at all.
 *
 * Field names, value formatting and Info text below are matched against
 * `tshark -V` on real captured queries and v3 reports.
 */
export interface IgmpDissectorResult {
  /** Protocol column text: "IGMPv1" / "IGMPv2" / "IGMPv3". */
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

const TYPE_MEMBERSHIP_QUERY = 0x11;
const TYPE_V1_MEMBERSHIP_REPORT = 0x12;
const TYPE_V2_MEMBERSHIP_REPORT = 0x16;
const TYPE_LEAVE_GROUP = 0x17;
const TYPE_V3_MEMBERSHIP_REPORT = 0x22;

const TYPE_NAMES: Record<number, string> = {
  [TYPE_MEMBERSHIP_QUERY]: 'Membership Query',
  [TYPE_V1_MEMBERSHIP_REPORT]: 'Membership Report',
  [TYPE_V2_MEMBERSHIP_REPORT]: 'Membership Report',
  [TYPE_LEAVE_GROUP]: 'Leave Group',
  [TYPE_V3_MEMBERSHIP_REPORT]: 'Membership Report',
};

/** RFC 3376 4.2.12 group record types. */
const RECORD_TYPE_NAMES: Record<number, string> = {
  1: 'Mode Is Include',
  2: 'Mode Is Exclude',
  3: 'Change To Include Mode',
  4: 'Change To Exclude Mode',
  5: 'Allow New Sources',
  6: 'Block Old Sources',
};

/** Ones-complement sum over the IGMP message, the same algorithm IP uses. */
function computeIgmpChecksum(bytes: Uint8Array, offset: number, length: number): number {
  let sum = 0;
  for (let i = 0; i < length; i += 2) {
    // Bytes 2-3 are the checksum field itself, which is zero for the purposes
    // of the computation.
    if (i === 2) continue;
    const word = i + 1 < length ? (bytes[offset + i] << 8) | bytes[offset + i + 1] : bytes[offset + i] << 8;
    sum += word;
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/**
 * Max Response Time / Max Response Code, in the tenths-of-a-second units the
 * field carries. Codes at or above 128 are a 3-bit exponent and 4-bit mantissa
 * rather than a plain count (RFC 3376 4.1.1), which matters because a query
 * from a real router routinely uses the compressed form.
 */
function decodeMaxRespTime(code: number): number {
  if (code < 128) return code / 10;
  const exponent = (code >> 4) & 0x07;
  const mantissa = code & 0x0f;
  return ((mantissa | 0x10) << (exponent + 3)) / 10;
}

/**
 * @param igmpLen bytes belonging to IGMP as declared by the IP header, NOT
 *   `rawBytes.length`. Ethernet pads short frames up to 60 bytes, and a padded
 *   8-byte v2 query would otherwise look long enough to be a v3 one.
 */
export function dissectIgmp(
  rawBytes: Uint8Array,
  offset: number,
  igmpLen: number,
): IgmpDissectorResult | null {
  if (rawBytes.length < offset + 8 || igmpLen < 8) return null;

  const type = rawBytes[offset];
  const maxRespCode = rawBytes[offset + 1];
  const checksum = (rawBytes[offset + 2] << 8) | rawBytes[offset + 3];
  const available = Math.min(igmpLen, rawBytes.length - offset);

  // Version is inferred from the type, and for queries from the length too:
  // v1/v2/v3 queries share type 0x11 and differ only in size (RFC 3376 7.1).
  let version: number;
  if (type === TYPE_MEMBERSHIP_QUERY) {
    version = available >= 12 ? 3 : maxRespCode === 0 ? 1 : 2;
  } else if (type === TYPE_V3_MEMBERSHIP_REPORT) {
    version = 3;
  } else if (type === TYPE_V1_MEMBERSHIP_REPORT) {
    version = 1;
  } else if (type === TYPE_V2_MEMBERSHIP_REPORT || type === TYPE_LEAVE_GROUP) {
    version = 2;
  } else {
    // An unknown type is still IGMP - better a named protocol with an honest
    // "Unknown type" than falling back through to the caller's TCP default.
    version = 3;
  }

  const typeName = TYPE_NAMES[type];
  const checksumCorrect = computeIgmpChecksum(rawBytes, offset, available) === checksum;

  const fields: ProtocolField[] = [
    { name: '[IGMP Version]', value: version, generated: true, abbrev: 'igmp.version' },
    {
      name: 'Type',
      value: `${typeName ?? 'Unknown'} (0x${type.toString(16).padStart(2, '0')})`,
      rawBytesRange: [offset, offset],
      abbrev: 'igmp.type',
    },
  ];

  const filterFields: Record<string, string | number> = {
    'igmp.type': type,
    'igmp.version': version,
  };

  let info: string;

  if (type === TYPE_V3_MEMBERSHIP_REPORT) {
    // v3 report: [type][reserved][checksum][reserved:2][num records:2], then
    // one variable-length group record each.
    fields.push({ name: 'Reserved', value: '00', rawBytesRange: [offset + 1, offset + 1], abbrev: 'igmp.reserved' });
    pushChecksum(fields, offset, checksum, checksumCorrect);
    fields.push({ name: 'Reserved', value: '0000', rawBytesRange: [offset + 4, offset + 5], abbrev: 'igmp.reserved' });

    const numRecords = (rawBytes[offset + 6] << 8) | rawBytes[offset + 7];
    fields.push({ name: 'Num Group Records', value: numRecords, rawBytesRange: [offset + 6, offset + 7], abbrev: 'igmp.num_grp_recs' });
    filterFields['igmp.num_grp_recs'] = numRecords;

    const descriptions: string[] = [];
    let cursor = offset + 8;
    for (let i = 0; i < numRecords; i++) {
      if (cursor + 8 > offset + available) break;
      const recordType = rawBytes[cursor];
      const auxDataLen = rawBytes[cursor + 1];
      const numSources = (rawBytes[cursor + 2] << 8) | rawBytes[cursor + 3];
      const group = formatIpv4Address(rawBytes, cursor + 4);
      const recordTypeName = RECORD_TYPE_NAMES[recordType] ?? `Unknown (${recordType})`;
      const recordLen = 8 + numSources * 4 + auxDataLen * 4;

      fields.push({
        name: 'Group Record',
        value: `${group}  ${recordTypeName}`,
        rawBytesRange: [cursor, Math.min(cursor + recordLen - 1, rawBytes.length - 1)],
        children: [
          { name: 'Record Type', value: `${recordTypeName} (${recordType})`, rawBytesRange: [cursor, cursor], abbrev: 'igmp.record_type' },
          { name: 'Aux Data Len', value: auxDataLen, rawBytesRange: [cursor + 1, cursor + 1], abbrev: 'igmp.aux_data_len' },
          { name: 'Num Src', value: numSources, rawBytesRange: [cursor + 2, cursor + 3], abbrev: 'igmp.num_src' },
          { name: 'Multicast Address', value: group, rawBytesRange: [cursor + 4, cursor + 7], abbrev: 'igmp.maddr' },
        ],
      });

      descriptions.push(describeGroupRecord(recordType, recordTypeName, numSources, group));
      cursor += recordLen;
    }

    info = descriptions.length
      ? `Membership Report / ${descriptions.join(' / ')}`
      : 'Membership Report';
  } else if (type === TYPE_MEMBERSHIP_QUERY) {
    const maxResp = decodeMaxRespTime(maxRespCode);
    fields.push({
      name: 'Max Resp Time',
      value: `${maxResp.toFixed(1)} sec (0x${maxRespCode.toString(16).padStart(2, '0')})`,
      rawBytesRange: [offset + 1, offset + 1],
      abbrev: 'igmp.max_resp',
    });
    pushChecksum(fields, offset, checksum, checksumCorrect);

    const group = formatIpv4Address(rawBytes, offset + 4);
    fields.push({ name: 'Multicast Address', value: group, rawBytesRange: [offset + 4, offset + 7], abbrev: 'igmp.maddr' });
    filterFields['igmp.maddr'] = group;

    if (version === 3 && available >= 12) {
      // Byte 8 packs the suppress-router-side-processing flag and the
      // querier's robustness variable into one byte.
      const flagsByte = rawBytes[offset + 8];
      const suppress = (flagsByte >> 3) & 0x1;
      const qrv = flagsByte & 0x07;
      const qqic = rawBytes[offset + 9];
      const numSources = (rawBytes[offset + 10] << 8) | rawBytes[offset + 11];
      fields.push(
        {
          name: 'S',
          value: suppress ? 'Suppress router side processing' : 'Do not suppress router side processing',
          rawBytesRange: [offset + 8, offset + 8],
          abbrev: 'igmp.s',
          bitfield: { bitOffset: 4, bitLength: 1, totalBits: 8 },
        },
        {
          name: 'QRV',
          value: qrv,
          rawBytesRange: [offset + 8, offset + 8],
          abbrev: 'igmp.qrv',
          bitfield: { bitOffset: 5, bitLength: 3, totalBits: 8 },
        },
        { name: 'QQIC', value: qqic, rawBytesRange: [offset + 9, offset + 9], abbrev: 'igmp.qqic' },
        { name: 'Num Src', value: numSources, rawBytesRange: [offset + 10, offset + 11], abbrev: 'igmp.num_src' },
      );
    }

    // The all-zero group address is what makes a query general rather than
    // aimed at one group.
    info = group === '0.0.0.0'
      ? 'Membership Query, general'
      : `Membership Query, specific for group ${group}`;
  } else {
    // v1/v2 report and leave: [type][max resp][checksum][group address].
    fields.push({
      name: 'Max Resp Time',
      value: `${decodeMaxRespTime(maxRespCode).toFixed(1)} sec (0x${maxRespCode.toString(16).padStart(2, '0')})`,
      rawBytesRange: [offset + 1, offset + 1],
      abbrev: 'igmp.max_resp',
    });
    pushChecksum(fields, offset, checksum, checksumCorrect);

    const group = formatIpv4Address(rawBytes, offset + 4);
    fields.push({ name: 'Multicast Address', value: group, rawBytesRange: [offset + 4, offset + 7], abbrev: 'igmp.maddr' });
    filterFields['igmp.maddr'] = group;

    info = type === TYPE_LEAVE_GROUP
      ? `Leave Group ${group}`
      : typeName
        ? `${typeName} group ${group}`
        : `IGMP Type 0x${type.toString(16).padStart(2, '0')} group ${group}`;
  }

  const protocolLabel = `IGMPv${version}`;

  return {
    protocolLabel,
    info,
    fields: filterFields,
    layer: {
      name: 'Internet Group Management Protocol',
      summary: `Internet Group Management Protocol, ${info}`,
      rawBytesRange: [offset, Math.min(offset + available - 1, rawBytes.length - 1)],
      fields,
    },
  };
}

function pushChecksum(fields: ProtocolField[], offset: number, checksum: number, correct: boolean): void {
  fields.push(
    {
      name: 'Checksum',
      value: `0x${checksum.toString(16).padStart(4, '0')} [${correct ? 'correct' : 'incorrect'}]`,
      rawBytesRange: [offset + 2, offset + 3],
      abbrev: 'igmp.checksum',
    },
    { name: '[Checksum Status]', value: correct ? 'Good' : 'Bad', generated: true, abbrev: 'igmp.checksum.status' },
  );
}

/**
 * The per-record phrase the reference analyzer puts in the Info column.
 *
 * The source-less forms are matched against `tshark -V`. A record that does
 * carry source addresses gets a descriptive phrase built from the record type
 * instead of a guessed copy of the reference analyzer's wording, which is not reproduced
 * here because no capture was available to verify it against.
 */
function describeGroupRecord(
  recordType: number,
  recordTypeName: string,
  numSources: number,
  group: string,
): string {
  if (numSources === 0) {
    // An exclude-mode record with an empty source list admits every source,
    // which is a join; an include-mode one admits none, which is a leave.
    if (recordType === 2 || recordType === 4) return `Join group ${group} for any sources`;
    if (recordType === 1 || recordType === 3) return `Leave group ${group}`;
  }
  return `${recordTypeName} for group ${group}, ${numSources} source(s)`;
}
