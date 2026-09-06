/**
 * SNMP v1 and v2c (RFC 1157, RFC 3416), UDP 161 and 162.
 *
 *   get-request 1.3.6.1.2.1.1.1.0
 *   snmpV2-trap 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.2.1.0
 *
 * What the network management station asked for and what the device answered -
 * and on a capture from a monitored network it is most of the UDP that is not
 * DNS. It was reaching the list as `50000 → 161 Len=41`.
 *
 * The message is ASN.1/BER, read through `dissectors/ber.ts`. Two things this
 * file knows that the reader does not:
 *
 *   - **The PDU type is a context-specific tag**, `0xa0` to `0xa8`, not a field
 *     inside the PDU. So "which operation is this" is the tag byte of the third
 *     element, and Wireshark's names for those tags are inconsistent by
 *     design - `get-request` but `getBulkRequest` - because they are the ASN.1
 *     module's own identifiers from two different RFCs. Matched verbatim.
 *   - **v3 is a different message entirely.** Its third element is a security
 *     header, not a PDU, and its payload may be encrypted. This declines v3
 *     rather than half-reading it: `snmp` in the Protocol column with an Info
 *     line describing a PDU that was never parsed would be worse than saying
 *     nothing.
 *
 * The community string is shown because it is on the wire in the clear, which
 * is the single most important thing a reader can learn from v1/v2c traffic -
 * it is the credential, and its presence in a capture is the finding.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';
import {
  BER_TAG, berChildren, berHex, berInteger, berOid, berString, berUnsigned, readBer,
  type BerValue,
} from './ber';

export interface SnmpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * Wireshark's names for the PDU tags, which come from the ASN.1 modules and
 * are inconsistent between RFC 1157 and RFC 3416. Copied, not tidied.
 */
const PDU_NAMES: Record<number, string> = {
  0xa0: 'get-request',
  0xa1: 'get-next-request',
  0xa2: 'get-response',
  0xa3: 'set-request',
  0xa4: 'trap',
  0xa5: 'getBulkRequest',
  0xa6: 'informRequest',
  0xa7: 'snmpV2-trap',
  0xa8: 'report',
};

const VERSION_NAMES: Record<number, string> = {
  0: 'version-1',
  1: 'v2c',
  3: 'v3',
};

const ERROR_STATUS_NAMES: Record<number, string> = {
  0: 'noError', 1: 'tooBig', 2: 'noSuchName', 3: 'badValue', 4: 'readOnly', 5: 'genErr',
  6: 'noAccess', 7: 'wrongType', 8: 'wrongLength', 9: 'wrongEncoding', 10: 'wrongValue',
  11: 'noCreation', 12: 'inconsistentValue', 13: 'resourceUnavailable',
  14: 'commitFailed', 15: 'undoFailed', 16: 'authorizationError', 17: 'notWritable',
  18: 'inconsistentName',
};

/** SNMP's own application tags, on top of BER's universal ones. */
const IP_ADDRESS = 0x40, COUNTER32 = 0x41, GAUGE32 = 0x42, TIMETICKS = 0x43,
  OPAQUE = 0x44, COUNTER64 = 0x46;

/**
 * True when these bytes are an SNMP message.
 *
 * A SEQUENCE whose length covers the payload exactly, opening with an INTEGER
 * version this build knows. The length equality is what makes it specific -
 * BER's SEQUENCE tag `0x30` is a common enough first byte on its own.
 */
export function looksLikeSnmp(bytes: Uint8Array, start: number, end: number): boolean {
  const outer = readBer(bytes, start, end);
  if (outer === null || outer.tag !== BER_TAG.SEQUENCE || outer.end !== end) return false;
  const first = readBer(bytes, outer.contentStart, outer.contentEnd);
  if (first === null || first.tag !== BER_TAG.INTEGER) return false;
  return VERSION_NAMES[berInteger(bytes, first)] !== undefined;
}

export function dissectSnmp(bytes: Uint8Array, start: number, end: number): SnmpResult | null {
  const outer = readBer(bytes, start, end);
  if (outer === null || outer.tag !== BER_TAG.SEQUENCE) return null;

  const top = berChildren(bytes, outer);
  if (top.length < 3) return null;
  const [versionValue, communityValue, pduValue] = top;
  if (versionValue.tag !== BER_TAG.INTEGER) return null;

  const version = berInteger(bytes, versionValue);
  const versionName = VERSION_NAMES[version];
  if (versionName === undefined) return null;
  // v3 puts a security header where v1/v2c put the PDU, and may encrypt what
  // follows. Declining is the honest answer; see the header note.
  if (version === 3) return null;

  const pduName = PDU_NAMES[pduValue.tag];
  if (pduName === undefined) return null;
  const community = berString(bytes, communityValue);

  const fields: Record<string, string | number> = {
    'snmp.version': version,
    'snmp.community': community,
  };

  const pduChildren = berChildren(bytes, pduValue);
  const pduRows: ProtocolField[] = [];
  const oids: string[] = [];

  // A v1 trap (0xa4) has an entirely different body - enterprise, agent
  // address, trap type - where every other PDU has request-id/error/error-index.
  if (pduValue.tag === 0xa4) {
    pduRows.push(...v1TrapRows(bytes, pduChildren, fields));
  } else if (pduChildren.length >= 4) {
    const [requestId, errorStatus, errorIndex] = pduChildren;
    const id = berInteger(bytes, requestId);
    const status = berInteger(bytes, errorStatus);
    const index = berInteger(bytes, errorIndex);
    fields['snmp.request_id'] = id;
    fields['snmp.error_status'] = status;
    fields['snmp.error_index'] = index;
    pduRows.push(
      { name: 'request-id', value: id, abbrev: 'snmp.request_id',
        rawBytesRange: [requestId.contentStart, requestId.contentEnd - 1] },
      // On a GetBulk these two fields are non-repeaters and max-repetitions
      // instead, which is why the labels come from the PDU tag.
      { name: pduValue.tag === 0xa5 ? 'non-repeaters' : 'error-status',
        value: pduValue.tag === 0xa5 ? status : `${ERROR_STATUS_NAMES[status] ?? 'unknown'} (${status})`,
        abbrev: 'snmp.error_status',
        rawBytesRange: [errorStatus.contentStart, errorStatus.contentEnd - 1] },
      { name: pduValue.tag === 0xa5 ? 'max-repetitions' : 'error-index', value: index,
        abbrev: 'snmp.error_index',
        rawBytesRange: [errorIndex.contentStart, errorIndex.contentEnd - 1] },
    );
  }

  // The variable bindings are the last element of every PDU shape.
  const bindingsValue = pduChildren[pduChildren.length - 1];
  const bindingRows: ProtocolField[] = [];
  if (bindingsValue && bindingsValue.constructed) {
    for (const binding of berChildren(bytes, bindingsValue)) {
      const parts = berChildren(bytes, binding);
      if (parts.length < 1 || parts[0].tag !== BER_TAG.OID) continue;
      const oid = berOid(bytes, parts[0]);
      oids.push(oid);
      const rendered = parts[1] ? renderValue(bytes, parts[1]) : { text: '', type: 'Null' };
      bindingRows.push({
        name: `${oid}: ${rendered.text}`,
        value: '',
        rawBytesRange: [binding.contentStart, Math.max(binding.contentStart, binding.contentEnd - 1)],
        children: [
          { name: 'Object Name', value: oid, abbrev: 'snmp.name',
            rawBytesRange: [parts[0].contentStart, parts[0].contentEnd - 1] },
          ...(parts[1]
            ? [{
                name: `Value (${rendered.type})`, value: rendered.text, abbrev: 'snmp.value',
                rawBytesRange: [
                  parts[1].contentStart,
                  Math.max(parts[1].contentStart, parts[1].contentEnd - 1),
                ] as [number, number],
              }]
            : []),
        ],
      });
    }
  }
  if (oids.length > 0) fields['snmp.name'] = oids[0];
  if (bindingRows.length > 0) {
    pduRows.push({
      name: 'variable-bindings',
      value: `${bindingRows.length} item${bindingRows.length === 1 ? '' : 's'}`,
      children: bindingRows,
    });
  }

  return {
    protocolLabel: 'SNMP',
    // tshark lists every varbind's OID, space separated, after the PDU name.
    info: oids.length > 0 ? `${pduName} ${oids.join(' ')}` : pduName,
    fields,
    layer: {
      name: 'Simple Network Management Protocol',
      summary: `Simple Network Management Protocol (${pduName})`,
      rawBytesRange: [start, Math.max(start, Math.min(outer.end, end) - 1)],
      fields: [
        { name: 'version', value: `${versionName} (${version})`, abbrev: 'snmp.version',
          rawBytesRange: [versionValue.contentStart, versionValue.contentEnd - 1] },
        { name: 'community', value: community, abbrev: 'snmp.community',
          rawBytesRange: [communityValue.contentStart, Math.max(communityValue.contentStart, communityValue.contentEnd - 1)] },
        { name: 'data', value: `${pduName} (${pduValue.tag & 0x1f})`,
          children: [{ name: pduName, value: '', children: pduRows }] },
      ],
    },
  };
}

/** The v1 trap PDU, which shares nothing with the others but its varbinds. */
function v1TrapRows(
  bytes: Uint8Array,
  children: BerValue[],
  fields: Record<string, string | number>,
): ProtocolField[] {
  const rows: ProtocolField[] = [];
  if (children[0]?.tag === BER_TAG.OID) {
    const enterprise = berOid(bytes, children[0]);
    fields['snmp.enterprise'] = enterprise;
    rows.push({ name: 'enterprise', value: enterprise, abbrev: 'snmp.enterprise' });
  }
  if (children[1]?.tag === IP_ADDRESS && children[1].contentEnd - children[1].contentStart === 4) {
    rows.push({ name: 'agent-addr', value: formatIpv4Address(bytes, children[1].contentStart) });
  }
  if (children[2]) rows.push({ name: 'generic-trap', value: berInteger(bytes, children[2]) });
  if (children[3]) rows.push({ name: 'specific-trap', value: berInteger(bytes, children[3]) });
  if (children[4]) rows.push({ name: 'time-stamp', value: berUnsigned(bytes, children[4]) });
  return rows;
}

/** A varbind's value, with the type name Wireshark uses for it. */
function renderValue(bytes: Uint8Array, value: BerValue): { text: string; type: string } {
  switch (value.tag) {
    case BER_TAG.NULL: return { text: '', type: 'Null' };
    case BER_TAG.INTEGER: return { text: String(berInteger(bytes, value)), type: 'Integer32' };
    case BER_TAG.OID: return { text: berOid(bytes, value), type: 'OID' };
    case BER_TAG.OCTET_STRING: return { text: `"${berString(bytes, value)}"`, type: 'OctetString' };
    case IP_ADDRESS:
      return value.contentEnd - value.contentStart === 4
        ? { text: formatIpv4Address(bytes, value.contentStart), type: 'IpAddress' }
        : { text: berHex(bytes, value), type: 'IpAddress' };
    case COUNTER32: return { text: String(berUnsigned(bytes, value)), type: 'Counter32' };
    case GAUGE32: return { text: String(berUnsigned(bytes, value)), type: 'Gauge32' };
    case TIMETICKS: return { text: String(berUnsigned(bytes, value)), type: 'Timeticks' };
    // Counter64 can exceed what a JS number holds exactly, so it is rendered
    // from its bytes rather than through a conversion that would round.
    case COUNTER64: return { text: `0x${berHex(bytes, value)}`, type: 'Counter64' };
    case OPAQUE: return { text: berHex(bytes, value), type: 'Opaque' };
    default: return { text: berHex(bytes, value), type: `Unknown (0x${value.tag.toString(16)})` };
  }
}
