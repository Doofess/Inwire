/**
 * Kerberos (RFC 4120), the third leg of a Windows domain.
 *
 * LDAP answers "who is this", SMB2 carries the files, and Kerberos is what
 * decides either is allowed to happen - so a capture of a corporate network
 * with the first two read and this one left as `TCP 88 → ...` is missing the
 * half that explains the other two. It is DER-encoded ASN.1, which `ber.ts`
 * already reads: that module was written for SNMP and named LDAP and Kerberos
 * as what it unlocked, and this is the second half of that being cashed in.
 *
 * Port-gated on 88, both transports, exactly as LDAP is gated on 389: the
 * outer shape here is `[APPLICATION n] SEQUENCE { [0] INTEGER 5, ... }`, and a
 * constructed tag wrapping a sequence that starts with a small integer is a
 * shape a great many binary protocols share.
 *
 * ## What the reference prints, none of which is in RFC 4120
 *
 * Established by building each message and asking tshark 4.6.8, the same way
 * SMB2's and LDAP's Info formats were:
 *
 *  - The Protocol column is **`KRB5`**, not "Kerberos". The filter token is
 *    `kerberos`, so the two differ and both are the reference's own choice.
 *  - Info for an ordinary message is the message NAME and nothing else -
 *    `AS-REQ`, `TGS-REP`. No principal, no realm, no service. This was the
 *    surprise: LDAP prints the DN and SMB2 prints the filename, so the obvious
 *    guess was that Kerberos prints `user1@EXAMPLE.COM`. It does not.
 *  - A KRB-ERROR carrying error code **0** prints `KRB-ERROR`, the plain
 *    message name. Only a NON-ZERO code takes the `KRB Error: NAME` form.
 *  - An unrecognised code prints `KRB Error: Unknown error code 0x1e` -
 *    lower-case hex, `0x` prefix, no zero padding.
 *  - The error names are **MIT's, not the RFC's**, and they are not internally
 *    consistent either: 1-52 carry a `KRB5` prefix (`KRB5KDC_ERR_*`,
 *    `KRB5KRB_AP_ERR_*`), 62-76 drop it entirely (`KDC_ERR_WRONG_REALM`), and
 *    within that second group some say `KDC_ERROR_` and others `KDC_ERR_`.
 *    51 is `KRB5KDC_AP_PATH_NOT_ACCEPTED`, with no `_ERR` at all. A table
 *    written from RFC 4120 §7.5.9 would print `KDC_ERR_PREAUTH_REQUIRED`
 *    where every reference, tutorial and saved filter says
 *    `KRB5KDC_ERR_PREAUTH_REQUIRED`. Same trap as SMB2's eight command names.
 *  - Codes 30, 53-59 and 77+ have no name at all and take the unknown form.
 *
 * ## The message is named by its FIELD, not by its tag
 *
 * The obvious discriminator is the outer `[APPLICATION n]` tag, and it is the
 * wrong one. Asked directly, tshark reads `[APPLICATION 10]` containing
 * `msg-type 12` as **TGS-REQ**, and `[APPLICATION 12]` containing `msg-type 10`
 * as **AS-REQ**: the tag decides only whether this is Kerberos at all, and the
 * field decides what it is called. Both are load-bearing and they are not the
 * same check - `[APPLICATION 16]` is declined outright however well-formed.
 *
 * `msg-type` does not sit in the same place in every message: KDC-REQ numbers
 * its fields from 1, so pvno is `[1]` and msg-type is `[2]`, while every other
 * message starts at 0. Reading `[1]` everywhere finds the *pvno* of a KDC-REQ,
 * which is 5, which is not a message type - so an AS-REQ would decline.
 *
 * ## Two deliberate divergences, both toward declining
 *
 * `[APPLICATION 22]` is KRB-CRED, a real Kerberos message, and tshark does not
 * accept it on port 88 - a well-formed one with one ticket and with two both
 * read as plain UDP. It travels inside GSS-API rather than to a KDC, so this
 * declines it too rather than claiming a frame the reference does not.
 *
 * And where a message cannot be read at all - no `msg-type`, an unknown one, an
 * application tag outside the named set, or a length prefix promising more than
 * the segment carries - tshark still labels the frame KRB5 and writes an
 * **empty** Info column. This declines instead, and the frame reads as plain
 * TCP or UDP. Two reasons, the first the stronger: LDAP already made exactly
 * this choice for an incomplete length-prefixed message, and two sibling
 * dissectors answering the same question differently would be the surprise.
 * The second is that a blank Info tells a reader nothing, where the TCP summary
 * at least says a segment arrived and how big it was.
 *
 * The price is stated rather than waved past: a `kerberos` display filter will
 * not select such a segment here and would in Wireshark. It applies only to
 * segments carrying no complete message, and `scripts/kerberos/dissect.ts`
 * pins it as the one deliberate exception in that suite.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';
import { BER_TAG, berChildren, berString, berUnsigned, readBer, type BerValue } from './ber';

/** The KDC port, for both transports. */
export const KERBEROS_PORT = 88;

/**
 * The message types the reference names on this port, and their exact wording.
 *
 * 22 (KRB-CRED) is deliberately absent - see the note above. 16-19 and 23-24
 * are unassigned and tshark declines them.
 */
const MESSAGE_NAMES: Record<number, string> = {
  10: 'AS-REQ',
  11: 'AS-REP',
  12: 'TGS-REQ',
  13: 'TGS-REP',
  14: 'AP-REQ',
  15: 'AP-REP',
  20: 'KRB-SAFE',
  21: 'KRB-PRIV',
  30: 'KRB-ERROR',
};

/**
 * Error names as the reference prints them, read off tshark one code at a time.
 *
 * Transcribed from the oracle rather than from RFC 4120 §7.5.9, because the two
 * disagree on every single entry - see the note above. The gaps (30, 53-59) are
 * gaps in tshark's own table and fall through to the unknown form.
 */
const ERROR_NAMES: Record<number, string> = {
  1: 'KRB5KDC_ERR_NAME_EXP',
  2: 'KRB5KDC_ERR_SERVICE_EXP',
  3: 'KRB5KDC_ERR_BAD_PVNO',
  4: 'KRB5KDC_ERR_C_OLD_MAST_KVNO',
  5: 'KRB5KDC_ERR_S_OLD_MAST_KVNO',
  6: 'KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN',
  7: 'KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN',
  8: 'KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE',
  9: 'KRB5KDC_ERR_NULL_KEY',
  10: 'KRB5KDC_ERR_CANNOT_POSTDATE',
  11: 'KRB5KDC_ERR_NEVER_VALID',
  12: 'KRB5KDC_ERR_POLICY',
  13: 'KRB5KDC_ERR_BADOPTION',
  14: 'KRB5KDC_ERR_ETYPE_NOSUPP',
  15: 'KRB5KDC_ERR_SUMTYPE_NOSUPP',
  16: 'KRB5KDC_ERR_PADATA_TYPE_NOSUPP',
  17: 'KRB5KDC_ERR_TRTYPE_NOSUPP',
  18: 'KRB5KDC_ERR_CLIENT_REVOKED',
  19: 'KRB5KDC_ERR_SERVICE_REVOKED',
  20: 'KRB5KDC_ERR_TGT_REVOKED',
  21: 'KRB5KDC_ERR_CLIENT_NOTYET',
  22: 'KRB5KDC_ERR_SERVICE_NOTYET',
  23: 'KRB5KDC_ERR_KEY_EXP',
  24: 'KRB5KDC_ERR_PREAUTH_FAILED',
  25: 'KRB5KDC_ERR_PREAUTH_REQUIRED',
  26: 'KRB5KDC_ERR_SERVER_NOMATCH',
  27: 'KRB5KDC_ERR_MUST_USE_USER2USER',
  28: 'KRB5KDC_ERR_PATH_NOT_ACCEPTED',
  29: 'KRB5KDC_ERR_SVC_UNAVAILABLE',
  31: 'KRB5KRB_AP_ERR_BAD_INTEGRITY',
  32: 'KRB5KRB_AP_ERR_TKT_EXPIRED',
  33: 'KRB5KRB_AP_ERR_TKT_NYV',
  34: 'KRB5KRB_AP_ERR_REPEAT',
  35: 'KRB5KRB_AP_ERR_NOT_US',
  36: 'KRB5KRB_AP_ERR_BADMATCH',
  37: 'KRB5KRB_AP_ERR_SKEW',
  38: 'KRB5KRB_AP_ERR_BADADDR',
  39: 'KRB5KRB_AP_ERR_BADVERSION',
  40: 'KRB5KRB_AP_ERR_MSG_TYPE',
  41: 'KRB5KRB_AP_ERR_MODIFIED',
  42: 'KRB5KRB_AP_ERR_BADORDER',
  43: 'KRB5KRB_AP_ERR_ILL_CR_TKT',
  44: 'KRB5KRB_AP_ERR_BADKEYVER',
  45: 'KRB5KRB_AP_ERR_NOKEY',
  46: 'KRB5KRB_AP_ERR_MUT_FAIL',
  47: 'KRB5KRB_AP_ERR_BADDIRECTION',
  48: 'KRB5KRB_AP_ERR_METHOD',
  49: 'KRB5KRB_AP_ERR_BADSEQ',
  50: 'KRB5KRB_AP_ERR_INAPP_CKSUM',
  // No `_ERR`, unlike every neighbour. The reference spells it this way.
  51: 'KRB5KDC_AP_PATH_NOT_ACCEPTED',
  52: 'KRB5KRB_ERR_RESPONSE_TOO_BIG',
  60: 'KRB5KRB_ERR_GENERIC',
  61: 'KRB5KRB_ERR_FIELD_TOOLONG',
  // From here the `KRB5` prefix is gone, and `KDC_ERROR_` and `KDC_ERR_`
  // alternate with no rule behind it. These are the PKINIT-era additions.
  62: 'KDC_ERROR_CLIENT_NOT_TRUSTED',
  63: 'KDC_ERROR_KDC_NOT_TRUSTED',
  64: 'KDC_ERROR_INVALID_SIG',
  65: 'KDC_ERR_KEY_TOO_WEAK',
  66: 'KDC_ERR_CERTIFICATE_MISMATCH',
  67: 'KRB_AP_ERR_NO_TGT',
  68: 'KDC_ERR_WRONG_REALM',
  69: 'KRB_AP_ERR_USER_TO_USER_REQUIRED',
  70: 'KDC_ERR_CANT_VERIFY_CERTIFICATE',
  71: 'KDC_ERR_INVALID_CERTIFICATE',
  72: 'KDC_ERR_REVOKED_CERTIFICATE',
  73: 'KDC_ERR_REVOCATION_STATUS_UNKNOWN',
  74: 'KDC_ERR_REVOCATION_STATUS_UNAVAILABLE',
  75: 'KDC_ERR_CLIENT_NAME_MISMATCH',
  76: 'KDC_ERR_KDC_NAME_MISMATCH',
};

/** `[APPLICATION n]`, constructed: class bits 01 with the constructed bit set. */
const APPLICATION_TAG_BASE = 0x60;
/** `[n]`, context-specific and constructed - every field in a Kerberos message. */
const CONTEXT_TAG_BASE = 0xa0;

/**
 * Which context tag holds `msg-type`.
 *
 * KDC-REQ numbers its fields from 1 and everything else from 0, so this is 2
 * for AS-REQ and TGS-REQ and 1 for the rest. Reading 1 everywhere finds a
 * KDC-REQ's pvno instead, which is 5 and names no message.
 */
function msgTypeIndex(applicationTag: number): number {
  return applicationTag === 10 || applicationTag === 12 ? 2 : 1;
}

/** The child carrying context tag `[index]`, or undefined. */
function contextChild(children: readonly BerValue[], index: number): BerValue | undefined {
  return children.find((c) => c.tag === (CONTEXT_TAG_BASE | index));
}

/** The unsigned integer inside `[index]`, or null when it is absent or not one. */
function contextUnsigned(
  bytes: Uint8Array, children: readonly BerValue[], index: number,
): number | null {
  const holder = contextChild(children, index);
  if (holder === undefined) return null;
  const inner = berChildren(bytes, holder, 1)[0];
  if (inner === undefined || inner.tag !== BER_TAG.INTEGER) return null;
  return berUnsigned(bytes, inner);
}

/** The string inside `[index]` - a Realm is a bare KerberosString. */
function contextString(
  bytes: Uint8Array, children: readonly BerValue[], index: number,
): string | null {
  const holder = contextChild(children, index);
  if (holder === undefined) return null;
  const inner = berChildren(bytes, holder, 1)[0];
  if (inner === undefined) return null;
  return berString(bytes, inner);
}

/**
 * A PrincipalName's name parts, joined the way a principal is written.
 *
 * `SEQUENCE { [0] name-type, [1] SEQUENCE OF KerberosString }`, and the strings
 * are the components: `krbtgt` + `EXAMPLE.COM` is the ticket-granting service,
 * written `krbtgt/EXAMPLE.COM`. Only ever a field here - the reference does not
 * put it in the Info column, and neither does this.
 */
function principalName(
  bytes: Uint8Array, children: readonly BerValue[], index: number,
): string | null {
  const holder = contextChild(children, index);
  if (holder === undefined) return null;
  const principal = berChildren(bytes, holder, 1)[0];
  if (principal === undefined || principal.tag !== BER_TAG.SEQUENCE) return null;
  const stringsHolder = contextChild(berChildren(bytes, principal, 4), 1);
  if (stringsHolder === undefined) return null;
  const list = berChildren(bytes, stringsHolder, 1)[0];
  if (list === undefined || list.tag !== BER_TAG.SEQUENCE) return null;
  const parts = berChildren(bytes, list, 8).map((s) => berString(bytes, s)).filter((s) => s !== '');
  return parts.length === 0 ? null : parts.join('/');
}

export interface KerberosResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

interface OneMessage {
  info: string;
  rows: ProtocolField[];
  fields: Record<string, string | number>;
  /** Where the next message starts. */
  end: number;
}

/** Reads one message. Returns null when this is not one, or is incomplete. */
function readMessage(bytes: Uint8Array, start: number, end: number): OneMessage | null {
  const envelope = readBer(bytes, start, end);
  if (envelope === null) return null;
  const applicationTag = envelope.tag - APPLICATION_TAG_BASE;
  // The tag decides whether this is Kerberos; the field below decides what it
  // is called. Both are needed and they are not the same question.
  if (applicationTag < 0 || applicationTag > 0x1e) return null;
  if (!(applicationTag in MESSAGE_NAMES)) return null;

  const body = berChildren(bytes, envelope, 1)[0];
  if (body === undefined || body.tag !== BER_TAG.SEQUENCE) return null;
  const children = berChildren(bytes, body, 16);

  const msgType = contextUnsigned(bytes, children, msgTypeIndex(applicationTag));
  const name = msgType === null ? undefined : MESSAGE_NAMES[msgType];
  // Declined rather than claimed with a blank column - see the note at the top.
  if (msgType === null || name === undefined) return null;

  const fields: Record<string, string | number> = { 'kerberos.msg_type': msgType };
  const rows: ProtocolField[] = [
    { name: 'msg-type', value: `${name} (${msgType})`, abbrev: 'kerberos.msg_type' },
  ];

  const pvno = contextUnsigned(bytes, children, applicationTag === 10 || applicationTag === 12 ? 1 : 0);
  if (pvno !== null) {
    fields['kerberos.pvno'] = pvno;
    rows.push({ name: 'pvno', value: String(pvno), abbrev: 'kerberos.pvno' });
  }

  let info = name;

  if (msgType === 30) {
    // KRB-ERROR: pvno[0] msg-type[1] ctime[2] cusec[3] stime[4] susec[5]
    // error-code[6] crealm[7] cname[8] realm[9] sname[10] e-text[11] e-data[12]
    const code = contextUnsigned(bytes, children, 6);
    if (code !== null) {
      fields['kerberos.error_code'] = code;
      const named = ERROR_NAMES[code];
      rows.push({
        name: 'error-code',
        value: named === undefined ? String(code) : `${named} (${code})`,
        abbrev: 'kerberos.error_code',
      });
      // Code 0 is "no error", and the reference prints the bare message name
      // for it rather than naming an error that did not happen.
      if (code !== 0) {
        info = `KRB Error: ${named ?? `Unknown error code 0x${code.toString(16)}`}`;
      }
    }
    addPrincipal(bytes, children, 7, 8, fields, rows);
    addRealmAndService(bytes, children, 9, 10, fields, rows);
  } else if (msgType === 10 || msgType === 12) {
    // KDC-REQ: the interesting names are inside req-body [4], not beside it.
    const bodyHolder = contextChild(children, 4);
    const reqBody = bodyHolder === undefined ? undefined : berChildren(bytes, bodyHolder, 1)[0];
    if (reqBody !== undefined && reqBody.tag === BER_TAG.SEQUENCE) {
      const bodyChildren = berChildren(bytes, reqBody, 16);
      const cname = principalName(bytes, bodyChildren, 1);
      if (cname !== null) {
        fields['kerberos.cname_string'] = cname;
        rows.push({ name: 'cname', value: cname, abbrev: 'kerberos.cname_string' });
      }
      addRealmAndService(bytes, bodyChildren, 2, 3, fields, rows);
    }
  } else if (msgType === 11 || msgType === 13) {
    // KDC-REP: crealm [3], cname [4].
    addPrincipal(bytes, children, 3, 4, fields, rows);
  }

  return { info, rows, fields, end: envelope.end };
}

/**
 * A client realm and client principal pair, wherever the message puts them.
 *
 * The key is written out rather than built from a parameter, and that is not
 * style: `scripts/dissect/registry.ts` finds a field's writer by scanning the
 * source for the literal name, so a key assembled from a template reads as a
 * registered field nobody writes. It caught this exact line.
 */
function addPrincipal(
  bytes: Uint8Array, children: readonly BerValue[], realmIndex: number, nameIndex: number,
  fields: Record<string, string | number>, rows: ProtocolField[],
): void {
  const realm = contextString(bytes, children, realmIndex);
  if (realm !== null) {
    fields['kerberos.crealm'] = realm;
    rows.push({ name: 'crealm', value: realm, abbrev: 'kerberos.crealm' });
  }
  const cname = principalName(bytes, children, nameIndex);
  if (cname !== null) {
    fields['kerberos.cname_string'] = cname;
    rows.push({ name: 'cname', value: cname, abbrev: 'kerberos.cname_string' });
  }
}

/** The server realm and the service being asked for. */
function addRealmAndService(
  bytes: Uint8Array, children: readonly BerValue[], realmIndex: number, nameIndex: number,
  fields: Record<string, string | number>, rows: ProtocolField[],
): void {
  const realm = contextString(bytes, children, realmIndex);
  if (realm !== null) {
    fields['kerberos.realm'] = realm;
    rows.push({ name: 'realm', value: realm, abbrev: 'kerberos.realm' });
  }
  const sname = principalName(bytes, children, nameIndex);
  if (sname !== null) {
    fields['kerberos.sname_string'] = sname;
    rows.push({ name: 'sname', value: sname, abbrev: 'kerberos.sname_string' });
  }
}

/** True for a payload whose outer shape is a Kerberos message. */
export function looksLikeKerberos(bytes: Uint8Array, start: number, end: number): boolean {
  const envelope = readBer(bytes, start, end);
  if (envelope === null) return false;
  const tag = envelope.tag - APPLICATION_TAG_BASE;
  return tag >= 0 && tag in MESSAGE_NAMES;
}

/**
 * Every Kerberos message in one payload.
 *
 * On TCP each message carries a four-byte big-endian length in front of it and
 * several can share a segment; on UDP there is one message and no prefix, and
 * trailing bytes after it are ignored (the reference reads such a datagram
 * happily). A message whose length runs past what was captured is **declined**
 * rather than half-read - the rule LDAP and DNS-over-TCP already follow.
 *
 * When a segment holds several, the Info column shows the **last** one, with no
 * separator and no join. That is not what the neighbours do - LDAP joins with
 * `" | "` and SMB2 with `"; "` - and it was verified three ways: `AS,TGS` reads
 * `TGS-REQ`, `TGS,AS` reads `AS-REQ`, and `AS,TGS,AS` reads `AS-REQ`. Every
 * message still contributes its tree rows and its fields; only the one-line
 * summary is the last one's.
 */
export function dissectKerberos(
  bytes: Uint8Array, start: number, end: number, framed: boolean,
): KerberosResult | null {
  const messages: OneMessage[] = [];
  let offset = start;
  while (offset < end) {
    let messageStart = offset;
    let limit = end;
    if (framed) {
      if (offset + 4 > end) break;
      const declared = (bytes[offset] << 24 | bytes[offset + 1] << 16
        | bytes[offset + 2] << 8 | bytes[offset + 3]) >>> 0;
      // A message that does not fit the captured bytes was never fully seen.
      if (declared === 0 || offset + 4 + declared > end) break;
      messageStart = offset + 4;
      limit = messageStart + declared;
    }
    const message = readMessage(bytes, messageStart, limit);
    if (message === null) break;
    messages.push(message);
    const next = framed ? limit : message.end;
    if (next <= offset) break;                    // never loop on a zero-length read
    offset = next;
    // A datagram carries one message; anything after it is not our business.
    if (!framed) break;
  }
  if (messages.length === 0) return null;

  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  for (const [index, message] of messages.entries()) {
    Object.assign(fields, message.fields);
    rows.push(messages.length === 1
      ? { name: 'Kerberos', value: '', children: message.rows }
      : { name: `Kerberos message ${index + 1}`, value: '', children: message.rows });
  }

  return {
    protocolLabel: 'KRB5',
    info: messages[messages.length - 1].info,
    fields,
    layer: {
      name: 'Kerberos',
      summary: messages.length === 1
        ? 'Kerberos'
        : `Kerberos (${messages.length} messages)`,
      fields: rows,
    },
  };
}

/**
 * The UDP entry point.
 *
 * A datagram carries one message with no length prefix, which is the only
 * difference from the TCP side - so this is a shim rather than a second
 * implementation, and it exists because the dispatch table's signature has no
 * room for the `framed` flag (and should not: twelve other entries would carry
 * a parameter that means nothing to them).
 */
export function dissectKerberosDatagram(
  bytes: Uint8Array, start: number, end: number,
): KerberosResult | null {
  return dissectKerberos(bytes, start, end, false);
}
