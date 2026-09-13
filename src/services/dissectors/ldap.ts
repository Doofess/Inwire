/**
 * LDAP (RFC 4511), read through the BER reader the SNMP dissector built.
 *
 * The first protocol here that is **not a leaf**. Every dissector added in the
 * batch behind `docs/decisions/0020` was one datagram in, one label out, with
 * no state between frames; LDAP carries a running count of search entries that
 * a later message reports, so it needs somewhere to keep it. That is
 * `LdapConversationState`, hung off the TCP connection beside the TLS one.
 *
 * **The Info format came from asking tshark, not from RFC 4511**, and none of
 * it is derivable from the standard. The rules, each pinned in
 * `scripts/ldap/dissect.ts`:
 *
 * - every message ends in a **trailing space**;
 * - several messages in one segment join with `" | "`, so the rendered result
 *   carries two spaces before the bar, each element having brought its own;
 * - `searchResDone` appends `[N result]` / `[N results]` after a second space,
 *   singular only at one, where N counts every `searchResEntry` seen for that
 *   messageID on this connection - including one earlier in the same segment;
 * - an **empty DN renders `<ROOT>`**, which is what a SASL bind sends;
 * - `abandonRequest` prints the messageID in its body - the request being
 *   abandoned - not its own;
 * - `extendedResp` and `searchResRef` print no detail at all, and
 *   `intermediateResponse` prints **nothing**, not even its own name.
 *
 * Scope: a message that fits inside one segment, and any number of them. A
 * message split across segments is declined rather than half-read, exactly as
 * DNS-over-TCP declines one - see `dissectLdap`'s note on `truncated`.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';
import { BER_TAG, readBer, berChildren, berUnsigned, berString, type BerValue } from './ber';

/**
 * `[APPLICATION n]` tags, and the names tshark prints for them.
 *
 * The tag byte is `0x60 | n` for the constructed operations and `0x40 | n` for
 * the three primitive ones (unbind, del, abandon), so the operation number is
 * the low five bits either way.
 */
const OP_NAMES: Record<number, string> = {
  0: 'bindRequest',
  1: 'bindResponse',
  2: 'unbindRequest',
  3: 'searchRequest',
  4: 'searchResEntry',
  5: 'searchResDone',
  6: 'modifyRequest',
  7: 'modifyResponse',
  8: 'addRequest',
  9: 'addResponse',
  10: 'delRequest',
  11: 'delResponse',
  12: 'modDNRequest',
  13: 'modDNResponse',
  14: 'compareRequest',
  15: 'compareResponse',
  16: 'abandonRequest',
  19: 'searchResRef',
  23: 'extendedReq',
  24: 'extendedResp',
  25: 'intermediateResponse',
};

/** RFC 4511 §4.1.9, spelled as the ASN.1 module spells them. */
const RESULT_NAMES: Record<number, string> = {
  0: 'success',
  1: 'operationsError',
  2: 'protocolError',
  3: 'timeLimitExceeded',
  4: 'sizeLimitExceeded',
  5: 'compareFalse',
  6: 'compareTrue',
  7: 'authMethodNotSupported',
  8: 'strongerAuthRequired',
  10: 'referral',
  11: 'adminLimitExceeded',
  12: 'unavailableCriticalExtension',
  13: 'confidentialityRequired',
  14: 'saslBindInProgress',
  16: 'noSuchAttribute',
  17: 'undefinedAttributeType',
  18: 'inappropriateMatching',
  19: 'constraintViolation',
  20: 'attributeOrValueExists',
  21: 'invalidAttributeSyntax',
  32: 'noSuchObject',
  33: 'aliasProblem',
  34: 'invalidDNSyntax',
  36: 'aliasDereferencingProblem',
  48: 'inappropriateAuthentication',
  49: 'invalidCredentials',
  50: 'insufficientAccessRights',
  51: 'busy',
  52: 'unavailable',
  53: 'unwillingToPerform',
  54: 'loopDetect',
  64: 'namingViolation',
  65: 'objectClassViolation',
  66: 'notAllowedOnNonLeaf',
  67: 'notAllowedOnRDN',
  68: 'entryAlreadyExists',
  69: 'objectClassModsProhibited',
  71: 'affectsMultipleDSAs',
  80: 'other',
};

const SCOPE_NAMES: Record<number, string> = {
  0: 'baseObject',
  1: 'singleLevel',
  2: 'wholeSubtree',
};

const DEREF_NAMES: Record<number, string> = {
  0: 'neverDerefAliases',
  1: 'derefInSearching',
  2: 'derefFindingBaseObj',
  3: 'derefAlways',
};

/**
 * Extended-operation OIDs tshark names, and its exact spelling for each.
 *
 * Deliberately short and verified one at a time against the oracle rather than
 * copied from a registry: the names are not mechanically derivable - two of
 * these five are SHOUTED with an `_OID` suffix, one is `passwdModifyOID` in
 * camel case, and one Wireshark declines to name at all.
 */
const EXTENDED_OID_NAMES: Record<string, string> = {
  '1.3.6.1.4.1.1466.20037': 'LDAP_START_TLS_OID',
  '1.3.6.1.4.1.4203.1.11.1': 'passwdModifyOID',
  '1.3.6.1.4.1.4203.1.11.3': 'LDAP_SERVER_WHO_AM_I_OID',
  '1.2.840.113556.1.4.1791': 'LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID',
};

/** The three root arcs, which is how an unnamed OID is rendered. */
const OID_ROOT_ARCS: Record<string, string> = {
  '0': 'itu-t',
  '1': 'iso',
  '2': 'joint-iso-itu-t',
};

/**
 * An OID as the reference analyzer shows it: by name when it knows one, and
 * otherwise with its FIRST ARC spelled out - `1.3.6.1.4.1.1466.20036` renders
 * `iso.3.6.1.4.1.1466.20036`. That is BER's display convention rather than
 * anything LDAP-specific, and it is not what a reader expects until they see it.
 */
function nameOid(oid: string): string {
  const known = EXTENDED_OID_NAMES[oid];
  if (known !== undefined) return known;
  const dot = oid.indexOf('.');
  if (dot <= 0) return oid;
  const root = OID_ROOT_ARCS[oid.slice(0, dot)];
  return root === undefined ? oid : `${root}${oid.slice(dot)}`;
}

/**
 * A distinguished name as it appears in the Info column.
 *
 * An empty DN is the root of the directory, and the reference analyzer says so
 * rather than printing `""`. A SASL bind sends exactly that, so this is the
 * common case and not an edge one.
 */
function renderDn(dn: string): string {
  return dn.length === 0 ? '<ROOT>' : dn;
}

// --- per-connection state -----------------------------------------------------

/**
 * How many connections' worth of search counters to keep, and how many message
 * ids within one.
 *
 * Bounded for the reason every tracker here is bounded (`docs/decisions/0014`):
 * an LDAP client raises the message id on every operation and never reuses one,
 * so an unbounded map grows for the length of the connection. Losing an old
 * count makes a later `searchResDone` report fewer results than it should,
 * which is the same degradation a capture started mid-connection already has.
 */
const MAX_TRACKED_MESSAGE_IDS = 256;

export interface LdapConversationState {
  /**
   * `searchResEntry` messages seen per messageID.
   *
   * Never reset by a `searchResDone` - measured, a second Done on the same id
   * reports the running total including the entries the first one already
   * counted. Insertion order is the eviction order, which is right here because
   * message ids only ever climb.
   */
  entries: Map<number, number>;
}

export function freshLdapConversation(): LdapConversationState {
  return { entries: new Map() };
}

function countEntry(state: LdapConversationState, messageId: number): void {
  state.entries.set(messageId, (state.entries.get(messageId) ?? 0) + 1);
  if (state.entries.size > MAX_TRACKED_MESSAGE_IDS) {
    const oldest = state.entries.keys().next();
    if (!oldest.done) state.entries.delete(oldest.value);
  }
}

// --- reading one message ------------------------------------------------------

export interface LdapResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

interface OneMessage {
  /** What the Info column shows for this message, trailing space and all. */
  info: string;
  /**
   * Text appended AFTER the trailing space, which is where `[N results]` goes.
   *
   * Measured: `searchResDone(2) success  [0 results]` carries two spaces before
   * the bracket and none after it, so the count is not part of the detail - it
   * follows the space every other message ends on. Folding it into `detail`
   * produced `success [0 results] `, which is wrong at both ends.
   */
  suffix?: string;
  rows: ProtocolField[];
  fields: Record<string, string | number>;
  /** Where the next message starts. */
  end: number;
}

/** The operation number and whether the tag is an LDAP protocolOp at all. */
function operationOf(tag: number): number | null {
  // [APPLICATION n]: class bits 01, so 0x40 primitive and 0x60 constructed.
  if ((tag & 0xc0) !== 0x40) return null;
  const op = tag & 0x1f;
  return OP_NAMES[op] === undefined ? null : op;
}

function stringChild(bytes: Uint8Array, children: BerValue[], index: number): string {
  const child = children[index];
  return child === undefined ? '' : berString(bytes, child);
}

function unsignedChild(bytes: Uint8Array, children: BerValue[], index: number): number | null {
  const child = children[index];
  return child === undefined ? null : berUnsigned(bytes, child);
}

/**
 * Reads one LDAPMessage at `offset`, or null when the bytes are not one.
 *
 * Null rather than a throw, and null rather than a partial answer: these bytes
 * came off a wire, and a dissector's response to "this is not what it claimed"
 * is to decline. A partial read is worse than none, because it produces a
 * confident wrong label.
 */
function readMessage(
  bytes: Uint8Array, offset: number, end: number, state: LdapConversationState,
): OneMessage | null {
  const envelope = readBer(bytes, offset, end);
  if (envelope === null || envelope.tag !== BER_TAG.SEQUENCE) return null;
  // A message whose declared length runs past what was captured is split across
  // segments. Declined - see the note in `dissectLdap`.
  if (envelope.contentEnd > end) return null;

  const parts = berChildren(bytes, envelope, 4);
  const idValue = parts[0];
  const op = parts[1];
  if (idValue === undefined || op === undefined || idValue.tag !== BER_TAG.INTEGER) return null;
  const messageId = berUnsigned(bytes, idValue);
  const operation = operationOf(op.tag);
  if (operation === null) return null;
  const opName = OP_NAMES[operation];

  const fields: Record<string, string | number> = {
    'ldap.messageID': messageId,
    'ldap.protocolOp': operation,
  };
  const rows: ProtocolField[] = [
    { name: 'messageID', value: messageId, abbrev: 'ldap.messageID' },
    { name: 'protocolOp', value: `${opName} (${operation})`, abbrev: 'ldap.protocolOp' },
  ];
  const children = berChildren(bytes, op, 8);

  /** The detail the Info column shows between the operation and its trailing space. */
  let detail = '';

  switch (operation) {
    case 0: {                                   // bindRequest
      const version = unsignedChild(bytes, children, 0);
      const name = stringChild(bytes, children, 1);
      const auth = children[2];
      // AuthenticationChoice: [0] simple, [3] sasl. The mechanism is not shown.
      const mechanism = auth !== undefined && (auth.tag & 0x1f) === 3 ? 'sasl' : 'simple';
      if (version !== null) {
        fields['ldap.version'] = version;
        rows.push({ name: 'version', value: version, abbrev: 'ldap.version' });
      }
      fields['ldap.name'] = name;
      fields['ldap.authentication'] = mechanism;
      rows.push({ name: 'name', value: renderDn(name), abbrev: 'ldap.name' });
      rows.push({ name: 'authentication', value: mechanism, abbrev: 'ldap.authentication' });
      detail = `"${renderDn(name)}" ${mechanism}`;
      break;
    }
    case 3: {                                   // searchRequest
      const base = stringChild(bytes, children, 0);
      const scope = unsignedChild(bytes, children, 1);
      const deref = unsignedChild(bytes, children, 2);
      fields['ldap.baseObject'] = base;
      rows.push({ name: 'baseObject', value: renderDn(base), abbrev: 'ldap.baseObject' });
      if (scope !== null) {
        fields['ldap.scope'] = scope;
        rows.push({ name: 'scope', value: `${SCOPE_NAMES[scope] ?? 'unknown'} (${scope})`, abbrev: 'ldap.scope' });
      }
      if (deref !== null) {
        fields['ldap.derefAliases'] = deref;
        rows.push({
          name: 'derefAliases', value: `${DEREF_NAMES[deref] ?? 'unknown'} (${deref})`,
          abbrev: 'ldap.derefAliases',
        });
      }
      detail = `"${renderDn(base)}" ${scope === null ? '' : SCOPE_NAMES[scope] ?? String(scope)}`;
      break;
    }
    case 4: {                                   // searchResEntry
      const name = stringChild(bytes, children, 0);
      fields['ldap.objectName'] = name;
      rows.push({ name: 'objectName', value: renderDn(name), abbrev: 'ldap.objectName' });
      countEntry(state, messageId);
      detail = `"${renderDn(name)}"`;
      break;
    }
    case 5: {                                   // searchResDone
      const code = unsignedChild(bytes, children, 0);
      const seen = state.entries.get(messageId) ?? 0;
      if (code !== null) {
        fields['ldap.resultCode'] = code;
        rows.push({ name: 'resultCode', value: `${RESULT_NAMES[code] ?? 'unknown'} (${code})`, abbrev: 'ldap.resultCode' });
      }
      rows.push({ name: 'entries returned', value: seen, generated: true });
      // Singular only at exactly one, so zero reads "[0 results]". The leading
      // space is the second of the pair - the message's own trailing space is
      // the first.
      return {
        info: `${opName}(${messageId}) ${code === null ? '' : RESULT_NAMES[code] ?? String(code)} `,
        suffix: ` [${seen} ${seen === 1 ? 'result' : 'results'}]`,
        rows, fields, end: envelope.end,
      };
    }
    case 1: case 7: case 9: case 11: case 13: case 15: {   // the *Response ops
      const code = unsignedChild(bytes, children, 0);
      const matched = stringChild(bytes, children, 1);
      if (code !== null) {
        fields['ldap.resultCode'] = code;
        rows.push({ name: 'resultCode', value: `${RESULT_NAMES[code] ?? 'unknown'} (${code})`, abbrev: 'ldap.resultCode' });
      }
      if (matched.length > 0) {
        fields['ldap.matchedDN'] = matched;
        rows.push({ name: 'matchedDN', value: matched, abbrev: 'ldap.matchedDN' });
      }
      const diagnostic = stringChild(bytes, children, 2);
      if (diagnostic.length > 0) {
        fields['ldap.errorMessage'] = diagnostic;
        rows.push({ name: 'errorMessage', value: diagnostic, abbrev: 'ldap.errorMessage' });
      }
      detail = code === null ? '' : RESULT_NAMES[code] ?? String(code);
      break;
    }
    case 6: case 8: case 14: case 12: {         // modify / add / compare / modDN
      const name = stringChild(bytes, children, 0);
      fields['ldap.objectName'] = name;
      rows.push({ name: 'object', value: renderDn(name), abbrev: 'ldap.objectName' });
      detail = `"${renderDn(name)}"`;
      break;
    }
    case 10: {                                  // delRequest - primitive, body IS the DN
      const name = berString(bytes, op);
      fields['ldap.entry'] = name;
      rows.push({ name: 'entry', value: renderDn(name), abbrev: 'ldap.entry' });
      detail = `"${renderDn(name)}"`;
      break;
    }
    case 16: {                                  // abandonRequest - primitive MessageID
      // The id printed is the one being ABANDONED, carried in the body, not the
      // LDAPMessage's own. Reading `messageId` here instead is the obvious bug.
      const abandoned = berUnsigned(bytes, {
        tag: BER_TAG.INTEGER, constructed: false,
        contentStart: op.contentStart, contentEnd: op.contentEnd, end: op.end,
      });
      rows.push({ name: 'abandonMsgId', value: abandoned });
      detail = '';
      return {
        info: `${opName}(${abandoned}) `,
        rows, fields, end: envelope.end,
      };
    }
    case 23: {                                  // extendedReq
      const request = children[0];
      // requestName is [0] OCTET STRING holding the OID as TEXT, not as a BER
      // OID - so `berString`, and `berOid` would read arbitrary bytes.
      const oid = request === undefined ? '' : berString(bytes, request);
      if (oid.length > 0) {
        fields['ldap.requestName'] = oid;
        rows.push({ name: 'requestName', value: oid, abbrev: 'ldap.requestName' });
      }
      detail = nameOid(oid);
      break;
    }
    case 25:                                     // intermediateResponse says NOTHING,
      return { info: '', rows, fields, end: envelope.end };
    default:                                     // unbind, searchResRef, extendedResp
      detail = '';
  }

  // Always a trailing space, and exactly one separator before the detail when
  // there is one. `unbindRequest(3) ` and `searchResRef(2) ` end here.
  return {
    info: detail.length > 0 ? `${opName}(${messageId}) ${detail} ` : `${opName}(${messageId}) `,
    rows, fields, end: envelope.end,
  };
}

// --- the segment ---------------------------------------------------------------

/**
 * Whether these bytes open an LDAPMessage.
 *
 * The cheap test that decides whether a non-LDAP port gets dissected at all. It
 * has to be strict: a SEQUENCE whose first child is an INTEGER is a shape
 * plenty of binary protocols share, so the operation tag must be one LDAP
 * actually defines before this says yes.
 */
export function looksLikeLdap(bytes: Uint8Array, start: number, end: number): boolean {
  const envelope = readBer(bytes, start, end);
  if (envelope === null || envelope.tag !== BER_TAG.SEQUENCE) return false;
  const parts = berChildren(bytes, envelope, 2);
  const idValue = parts[0];
  const op = parts[1];
  return idValue !== undefined && op !== undefined
    && idValue.tag === BER_TAG.INTEGER && operationOf(op.tag) !== null;
}

/**
 * Every LDAPMessage in one segment.
 *
 * A message whose declared length runs past the captured bytes is **declined**,
 * not half-read - the same rule DNS-over-TCP follows, and for the same reason:
 * reporting the half that arrived means reporting a message that was never
 * sent. When that happens after at least one whole message, what did fit is
 * still reported; when it happens on the first, this returns null and the frame
 * reads as plain TCP.
 */
export function dissectLdap(
  bytes: Uint8Array, start: number, end: number, state: LdapConversationState,
): LdapResult | null {
  const messages: OneMessage[] = [];
  let offset = start;
  while (offset < end) {
    const message = readMessage(bytes, offset, end, state);
    if (message === null) break;
    messages.push(message);
    if (message.end <= offset) break;           // never loop on a zero-length read
    offset = message.end;
  }
  if (messages.length === 0) return null;

  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  for (const [index, message] of messages.entries()) {
    Object.assign(fields, message.fields);
    rows.push(messages.length === 1
      ? { name: 'LDAPMessage', value: '', children: message.rows }
      : { name: `LDAPMessage ${index + 1}`, value: '', children: message.rows });
  }

  return {
    protocolLabel: 'LDAP',
    // Each message already ends in its own space, so joining with " | " puts
    // TWO before the bar - which is exactly what the reference prints.
    info: messages.map((m) => `${m.info}${m.suffix ?? ''}`).join(' | '),
    fields,
    layer: {
      name: 'Lightweight Directory Access Protocol',
      summary: messages.length === 1
        ? 'Lightweight Directory Access Protocol'
        : `Lightweight Directory Access Protocol (${messages.length} messages)`,
      fields: rows,
    },
  };
}
