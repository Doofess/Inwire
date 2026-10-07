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
import { hexColons } from '../dissect/hexBytes';

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
  /**
   * Each request's frame and time, by messageID, for the response's
   * `[Response To]` and `[Time]`. Bounded with `entries`, for the same reason.
   */
  requests: Map<number, { frame: number; tsUs: number }>;
}

export function freshLdapConversation(): LdapConversationState {
  return { entries: new Map(), requests: new Map() };
}

/** The operations that answer a request - whose rows name the request's frame. */
const RESPONSES = new Set([1, 4, 5, 7, 9, 11, 13, 15, 19, 24, 25]);

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
  /** The first of `layers`. */
  layer: ProtocolLayer;
  /**
   * One layer per message over TCP, as the reference stacks them; one for
   * the whole datagram over UDP (CLDAP), which it draws as one protocol.
   */
  layers: ProtocolLayer[];
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
  /** The message's heading, `LDAPMessage <what Info says>`. */
  title: string;
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
  frame?: { id: number; tsUs: number },
): OneMessage | null {
  const message = readMessageInfo(bytes, offset, end, state);
  if (message === null) return null;
  const envelope = readBer(bytes, offset, end)!;
  const [idValue, op] = berChildren(bytes, envelope, 4);
  const messageId = berUnsigned(bytes, idValue);
  const operation = operationOf(op.tag)!;
  const opName = OP_NAMES[operation];
  const children = berChildren(bytes, op, 8);
  const abandoned = operation === 16 ? message.info.trim() : '';

  // The heading: what Info says of the message, trimmed - and for an entry
  // or a Done, the running count the reference appends to it.
  let title = `LDAPMessage ${message.info.trim()}`;
  if (operation === 4 || operation === 5) {
    const seen = state.entries.get(messageId) ?? 0;
    title = `LDAPMessage ${message.info.trim()} [${seen} ${seen === 1 ? 'result' : 'results'}]`;
  } else if (operation === 23) {
    title = `LDAPMessage ${opName}(${messageId})`;
  } else if (operation === 16) {
    title = 'LDAPMessage';
  }
  const rows: ProtocolField[] = [
    { name: 'messageID', value: messageId, abbrev: 'ldap.messageID' },
    {
      name: 'protocolOp', value: operation === 16 ? `${opName} (${operation}) ${abandoned}` : `${opName} (${operation})`,
      abbrev: 'ldap.protocolOp', children: operationRows(bytes, operation, op, children),
    },
  ];
  // A response names its request's frame and how long it took; a request is
  // remembered for the response that will.
  if (frame !== undefined) {
    if (RESPONSES.has(operation)) {
      const asked = state.requests.get(messageId);
      if (asked !== undefined && asked.frame !== frame.id) {
        rows.push(
          { name: 'Response To', value: asked.frame, abbrev: 'ldap.response_to', generated: true, linkToFrame: asked.frame },
          { name: 'Time', value: elapsedText(frame.tsUs - asked.tsUs), abbrev: 'ldap.time', generated: true },
        );
      }
    } else {
      state.requests.set(messageId, { frame: frame.id, tsUs: frame.tsUs });
      if (state.requests.size > MAX_TRACKED_MESSAGE_IDS) {
        const oldest = state.requests.keys().next();
        if (!oldest.done) state.requests.delete(oldest.value);
      }
    }
  }
  return { ...message, rows, title };
}

function readMessageInfo(
  bytes: Uint8Array, offset: number, end: number, state: LdapConversationState,
): Omit<OneMessage, 'title'> | null {
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

// --- the tree, as the reference draws it ----------------------------------------
//
// asn2wrs's LDAP tree, row for row: each LDAPMessage a heading with its ID and
// its operation, the operation an element holding every field of its body, a
// search filter as a tree of the choices it is made of, and a result's
// matchedDN and errorMessage drawn even when empty (`<MISSING>`).

const items = (n: number) => `${n} item${n === 1 ? '' : 's'}`;
const missingIfEmpty = (text: string) => (text.length === 0 ? '<MISSING>' : text);
const printable = (bytes: Uint8Array, value: BerValue) => {
  for (let i = value.contentStart; i < value.contentEnd; i++) {
    const b = bytes[i];
    if (b < 0x20 || b > 0x7e) return false;
  }
  return true;
};
const valueText = (bytes: Uint8Array, value: BerValue) =>
  (printable(bytes, value) ? berString(bytes, value) : hexColons(bytes, value.contentStart, value.contentEnd));

/** The reference's names for the Filter CHOICE (RFC 4511 §4.5.1). */
const FILTER_NAMES: Record<number, string> = {
  0: 'and', 1: 'or', 2: 'not', 3: 'equalityMatch', 4: 'substrings', 5: 'greaterOrEqual',
  6: 'lessOrEqual', 7: 'present', 8: 'approxMatch', 9: 'extensibleMatch',
};

/** An attribute value assertion's value, read as the reference reads Active Directory's locator ones. */
function assertionRows(bytes: Uint8Array, attribute: string, value: BerValue): { rows: ProtocolField[]; text: string } {
  if (attribute.toLowerCase() === 'ntver' && value.contentEnd - value.contentStart === 4) {
    const flags = le32(bytes, value.contentStart);
    return { rows: [ntVersionRow(flags)], text: `0x${flags.toString(16).padStart(8, '0')}` };
  }
  const text = valueText(bytes, value);
  return { rows: [{ name: 'assertionValue', value: text, abbrev: 'ldap.assertionValue' }], text };
}

/**
 * One Filter: its rows, and its string form. The string is built the way the
 * reference builds it, which nests a set's earlier members one level deeper
 * for each that follows - `(&(&(&(A))(B))(C))` for `(&(A)(B)(C))` - and is
 * reproduced rather than tidied, so the line reads as it does there.
 */
function filterTree(bytes: Uint8Array, value: BerValue, depth = 0): { rows: ProtocolField[]; text: string; choice: number } {
  const choice = value.tag & 0x1f;
  const name = FILTER_NAMES[choice] ?? `unknown (${choice})`;
  if (depth > 32) return { rows: [], text: '', choice };
  if (choice === 0 || choice === 1) {
    const members = berChildren(bytes, value, 64);
    const op = choice === 0 ? '&' : '|';
    const abbrev = choice === 0 ? 'ldap.and' : 'ldap.or';
    const itemAbbrev = choice === 0 ? 'ldap.and_item' : 'ldap.or_item';
    let text = '';
    const memberRows: ProtocolField[] = [];
    for (const member of members) {
      const inner = filterTree(bytes, member, depth + 1);
      text = text.length === 0 ? `(${op}${inner.text})` : `(${op}${text}${inner.text})`;
      memberRows.push({
        name: `Filter: ${inner.text}`, value: '',
        children: [{ name: `${name} item`, value: `${FILTER_NAMES[inner.choice] ?? 'unknown'} (${inner.choice})`, abbrev: itemAbbrev, children: inner.rows }],
      });
    }
    return {
      rows: [{ name: `${name}: ${text}`, value: '', children: [{ name, value: items(members.length), abbrev, children: memberRows }] }],
      text, choice,
    };
  }
  if (choice === 2) {
    const inner = filterTree(bytes, berChildren(bytes, value, 1)[0] ?? value, depth + 1);
    const text = `(!${inner.text})`;
    return { rows: [{ name: 'not', value: `${FILTER_NAMES[inner.choice] ?? 'unknown'} (${inner.choice})`, abbrev: 'ldap.not', children: inner.rows }], text, choice };
  }
  if (choice === 7) {
    const attribute = berString(bytes, value);
    return { rows: [{ name: 'present', value: attribute, abbrev: 'ldap.present' }], text: `(${attribute}=*)`, choice };
  }
  if (choice === 3 || choice === 5 || choice === 6 || choice === 8) {
    const [desc, assertion] = berChildren(bytes, value, 2);
    const attribute = desc === undefined ? '' : berString(bytes, desc);
    const shown = assertion === undefined ? { rows: [], text: '' } : assertionRows(bytes, attribute, assertion);
    const relation = { 3: '=', 5: '>=', 6: '<=', 8: '~=' }[choice];
    return {
      rows: [{
        name, value: '', abbrev: `ldap.${name}_element`,
        children: [{ name: 'attributeDesc', value: attribute, abbrev: 'ldap.attributeDesc' }, ...shown.rows],
      }],
      text: `(${attribute}${relation}${shown.text})`, choice,
    };
  }
  if (choice === 4) {
    const [type, list] = berChildren(bytes, value, 2);
    const attribute = type === undefined ? '' : berString(bytes, type);
    const parts = list === undefined ? [] : berChildren(bytes, list, 64);
    const SUB = ['initial', 'any', 'final'];
    let initial = '';
    let final = '';
    const any: string[] = [];
    const partRows = parts.map((part): ProtocolField => {
      const kind = part.tag & 0x1f;
      const text = berString(bytes, part);
      if (kind === 0) initial = text; else if (kind === 2) final = text; else any.push(text);
      return {
        name: 'substrings item', value: `${SUB[kind] ?? 'unknown'} (${kind})`, abbrev: 'ldap.substringFilter_substrings_item',
        children: [{ name: SUB[kind] ?? 'unknown', value: text, abbrev: `ldap.${SUB[kind] ?? 'initial'}` }],
      };
    });
    return {
      rows: [{
        name: `substrings ${attribute}`, value: '', abbrev: 'ldap.substrings_element',
        children: [
          { name: 'type', value: attribute, abbrev: 'ldap.type' },
          { name: 'substrings', value: items(parts.length), abbrev: 'ldap.substringFilter_substrings', children: partRows },
        ],
      }],
      text: `(${attribute}=${initial}*${any.map((a) => `${a}*`).join('')}${final})`, choice,
    };
  }
  return { rows: [], text: '', choice };
}

// --- MS-ADTS's Netlogon answer, the locator's reply ---------------------------

const le16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

const NETLOGON_OPCODES: Record<number, string> = {
  7: 'LOGON_PRIMARY_QUERY', 12: 'LOGON_PRIMARY_RESPONSE', 18: 'LOGON_SAM_LOGON_REQUEST', 19: 'LOGON_SAM_LOGON_RESPONSE',
  20: 'LOGON_SAM_PAUSE_RESPONSE', 23: 'LOGON_SAM_LOGON_RESPONSE_EX', 24: 'LOGON_SAM_PAUSE_RESPONSE_EX', 25: 'LOGON_SAM_USER_UNKNOWN_EX',
};

/** A flag word's bits, each with the reference's name and both of its sentences. */
type FlagBit = [mask: number, abbrev: string, name: string, set: string, unset: string];
const NETLOGON_FLAGS: FlagBit[] = [
  [0x80000000, 'mscldap.netlogon.flags.forestnc', 'FDC', 'The NC is the default forest NC(Windows 2008)', 'The NC is not the default forest NC (Windows 2008)'],
  [0x40000000, 'mscldap.netlogon.flags.defaultnc', 'DNC', 'The NC is the default NC (Windows 2008)', 'The NC is not the default NC (Windows 2008)'],
  [0x20000000, 'mscldap.netlogon.flags.dnsname', 'DNS', 'Server name is in DNS format (Windows 2008)', 'Server name is not in DNS format (Windows 2008)'],
  [0x00001000, 'mscldap.netlogon.flags.writabledc', 'WDC', 'Domain controller is a Windows 2008 writable NC', 'Domain controller is not a Windows 2008 writable NC'],
  [0x00000800, 'mscldap.netlogon.flags.rodc', 'RODC', 'Domain controller is a Windows 2008 RODC', 'Domain controller is not a Windows 2008 RODC'],
  [0x00000400, 'mscldap.netlogon.flags.ndnc', 'NDNC', 'Domain is NON-DOMAIN NC serviced by ldap server', 'Domain is NOT non-domain nc serviced by ldap server'],
  [0x00000200, 'mscldap.netlogon.flags.good_timeserv', 'Good Time Serv', 'This dc has a GOOD TIME SERVICE (i.e. hardware clock)', 'This dc does NOT have a good time service (i.e. no hardware clock)'],
  [0x00000100, 'mscldap.netlogon.flags.writable', 'Writable', 'This dc is WRITABLE', 'This dc is NOT writable'],
  [0x00000080, 'mscldap.netlogon.flags.closest', 'Closest', 'This server is in the same site as the client', 'This server is NOT in the same site as the client'],
  [0x00000040, 'mscldap.netlogon.flags.timeserv', 'Time Serv', 'This dc is running TIME SERVICES (ntp)', 'This dc is NOT running time services (ntp)'],
  [0x00000020, 'mscldap.netlogon.flags.kdc', 'KDC', 'This is a KDC (kerberos)', 'This is NOT a kdc (kerberos)'],
  [0x00000010, 'mscldap.netlogon.flags.ds', 'DS', 'This dc supports DS', 'This dc does NOT support ds'],
  [0x00000008, 'mscldap.netlogon.flags.ldap', 'LDAP', 'This is an LDAP server', 'This is NOT an ldap server'],
  [0x00000004, 'mscldap.netlogon.flags.gc', 'GC', 'This is a GLOBAL CATALOGUE of forest', 'This is NOT a global catalog of forest'],
  [0x00000001, 'mscldap.netlogon.flags.pdc', 'PDC', 'This is a PDC', 'This is NOT a pdc'],
];
const NT_VERSION_FLAGS: FlagBit[] = [
  [0x00000001, 'mscldap.ntver.searchflags.v1', 'V1', 'Client requested version 1 netlogon response', 'Version 1 netlogon response not requested'],
  [0x00000002, 'mscldap.ntver.searchflags.v5', 'V5', 'Client requested version 5 netlogon response', 'Version 5 netlogon response not requested'],
  [0x00000004, 'mscldap.ntver.searchflags.v5ex', 'V5EX', 'Client requested version 5 extended netlogon response', 'Version 5 extended response not requested'],
  [0x00000008, 'mscldap.ntver.searchflags.v5ep', 'V5EP', 'Client has requested IP address of the server', 'IP address of server not requested'],
  [0x00000010, 'mscldap.ntver.searchflags.vcs', 'VCS', 'Client has asked for the closest site information', 'Closest site information not requested'],
  [0x01000000, 'mscldap.ntver.searchflags.vnt4', 'VNT4', 'Client is requesting server to avoid NT4 emulation', 'Only full AD DS requested'],
  [0x10000000, 'mscldap.ntver.searchflags.vpdc', 'VPDC', 'Client has requested the Primary Domain Controller', 'Primary Domain Controller not requested'],
  [0x20000000, 'mscldap.ntver.searchflags.vip', 'VIP', 'Client has requested IP details (obsolete)', 'IP details not requested (obsolete)'],
  [0x40000000, 'mscldap.ntver.searchflags.vl', 'VL', 'Client indicated that it is the local machine', 'Client is not the local machine'],
  [0x80000000, 'mscldap.ntver.searchflags.vgc', 'VGC', 'Client has requested a Global Catalog server', 'Global Catalog not requested'],
];

/** A flag word as the reference draws one: its value and the set flags' sentences, then a row per bit. */
function flagsRow(name: string, abbrev: string, word: number, bits: FlagBit[]): ProtocolField {
  const set = bits.filter(([mask]) => (word & mask) !== 0).map(([, , flag, sentence]) => `, ${flag}: ${sentence}`).join('');
  return {
    name, value: `0x${word.toString(16).padStart(8, '0')}${set}`, abbrev,
    children: bits.map(([mask, bitAbbrev, flag, on, off]): ProtocolField => ({
      name: flag, value: (word & mask) !== 0 ? on : off, abbrev: bitAbbrev,
      bitfield: { bitOffset: 31 - Math.log2(mask), bitLength: 1, totalBits: 32 },
    })),
  };
}
const ntVersionRow = (word: number) => flagsRow('Version Flags', 'mscldap.ntver.flags', word, NT_VERSION_FLAGS);

/** A name in RFC 1035 form, compression pointers relative to the Netlogon blob. */
function netlogonName(b: Uint8Array, start: number, end: number, at: number): { name: string; next: number } {
  const labels: string[] = [];
  let p = at;
  let next = -1;
  for (let jumps = 0; p < end && jumps < 16;) {
    const length = b[p];
    if (length === 0) { p += 1; break; }
    if ((length & 0xc0) === 0xc0) {
      if (next < 0) next = p + 2;
      p = start + (((length & 0x3f) << 8) | b[p + 1]);
      jumps++;
      continue;
    }
    labels.push(new TextDecoder().decode(b.subarray(p + 1, p + 1 + length)));
    p += 1 + length;
  }
  return { name: labels.length === 0 ? '<Root>' : labels.join('.'), next: next >= 0 ? next : p };
}

/** A GUID in its mixed-endian text form. */
function guidText(b: Uint8Array, at: number): string {
  const h = (i: number) => b[at + i].toString(16).padStart(2, '0');
  return `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${[10, 11, 12, 13, 14, 15].map(h).join('')}`;
}

/** A Netlogon attribute value (MS-ADTS 6.3.1.9): the locator's answer, field by field. */
function netlogonRows(b: Uint8Array, start: number, end: number): ProtocolField[] | null {
  if (end - start < 24) return null;
  const opcode = le16(b, start);
  if (opcode !== 23 && opcode !== 25) return null;
  const rows: ProtocolField[] = [
    { name: 'Operation code', value: `${NETLOGON_OPCODES[opcode] ?? 'Unknown'} (${opcode})`, abbrev: 'mscldap.netlogon.opcode' },
    flagsRow('Flags', 'mscldap.netlogon.flags', le32(b, start + 4), NETLOGON_FLAGS),
    { name: 'Domain GUID', value: guidText(b, start + 8), abbrev: 'mscldap.domain.guid' },
  ];
  let p = start + 24;
  const NAMES: [string, string][] = [
    ['Forest', 'mscldap.forest'], ['Domain', 'mscldap.domain'], ['Hostname', 'mscldap.hostname'],
    ['NetBIOS Domain', 'mscldap.nb_domain'], ['NetBIOS Hostname', 'mscldap.nb_hostname'], ['Username', 'mscldap.username'],
    ['Server Site', 'mscldap.sitename'], ['Client Site', 'mscldap.clientsitename'],
  ];
  for (const [name, abbrev] of NAMES) {
    if (p >= end) return rows;
    const read = netlogonName(b, start, end, p);
    rows.push({ name, value: read.name, abbrev });
    p = read.next;
  }
  if (p + 8 <= end) {
    rows.push(
      ntVersionRow(le32(b, p)),
      { name: 'LM Token', value: `0x${le16(b, p + 4).toString(16).padStart(4, '0')}`, abbrev: 'mscldap.netlogon.lm_token' },
      { name: 'NT Token', value: `0x${le16(b, p + 6).toString(16).padStart(4, '0')}`, abbrev: 'mscldap.netlogon.nt_token' },
    );
  }
  return rows;
}

/** A PartialAttributeList item: its type and its values, Netlogon's decoded. */
function attributeRows(bytes: Uint8Array, attribute: BerValue): ProtocolField {
  const [type, vals] = berChildren(bytes, attribute, 2);
  const name = type === undefined ? '' : berString(bytes, type);
  const values = vals === undefined ? [] : berChildren(bytes, vals, 256);
  const valueRows = values.flatMap((v): ProtocolField[] => {
    if (name.toLowerCase() === 'netlogon') {
      const decoded = netlogonRows(bytes, v.contentStart, v.contentEnd);
      if (decoded !== null) return decoded;
    }
    return [{ name: 'AttributeValue', value: valueText(bytes, v), abbrev: 'ldap.AttributeValue' }];
  });
  return {
    name: `PartialAttributeList item ${name}`, value: '', abbrev: 'ldap.PartialAttributeList_item_element',
    children: [
      { name: 'type', value: name, abbrev: 'ldap.type' },
      { name: 'vals', value: items(values.length), abbrev: 'ldap.vals', children: valueRows },
    ],
  };
}

/** A result's body: code, matchedDN, errorMessage - the last two drawn even when empty. */
function resultRows(bytes: Uint8Array, children: BerValue[], codeAbbrev: string): ProtocolField[] {
  const code = unsignedChild(bytes, children, 0);
  return [
    { name: 'resultCode', value: `${code === null ? 'unknown' : RESULT_NAMES[code] ?? 'unknown'} (${code ?? 0})`, abbrev: codeAbbrev },
    { name: 'matchedDN', value: missingIfEmpty(stringChild(bytes, children, 1)), abbrev: 'ldap.matchedDN' },
    { name: 'errorMessage', value: missingIfEmpty(stringChild(bytes, children, 2)), abbrev: 'ldap.errorMessage' },
  ];
}

/** The rows of one operation's body, under its `<op>_element` heading where it has one. */
function operationRows(bytes: Uint8Array, operation: number, op: BerValue, children: BerValue[]): ProtocolField[] {
  const opName = OP_NAMES[operation];
  const element = (rows: ProtocolField[]): ProtocolField[] =>
    [{ name: opName, value: '', abbrev: `ldap.${opName}_element`, children: rows }];
  switch (operation) {
    case 0: {
      const auth = children[2];
      const choice = auth === undefined ? 0 : auth.tag & 0x1f;
      const authRows: ProtocolField[] = auth === undefined ? [] : choice === 0
        ? [{ name: 'simple', value: berString(bytes, auth), abbrev: 'ldap.simple' }]
        : [];
      return element([
        { name: 'version', value: unsignedChild(bytes, children, 0) ?? 0, abbrev: 'ldap.version' },
        { name: 'name', value: missingIfEmpty(stringChild(bytes, children, 1)), abbrev: 'ldap.name' },
        { name: 'authentication', value: `${choice === 3 ? 'sasl' : 'simple'} (${choice})`, abbrev: 'ldap.authentication', children: authRows },
      ]);
    }
    case 1:
      return element(resultRows(bytes, children, 'ldap.bindResponse_resultCode'));
    case 2:
      return element([]);
    case 3: {
      const scope = unsignedChild(bytes, children, 1) ?? 0;
      const deref = unsignedChild(bytes, children, 2) ?? 0;
      const typesOnly = children[5] !== undefined && bytes[children[5].contentStart] !== 0;
      const rows: ProtocolField[] = [
        { name: 'baseObject', value: missingIfEmpty(stringChild(bytes, children, 0)), abbrev: 'ldap.baseObject' },
        { name: 'scope', value: `${SCOPE_NAMES[scope] ?? 'unknown'} (${scope})`, abbrev: 'ldap.scope' },
        { name: 'derefAliases', value: `${DEREF_NAMES[deref] ?? 'unknown'} (${deref})`, abbrev: 'ldap.derefAliases' },
        { name: 'sizeLimit', value: unsignedChild(bytes, children, 3) ?? 0, abbrev: 'ldap.sizeLimit' },
        { name: 'timeLimit', value: unsignedChild(bytes, children, 4) ?? 0, abbrev: 'ldap.timeLimit' },
        { name: 'typesOnly', value: typesOnly ? 'True' : 'False', abbrev: 'ldap.typesOnly' },
      ];
      if (children[6] !== undefined) {
        const filter = filterTree(bytes, children[6]);
        rows.push({
          name: `Filter: ${filter.text}`, value: '',
          children: [{ name: 'filter', value: `${FILTER_NAMES[filter.choice] ?? 'unknown'} (${filter.choice})`, abbrev: 'ldap.filter', children: filter.rows }],
        });
      }
      const attributes = children[7] === undefined ? [] : berChildren(bytes, children[7], 256);
      rows.push({
        name: 'attributes', value: items(attributes.length), abbrev: 'ldap.searchRequest_attributes',
        children: attributes.map((a) => ({ name: 'AttributeDescription', value: berString(bytes, a), abbrev: 'ldap.AttributeDescription' })),
      });
      return element(rows);
    }
    case 4: {
      const attributes = children[1] === undefined ? [] : berChildren(bytes, children[1], 256);
      return element([
        { name: 'objectName', value: missingIfEmpty(stringChild(bytes, children, 0)), abbrev: 'ldap.objectName' },
        {
          name: 'attributes', value: items(attributes.length), abbrev: 'ldap.searchResultEntry_attributes',
          children: attributes.map((a) => attributeRows(bytes, a)),
        },
      ]);
    }
    case 5: case 7: case 9: case 11: case 13: case 15: case 24:
      return element(resultRows(bytes, children, 'ldap.resultCode'));
    case 10:
      return [{ name: 'delRequest', value: missingIfEmpty(berString(bytes, op)), abbrev: 'ldap.delRequest' }];
    case 16:
      return [{
        name: 'abandonRequest',
        value: berUnsigned(bytes, { tag: BER_TAG.INTEGER, constructed: false, contentStart: op.contentStart, contentEnd: op.contentEnd, end: op.end }),
        abbrev: 'ldap.abandonRequest',
      }];
    case 19:
      return [{
        name: 'searchResRef', value: items(children.length), abbrev: 'ldap.searchResRef',
        children: children.map((c) => ({ name: 'LDAPURL', value: berString(bytes, c), abbrev: 'ldap.LDAPURL' })),
      }];
    case 23: {
      const oid = children[0] === undefined ? '' : berString(bytes, children[0]);
      const known = EXTENDED_OID_NAMES[oid];
      return element([{ name: 'requestName', value: known === undefined ? oid : `${oid} (${known})`, abbrev: 'ldap.requestName' }]);
    }
    default:
      return element([]);
  }
}

/** A response time, in the unit the reference scales it to. */
function elapsedText(us: number): string {
  if (us < 1000) return `${us.toFixed(3)} microseconds`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(6)} milliseconds`;
  if (us % 1_000_000 === 0) return `${us / 1_000_000} second${us === 1_000_000 ? '' : 's'}`;
  return `${(us / 1_000_000).toFixed(9)} seconds`;
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
  options: { frame?: { id: number; tsUs: number }; connectionless?: boolean } = {},
): LdapResult | null {
  const messages: OneMessage[] = [];
  let offset = start;
  while (offset < end) {
    const message = readMessage(bytes, offset, end, state, options.frame);
    if (message === null) break;
    messages.push(message);
    if (message.end <= offset) break;           // never loop on a zero-length read
    offset = message.end;
  }
  if (messages.length === 0) return null;

  const fields: Record<string, string | number> = {};
  for (const message of messages) Object.assign(fields, message.fields);
  const element = (message: OneMessage): ProtocolField =>
    ({ name: message.title, value: '', abbrev: 'ldap.LDAPMessage_element', children: message.rows });
  const layers: ProtocolLayer[] = options.connectionless
    ? [{
      name: 'Connectionless Lightweight Directory Access Protocol', summary: 'Connectionless Lightweight Directory Access Protocol',
      fields: messages.map(element),
    }]
    : messages.map((m) => ({ name: 'Lightweight Directory Access Protocol', summary: 'Lightweight Directory Access Protocol', fields: [element(m)] }));

  return {
    protocolLabel: options.connectionless ? 'CLDAP' : 'LDAP',
    // Each message already ends in its own space, so joining with " | " puts
    // TWO before the bar - which is exactly what the reference prints. A
    // CLDAP datagram's messages run together with no bar at all.
    info: messages.map((m) => `${m.info}${m.suffix ?? ''}`).join(options.connectionless ? '' : ' | '),
    fields,
    layer: layers[0],
    layers,
  };
}
