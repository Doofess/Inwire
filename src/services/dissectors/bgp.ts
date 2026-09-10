/**
 * BGP-4 (RFC 4271), the routing protocol the internet is actually made of.
 *
 * It is the fourth length-delimited message on a well-known TCP port in this
 * build - after DNS-over-TCP, LDAP and SMB2 - and the first that cannot follow
 * their shared rule of **declining a message split across segments**. LDAP's
 * messages are small and a split one is an oddity; a BGP session's dominant
 * traffic is the full-table UPDATE, which at 4 kB (65 kB with RFC 8654's
 * extended messages) does not fit a segment and never did. A dissector that
 * declined those would read only the KEEPALIVEs, which is the half of a BGP
 * capture nobody opens an analyzer for.
 *
 * So this one carries state across segments, and in a **direction** rather
 * than a connection (`TcpDirection.bgp`): the two halves of a peering are
 * independent byte streams, and a message boundary in one says nothing about
 * where the other is.
 *
 * ## What was measured rather than read off RFC 4271
 *
 * Asked directly (tshark 4.6.8), none of these follows from the RFC's prose:
 *
 *  - **Info is the message type and nothing else** - `KEEPALIVE Message`,
 *    `UPDATE Message`. No AS number, no prefix count, no error name. A
 *    NOTIFICATION that tears the session down reads exactly as long as a
 *    KEEPALIVE. Every detail lives in the tree instead.
 *  - **Several messages in one segment join with `", "`.** That is a fourth
 *    join convention in this build: LDAP uses `" | "`, SMB2 uses `"; "`, and
 *    Kerberos reports only the last message and joins nothing. Not one of them
 *    is derivable from the others, which is why each was asked for.
 *  - **An unknown type is `Unknown message type (0x09)`** - lower-case hex,
 *    two digits, parenthesised, and with no trailing " Message".
 *  - **The marker is the gate, not the port.** Sixteen bytes that are not all
 *    ones on port 179 are read as plain TCP, not as a malformed BGP message.
 *    It is a far stronger signal than the two-bit shapes
 *    `dissectors/heuristics.ts` refuses to key on - and it is still not used
 *    for detection, because:
 *  - **Port 179 only.** The identical bytes on port 1790 are plain TCP. The
 *    reference does not detect BGP by content however unmistakable the marker
 *    is, so neither does this.
 *
 * ## The one place this deliberately differs
 *
 * A segment that *begins* a multi-segment message gets an **empty** Info
 * column from tshark - not `[TCP segment of a reassembled PDU]`, which is what
 * that message's later segments get. The asymmetry is an artefact of where its
 * BGP dissector clears the column before asking for more bytes, and an empty
 * Info column tells a reader nothing at all. Such a frame reads here as the
 * plain TCP segment it is, which is also what the reference gives for every
 * later segment of the same message. `scripts/bgp/dissect.ts` states the
 * difference as an exception with this reason rather than skipping the case.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';

/** BGP's assigned port. The reference dispatches on this and nothing else. */
export const BGP_PORT = 179;

/** Sixteen bytes of ones, then a 2-byte length and a 1-byte type. */
const MARKER_LENGTH = 16;
const HEADER_LENGTH = 19;

const MESSAGE_NAMES: Record<number, string> = {
  1: 'OPEN',
  2: 'UPDATE',
  3: 'NOTIFICATION',
  4: 'KEEPALIVE',
  5: 'ROUTE-REFRESH',
};

/** RFC 4271 4.5, with RFC 4486's and RFC 7313's additions. */
const NOTIFY_MAJOR: Record<number, string> = {
  1: 'Message Header Error',
  2: 'OPEN Message Error',
  3: 'UPDATE Message Error',
  4: 'Hold Timer Expired',
  5: 'Finite State Machine Error',
  6: 'Cease',
  7: 'ROUTE-REFRESH Message Error',
};

const NOTIFY_MINOR: Record<number, Record<number, string>> = {
  1: { 1: 'Connection Not Synchronized', 2: 'Bad Message Length', 3: 'Bad Message Type' },
  2: {
    1: 'Unsupported Version Number', 2: 'Bad Peer AS', 3: 'Bad BGP Identifier',
    4: 'Unsupported Optional Parameter', 5: 'Authentication Failure',
    6: 'Unacceptable Hold Time', 7: 'Unsupported Capability',
  },
  3: {
    1: 'Malformed Attribute List', 2: 'Unrecognized Well-known Attribute',
    3: 'Missing Well-known Attribute', 4: 'Attribute Flags Error',
    5: 'Attribute Length Error', 6: 'Invalid ORIGIN Attribute',
    7: 'AS Routing Loop', 8: 'Invalid NEXT_HOP Attribute',
    9: 'Optional Attribute Error', 10: 'Invalid Network Field', 11: 'Malformed AS_PATH',
  },
  6: {
    1: 'Maximum Number of Prefixes Reached', 2: 'Administrative Shutdown',
    3: 'Peer De-configured', 4: 'Administrative Reset', 5: 'Connection Rejected',
    6: 'Other Configuration Change', 7: 'Connection Collision Resolution',
    8: 'Out of Resources', 9: 'Hard Reset', 10: 'BFD Down',
  },
  7: { 1: 'Invalid Message Length' },
};

/**
 * The abbrev for a NOTIFICATION's minor code, which depends on its major code.
 *
 * The reference gives each major its own field rather than one shared minor -
 * a subcode of 2 is "Bad Message Length" under a header error and
 * "Administrative Shutdown" under a Cease, so a single field holding both
 * would be a number whose meaning no filter could express. Written out as
 * literals because `scripts/dissect/registry.ts` scans the source for them: a
 * table built by concatenation would leave seven registered fields reading as
 * having no writer, which is how `kerberos.crealm` slipped through once.
 */
const NOTIFY_MINOR_ABBREV: Record<number, string> = {
  1: 'bgp.notify.minor_error',
  2: 'bgp.notify.minor_error_open',
  3: 'bgp.notify.minor_error_update',
  4: 'bgp.notify.minor_error_expired',
  5: 'bgp.notify.minor_error_state',
  6: 'bgp.notify.minor_error_cease',
  7: 'bgp.notify.minor_error_route_refresh',
};

/** The address families a BGP session actually carries. */
const AFI_NAMES: Record<number, string> = { 1: 'IPv4', 2: 'IPv6' };
const SAFI_NAMES: Record<number, string> = {
  1: 'Unicast', 2: 'Multicast', 4: 'Labeled Unicast', 128: 'MPLS-labeled VPN',
};

/**
 * How far through a message this direction is.
 *
 * Two carries, and they are different things. `owed` is a message whose header
 * was read in an earlier segment and whose body is still arriving - the type
 * travels with it because the frame that *completes* a message is the one the
 * reference names it in. `header` is the rarer case of a segment boundary
 * landing inside the nineteen header bytes themselves, where not even the type
 * is known yet.
 *
 * Both are bounded by construction: `header` never reaches nineteen bytes, and
 * `owed` is a 16-bit length counting down. Neither accumulates for the life of
 * a connection, which is what `docs/decisions/0014` asks of tracker state.
 */
export interface BgpDirectionState {
  /** Body bytes still owed to a message that began in an earlier segment. */
  owed: number;
  /** That message's type byte. */
  owedType: number;
  /** A header split across the segment boundary; fewer than 19 bytes. */
  header: number[];
}

export function freshBgpDirection(): BgpDirectionState {
  return { owed: 0, owedType: 0, header: [] };
}

export interface BgpResult {
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

interface OneMessage {
  info: string;
  rows: ProtocolField[];
  fields: Record<string, string | number>;
}

const u16 = (b: Uint8Array, at: number): number => (b[at] << 8) | b[at + 1];

const typeName = (type: number): string =>
  MESSAGE_NAMES[type] ?? `Unknown message type (0x${type.toString(16).padStart(2, '0')})`;

/** The Info column's phrasing: a named type gets " Message", an unknown one does not. */
const infoFor = (type: number): string =>
  MESSAGE_NAMES[type] !== undefined ? `${MESSAGE_NAMES[type]} Message` : typeName(type);

/** True when sixteen bytes of ones start here. */
function hasMarker(bytes: ArrayLike<number>, start: number): boolean {
  for (let i = 0; i < MARKER_LENGTH; i++) if (bytes[start + i] !== 0xff) return false;
  return true;
}

/**
 * True when this segment opens with a BGP message header.
 *
 * The marker carries the whole decision. A stream on port 179 that does not
 * begin with sixteen ones is not read as BGP at all - the reference reports it
 * as plain TCP rather than as a damaged BGP message, and that is the only
 * thing separating a real peering from whatever else landed on the port.
 */
export function looksLikeBgp(bytes: Uint8Array, start: number, end: number): boolean {
  return end - start >= HEADER_LENGTH && hasMarker(bytes, start);
}

/** The rows every message carries, whatever its type. */
function headerRows(start: number, declared: number, type: number): ProtocolField[] {
  return [
    { name: 'Marker', value: '16 bytes', rawBytesRange: [start, start + MARKER_LENGTH - 1] },
    {
      name: 'Length', value: declared, abbrev: 'bgp.length',
      rawBytesRange: [start + MARKER_LENGTH, start + MARKER_LENGTH + 1],
    },
    {
      name: 'Type', value: `${typeName(type)} (${type})`, abbrev: 'bgp.type',
      rawBytesRange: [start + HEADER_LENGTH - 1, start + HEADER_LENGTH - 1],
    },
  ];
}

/** The body rows for the four types with a body worth showing. */
function bodyRows(
  bytes: Uint8Array, bodyStart: number, bodyEnd: number, type: number,
  fields: Record<string, string | number>,
): ProtocolField[] {
  const rows: ProtocolField[] = [];
  const available = bodyEnd - bodyStart;

  if (type === 1 && available >= 10) {
    const version = bytes[bodyStart];
    const myAs = u16(bytes, bodyStart + 1);
    const holdTime = u16(bytes, bodyStart + 3);
    const identifier = Array.from(bytes.subarray(bodyStart + 5, bodyStart + 9)).join('.');
    const optLen = bytes[bodyStart + 9];
    fields['bgp.open.version'] = version;
    fields['bgp.open.myas'] = myAs;
    fields['bgp.open.holdtime'] = holdTime;
    fields['bgp.open.identifier'] = identifier;
    fields['bgp.open.opt.len'] = optLen;
    rows.push(
      { name: 'Version', value: version, abbrev: 'bgp.open.version', rawBytesRange: [bodyStart, bodyStart] },
      { name: 'My AS', value: myAs, abbrev: 'bgp.open.myas', rawBytesRange: [bodyStart + 1, bodyStart + 2] },
      {
        name: 'Hold Time', value: `${holdTime} seconds`, abbrev: 'bgp.open.holdtime',
        rawBytesRange: [bodyStart + 3, bodyStart + 4],
      },
      {
        name: 'BGP Identifier', value: identifier, abbrev: 'bgp.open.identifier',
        rawBytesRange: [bodyStart + 5, bodyStart + 8],
      },
      {
        name: 'Optional Parameters Length', value: optLen, abbrev: 'bgp.open.opt.len',
        rawBytesRange: [bodyStart + 9, bodyStart + 9],
      },
    );
  } else if (type === 2 && available >= 2) {
    // The two lengths, and deliberately not the path attributes themselves.
    // Those are some forty attribute types each with its own layout, and not
    // one of them reaches the Info column - so reading them is a tree feature
    // with no parity consequence, which is a different piece of work.
    const withdrawnLen = u16(bytes, bodyStart);
    fields['bgp.update.withdrawn_routes.length'] = withdrawnLen;
    rows.push({
      name: 'Withdrawn Routes Length', value: withdrawnLen,
      abbrev: 'bgp.update.withdrawn_routes.length', rawBytesRange: [bodyStart, bodyStart + 1],
    });
    const attrLenAt = bodyStart + 2 + withdrawnLen;
    if (attrLenAt + 2 <= bodyEnd) {
      const attrLen = u16(bytes, attrLenAt);
      fields['bgp.update.path_attributes.length'] = attrLen;
      rows.push({
        name: 'Total Path Attribute Length', value: attrLen,
        abbrev: 'bgp.update.path_attributes.length', rawBytesRange: [attrLenAt, attrLenAt + 1],
      });
    }
  } else if (type === 3 && available >= 2) {
    const major = bytes[bodyStart];
    const minor = bytes[bodyStart + 1];
    const minorName = NOTIFY_MINOR[major]?.[minor];
    const minorAbbrev = NOTIFY_MINOR_ABBREV[major] ?? 'bgp.notify.minor_error_unknown';
    fields['bgp.notify.major_error'] = major;
    fields[minorAbbrev] = minor;
    rows.push(
      {
        name: 'Major error Code',
        value: `${NOTIFY_MAJOR[major] ?? 'Unknown'} (${major})`,
        abbrev: 'bgp.notify.major_error', rawBytesRange: [bodyStart, bodyStart],
      },
      {
        name: 'Minor error Code',
        value: minorName !== undefined ? `${minorName} (${minor})` : String(minor),
        abbrev: minorAbbrev, rawBytesRange: [bodyStart + 1, bodyStart + 1],
      },
    );
  } else if (type === 5 && available >= 4) {
    const afi = u16(bytes, bodyStart);
    const safi = bytes[bodyStart + 3];
    fields['bgp.route_refresh.afi'] = afi;
    fields['bgp.route_refresh.safi'] = safi;
    rows.push(
      {
        name: 'Address family identifier (AFI)',
        value: `${AFI_NAMES[afi] ?? 'Unknown'} (${afi})`,
        abbrev: 'bgp.route_refresh.afi', rawBytesRange: [bodyStart, bodyStart + 1],
      },
      {
        name: 'Subsequent address family identifier (SAFI)',
        value: `${SAFI_NAMES[safi] ?? 'Unknown'} (${safi})`,
        abbrev: 'bgp.route_refresh.safi', rawBytesRange: [bodyStart + 3, bodyStart + 3],
      },
    );
  }
  return rows;
}

/**
 * Every BGP message that ENDS in this segment.
 *
 * Returns null when the segment holds no message boundary at all - it is
 * entirely the middle of one that started earlier - because such a frame has
 * nothing of its own to report, and the reference does not label it either.
 */
export function dissectBgp(
  bytes: Uint8Array, start: number, end: number, state: BgpDirectionState,
): BgpResult | null {
  const messages: OneMessage[] = [];
  let offset = start;

  // A body carried over from an earlier segment. Its type came with it,
  // because the frame that completes a message is the one that names it.
  if (state.owed > 0) {
    const available = end - offset;
    if (state.owed > available) {
      state.owed -= available;
      return null;
    }
    offset += state.owed;
    state.owed = 0;
    messages.push({
      info: infoFor(state.owedType),
      // No byte ranges: this message is mostly bytes that are not in this
      // frame's hex dump, the rule IP fragment reassembly already follows.
      rows: [{ name: 'Type', value: `${typeName(state.owedType)} (${state.owedType})`, abbrev: 'bgp.type' }],
      fields: { 'bgp.type': state.owedType },
    });
  }

  for (;;) {
    const carried = state.header.length;
    // Not even a whole header, counting what the last segment left behind.
    if (end - offset + carried < HEADER_LENGTH) {
      for (let i = offset; i < end; i++) state.header.push(bytes[i]);
      break;
    }

    const split = carried > 0;
    const head: ArrayLike<number> = split
      ? [...state.header, ...bytes.subarray(offset, offset + HEADER_LENGTH - carried)]
      : bytes.subarray(offset, offset + HEADER_LENGTH);
    if (!hasMarker(head, 0)) break;

    const declared = (head[MARKER_LENGTH] << 8) | head[MARKER_LENGTH + 1];
    const type = head[HEADER_LENGTH - 1];
    // A length below the header's own size cannot be honoured: advancing by it
    // would not move forward, so the loop would never end. The reference calls
    // such a message malformed and stops too.
    if (declared < HEADER_LENGTH) break;

    state.header.length = 0;
    const bodyStart = offset + HEADER_LENGTH - carried;
    const bodyEnd = bodyStart + (declared - HEADER_LENGTH);
    if (bodyEnd > end) {
      state.owed = bodyEnd - end;
      state.owedType = type;
      break;
    }

    const fields: Record<string, string | number> = { 'bgp.type': type, 'bgp.length': declared };
    const rows = split
      // A header spanning two segments has no coherent range in either.
      ? [
          { name: 'Length', value: declared, abbrev: 'bgp.length' },
          { name: 'Type', value: `${typeName(type)} (${type})`, abbrev: 'bgp.type' },
        ]
      : headerRows(offset, declared, type);
    messages.push({
      info: infoFor(type),
      rows: [...rows, ...bodyRows(bytes, bodyStart, bodyEnd, type, fields)],
      fields,
    });
    offset = bodyEnd;
  }

  if (messages.length === 0) return null;

  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  for (const [index, message] of messages.entries()) {
    Object.assign(fields, message.fields);
    rows.push({
      name: messages.length === 1 ? 'Border Gateway Protocol' : `Border Gateway Protocol ${index + 1}`,
      value: '', children: message.rows,
    });
  }
  return {
    info: messages.map((m) => m.info).join(', '),
    fields,
    layer: {
      name: 'Border Gateway Protocol',
      summary: messages.length === 1
        ? `Border Gateway Protocol, ${messages[0].info}`
        : `Border Gateway Protocol (${messages.length} messages)`,
      fields: rows,
    },
  };
}
