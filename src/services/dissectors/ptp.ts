/**
 * PTP / IEEE 1588-2019, UDP 319 (event) and 320 (general).
 *
 *   Sync Message
 *   Announce Message
 *
 * The protocol that synchronises clocks to well under a microsecond, which is
 * why it exists in broadcast plants, trading floors, power substations and
 * industrial control - anywhere the *order* of events across machines is the
 * measurement. NTP gets a network to within milliseconds; PTP is three orders
 * of magnitude tighter, and it buys that with hardware timestamping at the
 * port, which is exactly what a packet capture can see going wrong.
 *
 * The split across two ports is the design and not an accident: **event**
 * messages (Sync, Delay_Req, and the peer-delay pair) are the ones whose
 * transmission instant is timestamped in hardware, and they go to 319 alone.
 * Everything else - the Follow_Up carrying the timestamp a one-step clock did
 * not need, Announce carrying the grandmaster's quality - is general and goes
 * to 320. A capture showing event messages arriving late relative to their
 * Follow_Up is a capture of the thing PTP was deployed to prevent.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface PtpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** IEEE 1588 Table 19. The low nibble of the first byte. */
const MESSAGE_TYPES: Record<number, string> = {
  0x0: 'Sync',
  0x1: 'Delay_Req',
  // Spelt out, as the reference analyzer spells them - IEEE 1588 abbreviates
  // these three to `Pdelay_*` and Wireshark does not.
  0x2: 'Peer_Delay_Req',
  0x3: 'Peer_Delay_Resp',
  0x8: 'Follow_Up',
  0x9: 'Delay_Resp',
  0xa: 'Peer_Delay_Resp_Follow_Up',
  0xb: 'Announce',
  0xc: 'Signaling',
  0xd: 'Management',
};

/** Messages whose send time is captured in hardware; these ride port 319. */
const EVENT_MESSAGES = new Set([0x0, 0x1, 0x2, 0x3]);

/** The common header every message carries. */
const HEADER_BYTES = 34;

const MANAGEMENT = 0x0d;

/**
 * A Management message's body: the fields between the common header and the
 * TLV that carries the actual request.
 */
const MANAGEMENT_ACTION_OFFSET = HEADER_BYTES + 12;
const MANAGEMENT_TLV_OFFSET = HEADER_BYTES + 14;

const MANAGEMENT_ACTIONS: Record<number, string> = {
  0: 'GET', 1: 'SET', 2: 'RESPONSE', 3: 'COMMAND', 4: 'ACKNOWLEDGE',
};

/**
 * What a Management message is asking about (IEEE 1588 Table 40).
 *
 * The capitalisation is the reference analyzer's and is not the standard's -
 * the spec writes `SAVE_IN_NON_VOLATILE_STORAGE` and Wireshark writes
 * `Save in non volatile storage`. Every entry here was read back from tshark
 * one id at a time rather than transliterated from the table, because that
 * transformation is not mechanical: `Default dataset` for DEFAULT_DATA_SET
 * loses a word boundary the standard has, and `Priority 1` gains one.
 */
const MANAGEMENT_IDS: Record<number, string> = {
  0x0000: 'Null management',
  0x0001: 'Clock description',
  0x0002: 'User description',
  0x0003: 'Save in non volatile storage',
  0x0004: 'Reset non volatile storage',
  0x0005: 'Initialize',
  0x0006: 'Fault log',
  0x0007: 'Fault log reset',
  0x2000: 'Default dataset',
  0x2001: 'Current dataset',
  0x2002: 'Parent dataset',
  0x2003: 'Time properties dataset',
  0x2004: 'Port dataset',
  0x2005: 'Priority 1',
  0x2006: 'Priority 2',
  0x2007: 'Domain',
  0x2008: 'Slave only',
  0x2009: 'Log announce interval',
  0x200a: 'Announce receipt timeout',
  0x200b: 'Log sync interval',
  0x200c: 'Version number',
  0x200d: 'Enable port',
  0x200e: 'Disable port',
  0x200f: 'Time',
  0x2010: 'Clock accuracy',
  0x2011: 'UTC properties',
  0x2012: 'Traceability properties',
  0x2013: 'Timescale properties',
  0x2014: 'Unicast negotiation enable',
  0x2015: 'Path trace list',
  0x2016: 'Path trace enable',
  0x4000: 'Transparent clock default dataset',
  0x4001: 'Transparent clock port dataset',
  0x4002: 'Primary domain',
  0x6000: 'Delay mechanism',
};

/** IEEE 1588 §7.6.2.5 - the coarse quality class of a grandmaster's clock. */
function clockClass(value: number): string {
  if (value === 6) return 'Primary reference (6)';
  if (value === 7) return 'Primary reference, holdover (7)';
  if (value === 13) return 'Application-specific (13)';
  if (value === 52 || value === 187) return `Degraded reference (${value})`;
  if (value === 248) return 'Default (248)';
  if (value === 255) return 'Slave-only (255)';
  return `${value}`;
}

/** A clock identity is an EUI-64, written as eight colon-separated bytes. */
function clockIdentity(bytes: Uint8Array, at: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) parts.push(bytes[at + i].toString(16).padStart(2, '0'));
  return parts.join(':');
}

export function dissectPtp(bytes: Uint8Array, start: number, end: number): PtpResult | null {
  if (start + HEADER_BYTES > end) return null;

  const messageType = bytes[start] & 0x0f;
  const typeName = MESSAGE_TYPES[messageType];
  if (typeName === undefined) return null;
  // The high nibble of byte 1 is the minor version; the low nibble is the
  // version, and only 2 has ever been deployed.
  const version = bytes[start + 1] & 0x0f;
  if (version !== 2) return null;
  const messageLength = (bytes[start + 2] << 8) | bytes[start + 3];
  // The header declares the message's own size. That is the check that makes
  // this specific enough to read, since the type nibble alone is not.
  if (messageLength < HEADER_BYTES || start + messageLength > end) return null;

  const domain = bytes[start + 4];
  const flags = (bytes[start + 6] << 8) | bytes[start + 7];
  const sequenceId = (bytes[start + 30] << 8) | bytes[start + 31];
  const sourceClock = clockIdentity(bytes, start + 20);
  const sourcePort = (bytes[start + 28] << 8) | bytes[start + 29];
  const logInterval = (bytes[start + 33] << 24) >> 24;   // signed byte

  const fields: Record<string, string | number> = {
    'ptp.v2.messagetype': messageType,
    'ptp.v2.versionptp': version,
    'ptp.v2.messagelength': messageLength,
    'ptp.v2.domainnumber': domain,
    'ptp.v2.flags': flags,
    'ptp.v2.sequenceid': sequenceId,
    'ptp.v2.sourceportid': sourcePort,
    'ptp.v2.clockidentity': sourceClock,
    'ptp.v2.logmessageperiod': logInterval,
  };

  const rows: ProtocolField[] = [
    { name: 'messageType', value: `${typeName} Message (0x${messageType.toString(16)})`,
      abbrev: 'ptp.v2.messagetype', rawBytesRange: [start, start] },
    { name: 'versionPTP', value: version, abbrev: 'ptp.v2.versionptp',
      rawBytesRange: [start + 1, start + 1] },
    { name: 'messageLength', value: messageLength, abbrev: 'ptp.v2.messagelength',
      rawBytesRange: [start + 2, start + 3] },
    { name: 'domainNumber', value: domain, abbrev: 'ptp.v2.domainnumber',
      rawBytesRange: [start + 4, start + 4] },
    { name: 'flags', value: `0x${flags.toString(16).padStart(4, '0')}`, abbrev: 'ptp.v2.flags',
      rawBytesRange: [start + 6, start + 7],
      children: [
        // The two that change how the rest of the exchange is read: a two-step
        // clock's Sync carries no usable timestamp and the Follow_Up does.
        { name: 'PTP_TWO_STEP', value: (flags & 0x0200) !== 0 ? 'True' : 'False' },
        { name: 'PTP_UNICAST', value: (flags & 0x0400) !== 0 ? 'True' : 'False' },
        { name: 'PTP_LI_61', value: (flags & 0x0001) !== 0 ? 'True' : 'False' },
        { name: 'PTP_LI_59', value: (flags & 0x0002) !== 0 ? 'True' : 'False' },
      ] },
    { name: 'sourcePortIdentity', value: `${sourceClock}/${sourcePort}`,
      abbrev: 'ptp.v2.clockidentity', rawBytesRange: [start + 20, start + 29] },
    { name: 'sequenceId', value: sequenceId, abbrev: 'ptp.v2.sequenceid',
      rawBytesRange: [start + 30, start + 31] },
    { name: 'logMessageInterval', value: logInterval, abbrev: 'ptp.v2.logmessageperiod',
      rawBytesRange: [start + 33, start + 33] },
    { name: '[Message class]', value: EVENT_MESSAGES.has(messageType) ? 'Event' : 'General',
      generated: true },
  ];

  // An Announce carries the grandmaster's quality, which is the whole content
  // of the best-master election - who wins, and how good the winner is.
  if (messageType === 0x0b && start + 64 <= end) {
    const grandmasterClass = bytes[start + 47];
    const grandmasterIdentity = clockIdentity(bytes, start + 53);
    const stepsRemoved = (bytes[start + 61] << 8) | bytes[start + 62];
    fields['ptp.v2.an.grandmasterclockclass'] = grandmasterClass;
    fields['ptp.v2.an.grandmasterclockidentity'] = grandmasterIdentity;
    fields['ptp.v2.an.localstepsremoved'] = stepsRemoved;
    rows.push(
      { name: 'grandmasterClockClass', value: clockClass(grandmasterClass),
        abbrev: 'ptp.v2.an.grandmasterclockclass', rawBytesRange: [start + 47, start + 47] },
      { name: 'grandmasterClockIdentity', value: grandmasterIdentity,
        abbrev: 'ptp.v2.an.grandmasterclockidentity', rawBytesRange: [start + 53, start + 60] },
      { name: 'stepsRemoved', value: stepsRemoved, abbrev: 'ptp.v2.an.localstepsremoved',
        rawBytesRange: [start + 61, start + 62] },
    );
  }

  // Management is the one message with an Info grammar of its own: it names
  // what is being asked about and what is being done to it, rather than
  // repeating its own type. `Management Message` would say nothing at all -
  // every management frame in a capture would read identically.
  let info = `${typeName} Message`;
  if (messageType === MANAGEMENT && start + MANAGEMENT_TLV_OFFSET + 6 <= end) {
    const action = bytes[start + MANAGEMENT_ACTION_OFFSET] & 0x0f;
    const managementId = (bytes[start + MANAGEMENT_TLV_OFFSET + 4] << 8)
      | bytes[start + MANAGEMENT_TLV_OFFSET + 5];
    // An unknown id is reported in decimal, which is the reference analyzer's
    // choice and reads oddly beside a table written in hex - copied anyway,
    // because the Info column is the contract.
    const idName = MANAGEMENT_IDS[managementId] ?? `Unknown management Id ${managementId}`;
    const actionName = MANAGEMENT_ACTIONS[action] ?? `Unknown Action ${action}`;
    fields['ptp.v2.mm.managementId'] = managementId;
    fields['ptp.v2.mm.action'] = action;
    rows.push(
      { name: 'actionField', value: actionName, abbrev: 'ptp.v2.mm.action',
        rawBytesRange: [start + MANAGEMENT_ACTION_OFFSET, start + MANAGEMENT_ACTION_OFFSET] },
      { name: 'managementId', value: `${idName} (0x${managementId.toString(16).padStart(4, '0')})`,
        abbrev: 'ptp.v2.mm.managementId',
        rawBytesRange: [start + MANAGEMENT_TLV_OFFSET + 4, start + MANAGEMENT_TLV_OFFSET + 5] },
    );
    info = `Management (${idName}) ${actionName}`;
  }

  return {
    protocolLabel: 'PTPv2',
    info,
    fields,
    layer: {
      name: 'Precision Time Protocol (IEEE1588)',
      summary: `Precision Time Protocol (IEEE1588), ${typeName} Message`,
      rawBytesRange: [start, start + messageLength - 1],
      fields: rows,
    },
  };
}
