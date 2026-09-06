/**
 * Syslog over UDP 514 (RFC 3164, and RFC 5424's newer framing).
 *
 *   AUTH.CRIT: Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
 *   USER.INFO: Jan  1 00:00:00 host app: hello
 *
 * A capture that contains syslog was usually taken *because* something logged,
 * so the message is often the reason the capture exists - and it was reaching
 * the packet list as `50000 → 514 Len=76`.
 *
 * The whole protocol on the wire is one line of text with a priority in angle
 * brackets at the front. `<34>` is not a number anyone reads directly: it is
 * `facility * 8 + severity`, so 34 is AUTH (4) at CRIT (2). Splitting it is the
 * dissector's entire job, and it is the difference between "a router said
 * something" and "a router said something CRITICAL".
 *
 * The two RFCs differ in what follows the priority - 3164 has a bare timestamp
 * and host, 5424 has a version digit, an ISO timestamp and structured data -
 * and Wireshark's Info column shows neither. It shows `FACILITY.SEVERITY:` and
 * then the rest of the line verbatim, which is what this does; the structured
 * halves are tree rows.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface SyslogResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 3164 §4.1.1, and the names Wireshark prints in the Info column. */
const FACILITIES = [
  'KERN', 'USER', 'MAIL', 'DAEMON', 'AUTH', 'SYSLOG', 'LPR', 'NEWS',
  'UUCP', 'CRON', 'AUTHPRIV', 'FTP', 'NTP', 'AUDIT', 'ALERT', 'CLOCK',
  'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7',
];

const SEVERITIES = ['EMERG', 'ALERT', 'CRIT', 'ERR', 'WARN', 'NOTICE', 'INFO', 'DEBUG'];

/** The long forms, for the tree. Wireshark writes these out in full. */
const FACILITY_LABELS = [
  'KERN - kernel messages', 'USER - random user-level messages',
  'MAIL - mail system', 'DAEMON - system daemons',
  'AUTH - security/authorization messages', 'SYSLOG - messages generated internally by syslogd',
  'LPR - line printer subsystem', 'NEWS - network news subsystem',
  'UUCP - UUCP subsystem', 'CRON - clock daemon',
  'AUTHPRIV - security/authorization messages', 'FTP - ftp daemon',
  'NTP - NTP subsystem', 'AUDIT - log audit', 'ALERT - log alert', 'CLOCK - clock daemon',
  'LOCAL0 - local use 0', 'LOCAL1 - local use 1', 'LOCAL2 - local use 2', 'LOCAL3 - local use 3',
  'LOCAL4 - local use 4', 'LOCAL5 - local use 5', 'LOCAL6 - local use 6', 'LOCAL7 - local use 7',
];

const SEVERITY_LABELS = [
  'EMERG - system is unusable', 'ALERT - action must be taken immediately',
  'CRIT - critical conditions', 'ERR - error conditions',
  'WARN - warning conditions', 'NOTICE - normal but significant condition',
  'INFO - informational', 'DEBUG - debug-level messages',
];

// One decoder, at module scope. A `new TextDecoder` per call is the allocation
// `scripts/perf/hot-path-allocations.ts` exists to prevent.
const utf8 = new TextDecoder('utf-8', { fatal: false });

/**
 * True when these bytes open with a syslog priority.
 *
 * `<` then one to three digits then `>`, and the value must be in range. That
 * is a narrow test but not a unique one - it would also accept an XML tag
 * beginning `<12>` - so this is offered to the heuristic path only after the
 * port-keyed dissectors have declined, never as a first guess.
 */
export function looksLikeSyslog(bytes: Uint8Array, start: number, end: number): boolean {
  return readPriority(bytes, start, end) !== null;
}

function readPriority(bytes: Uint8Array, start: number, end: number): { value: number; after: number } | null {
  if (start >= end || bytes[start] !== 0x3c /* < */) return null;
  let p = start + 1;
  let value = 0;
  let digits = 0;
  while (p < end && bytes[p] >= 0x30 && bytes[p] <= 0x39 && digits < 3) {
    value = value * 10 + (bytes[p] - 0x30);
    p++; digits++;
  }
  if (digits === 0 || p >= end || bytes[p] !== 0x3e /* > */) return null;
  // 23 facilities * 8 + 7 = 191 is the largest legal priority.
  if (value > 191) return null;
  return { value, after: p + 1 };
}

export function dissectSyslog(bytes: Uint8Array, start: number, end: number): SyslogResult | null {
  const priority = readPriority(bytes, start, end);
  if (priority === null) return null;

  const facility = priority.value >> 3;
  const severity = priority.value & 0x07;
  const message = utf8.decode(bytes.subarray(priority.after, end));

  const fields: Record<string, string | number> = {
    'syslog.priority': priority.value,
    'syslog.facility': facility,
    'syslog.level': severity,
    'syslog.msg': message,
  };

  const layerFields: ProtocolField[] = [
    {
      name: 'Priority',
      value: priority.value,
      abbrev: 'syslog.priority',
      rawBytesRange: [start, priority.after - 1],
      children: [
        { name: 'Facility', value: `${FACILITY_LABELS[facility] ?? `Unknown (${facility})`} (${facility})`,
          abbrev: 'syslog.facility' },
        { name: 'Level', value: `${SEVERITY_LABELS[severity] ?? `Unknown (${severity})`} (${severity})`,
          abbrev: 'syslog.level' },
      ],
    },
    { name: 'Message', value: message, abbrev: 'syslog.msg',
      rawBytesRange: [priority.after, Math.max(priority.after, end - 1)] },
  ];

  return {
    protocolLabel: 'Syslog',
    info: `${FACILITIES[facility] ?? facility}.${SEVERITIES[severity] ?? severity}: ${message}`,
    fields,
    layer: {
      name: 'Syslog message',
      summary: `Syslog message: ${FACILITIES[facility] ?? facility}.${SEVERITIES[severity] ?? severity}`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: layerFields,
    },
  };
}
