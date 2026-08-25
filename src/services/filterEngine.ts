import { Packet, FilterPreset } from '../types/packet';
import { addressInCidr } from './addressFormat';

export const DEFAULT_FILTER_PRESETS: FilterPreset[] = [
  {
    id: 'all',
    name: 'All Traffic',
    filter: '',
    category: 'Custom',
    description: 'Show all captured network packets without filtering',
  },
  {
    id: 'web-traffic',
    name: 'Web (HTTP/HTTPS/TLS)',
    filter: 'http || tls || tcp.port == 443 || tcp.port == 80',
    category: 'Web',
    description: 'Hypertext and Transport Layer Security web traffic',
  },
  {
    id: 'dns-queries',
    name: 'DNS Resolution',
    filter: 'dns || udp.port == 53',
    category: 'Web',
    description: 'Domain Name System queries, responses, and records',
  },
  {
    id: 'threats-anomalies',
    name: 'Security Anomalies & Alerts',
    filter: 'status == alert || status == warning || anomaly',
    category: 'Security',
    description: 'SYN floods, port scans, DNS tunneling, and IDS triggers',
  },
  {
    id: 'syn-handshakes',
    name: 'TCP Handshakes (SYN/FIN)',
    filter: 'info contains "SYN" || info contains "FIN"',
    category: 'Troubleshooting',
    description: 'Connection initiation and termination frames',
  },
  {
    id: 'high-bandwidth',
    name: 'Large Payloads (> 1000B)',
    filter: 'len > 1000',
    category: 'Troubleshooting',
    description: 'Jumbo frames and high-throughput data segments',
  },
  {
    id: 'custom-dissector',
    name: 'Custom Plugins (IoT / Fast)',
    filter: 'proto_iot || finfast || port == 18833',
    category: 'Custom',
    description: 'Frames processed by custom dissector engine',
  },
  {
    id: 'mqtt-telemetry',
    name: 'IoT MQTT Traffic',
    filter: 'mqtt || tcp.port == 1883',
    category: 'Web',
    description: 'Message Queuing Telemetry Transport broker streams',
  },
];

export interface FilterValidationResult {
  isValid: boolean;
  errorMessage?: string;
  matchedCount?: number;
}

export class FilterEngine {
  /**
   * Evaluates a display filter expression against a list of packets
   */
  public static filterPackets(packets: Packet[], filterString: string): Packet[] {
    const trimmed = filterString.trim();
    if (!trimmed) return packets;

    try {
      const matcher = FilterEngine.compileFilter(trimmed);
      return packets.filter(packet => {
        try {
          return matcher(packet);
        } catch {
          return false;
        }
      });
    } catch {
      // Fallback simple search if syntax parse fails
      const lower = trimmed.toLowerCase();
      return packets.filter(
        p =>
          p.protocol.toLowerCase().includes(lower) ||
          p.source.toLowerCase().includes(lower) ||
          p.destination.toLowerCase().includes(lower) ||
          p.info.toLowerCase().includes(lower) ||
          p.status.toLowerCase().includes(lower)
      );
    }
  }

  /**
   * Validate filter syntax without throwing
   */
  public static validateFilter(filterString: string): FilterValidationResult {
    const trimmed = filterString.trim();
    if (!trimmed) return { isValid: true };

    try {
      FilterEngine.compileFilter(trimmed);
    } catch (e: any) {
      return {
        isValid: false,
        errorMessage: e.message || 'Invalid filter expression',
      };
    }

    // Syntax alone can't catch a typo'd field name (e.g. "tc.port == 80") -
    // the runtime evaluator is deliberately lenient about unknown fields
    // (falls through to "no match" rather than throwing), so this second
    // pass is the only thing that surfaces it to the user.
    let normalized = trimmed;
    normalized = normalized.replace(/\band\b/gi, '&&');
    normalized = normalized.replace(/\bor\b/gi, '||');
    normalized = normalized.replace(/\bnot\b/gi, '!');
    const semanticError = checkFilterSemantics(normalized);
    if (semanticError) {
      return { isValid: false, errorMessage: semanticError };
    }

    return { isValid: true };
  }

  /**
   * Compiles filter string into a fast predicate function
   */
  public static compileFilter(filterStr: string): (p: Packet) => boolean {
    let expr = filterStr.trim();

    // Standardize boolean keywords
    expr = expr.replace(/\band\b/gi, '&&');
    expr = expr.replace(/\bor\b/gi, '||');
    expr = expr.replace(/\bnot\b/gi, '!');

    // Tokens parsing
    return (packet: Packet): boolean => {
      return evaluateComplexExpression(expr, packet);
    };
  }

  /**
   * Provide autocomplete suggestions based on current cursor text
   */
  public static getSuggestions(input: string): string[] {
    const keywords = [
      'ip.src == ',
      'ip.dst == ',
      'ip.addr == ',
      'tcp.port == 443',
      'tcp.port == 80',
      'udp.port == 53',
      'port == ',
      'proto == http',
      'proto == tls',
      'proto == dns',
      'proto == tcp',
      'proto == udp',
      'proto == mqtt',
      'proto == icmp',
      'proto == arp',
      'len > 1000',
      'len < 100',
      'status == alert',
      'status == warning',
      'info contains "SYN"',
      'info contains "GET"',
      'anomaly',
      'stream == 1',
    ];

    const currentToken = input.split(/[\s(&|)]+/).pop()?.toLowerCase() || '';
    if (!currentToken) return keywords.slice(0, 8);

    return keywords.filter(k => k.toLowerCase().includes(currentToken));
  }
}

// Every field name handled by the `field op value` branch in
// evaluateAtomicCondition below - kept in sync with that switch so
// validateFilter can flag a typo'd/unknown field before the user hits Apply.
const KNOWN_FIELD_NAMES = new Set([
  'ip.src', 'src', 'ip.dst', 'dst', 'ip.addr', 'ip', 'addr',
  'tcp.port', 'udp.port', 'port',
  'tcp.srcport', 'udp.srcport', 'srcport',
  'tcp.dstport', 'udp.dstport', 'dstport',
  'protocol', 'proto',
  'len', 'length', 'frame.len', 'frame.number',
  'status',
  'stream', 'tcp.stream',
  'info',
  'anomaly.severity',
  // Fields the dissectors publish into Packet.fields. These resolve through
  // the generic lookup rather than the switch, but still need naming here so
  // a filter that uses them isn't reported as a typo.
  'ip.ttl', 'ip.proto',
  'ipv6.src', 'ipv6.dst', 'ipv6.hlim', 'ipv6.nxt',
  'tcp.flags', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.flags.reset',
  'tcp.flags.push', 'tcp.flags.ack', 'tcp.window_size', 'tcp.len',
  'udp.length',
  'icmp.type', 'icmp.code', 'icmpv6.type', 'icmpv6.code',
  'arp.opcode', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4',
  'arp.src.hw_mac', 'arp.dst.hw_mac',
  'stp.type', 'stp.version', 'stp.root.cost', 'stp.port',
  'ieee1905.message.type', 'ieee1905.message.id',
]);

function checkFilterSemantics(expr: string): string | null {
  if (expr.includes('||')) {
    const orParts = splitTopLevel(expr, '||');
    if (orParts.length > 1) {
      for (const part of orParts) {
        const err = checkFilterSemantics(part.trim());
        if (err) return err;
      }
      return null;
    }
  }

  if (expr.includes('&&')) {
    const andParts = splitTopLevel(expr, '&&');
    if (andParts.length > 1) {
      for (const part of andParts) {
        const err = checkFilterSemantics(part.trim());
        if (err) return err;
      }
      return null;
    }
  }

  const trimmed = expr.trim();
  if (trimmed.startsWith('!')) {
    return checkFilterSemantics(trimmed.slice(1).trim());
  }

  if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
    return checkFilterSemantics(trimmed.slice(1, -1));
  }

  return checkAtomicSemantics(trimmed);
}

function checkAtomicSemantics(cond: string): string | null {
  const c = cond.trim();
  if (!c) return null;

  // `info contains "something"` - not a field comparison, always valid.
  if (/^info\s+(?:contains|matches|icontains)\s+["']?[^"']+["']?$/i.test(c)) return null;

  const compMatch = c.match(/^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<|=)\s*["']?([^"']+)["']?$/);
  if (!compMatch) {
    // A bareword with no comparison operator is either a known protocol
    // keyword (e.g. "dns") or an intentional free-text substring search -
    // both are valid at runtime, so there's nothing to flag here.
    return null;
  }

  const field = compMatch[1].toLowerCase();
  return KNOWN_FIELD_NAMES.has(field) ? null : `Unknown field "${compMatch[1]}" in filter expression`;
}

function evaluateComplexExpression(expr: string, packet: Packet): boolean {
  // Support OR clauses
  if (expr.includes('||')) {
    const orParts = splitTopLevel(expr, '||');
    if (orParts.length > 1) {
      return orParts.some(part => evaluateComplexExpression(part.trim(), packet));
    }
  }

  // Support AND clauses
  if (expr.includes('&&')) {
    const andParts = splitTopLevel(expr, '&&');
    if (andParts.length > 1) {
      return andParts.every(part => evaluateComplexExpression(part.trim(), packet));
    }
  }

  // Support NOT clause
  const trimmed = expr.trim();
  if (trimmed.startsWith('!')) {
    return !evaluateComplexExpression(trimmed.slice(1).trim(), packet);
  }

  // Parentheses stripping if outer
  if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
    return evaluateComplexExpression(trimmed.slice(1, -1), packet);
  }

  return evaluateAtomicCondition(trimmed, packet);
}

function splitTopLevel(str: string, delimiter: string): string[] {
  const result: string[] = [];
  let depth = 0;
  let current = '';
  let i = 0;

  while (i < str.length) {
    if (str[i] === '(') depth++;
    else if (str[i] === ')') depth--;

    if (depth === 0 && str.startsWith(delimiter, i)) {
      result.push(current);
      current = '';
      i += delimiter.length;
      continue;
    }

    current += str[i];
    i++;
  }

  result.push(current);
  return result;
}

/**
 * Protocols that show up as dissected layers in Packet.frameProtocols. For
 * these, presence is decided by what the frame actually contains rather than
 * by its top-most protocol name: a TLSv1.2 frame must satisfy `tcp`, and a
 * frame whose transport layer failed to dissect must not, which the single
 * top-most name can't express.
 */
const LAYER_PROTOCOL_NAMES = new Set([
  'frame', 'eth', 'vlan', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'arp', 'stp', 'ieee1905',
]);

/** Reads a numeric literal in decimal or 0x-prefixed hex. */
function parseNumericLiteral(text: string): number | null {
  const trimmed = text.trim();
  if (/^0x[0-9a-f]+$/i.test(trimmed)) return parseInt(trimmed.slice(2), 16);
  if (/^-?\d+$/.test(trimmed)) return Number(trimmed);
  return null;
}

/**
 * Expands a display-filter set literal - "{ 3..5, 11 }" or "{1, 64, 255}" -
 * into the numbers it contains. Wireshark's `in` operator accepts both bare
 * values and inclusive ranges in the same braces.
 */
function parseSetLiteral(text: string): number[] | null {
  const body = text.trim().replace(/^\{/, '').replace(/\}$/, '');
  const values: number[] = [];
  for (const entry of body.split(',')) {
    const range = entry.trim().match(/^(\S+)\s*\.\.\s*(\S+)$/);
    if (range) {
      const from = parseNumericLiteral(range[1]);
      const to = parseNumericLiteral(range[2]);
      if (from === null || to === null || to < from || to - from > 65535) return null;
      for (let v = from; v <= to; v++) values.push(v);
    } else {
      const value = parseNumericLiteral(entry);
      if (value === null) return null;
      values.push(value);
    }
  }
  return values.length > 0 ? values : null;
}

/**
 * Resolves a field name to its dissected value, checking the generic field bag
 * the dissectors populate before falling back to the shaped Packet properties.
 * Returns undefined when the frame simply doesn't carry the field, which a
 * filter must treat as "no match" rather than as an error.
 */
function lookupField(field: string, packet: Packet): string | number | undefined {
  const fromDissector = packet.fields?.[field];
  if (fromDissector !== undefined) return fromDissector;

  switch (field) {
    case 'frame.len': case 'len': case 'length': return packet.length;
    case 'frame.number': return packet.id;
    case 'ip.src': case 'ipv6.src': case 'src': return packet.source;
    case 'ip.dst': case 'ipv6.dst': case 'dst': return packet.destination;
    case 'info': return packet.info;
    case 'status': return packet.status;
    case 'protocol': case 'proto': return packet.protocolLabel ?? packet.protocol;
    case 'tcp.stream': case 'stream': return packet.streamId;
    default: return undefined;
  }
}

function evaluateAtomicCondition(cond: string, packet: Packet): boolean {
  const c = cond.trim();
  if (!c) return true;

  // Single keyword checks (e.g. "http", "dns", "tls", "anomaly")
  const lower = c.toLowerCase();

  // Layer presence, decided from what the frame actually contains.
  if (LAYER_PROTOCOL_NAMES.has(lower)) {
    return packet.frameProtocols?.includes(lower)
      // Packets from sources that don't record layers (the metadata-only
      // agent fallback) still answer from their top-most protocol name.
      ?? packet.protocol.toLowerCase() === lower;
  }

  // A bare "tcp.analysis.flags" asks whether *any* analysis flag fired;
  // a bare "tcp.analysis.retransmission" asks about that one specifically.
  if (lower.startsWith('tcp.analysis.')) {
    const flags = packet.analysisFlags ?? [];
    const which = lower.slice('tcp.analysis.'.length);
    return which === 'flags' ? flags.length > 0 : flags.includes(which);
  }

  // Byte-slice bitmask, as in Broadcast's "eth[0] & 1" - the low bit of the
  // first destination-MAC byte is the multicast bit.
  const byteSliceMatch = c.match(/^eth\[(\d+)\]\s*&\s*(\S+)$/i);
  if (byteSliceMatch) {
    const index = Number(byteSliceMatch[1]);
    const mask = parseNumericLiteral(byteSliceMatch[2]);
    if (mask === null || index >= packet.rawBytes.length) return false;
    return (packet.rawBytes[index] & mask) !== 0;
  }

  // Bitmask test on a named field, as in TCP SYN/FIN's "tcp.flags & 0x02".
  const bitmaskMatch = c.match(/^([a-z0-9_.]+)\s*&\s*(\S+)$/i);
  if (bitmaskMatch) {
    const value = lookupField(bitmaskMatch[1].toLowerCase(), packet);
    const mask = parseNumericLiteral(bitmaskMatch[2]);
    if (typeof value !== 'number' || mask === null) return false;
    return (value & mask) !== 0;
  }

  // Set membership: "icmp.type in { 3..5, 11 }" and its negation.
  const setMatch = c.match(/^([a-z0-9_.]+)\s+(not\s+in|in)\s*(\{.*\})$/i);
  if (setMatch) {
    const value = lookupField(setMatch[1].toLowerCase(), packet);
    const set = parseSetLiteral(setMatch[3]);
    if (set === null) return false;
    const negated = /not/i.test(setMatch[2]);
    // A field the frame doesn't carry is not in the set, and equally is not
    // "not in" it - an absent field never matches either way.
    if (typeof value !== 'number') return false;
    return negated ? !set.includes(value) : set.includes(value);
  }

  if (lower === 'http') return packet.protocol === 'HTTP';
  if (lower === 'https') return packet.protocol === 'HTTPS';
  if (lower === 'tls') return packet.protocol === 'TLS' || packet.protocol === 'HTTPS';
  if (lower === 'dns') return packet.protocol === 'DNS';
  if (lower === 'tcp') return packet.protocol === 'TCP';
  if (lower === 'udp') return packet.protocol === 'UDP';
  if (lower === 'icmp') return packet.protocol === 'ICMP';
  if (lower === 'arp') return packet.protocol === 'ARP';
  if (lower === 'mqtt') return packet.protocol === 'MQTT';
  if (lower === 'ssh') return packet.protocol === 'SSH';
  if (lower === 'quic') return packet.protocol === 'QUIC';
  if (lower === 'anomaly') return (!!packet.anomalies && packet.anomalies.length > 0) || packet.status === 'alert';
  if (lower === 'proto_iot') return packet.protocol === 'CUSTOM' || packet.info.includes('Proto-IoT');
  if (lower === 'finfast') return packet.protocol === 'CUSTOM' || packet.info.includes('FinFast');

  // `info contains "something"`
  const containsMatch = c.match(/^info\s+(?:contains|matches|icontains)\s+["']?([^"']+)["']?$/i);
  if (containsMatch) {
    return packet.info.toLowerCase().includes(containsMatch[1].toLowerCase());
  }

  // Operator comparisons. Wireshark accepts both symbolic and worded
  // operators ("tcp.flags.reset eq 1"), so the worded ones are normalized to
  // their symbols before matching.
  const normalized = c.replace(/\s+(eq|ne|gt|lt|ge|le)\s+/gi, (_, word: string) => {
    const symbols: Record<string, string> = { eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=' };
    return ` ${symbols[word.toLowerCase()]} `;
  });
  const compMatch = normalized.match(/^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<|=)\s*["']?([^"']+)["']?$/);
  if (!compMatch) {
    // Fallback: substring search in packet summary
    return (
      packet.protocol.toLowerCase().includes(lower) ||
      packet.source.toLowerCase().includes(lower) ||
      packet.destination.toLowerCase().includes(lower) ||
      packet.info.toLowerCase().includes(lower)
    );
  }

  const [, rawField, op, rawVal] = compMatch;
  const field = rawField.toLowerCase();
  const val = rawVal.trim();
  const numVal = Number(val);
  const isNumeric = !isNaN(numVal);

  // A CIDR on the right-hand side compares networks, not text. This has to be
  // decided before the switch below, because the address cases there would
  // otherwise treat "224.0.0.0/4" as a literal string - making
  // "ip.dst != 224.0.0.0/4" true for every multicast address, the exact
  // opposite of what it means.
  if (val.includes('/') && /^\d|^[0-9a-f]*:/i.test(val)) {
    const address = lookupField(field, packet);
    if (typeof address !== 'string') return false;
    const inside = addressInCidr(address, val);
    return op === '!=' ? !inside : inside;
  }

  switch (field) {
    case 'ip.src':
    case 'src':
      return compareStrings(packet.source, val, op);

    case 'ip.dst':
    case 'dst':
      return compareStrings(packet.destination, val, op);

    case 'ip.addr':
    case 'ip':
    case 'addr':
      return (
        compareStrings(packet.source, val, op) ||
        compareStrings(packet.destination, val, op)
      );

    case 'tcp.port':
    case 'udp.port':
    case 'port': {
      const srcPortMatch = packet.sourcePort !== undefined && compareNumbers(packet.sourcePort, numVal, op);
      const dstPortMatch = packet.destPort !== undefined && compareNumbers(packet.destPort, numVal, op);
      return srcPortMatch || dstPortMatch;
    }

    case 'tcp.srcport':
    case 'udp.srcport':
    case 'srcport':
      return packet.sourcePort !== undefined && compareNumbers(packet.sourcePort, numVal, op);

    case 'tcp.dstport':
    case 'udp.dstport':
    case 'dstport':
      return packet.destPort !== undefined && compareNumbers(packet.destPort, numVal, op);

    case 'protocol':
    case 'proto':
      // Matches either the displayed name ("TLSv1.2") or the coarse type
      // ("TLS"), so both `proto == tlsv1.2` from a clicked breakdown segment
      // and a hand-typed `proto == tls` resolve to the same frames.
      return compareStrings(packet.protocolLabel ?? packet.protocol, val, op)
        || compareStrings(packet.protocol, val, op);

    case 'len':
    case 'length':
    case 'frame.len':
      return isNumeric && compareNumbers(packet.length, numVal, op);

    case 'status':
      return compareStrings(packet.status, val, op);

    case 'stream':
    case 'tcp.stream':
      return packet.streamId !== undefined && isNumeric && compareNumbers(packet.streamId, numVal, op);

    case 'info':
      return compareStrings(packet.info, val, op);

    case 'anomaly.severity':
      return !!packet.anomalies?.some(a => compareStrings(a.severity, val, op));

    default: {
      // A CIDR on the right-hand side compares networks, not text - "ip.dst ==
      // 224.0.0.0/4" must match every multicast address, not the literal
      // string. Checked before the generic path so the address fields resolve
      // through it.
      if (val.includes('/')) {
        const address = lookupField(field, packet);
        if (typeof address !== 'string') return false;
        const inside = addressInCidr(address, val);
        return op === '!=' ? !inside : inside;
      }

      const value = lookupField(field, packet);
      // An absent field never matches - including under "!=", since a frame
      // that has no ip.ttl at all is not a frame whose ttl differs. Returning
      // true here (as this used to) makes any rule mentioning an unknown field
      // match every packet, which would paint the whole list one color.
      if (value === undefined) return false;
      if (typeof value === 'number') {
        const literal = parseNumericLiteral(val);
        return literal !== null && compareNumbers(value, literal, op);
      }
      return compareStrings(String(value), val, op);
    }
  }
}

function compareStrings(actual: string, target: string, op: string): boolean {
  const a = actual.toLowerCase();
  const t = target.toLowerCase();
  if (op === '==' || op === '=') return a === t || a.includes(t);
  if (op === '!=') return a !== t && !a.includes(t);
  return false;
}

function compareNumbers(actual: number, target: number, op: string): boolean {
  if (op === '==' || op === '=') return actual === target;
  if (op === '!=') return actual !== target;
  if (op === '>') return actual > target;
  if (op === '<') return actual < target;
  if (op === '>=') return actual >= target;
  if (op === '<=') return actual <= target;
  return false;
}
