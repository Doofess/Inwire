import { Packet, FilterPreset } from '../types/packet';

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
      return { isValid: true };
    } catch (e: any) {
      return {
        isValid: false,
        errorMessage: e.message || 'Invalid filter expression',
      };
    }
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

function evaluateAtomicCondition(cond: string, packet: Packet): boolean {
  const c = cond.trim();
  if (!c) return true;

  // Single keyword checks (e.g. "http", "dns", "tls", "anomaly")
  const lower = c.toLowerCase();
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
  if (lower === 'anomaly') return !!packet.anomaly || packet.status === 'alert';
  if (lower === 'proto_iot') return packet.protocol === 'CUSTOM' || packet.info.includes('Proto-IoT');
  if (lower === 'finfast') return packet.protocol === 'CUSTOM' || packet.info.includes('FinFast');

  // `info contains "something"`
  const containsMatch = c.match(/^info\s+(?:contains|matches|icontains)\s+["']?([^"']+)["']?$/i);
  if (containsMatch) {
    return packet.info.toLowerCase().includes(containsMatch[1].toLowerCase());
  }

  // Operator comparisons: `key == val`, `key != val`, `key >= val`, `key <= val`, `key > val`, `key < val`
  const compMatch = c.match(/^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<|=)\s*["']?([^"']+)["']?$/);
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
      return compareStrings(packet.protocol, val, op);

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
      return packet.anomaly ? compareStrings(packet.anomaly.severity, val, op) : false;

    default:
      return true;
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
