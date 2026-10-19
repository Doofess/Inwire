/**
 * The names rollups and queries file a flow source under (ADRs 0059, 0062).
 *
 * A **source** is an exporter and what it calls itself. For NetFlow v5 that is
 * the engine type and id, and the key stays `ip/type/id`: it is a legacy
 * identifier that existing datasets, sidecars and archives already hold, so it
 * is not given a prefix. NetFlow v9 and IPFIX name their sources by a 32-bit
 * source id and observation domain id; those keys carry their protocol,
 * `v9:ip/sourceId` and `ipfix:ip/odid`, so no v5 key can ever equal one.
 * Milestone 1.5 only reserves the forms; milestone 2 decodes them.
 *
 * Pure strings: no `node:*`, no Electron, like everything under `src/services/`.
 */

export type FlowProtocol = 'v5' | 'v9' | 'ipfix';

/** A source is the configured exporter plus the v5 engine type and id (ADR 0059). */
export function sourceKey(exporterIPv4: string, engineType: number, engineId: number): string {
  return `${exporterIPv4}/${engineType}/${engineId}`;
}

/**
 * The key a datagram with no engine is rolled up under: the bare exporter
 * address, with no slashes, so it can never equal a `sourceKey`. A malformed or
 * unsupported datagram has no engine to name, and a rollup minute still has to
 * count it (ADR 0059).
 */
export function exporterKey(exporterIPv4: string): string {
  return exporterIPv4;
}

const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = `((?:${OCTET}\\.){3}${OCTET})`;
const BYTE = '(0|[1-9]\\d{0,2})';
const U32 = '(0|[1-9]\\d{0,9})';
const V5_KEY = new RegExp(`^${IPV4}/${BYTE}/${BYTE}$`);
const V9_KEY = new RegExp(`^v9:${IPV4}/${U32}$`);
const IPFIX_KEY = new RegExp(`^ipfix:${IPV4}/${U32}$`);
const U32_MAX = 2 ** 32 - 1;

export interface ParsedSourceKey { protocol: FlowProtocol; exporter: string; a: number; b?: number }

/**
 * The inverse of `sourceKeyFor`, or null for anything it does not produce: a
 * bare `exporterKey`, a non-canonical number (`01`), a number out of its
 * field's range, an unknown prefix.
 */
export function parseSourceKey(key: string): ParsedSourceKey | null {
  if (typeof key !== 'string') return null;
  const v5 = V5_KEY.exec(key);
  if (v5 !== null) {
    const a = Number(v5[2]);
    const b = Number(v5[3]);
    return a <= 255 && b <= 255 ? { protocol: 'v5', exporter: v5[1], a, b } : null;
  }
  const v9 = V9_KEY.exec(key);
  if (v9 !== null) {
    const a = Number(v9[2]);
    return a <= U32_MAX ? { protocol: 'v9', exporter: v9[1], a } : null;
  }
  const ipfix = IPFIX_KEY.exec(key);
  if (ipfix !== null) {
    const a = Number(ipfix[2]);
    return a <= U32_MAX ? { protocol: 'ipfix', exporter: ipfix[1], a } : null;
  }
  return null;
}

/**
 * `a` is the v5 engine type, the v9 source id or the IPFIX observation domain
 * id; `b` is the v5 engine id and must be absent for the other two. A number
 * outside its field is a caller bug and throws, so a key that cannot be parsed
 * back is never made.
 */
export function sourceKeyFor(protocol: FlowProtocol, exporter: string, a: number, b?: number): string {
  const inRange = (n: unknown, max: number): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= max;
  if (protocol === 'v5') {
    if (!inRange(a, 255) || !inRange(b, 255)) throw new RangeError('a v5 source is an engine type and an engine id, each 0 to 255');
    return sourceKey(exporter, a, b);
  }
  if (b !== undefined) throw new RangeError(`a ${protocol} source has one id, not two`);
  if (!inRange(a, U32_MAX)) throw new RangeError(`a ${protocol} source id is an unsigned 32-bit integer`);
  return protocol === 'v9' ? `v9:${exporter}/${a}` : `ipfix:${exporter}/${a}`;
}

/**
 * Whether `key` is exactly what `sourceKeyFor` produces: an exporter and its
 * source ids, each a canonical number, under one of the three protocols. The
 * bare `exporterKey` is not one - it is where the malformed and unsupported
 * counts live, never a source a query can name or an engine that can be admitted.
 */
export function isEngineSourceKey(key: string): boolean {
  return parseSourceKey(key) !== null;
}

/** The exporter a `sourceKey`, a `sourceKeyFor` key or an `exporterKey` belongs to. */
export function exporterOf(key: string): string {
  const colon = key.indexOf(':');
  const rest = colon >= 0 && (key.startsWith('v9:') || key.startsWith('ipfix:')) ? key.slice(colon + 1) : key;
  const slash = rest.indexOf('/');
  return slash < 0 ? rest : rest.slice(0, slash);
}
