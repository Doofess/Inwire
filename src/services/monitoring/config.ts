/**
 * Reading the one source's configuration (ADR 0058).
 *
 * The configuration is an exporter's address, a specific local address and a
 * port, and a storage limit - nothing else. It arrives as `unknown` from a
 * message or a file, so this is a reader that returns a clean `SourceConfig`
 * or null, never a half-trusted object: a caller that holds one has a value
 * that is safe to bind and to journal against.
 *
 * Addresses are literal dotted quads and nothing looser. A host name would
 * need a resolver (and a second answer that can change); a leading zero is
 * read as octal by some parsers and decimal by others, so it is refused
 * rather than guessed at; surrounding whitespace is a paste error the user
 * should see, not have quietly fixed.
 */
import { LIMITS, type SourceConfig } from './types';

/** The common NetFlow collector port (ADR 0058); Cisco documents 9995 too. */
export const DEFAULT_PORT = 2055;

/**
 * The most a storage limit may be: 64 TiB, far past any disk this runs on and
 * well below where `openDeadlineMs` (the limit scanned at 64 MiB/s, in ms)
 * reaches `setTimeout`'s 2^31-1 ms, which Node fires after about a millisecond -
 * a saved limit past it would fail every connect at once, for good. At the
 * ceiling the deadline is about 12 days of the 24.8 the timer allows.
 */
export const MAX_STORAGE_BYTES = 64 * 1024 ** 4;

const DOTTED_QUAD = /^(0|[1-9]\d{0,2})(?:\.(0|[1-9]\d{0,2})){3}$/;

function isDottedQuad(value: unknown): value is string {
  if (typeof value !== 'string' || !DOTTED_QUAD.test(value)) return false;
  return value.split('.').every((octet) => Number(octet) <= 255);
}

export function readSourceConfig(value: unknown): SourceConfig | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  const { exporterIPv4, bindIPv4, port, storageLimitBytes } = v;
  if (!isDottedQuad(exporterIPv4) || !isDottedQuad(bindIPv4)) return null;
  // A wildcard listens on every adapter (ADR 0058); as the exporter it would
  // admit nobody in particular, and the broadcast address is never a sender.
  if (bindIPv4 === '0.0.0.0') return null;
  if (exporterIPv4 === '0.0.0.0' || exporterIPv4 === '255.255.255.255') return null;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65_535) return null;
  if (typeof storageLimitBytes !== 'number' || !Number.isSafeInteger(storageLimitBytes)
    || storageLimitBytes < LIMITS.minStorageBytes || storageLimitBytes > MAX_STORAGE_BYTES) return null;
  return { exporterIPv4, bindIPv4, port, storageLimitBytes };
}
