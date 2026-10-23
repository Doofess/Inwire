/**
 * The stored form of one `MinuteRollup` (ADRs 0059, 0066).
 *
 * The Worker encodes and decodes these; the utility that owns the sidecar
 * stores the result as opaque bytes and never opens it. That split is why the
 * deflate functions are **injected**: node's zlib at level 1 in the utility's
 * tests and the Worker's host, `fflate` where only that is available, and this
 * file imports neither.
 *
 * A minute is stored in the layout of its own policy, the policy of the
 * segment its entries came from, so a policy-1 minute keeps its bytes for good:
 *
 * ```
 * u16  decoder policy version          (outside the deflate, so a reader can refuse before inflating)
 * ...  deflate of, policy 1:
 *   u8   flags                         bit 0: complete
 *   u16  key length, then the source key (UTF-8)
 *   u64  minuteMs, records, reportedOctets, reportedPackets, malformed, unsupported, unknownSamplingRecords
 *   u32  endpoint count, then per endpoint: 4 address bytes, u64 sent, u64 received
 *   u32  conversation count, then per conversation: 4 src, 4 dst, u64 octets, u64 packets
 * ...  deflate of, policy 2:
 *   u8   flags                         bit 0: complete, bit 1: clock present
 *   u16  key length, then the source key (UTF-8)
 *   u64  the seven counters of policy 1,
 *        then awaitingSets, awaitingBytes, unsupportedTemplateRecords, unsupportedSamplingRecords
 *   u32  samplingInterval              0: none stated, 0xffffffff: several
 *   i64  minSkewMs, maxSkewMs, lastSkewMs   (only with flag bit 1)
 *   u32  endpoint count, then per endpoint: u8 address length (4 or 16), the address, u64 sent, u64 received
 *   u32  conversation count, then per conversation: u8 length, src, u8 length, dst, u64 octets, u64 packets
 * ```
 *
 * Counters are `u64` because a minute's octets can pass 2^53 and a `number`
 * would silently round them: `bigint` in, `bigint` out, and a value that does
 * not fit is a `RangeError` on the way in rather than a wrong total stored.
 * Counts and the minute are `number` in the type, so they are checked to be
 * safe integers coming back too.
 *
 * A decoder believes nothing it reads: each count is compared with the bytes
 * left **before** anything is allocated for it, and bytes left over after the
 * last field are an error, not slack.
 */
import { formatIpv6Address, parseIpv6 } from '../addressFormat';
import { ipv4FromBytes, ipv4ToBytes } from './journalCodec';
import {
  ACCEPTED_POLICIES, LIMITS, SAMPLING_MIXED, isReadablePolicy,
  type ConversationTotals, type EndpointTotals, type MinuteClock, type MinuteRollup,
} from './types';

export type Deflate = (bytes: Uint8Array) => Uint8Array;
/**
 * `maxOutput` is the codec's bound on what the inflate may produce
 * (`MAX_ROLLUP_INFLATED_BYTES`). An implementation must stop there - node's
 * zlib takes it as `maxOutputLength` - because the bytes are the sidecar's and
 * a deflate stream of a few kilobytes can name gigabytes. The codec checks the
 * length it gets back as well, so an implementation that ignores the bound is
 * refused rather than trusted.
 */
export type Inflate = (bytes: Uint8Array, maxOutput: number) => Uint8Array;

const U64_MAX = (1n << 64n) - 1n;
const ENDPOINT_BYTES = 4 + 8 + 8;
const CONVERSATION_BYTES = 4 + 4 + 8 + 8;
const MAX_KEY_BYTES = 0xffff;
/** Policy 2's address: a length byte, then 4 or 16 bytes. Policy 1's is 4 bytes and no length. */
const ENDPOINT_BYTES_2 = 1 + 16 + 8 + 8;
const CONVERSATION_BYTES_2 = 2 * (1 + 16) + 8 + 8;
const CLOCK_BYTES = 3 * 8;

/**
 * The most a valid rollup inflates to, computed from the shapes above and not
 * typed: the flags and key length, the longest key, the counters, the clock,
 * two counts, and `LIMITS.minuteKeyBudget` keys at the largest row size of
 * either policy.
 *
 * **The budget is a total, not per table.** `types.ts` defines it as
 * "endpoints and conversations together, per source and minute", so the codec
 * refuses `endpoints + conversations` above it, and the bound here prices every
 * one of those keys as a policy-2 IPv6 conversation, the largest row.
 */
export const MAX_ROLLUP_INFLATED_BYTES =
  1 + 2 + MAX_KEY_BYTES + 11 * 8 + 4 + CLOCK_BYTES + 4 + 4
  + LIMITS.minuteKeyBudget * Math.max(ENDPOINT_BYTES, CONVERSATION_BYTES, ENDPOINT_BYTES_2, CONVERSATION_BYTES_2);
const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

function u64(value: bigint, what: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) throw new RangeError(`${what} does not fit a u64`);
  return value;
}

function safe(value: number, what: string): bigint {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${what} is not a non-negative safe integer`);
  return BigInt(value);
}

function signed(value: number, what: string): bigint {
  if (!Number.isSafeInteger(value)) throw new RangeError(`${what} is not a safe integer`);
  return BigInt(value);
}

/** An address as policy 2 stores it: 4 bytes for dotted IPv4, 16 for IPv6. */
export function addressBytes(address: string): Uint8Array {
  if (!address.includes(':')) return ipv4ToBytes(address);
  const b = parseIpv6(address);
  if (b === null) throw new RangeError(`not an IP address: ${address}`);
  return b;
}

/** The stored order of rows (ADR 0066): by address bytes, a 4-byte address before a 16-byte one. */
export function compareAddresses(a: string, b: string): number {
  const x = addressBytes(a);
  const y = addressBytes(b);
  if (x.length !== y.length) return x.length - y.length;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

const isPolicy2 = (policy: number): boolean => policy >= 2;

/**
 * Encodes a minute in its own policy's layout. A policy-1 minute has no IPv6
 * address and none of policy 2's counts: holding one is a caller's error, not
 * something to drop silently.
 */
export function encodeMinuteRollup(rollup: MinuteRollup, deflate: Deflate): Uint8Array {
  const policy = rollup.policy;
  if (!ACCEPTED_POLICIES.includes(policy)) throw new RangeError(`policy ${policy} is not one this build writes`);
  const two = isPolicy2(policy);
  const key = utf8.encode(rollup.sourceKey);
  if (key.length > MAX_KEY_BYTES) throw new RangeError('a source key is at most 65,535 bytes');
  if (rollup.endpoints.length + rollup.conversations.length > LIMITS.minuteKeyBudget) {
    throw new RangeError(`a rollup holds at most ${LIMITS.minuteKeyBudget} endpoints and conversations together`);
  }
  if (!two && (rollup.awaitingSets !== 0 || rollup.awaitingBytes !== 0 || rollup.unsupportedTemplateRecords !== 0
    || rollup.unsupportedSamplingRecords !== 0 || rollup.samplingInterval !== 0 || rollup.clock !== null)) {
    throw new RangeError('a policy-1 rollup has none of policy 2\'s counts');
  }
  const address = (a: string): Uint8Array => (two ? addressBytes(a) : ipv4ToBytes(a));
  const endpointAddresses = rollup.endpoints.map((e) => address(e.address));
  const conversationAddresses = rollup.conversations.map((c) => [address(c.srcAddr), address(c.dstAddr)] as const);
  const lengthBytes = two ? 1 : 0;
  let size = 1 + 2 + key.length + 7 * 8 + 4 + 4;
  if (two) size += 4 * 8 + 4 + (rollup.clock === null ? 0 : CLOCK_BYTES);
  for (const a of endpointAddresses) size += lengthBytes + a.length + 16;
  for (const [s, d] of conversationAddresses) size += 2 * lengthBytes + s.length + d.length + 16;
  const raw = new Uint8Array(size);
  const v = new DataView(raw.buffer);
  let at = 0;
  const putAddress = (a: Uint8Array): void => {
    if (two) raw[at++] = a.length;
    raw.set(a, at); at += a.length;
  };
  raw[at++] = (rollup.complete ? 1 : 0) | (two && rollup.clock !== null ? 2 : 0);
  v.setUint16(at, key.length, true); at += 2;
  raw.set(key, at); at += key.length;
  const counters = [
    safe(rollup.minuteMs, 'minuteMs'),
    safe(rollup.records, 'records'),
    u64(rollup.reportedOctets, 'reportedOctets'),
    u64(rollup.reportedPackets, 'reportedPackets'),
    safe(rollup.malformed, 'malformed'),
    safe(rollup.unsupported, 'unsupported'),
    safe(rollup.unknownSamplingRecords, 'unknownSamplingRecords'),
  ];
  if (two) {
    counters.push(
      safe(rollup.awaitingSets, 'awaitingSets'),
      safe(rollup.awaitingBytes, 'awaitingBytes'),
      safe(rollup.unsupportedTemplateRecords, 'unsupportedTemplateRecords'),
      safe(rollup.unsupportedSamplingRecords, 'unsupportedSamplingRecords'),
    );
  }
  for (const n of counters) { v.setBigUint64(at, n, true); at += 8; }
  if (two) {
    if (!Number.isInteger(rollup.samplingInterval) || rollup.samplingInterval < 0 || rollup.samplingInterval > SAMPLING_MIXED) {
      throw new RangeError('samplingInterval does not fit a u32');
    }
    v.setUint32(at, rollup.samplingInterval, true); at += 4;
    if (rollup.clock !== null) {
      const c = rollup.clock;
      for (const [n, what] of [[c.minSkewMs, 'minSkewMs'], [c.maxSkewMs, 'maxSkewMs'], [c.lastSkewMs, 'lastSkewMs']] as const) {
        v.setBigInt64(at, signed(n, what), true); at += 8;
      }
    }
  }
  v.setUint32(at, rollup.endpoints.length, true); at += 4;
  rollup.endpoints.forEach((e, i) => {
    putAddress(endpointAddresses[i]);
    v.setBigUint64(at, u64(e.sentOctets, 'sentOctets'), true); at += 8;
    v.setBigUint64(at, u64(e.receivedOctets, 'receivedOctets'), true); at += 8;
  });
  v.setUint32(at, rollup.conversations.length, true); at += 4;
  rollup.conversations.forEach((c, i) => {
    putAddress(conversationAddresses[i][0]);
    putAddress(conversationAddresses[i][1]);
    v.setBigUint64(at, u64(c.reportedOctets, 'reportedOctets'), true); at += 8;
    v.setBigUint64(at, u64(c.reportedPackets, 'reportedPackets'), true); at += 8;
  });
  const packed = deflate(raw);
  const out = new Uint8Array(2 + packed.length);
  new DataView(out.buffer).setUint16(0, policy, true);
  out.set(packed, 2);
  return out;
}

export function decodeMinuteRollup(bytes: Uint8Array, inflate: Inflate): MinuteRollup {
  if (bytes.length < 2) throw new Error('a stored rollup is shorter than its version');
  const policy = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, true);
  // Before inflating: bytes of another policy are not ours to interpret.
  if (!isReadablePolicy(policy)) {
    throw new Error(`a stored rollup is decoder policy version ${policy}; this build reads ${ACCEPTED_POLICIES.join(', ')}`);
  }
  const two = isPolicy2(policy);
  const raw = inflate(bytes.subarray(2), MAX_ROLLUP_INFLATED_BYTES);
  if (raw.length > MAX_ROLLUP_INFLATED_BYTES) throw new Error('a stored rollup inflates past the most a rollup can hold');
  const v = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let at = 0;
  const need = (n: number, what: string): void => {
    if (n > raw.length - at) throw new Error(`a stored rollup ends inside ${what}`);
  };
  const counter = (what: string): number => {
    need(8, what);
    const n = v.getBigUint64(at, true);
    at += 8;
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${what} is past 2^53`);
    return Number(n);
  };
  const skew = (what: string): number => {
    need(8, what);
    const n = v.getBigInt64(at, true);
    at += 8;
    if (n > BigInt(Number.MAX_SAFE_INTEGER) || n < BigInt(Number.MIN_SAFE_INTEGER)) throw new Error(`${what} is past 2^53`);
    return Number(n);
  };
  const big = (what: string): bigint => {
    need(8, what);
    const n = v.getBigUint64(at, true);
    at += 8;
    return n;
  };
  const address = (what: string): string => {
    if (!two) {
      need(4, what);
      const a = ipv4FromBytes(raw, at);
      at += 4;
      return a;
    }
    need(1, what);
    const length = raw[at++];
    if (length !== 4 && length !== 16) throw new Error(`a stored rollup has a ${length}-byte address`);
    need(length, what);
    const a = length === 4 ? ipv4FromBytes(raw, at) : formatIpv6Address(raw, at);
    at += length;
    return a;
  };

  need(3, 'its header');
  const flags = raw[at++];
  if (flags > (two ? 3 : 1)) throw new Error('a stored rollup has unknown flags');
  const keyLength = v.getUint16(at, true); at += 2;
  need(keyLength, 'its source key');
  let sourceKey: string;
  try {
    sourceKey = utf8Strict.decode(raw.subarray(at, at + keyLength));
  } catch {
    throw new Error('a stored rollup has a source key that is not UTF-8');
  }
  at += keyLength;
  const minuteMs = counter('minuteMs');
  const records = counter('records');
  const reportedOctets = big('reportedOctets');
  const reportedPackets = big('reportedPackets');
  const malformed = counter('malformed');
  const unsupported = counter('unsupported');
  const unknownSamplingRecords = counter('unknownSamplingRecords');
  let awaitingSets = 0;
  let awaitingBytes = 0;
  let unsupportedTemplateRecords = 0;
  let unsupportedSamplingRecords = 0;
  let samplingInterval = 0;
  let clock: MinuteClock | null = null;
  if (two) {
    awaitingSets = counter('awaitingSets');
    awaitingBytes = counter('awaitingBytes');
    unsupportedTemplateRecords = counter('unsupportedTemplateRecords');
    unsupportedSamplingRecords = counter('unsupportedSamplingRecords');
    need(4, 'samplingInterval');
    samplingInterval = v.getUint32(at, true); at += 4;
    if ((flags & 2) !== 0) clock = { minSkewMs: skew('minSkewMs'), maxSkewMs: skew('maxSkewMs'), lastSkewMs: skew('lastSkewMs') };
  }
  const endpointMin = two ? 1 + 4 + 16 : ENDPOINT_BYTES;
  const conversationMin = two ? 2 * (1 + 4) + 16 : CONVERSATION_BYTES;

  need(4, 'the endpoint count');
  const endpointCount = v.getUint32(at, true); at += 4;
  // Checked against what is left before the array exists: a count is a claim.
  if (endpointCount > (raw.length - at) / endpointMin) throw new Error('a stored rollup counts more endpoints than it holds');
  if (endpointCount > LIMITS.minuteKeyBudget) throw new Error('a stored rollup counts more endpoints than a minute may hold');
  const endpoints: EndpointTotals[] = [];
  for (let i = 0; i < endpointCount; i++) {
    const a = address('an endpoint address');
    endpoints.push({ address: a, sentOctets: big('sentOctets'), receivedOctets: big('receivedOctets') });
  }

  need(4, 'the conversation count');
  const conversationCount = v.getUint32(at, true); at += 4;
  if (conversationCount > (raw.length - at) / conversationMin) throw new Error('a stored rollup counts more conversations than it holds');
  if (endpointCount + conversationCount > LIMITS.minuteKeyBudget) {
    throw new Error('a stored rollup holds more endpoints and conversations than a minute may');
  }
  const conversations: ConversationTotals[] = [];
  for (let i = 0; i < conversationCount; i++) {
    const srcAddr = address('a conversation source');
    const dstAddr = address('a conversation destination');
    conversations.push({ srcAddr, dstAddr, reportedOctets: big('reportedOctets'), reportedPackets: big('reportedPackets') });
  }
  if (at !== raw.length) throw new Error('a stored rollup has bytes after its last field');

  return {
    sourceKey, minuteMs, complete: (flags & 1) === 1, records, reportedOctets, reportedPackets,
    endpoints, conversations, malformed, unsupported, unknownSamplingRecords,
    policy, awaitingSets, awaitingBytes, unsupportedTemplateRecords, unsupportedSamplingRecords, samplingInterval, clock,
  };
}
