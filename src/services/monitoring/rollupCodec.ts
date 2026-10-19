/**
 * The stored form of one `MinuteRollup` (ADR 0059).
 *
 * The Worker encodes and decodes these; the utility that owns the sidecar
 * stores the result as opaque bytes and never opens it. That split is why the
 * deflate functions are **injected**: node's zlib at level 1 in the utility's
 * tests and the Worker's host, `fflate` where only that is available, and this
 * file imports neither.
 *
 * ```
 * u16  decoder policy version          (outside the deflate, so a reader can refuse before inflating)
 * ...  deflate of:
 *   u8   flags                         bit 0: complete
 *   u16  key length, then the source key (UTF-8)
 *   u64  minuteMs, records, reportedOctets, reportedPackets, malformed, unsupported, unknownSamplingRecords
 *   u32  endpoint count, then per endpoint: 4 address bytes, u64 sent, u64 received
 *   u32  conversation count, then per conversation: 4 src, 4 dst, u64 octets, u64 packets
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
import { ipv4FromBytes, ipv4ToBytes } from './journalCodec';
import { ACCEPTED_POLICIES, LIMITS, WRITE_POLICY_VERSION, type ConversationTotals, type EndpointTotals, type MinuteRollup } from './types';

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

/**
 * The most a valid rollup inflates to, computed from the shape above and not
 * typed: the flags and key length, the longest key, six u64s, two counts, and
 * `LIMITS.minuteKeyBudget` keys at the larger of the two row sizes.
 *
 * **The budget is a total, not per table.** `types.ts` defines it as
 * "endpoints and conversations together, per source and minute", so the codec
 * refuses `endpoints + conversations` above it, and the bound here prices every
 * one of those keys as a conversation, the larger row.
 */
export const MAX_ROLLUP_INFLATED_BYTES =
  1 + 2 + MAX_KEY_BYTES + 7 * 8 + 4 + 4 + LIMITS.minuteKeyBudget * Math.max(ENDPOINT_BYTES, CONVERSATION_BYTES);
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

export function encodeMinuteRollup(rollup: MinuteRollup, deflate: Deflate): Uint8Array {
  const key = utf8.encode(rollup.sourceKey);
  if (key.length > MAX_KEY_BYTES) throw new RangeError('a source key is at most 65,535 bytes');
  if (rollup.endpoints.length + rollup.conversations.length > LIMITS.minuteKeyBudget) {
    throw new RangeError(`a rollup holds at most ${LIMITS.minuteKeyBudget} endpoints and conversations together`);
  }
  const size = 1 + 2 + key.length + 7 * 8 + 4 + rollup.endpoints.length * ENDPOINT_BYTES + 4
    + rollup.conversations.length * CONVERSATION_BYTES;
  const raw = new Uint8Array(size);
  const v = new DataView(raw.buffer);
  let at = 0;
  raw[at++] = rollup.complete ? 1 : 0;
  v.setUint16(at, key.length, true); at += 2;
  raw.set(key, at); at += key.length;
  for (const n of [
    safe(rollup.minuteMs, 'minuteMs'),
    safe(rollup.records, 'records'),
    u64(rollup.reportedOctets, 'reportedOctets'),
    u64(rollup.reportedPackets, 'reportedPackets'),
    safe(rollup.malformed, 'malformed'),
    safe(rollup.unsupported, 'unsupported'),
    safe(rollup.unknownSamplingRecords, 'unknownSamplingRecords'),
  ]) {
    v.setBigUint64(at, n, true); at += 8;
  }
  v.setUint32(at, rollup.endpoints.length, true); at += 4;
  for (const e of rollup.endpoints) {
    raw.set(ipv4ToBytes(e.address), at); at += 4;
    v.setBigUint64(at, u64(e.sentOctets, 'sentOctets'), true); at += 8;
    v.setBigUint64(at, u64(e.receivedOctets, 'receivedOctets'), true); at += 8;
  }
  v.setUint32(at, rollup.conversations.length, true); at += 4;
  for (const c of rollup.conversations) {
    raw.set(ipv4ToBytes(c.srcAddr), at); at += 4;
    raw.set(ipv4ToBytes(c.dstAddr), at); at += 4;
    v.setBigUint64(at, u64(c.reportedOctets, 'reportedOctets'), true); at += 8;
    v.setBigUint64(at, u64(c.reportedPackets, 'reportedPackets'), true); at += 8;
  }
  const packed = deflate(raw);
  const out = new Uint8Array(2 + packed.length);
  new DataView(out.buffer).setUint16(0, WRITE_POLICY_VERSION, true);
  out.set(packed, 2);
  return out;
}

export function decodeMinuteRollup(bytes: Uint8Array, inflate: Inflate): MinuteRollup {
  if (bytes.length < 2) throw new Error('a stored rollup is shorter than its version');
  const version = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, true);
  // Before inflating: bytes of another policy are not ours to interpret.
  if (!ACCEPTED_POLICIES.includes(version)) {
    throw new Error(`a stored rollup is decoder policy version ${version}; this build reads ${ACCEPTED_POLICIES.join(", ")}`);
  }
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
  const big = (what: string): bigint => {
    need(8, what);
    const n = v.getBigUint64(at, true);
    at += 8;
    return n;
  };

  need(3, 'its header');
  const flags = raw[at++];
  if (flags > 1) throw new Error('a stored rollup has unknown flags');
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

  need(4, 'the endpoint count');
  const endpointCount = v.getUint32(at, true); at += 4;
  // Checked against what is left before the array exists: a count is a claim.
  if (endpointCount > (raw.length - at) / ENDPOINT_BYTES) throw new Error('a stored rollup counts more endpoints than it holds');
  if (endpointCount > LIMITS.minuteKeyBudget) throw new Error('a stored rollup counts more endpoints than a minute may hold');
  const endpoints: EndpointTotals[] = [];
  for (let i = 0; i < endpointCount; i++) {
    const address = ipv4FromBytes(raw, at); at += 4;
    endpoints.push({ address, sentOctets: big('sentOctets'), receivedOctets: big('receivedOctets') });
  }

  need(4, 'the conversation count');
  const conversationCount = v.getUint32(at, true); at += 4;
  if (conversationCount > (raw.length - at) / CONVERSATION_BYTES) throw new Error('a stored rollup counts more conversations than it holds');
  if (endpointCount + conversationCount > LIMITS.minuteKeyBudget) {
    throw new Error('a stored rollup holds more endpoints and conversations than a minute may');
  }
  const conversations: ConversationTotals[] = [];
  for (let i = 0; i < conversationCount; i++) {
    const srcAddr = ipv4FromBytes(raw, at); at += 4;
    const dstAddr = ipv4FromBytes(raw, at); at += 4;
    conversations.push({ srcAddr, dstAddr, reportedOctets: big('reportedOctets'), reportedPackets: big('reportedPackets') });
  }
  if (at !== raw.length) throw new Error('a stored rollup has bytes after its last field');

  return {
    sourceKey, minuteMs, complete: flags === 1, records, reportedOctets, reportedPackets,
    endpoints, conversations, malformed, unsupported, unknownSamplingRecords,
  };
}
