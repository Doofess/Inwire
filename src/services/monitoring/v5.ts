/**
 * An exact NetFlow v5 decoder for the monitoring journal (ADRs 0058, 0059).
 *
 * `services/flow/flowExport.ts` reads v5 too, and is deliberately lax: it
 * serves a packet tree, where a short datagram should still show whatever it
 * has, so it drops a partial record and carries on. That is the wrong
 * behaviour here. A history built from a datagram that was read as "fewer
 * flows than it said" would be quietly wrong, so this decoder demands the
 * length the header implies - `24 + count * 48`, no more and no less - and a
 * datagram that fails it is `malformed`, counted, and kept in the journal as
 * evidence.
 *
 * Nothing here is cross-datagram state. Sequence, freshness and engine limits
 * are `sourceHealth.ts`'s; rolling up is the Worker's.
 *
 * **Time.** A record's First and Last are the exporter's sysUptime in
 * milliseconds. They become epoch milliseconds as the export time (unix_secs
 * and unix_nsecs) less how long before the export the flow's packet was seen:
 * `(sysUptime - First) mod 2^32`. Taking the difference modulo 2^32 is what
 * makes the 32-bit uptime's wrap (every 49.7 days) harmless - a flow that began
 * before the wrap has First numerically above sysUptime, and the modular
 * difference is still its true age. The cost is that a flow genuinely older
 * than 2^32 ms is indistinguishable from a younger one; no exporter's flow
 * lives that long. For the same reason a time *later* than the header's uptime
 * cannot be accepted: its modular age comes out near 2^32 and would place the
 * flow 49.7 days in the past, as if valid. A real wrap leaves an age just past
 * the wrap point, far below 2^31, so an age of 2^31 or more is read as a future
 * time and the datagram is `malformed`. A record whose times cannot be derived (nanoseconds past a
 * second, an exporter with no clock whose flows would start before the epoch,
 * a flow that ends before it starts) makes the whole datagram `malformed`:
 * receipt time is never substituted, because the sheet shows flow times as the
 * exporter reported them.
 *
 * No `node:*` and no Electron, like everything under `src/services/`.
 */
import type { DatagramEvidence, DecodeResult, NormalizedV5, Sampling } from './types';

const HEADER_LENGTH = 24;
const RECORD_LENGTH = 48;
const U32 = 2 ** 32;
/** An age at or past this is a time after the header's uptime, not a flow that old. */
const FUTURE_AGE = 2 ** 31;

/** A source is the configured exporter plus the v5 engine type and id (ADR 0059). */
export function sourceKey(exporterIPv4: string, engineType: number, engineId: number): string {
  return `${exporterIPv4}/${engineType}/${engineId}`;
}

function ipv4(v: DataView, at: number): string {
  return `${v.getUint8(at)}.${v.getUint8(at + 1)}.${v.getUint8(at + 2)}.${v.getUint8(at + 3)}`;
}

/**
 * Header bits 15-14 are the mode and 13-0 the interval; all zero means the
 * exporter did not say. A non-zero mode with interval 0 stays `reported`,
 * because the exporter did say something: interval 0 there means it gave no
 * interval, and a consumer must not divide by it.
 */
function readSampling(field: number): Sampling {
  if (field === 0) return { kind: 'unknown' };
  return { kind: 'reported', mode: field >>> 14, interval: field & 0x3fff };
}

/**
 * `exporterIPv4` is the *configured* address, passed in because it names the
 * source; `evidence.remoteIPv4` is where the datagram came from and stays
 * provenance, which is why a changing sender port or address cannot split a
 * source.
 */
export function decodeV5(evidence: DatagramEvidence, exporterIPv4: string): DecodeResult {
  const b = evidence.bytes;
  if (b.length < 2) return { kind: 'malformed', reason: `${b.length} bytes cannot carry a version` };
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const version = v.getUint16(0);
  if (version !== 5) return { kind: 'unsupported', reason: `NetFlow version ${version}, only 5 is read` };
  if (b.length < HEADER_LENGTH) {
    return { kind: 'malformed', reason: `header truncated: ${b.length} bytes, a v5 header is ${HEADER_LENGTH}` };
  }

  const count = v.getUint16(2);
  const expected = HEADER_LENGTH + count * RECORD_LENGTH;
  if (b.length < expected) {
    return { kind: 'malformed', reason: `truncated: ${count} records need ${expected} bytes, the datagram has ${b.length}` };
  }
  if (b.length > expected) {
    return { kind: 'malformed', reason: `trailing bytes: ${count} records end at ${expected}, the datagram has ${b.length}` };
  }

  const uptimeMs = v.getUint32(4);
  const unixSecs = v.getUint32(8);
  const unixNsecs = v.getUint32(12);
  const sequence = v.getUint32(16);
  const engineType = v.getUint8(20);
  const engineId = v.getUint8(21);
  const sampling = readSampling(v.getUint16(22));

  if (count > 0 && unixNsecs >= 1_000_000_000) {
    return { kind: 'malformed', reason: `unix_nsecs ${unixNsecs} is past a second, so flow times cannot be derived` };
  }
  const exportMs = unixSecs * 1000 + Math.floor(unixNsecs / 1e6);
  const key = sourceKey(exporterIPv4, engineType, engineId);

  const flows: NormalizedV5[] = [];
  for (let i = 0; i < count; i++) {
    const p = HEADER_LENGTH + i * RECORD_LENGTH;
    const startAgo = (uptimeMs - v.getUint32(p + 24) + U32) % U32;
    const endAgo = (uptimeMs - v.getUint32(p + 28) + U32) % U32;
    if (startAgo >= FUTURE_AGE) {
      return { kind: 'malformed', reason: `record ${i} First is later than the header's uptime, so its time cannot be derived` };
    }
    if (endAgo >= FUTURE_AGE) {
      return { kind: 'malformed', reason: `record ${i} Last is later than the header's uptime, so its time cannot be derived` };
    }
    if (endAgo > startAgo) {
      return { kind: 'malformed', reason: `record ${i} ends before it starts` };
    }
    const startMs = exportMs - startAgo;
    if (startMs < 0) {
      return { kind: 'malformed', reason: `record ${i} would start before the epoch, so its time cannot be derived` };
    }
    flows.push({
      ref: evidence.ref,
      recordIndex: i,
      sourceKey: key,
      receivedMs: evidence.receivedMs,
      startMs,
      endMs: exportMs - endAgo,
      srcAddr: ipv4(v, p),
      dstAddr: ipv4(v, p + 4),
      srcPort: v.getUint16(p + 32),
      dstPort: v.getUint16(p + 34),
      protocol: v.getUint8(p + 38),
      inputIf: v.getUint16(p + 12),
      outputIf: v.getUint16(p + 14),
      // u32 into bigint: getUint32 is exact in a double, so there is no
      // rounding to avoid, and no arithmetic is done on the way.
      reportedOctets: BigInt(v.getUint32(p + 20)),
      reportedPackets: BigInt(v.getUint32(p + 16)),
      sampling,
    });
  }
  return { kind: 'valid', engineType, engineId, sequence, uptimeMs, flows };
}
