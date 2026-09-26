/**
 * The real fixtures, dissected the way the app dissects them as they arrive,
 * with a frame record kept for each - and the revisit that rebuilds one tree
 * from its record. Shared by the scripts that hold records to account
 * (`pipeline/revisit.ts`, `capture/records.ts`).
 *
 * Not an assertion script: it never calls `process.exit`, so `check.ts` does
 * not run it on its own.
 */
import { readFileSync } from 'node:fs';
import { PcapService, decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { applyInfoPatch } from '../../src/services/dissect/infoPatch';
import { withDissectEnv } from '../../src/services/dissect/dissectEnv';
import { FrameRecorder, FrameRevisit } from '../../src/services/dissect/frameRecord';
import type { HostIdentity } from '../../src/services/direction';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet, ProtocolLayer } from '../../src/types/packet';

export const FIXTURES: { name: string; path: string; optional?: boolean }[] = [
  { name: 'inwire', path: 'test/fixtures/inwire_capture_1788478187989.pcap' },
  { name: 'bulk', path: 'test/fixtures/bulk_capture_1788426090876.pcap' },
  { name: 'icmpErrors', path: 'test/fixtures/icmp_errors_capture_1790359378632.pcapng', optional: true },
  { name: 'keyLog', path: 'test/fixtures/keylog_capture_1790455330535.pcapng', optional: true },
];

/** One frame as it arrived: the eager dissection, and what a revisit needs. */
export interface Arrived {
  /** With its tree, and with every patch later frames applied to it. */
  packet: Packet;
  record: Uint8Array;
  /** Its decrypted answers, which the app holds in memory only; null when it had none. */
  derived: Uint8Array | null;
  input: {
    bytes: Uint8Array; tsUs: number; relativeTime: number; timeDelta: number;
    origLen: number; linktype: number;
  };
}

export interface Arrival {
  arrived: Arrived[];
  /** The patches each frame received from later ones, by frame id. */
  patchesFor: Map<number, InfoPatch[]>;
  host: HostIdentity | undefined;
  /** Wall time the arrival pass took, recording included. */
  ms: number;
}

/** The importer's own loop over a real capture, with a recorder in front. */
export async function arrive(path: string): Promise<Arrival> {
  const file = new File([new Uint8Array(readFileSync(path))], 'fixture.pcap');
  const { frames } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames);

  const recorder = new FrameRecorder({
    tcp: new TcpStreamTracker(), quic: new QuicFlowTracker(), dns: new DnsTracker(),
    icmp: new IcmpEchoTracker(), l3: new L3Tracker(),
  });
  const src = recorder.sources;
  const arrived: Arrived[] = [];
  const patchesFor = new Map<number, InfoPatch[]>();
  let baseNanos: bigint | null = null;
  let prevNanos: bigint | null = null;
  const t0 = performance.now();
  for (const frame of frames) {
    if (baseNanos === null) baseNanos = frame.tsNanos;
    const relativeTime = Number(frame.tsNanos - baseNanos) / 1e9;
    const timeDelta = prevNanos === null ? 0 : Number(frame.tsNanos - prevNanos) / 1e9;
    prevNanos = frame.tsNanos;
    const tsUs = Number(frame.tsNanos / 1000n);
    const id = arrived.length + 1;

    recorder.begin();
    const { packet, icmpMatchedRequestFrameId, infoPatches } = withDissectEnv(src.env, () =>
      decodeRawEthernetPacket(frame.rawBytes, id, tsUs, relativeTime, timeDelta, frame.origLen,
        src.tcp, src.icmp, src.quic, src.dns, undefined, frame.linktype, src.l3, host));
    packet.rawBytes = frame.rawBytes;
    arrived.push({
      packet, record: recorder.end(), derived: recorder.endDerived(),
      input: { bytes: frame.rawBytes, tsUs, relativeTime, timeDelta, origLen: frame.origLen, linktype: frame.linktype },
    });
    if (icmpMatchedRequestFrameId !== undefined) {
      arrived[icmpMatchedRequestFrameId - 1].packet.info += ` (reply in ${packet.id})`;
    }
    for (const patch of infoPatches ?? []) {
      applyInfoPatch(arrived[patch.frameId - 1].packet, patch);
      const list = patchesFor.get(patch.frameId) ?? [];
      list.push(patch);
      patchesFor.set(patch.frameId, list);
    }
  }
  return { arrived, patchesFor, host, ms: performance.now() - t0 };
}

/**
 * One frame's tree, rebuilt from its bytes and its record alone. Throws
 * `RecordMiss` when the record cannot give it back.
 *
 * `bytesOf` is how the revisit reaches the other frames its record names - by
 * id, the way the store answers.
 */
export function revisit(
  input: Arrived['input'], id: number, record: Uint8Array, host: HostIdentity | undefined,
  patches: readonly InfoPatch[], bytesOf: (frame: number) => Uint8Array | undefined,
  derived: Uint8Array | null = null,
): ProtocolLayer[] {
  const again = new FrameRevisit(record, bytesOf, derived);
  const rs = again.sources;
  const { packet } = withDissectEnv(rs.env, () =>
    decodeRawEthernetPacket(input.bytes, id, input.tsUs, input.relativeTime, input.timeDelta,
      input.origLen, rs.tcp, rs.icmp, rs.quic, rs.dns, undefined, input.linktype, rs.l3, host));
  again.finish();
  for (const patch of patches) applyInfoPatch(packet, patch);
  return packet.layers;
}

/** A tree, as a string, so a diff points at the row that moved. */
export function render(layers: ProtocolLayer[]): string {
  const lines: string[] = [];
  const visit = (fields: ProtocolLayer['fields'], depth: number) => {
    for (const f of fields) {
      lines.push(`${'  '.repeat(depth)}${f.name}: ${String(f.value)}`);
      if (f.children) visit(f.children, depth + 1);
    }
  };
  for (const layer of layers) {
    lines.push(`${layer.name} | ${layer.summary}`);
    visit(layer.fields, 1);
  }
  return lines.join('\n');
}

/** The first line two renders differ on. */
export function firstDifference(want: string, got: string): string {
  const a = want.split('\n');
  const b = got.split('\n');
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) return `line ${i + 1}: arrival "${a[i] ?? '(none)'}" / revisit "${b[i] ?? '(none)'}"`;
  }
  return '(identical)';
}
