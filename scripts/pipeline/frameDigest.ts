/**
 * Everything one arrival pass says about every frame, as one hash a frame -
 * so two builds can be held to byte-identical output over a capture too big to
 * keep in memory.
 *
 * A frame's hash covers its columns, its whole field bag in key order, its
 * analysis flags and protocol chain, its tree as `render` draws it, its frame
 * record's bytes and its derived (decrypted) answers. The patches later frames
 * send it are hashed where they are emitted, under the frame that emitted
 * them, so nothing has to be held back to see them land.
 *
 * Not an assertion script: it never calls `process.exit`, so `check.ts` does
 * not run it on its own. `scripts/pipeline/sequencer.ts` is what uses it.
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { PcapService, decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { LIVE_ENV, withDissectEnv, type DissectEnv } from '../../src/services/dissect/dissectEnv';
import { FrameRecorder, type FrameSources } from '../../src/services/dissect/frameRecord';
import { keyLog } from '../../src/services/tls/keyLog';
import type { Packet } from '../../src/types/packet';
import { render } from './arrival';

export interface Trackers {
  tcp: TcpStreamTracker; icmp: IcmpEchoTracker; quic: QuicFlowTracker; dns: DnsTracker; l3: L3Tracker;
}

/**
 * The live environment with its clock stopped. `now()` judges a certificate's
 * validity and is recorded, so a wall clock would make two runs' records
 * differ by the moment they ran rather than by anything they dissected.
 */
const FIXED_ENV: DissectEnv = { ...LIVE_ENV, now: () => new Date(Date.UTC(2026, 9, 8)) };

const hex = (bytes: Uint8Array | null) => (bytes === null ? '-' : Buffer.from(bytes).toString('hex'));

function describe(packet: Packet): string {
  const fields = packet.fields ?? {};
  return JSON.stringify([
    packet.id, packet.source, packet.destination, packet.sourcePort, packet.destPort,
    packet.protocol, packet.protocolLabel, packet.info, packet.status, packet.length,
    packet.frameProtocols, packet.analysisFlags,
    Object.keys(fields).map((k) => [k, fields[k]]),
  ]);
}

/**
 * One hash per frame, in order, for a capture dissected the way the app
 * dissects it as it arrives. `trackers` lets a caller hand in its own (a
 * spy, or trackers sharing one sequencer); `observe` sees every frame's
 * packet before it is dropped.
 */
export async function digestCapture(
  path: string,
  options: {
    trackers?: () => Trackers;
    wrap?: (sources: FrameSources, frame: number) => FrameSources;
    observe?: (packet: Packet, bytes: Uint8Array, linktype: number) => void;
    limit?: number;
  } = {},
): Promise<string[]> {
  const keysPath = path.replace(/\.pcapng?$/, '.keys');
  const keys = keysPath !== path && existsSync(keysPath) ? readFileSync(keysPath, 'utf8') : null;
  const file = new File([new Uint8Array(readFileSync(path))], 'capture.pcap');
  const { frames } = await PcapService.extractFrames(file, options.limit ?? Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames);
  keyLog.clear();
  if (keys !== null) keyLog.add(keys);

  const trackers = options.trackers?.() ?? {
    tcp: new TcpStreamTracker(), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(),
  };
  const recorder = new FrameRecorder({ ...trackers, env: FIXED_ENV });
  const out: string[] = [];
  let base: bigint | null = null;
  let previous: bigint | null = null;
  try {
    for (const frame of frames) {
      if (base === null) base = frame.tsNanos;
      const relativeTime = Number(frame.tsNanos - base) / 1e9;
      const timeDelta = previous === null ? 0 : Number(frame.tsNanos - previous) / 1e9;
      previous = frame.tsNanos;
      const id = out.length + 1;
      const own = frame.rawBytes.slice();
      recorder.begin();
      const src = options.wrap ? options.wrap(recorder.sources, id) : recorder.sources;
      const decoded = withDissectEnv(src.env, () => decodeRawEthernetPacket(
        own, id, Number(frame.tsNanos / 1000n), relativeTime, timeDelta, frame.origLen,
        src.tcp, src.icmp, src.quic, src.dns, undefined, frame.linktype, src.l3, host));
      const record = recorder.end();
      const derived = recorder.endDerived();
      options.observe?.(decoded.packet, frame.rawBytes, frame.linktype);
      const hash = createHash('sha256');
      hash.update(describe(decoded.packet));
      hash.update('\n');
      hash.update(render(decoded.packet.layers));
      hash.update('\n');
      hash.update(hex(record));
      hash.update('\n');
      hash.update(hex(derived));
      hash.update('\n');
      hash.update(JSON.stringify([decoded.icmpMatchedRequestFrameId ?? null, decoded.infoPatches ?? []]));
      out.push(hash.digest('hex'));
      // What the live Worker does once a flush is posted.
      structuredClone(own.buffer, { transfer: [own.buffer] });
    }
  } finally {
    keyLog.clear();
  }
  return out;
}
