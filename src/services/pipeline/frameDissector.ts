/**
 * One lane's dissection of one frame, with its record - the code a TCP shard
 * and the coordinator's own sequential lane share when the live capture is
 * dissected on several cores (ADR 0053 phase 3).
 *
 * The same thing the single Worker's `ingest` does up to the record, and no
 * further: what comes after - the process a socket belonged to, a fingerprint
 * learned from it, the facts about the network - reads and writes state shared
 * by every conversation, so it happens once, on the coordinator, as frames are
 * merged back into order (`coordinator.ts`).
 */
import { decodeRawEthernetPacket } from '../pcapParser';
import { withDissectEnv, type DissectEnv } from '../dissect/dissectEnv';
import { FrameRecorder } from '../dissect/frameRecord';
import type { DeferredTlsNumbers } from '../dissect/sequencer';
import type { TcpStreamTracker } from '../tcpStreamTracker';
import type { IcmpEchoTracker } from '../icmpEchoTracker';
import type { QuicFlowTracker } from '../quicFlowTracker';
import type { DnsTracker } from '../dnsTracker';
import type { L3Tracker } from '../l3Tracker';
import { NO_HOST, type HostIdentity } from '../direction';
import type { InfoPatch } from '../dissect/types';
import type { Packet } from '../../types/packet';

export interface LaneTrackers {
  tcp: TcpStreamTracker; icmp: IcmpEchoTracker; quic: QuicFlowTracker; dns: DnsTracker; l3: L3Tracker;
}

/** A frame as a lane is handed it: its bytes, and what the coordinator already worked out. */
export interface DissectInput {
  id: number;
  bytes: Uint8Array;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  origLen: number;
  linktype: number;
  iface?: { name: string; label: string };
  /** The decode's `frameFacts`, exactly as the single Worker passes it. */
  facts?: { nanosRemainder?: number };
}

/** What a lane's dissection of a frame produced. */
export interface Dissected {
  /** With its tree. */
  packet: Packet;
  record: Uint8Array;
  derived: Uint8Array | null;
  /** Offsets of placeholder `tls.stream` answers in `record` (`settleDeferredAnswers`). */
  deferredAt: readonly number[];
  icmpMatchedRequestFrameId?: number;
  infoPatches?: InfoPatch[];
}

export class FrameDissector {
  readonly recorder: FrameRecorder;
  host: HostIdentity = NO_HOST;

  constructor(
    readonly trackers: LaneTrackers,
    env: DissectEnv | undefined,
    /** The lane's `tls.stream` placeholders, when it hands them out. */
    readonly tls: DeferredTlsNumbers | null,
  ) {
    this.recorder = new FrameRecorder({ ...trackers, ...(env ? { env } : {}) });
  }

  /** Throws as the dissection throws; `takeTls` still says what it numbered. */
  dissect(input: DissectInput): Dissected {
    const recorder = this.recorder;
    recorder.begin();
    const src = recorder.sources;
    const decoded = withDissectEnv(src.env, () => decodeRawEthernetPacket(
      input.bytes, input.id, input.tsUs, input.relativeTime, input.timeDelta, input.origLen,
      src.tcp, src.icmp, src.quic, src.dns, input.iface, input.linktype, src.l3, this.host, input.facts,
    ));
    const record = recorder.end();
    return {
      packet: decoded.packet,
      record,
      derived: recorder.endDerived(),
      deferredAt: recorder.deferredAnswers,
      ...(decoded.icmpMatchedRequestFrameId !== undefined
        ? { icmpMatchedRequestFrameId: decoded.icmpMatchedRequestFrameId } : {}),
      ...(decoded.infoPatches ? { infoPatches: decoded.infoPatches } : {}),
    };
  }

  /**
   * The `tls.stream` placeholders the last frame handed out - read whether it
   * dissected or threw, because a number taken by a frame that failed is still
   * taken, as it is on one core.
   */
  takeTls(): number[] {
    return this.tls === null ? [] : this.tls.takeFresh();
  }
}
