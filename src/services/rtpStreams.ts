/**
 * Which UDP flows carry RTP, and the per-stream numbers the reference derives
 * for each packet of one.
 *
 * **An RTP packet is not recognisable on its own**, and that is the whole
 * difficulty. Its only fixed field is two version bits: a quarter of all
 * random first bytes have them. The reference's answer is a heuristic it
 * ships switched off (`rtp_udp`), which claims the first datagram that passes
 * its structural checks and from then on reads the whole flow as RTP - a
 * confident label on a quarter of everything encrypted that nobody else
 * claimed. This build claims a flow only when a SECOND datagram on it agrees
 * with the first: the same 32-bit SSRC, and a sequence number a little ahead.
 * Random bytes do that about once in four billion; a media stream does it on
 * its second packet. So a call reads as RTP from its second packet on, and
 * the first stays UDP - the one place this differs from the reference with
 * its heuristic on, and the price of not guessing.
 *
 * What is kept per flow is what the reference keeps per RTP conversation:
 * - the frame that set it up (`rtp.setup-frame`) - the first datagram the
 *   structural checks accepted, which is the frame the reference names;
 * - the extended sequence number and timestamp (`rtp.extseq`,
 *   `rtp.timestamp_ext`), unwrapped across 16- and 32-bit rollovers and
 *   SHARED by every SSRC on the flow, as packet-rtp.c shares them. The
 *   candidate datagram advances them too, so the second packet's numbers are
 *   the reference's.
 *
 * A flow is keyed as the reference registers one: the destination address
 * and port, and the source port. Each direction of a call is its own flow.
 */

/** What a datagram's stream contributes to its tree. */
export interface RtpStreamFacts {
  setupFrame: number;
  /** `HEUR RTP` for a flow found by content; `SDP` for one a session description announced. */
  setupMethod: string;
  extSeq: number;
  extTs: number;
}

interface Flow {
  setupFrame: number;
  confirmed: boolean;
  lastSsrc: number;
  lastSeq: number;
  extSeq: number;
  extTs: number;
}

/** How far ahead a second packet's sequence number may be and still confirm: a few lost packets. */
const MAX_CONFIRM_GAP = 64;
/** Flows held at once; the oldest goes first. A call is two; a busy capture is a few hundred. */
const MAX_FLOWS = 4096;

const TWO_32 = 0x100000000;

/** packet-rtp.c's `calculate_extended_seqno`: the 16-bit number placed nearest the last one. */
function extendSeq(previous: number, raw: number): number {
  let seq = (previous - (previous % 0x10000)) + raw;
  if (seq + 0x8000 < previous) seq += 0x10000;
  else if (previous + 0x8000 < seq) seq -= 0x10000;
  return seq;
}

/** The same for the 32-bit timestamp, in 64 bits. */
function extendTs(previous: number, raw: number): number {
  let ts = (previous - (previous % TWO_32)) + raw;
  if (ts + 0x80000000 < previous) ts += TWO_32;
  else if (previous + 0x80000000 < ts) ts -= TWO_32;
  return ts;
}

export class RtpStreams {
  private flows = new Map<string, Flow>();

  /**
   * One datagram that passed RTP's structural checks: its stream's facts if
   * the flow is RTP, or null while it is still a candidate.
   */
  observe(
    srcPort: number, dstIp: string, dstPort: number, frame: number,
    ssrc: number, seq: number, ts: number,
  ): RtpStreamFacts | null {
    const key = `${dstIp}|${dstPort}|${srcPort}`;
    let flow = this.flows.get(key);
    if (flow === undefined) {
      if (this.flows.size >= MAX_FLOWS) {
        const oldest = this.flows.keys().next();
        if (!oldest.done) this.flows.delete(oldest.value);
      }
      flow = { setupFrame: frame, confirmed: false, lastSsrc: ssrc, lastSeq: seq, extSeq: 0x10000, extTs: TWO_32 };
      this.flows.set(key, flow);
    } else if (!flow.confirmed) {
      const ahead = (seq - flow.lastSeq) & 0xffff;
      flow.confirmed = ssrc === flow.lastSsrc && ahead >= 1 && ahead <= MAX_CONFIRM_GAP;
      flow.lastSsrc = ssrc;
      flow.lastSeq = seq;
    }
    flow.extSeq = extendSeq(flow.extSeq, seq);
    flow.extTs = extendTs(flow.extTs, ts);
    return flow.confirmed
      ? { setupFrame: flow.setupFrame, setupMethod: 'HEUR RTP', extSeq: flow.extSeq, extTs: flow.extTs }
      : null;
  }

  reset(): void {
    this.flows.clear();
  }
}
