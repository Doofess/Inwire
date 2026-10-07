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
 *
 * **A signalled call needs none of that.** A SIP message's session
 * description names the address and port each end will receive media on
 * (`dissectors/sdp.ts`), and from then on a datagram to or from one of them is
 * RTP from its first packet, as the reference reads it - payload types named
 * with that description's `a=rtpmap` encodings, and RTCP's reserved types
 * accepted. An answer's endpoints are set up by the OFFER's frame, which is
 * the frame the reference names for both ends of the exchange.
 */
import type { SdpMedia } from './dissectors/sdp';


/** What a datagram's stream contributes to its tree. */
export interface RtpStreamFacts {
  setupFrame: number;
  /** `HEUR RTP` for a flow found by content; `SDP` for one a session description announced. */
  setupMethod: string;
  extSeq: number;
  extTs: number;
  /** The payload type's encoding, when a session description named it. */
  encoding?: string;
}

/** A session description's endpoint: one end's media address and port. */
interface Endpoint {
  setupFrame: number;
  encodings: Record<number, string>;
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
/** Signalled endpoints, and calls with an offer outstanding. */
const MAX_ENDPOINTS = 4096;
const MAX_OFFERS = 1024;

/** Adds to a bounded map, dropping its oldest entry when full. */
function bounded<K, V>(map: Map<K, V>, max: number, key: K, value: V): void {
  if (!map.has(key) && map.size >= max) {
    const oldest = map.keys().next();
    if (!oldest.done) map.delete(oldest.value);
  }
  map.set(key, value);
}

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
  private endpoints = new Map<string, Endpoint>();
  /** By Call-ID: the frame whose description is awaiting its answer, and which side sent it. */
  private offers = new Map<string, { frame: number; request: boolean }>();

  /**
   * A SIP message's session description: its media endpoints are RTP from
   * now on. The first description of an exchange is the offer; the next one
   * from the other side is its answer, and is set up by the offer's frame.
   */
  describe(callId: string, request: boolean, frame: number, media: readonly SdpMedia[]): void {
    const offer = this.offers.get(callId);
    let setupFrame = frame;
    if (offer !== undefined && offer.request !== request) {
      setupFrame = offer.frame;
      this.offers.delete(callId);
    } else {
      bounded(this.offers, MAX_OFFERS, callId, { frame, request });
    }
    for (const m of media) {
      const key = `${m.address}|${m.port}`;
      const known = this.endpoints.get(key);
      // A description repeated in a re-INVITE keeps the stream's numbers
      // running, as the reference keeps its conversation's.
      bounded(this.endpoints, MAX_ENDPOINTS, key, {
        setupFrame, encodings: m.encodings, extSeq: known?.extSeq ?? 0x10000, extTs: known?.extTs ?? TWO_32,
      });
    }
  }

  /**
   * One version-2 datagram: its stream's facts if it is RTP, or null. A
   * signalled endpoint takes any; a flow found by content takes only one that
   * passed the structural checks (`shaped`), and only once it is confirmed.
   */
  observe(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number, frame: number,
    ssrc: number, seq: number, ts: number, payloadType: number, shaped: boolean,
  ): RtpStreamFacts | null {
    // The receiving end first, as the reference looks it up.
    const endpoint = this.endpoints.get(`${dstIp}|${dstPort}`) ?? this.endpoints.get(`${srcIp}|${srcPort}`);
    if (endpoint !== undefined) {
      endpoint.extSeq = extendSeq(endpoint.extSeq, seq);
      endpoint.extTs = extendTs(endpoint.extTs, ts);
      const encoding = endpoint.encodings[payloadType];
      return {
        setupFrame: endpoint.setupFrame, setupMethod: 'SDP', extSeq: endpoint.extSeq, extTs: endpoint.extTs,
        ...(encoding !== undefined ? { encoding } : {}),
      };
    }
    if (!shaped) return null;
    const key = `${dstIp}|${dstPort}|${srcPort}`;
    let flow = this.flows.get(key);
    if (flow === undefined) {
      flow = { setupFrame: frame, confirmed: false, lastSsrc: ssrc, lastSeq: seq, extSeq: 0x10000, extTs: TWO_32 };
      bounded(this.flows, MAX_FLOWS, key, flow);
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
    this.endpoints.clear();
    this.offers.clear();
  }
}
