/**
 * TCP sequence analysis - Wireshark's `tcp_analyze_sequence_number`
 * (epan/dissectors/packet-tcp.c, release 4.6), as a pure function over
 * per-direction state.
 *
 * The flags this produces are the ones a person reads first when a
 * connection misbehaves: retransmission, out-of-order, duplicate ACK, zero
 * window, keep-alive. They are only as useful as they are *comparable*, so
 * this follows the reference function check for check - same order, same
 * thresholds, same bookkeeping - rather than a simpler heuristic. The
 * previous tracker classified by overlap alone, which called a third of one
 * fixture's out-of-order segments retransmissions and flagged every SYN-ACK
 * as acknowledging unseen data because it did not count the SYN. The parity
 * harness holds the counts to tshark's.
 *
 * Details that are easy to get wrong and are taken from the source:
 * - a direction that has only ever sent ACKs still has a `nextSeq` (its ACKs
 *   establish it), which is what lets its duplicate ACKs be recognised;
 * - `maxSeqToBeAcked` advances only when a segment starts exactly at it, so a
 *   gap leaves it behind and the ACK that covers the gap is the one flagged;
 * - the retransmission timer runs from the peer's last ACK, not from this
 *   direction's last data;
 * - a segment wholly contained in one already seen is never "out-of-order".
 */

export interface UnackedSegment {
  seq: number;
  nextSeq: number;
  frame: number;
  timeUs: number;
}

export interface TcpDirectionState {
  /** Sequence number of the next byte this direction is expected to send; 0 until known. */
  nextSeq: number;
  nextSeqTimeUs: number;
  nextSeqFrame: number;
  /** Highest sequence the other side may acknowledge before it is acknowledging unseen data. */
  maxSeqToBeAcked: number;
  /** Last acknowledgment number this direction sent, and when. */
  lastAck: number;
  lastAckTimeUs: number;
  /** Segment length of the last segment that advanced nextSeq. */
  lastAckLen: number;
  /** Raw window this direction last advertised. */
  window: number;
  /**
   * Whether any segment has been seen in this direction at all.
   *
   * `window` starts at 0, which is indistinguishable from a peer that really
   * did advertise a zero window - and the zero-window-probe rule reads the
   * REVERSE direction's window, so on a capture where one side was never seen
   * every one-byte segment was reported as a probe. That is not a rare shape:
   * `bulk` is 30 TCP streams with a single SYN, and a one-sided capture is the
   * normal result of spanning a port in one direction.
   */
  windowSeen: boolean;
  /** Window scale shift this direction advertised in its SYN; -1 when unknown. */
  winScale: number;
  dupAckNum: number;
  lastNonDupAckFrame: number;
  /** Flags of this direction's previous segment. */
  lastWasKeepAlive: boolean;
  lastWasZeroWindowProbe: boolean;
  /** SACK ranges this direction last advertised. */
  sackRanges: { left: number; right: number }[];
  /** Segments sent and not yet acknowledged, newest first. */
  segments: UnackedSegment[];
  synTimeUs: number | null;
  synSeen: boolean;
}

export interface TcpConnectionState {
  a: TcpDirectionState;
  b: TcpDirectionState;
  /** Initial RTT (SYN to the ACK of the SYN-ACK), microseconds, once known. */
  initialRttUs: number | null;
}

function freshDirection(): TcpDirectionState {
  return {
    nextSeq: 0, nextSeqTimeUs: 0, nextSeqFrame: 0, maxSeqToBeAcked: 0, lastAck: 0, lastAckTimeUs: 0, lastAckLen: 0,
    window: 0, windowSeen: false, winScale: -1, dupAckNum: 0, lastNonDupAckFrame: 0, lastWasKeepAlive: false, lastWasZeroWindowProbe: false,
    sackRanges: [], segments: [], synTimeUs: null, synSeen: false,
  };
}

export function freshConnection(): TcpConnectionState {
  return { a: freshDirection(), b: freshDirection(), initialRttUs: null };
}

export interface TcpSegment {
  frame: number;
  timeUs: number;
  seq: number;
  ack: number;
  /** Raw (unscaled) window. */
  window: number;
  segLen: number;
  syn: boolean;
  ack_: boolean;
  fin: boolean;
  rst: boolean;
  /** Window scale option from a SYN, if present. */
  windowScaleOption?: number;
  /** SACK blocks this segment carries, in the peer's sequence space. */
  sackBlocks?: { left: number; right: number }[];
}

import type { ExpertCategory } from '../../types/packet';

export type TcpAnalysisFlag =
  | 'retransmission' | 'fast_retransmission' | 'spurious_retransmission' | 'out_of_order'
  | 'lost_segment' | 'ack_lost_segment' | 'window_update' | 'window_full'
  | 'keep_alive' | 'keep_alive_ack' | 'duplicate_ack' | 'zero_window_probe' | 'zero_window'
  | 'zero_window_probe_ack' | 'reused_ports';

export interface TcpAnalysis {
  flags: TcpAnalysisFlag[];
  /** Wireshark's Info tags, leftmost first, e.g. "[TCP ACKed unseen segment]". */
  tags: string[];
  dupAckNum?: number;
  dupAckFrame?: number;
  /** Frame this segment acknowledges (fully, or partially), and how long that took (us). */
  ackOfFrame?: number;
  ackRttUs?: number;
  partialAck?: boolean;
  initialRttUs?: number;
  bytesInFlight?: number;
  /** For a retransmission: how long after the original, and which frame it was. */
  rtoUs?: number;
  rtoFrame?: number;
  nextSeq: number;
}

const OUT_OF_ORDER_THRESHOLD_US = 3_000;
const FAST_RETRANSMISSION_WINDOW_US = 20_000;
const MAX_UNACKED_SEGMENTS = 1000;

const gt = (a: number, b: number) => ((a - b) | 0) > 0;
const ge = (a: number, b: number) => ((a - b) | 0) >= 0;
const lt = (a: number, b: number) => ((a - b) | 0) < 0;
const le = (a: number, b: number) => ((a - b) | 0) <= 0;
const add = (a: number, b: number) => (a + b) >>> 0;

/**
 * Wireshark builds the Info column by *prepending* each tag it prints, so the
 * display order is the reverse of this list - "[TCP ACKed unseen segment]
 * [TCP Previous segment not captured]", "[TCP Previous segment not captured]
 * [TCP Out-Of-Order]". Kept as the print order so it reads like the source.
 */
const PRINT_ORDER: [TcpAnalysisFlag, string][] = [
  ['retransmission', '[TCP Retransmission]'],
  ['fast_retransmission', '[TCP Fast Retransmission]'],
  ['spurious_retransmission', '[TCP Spurious Retransmission]'],
  ['out_of_order', '[TCP Out-Of-Order]'],
  ['reused_ports', '[TCP Port numbers reused]'],
  ['lost_segment', '[TCP Previous segment not captured]'],
  ['ack_lost_segment', '[TCP ACKed unseen segment]'],
  ['window_update', '[TCP Window Update]'],
  ['window_full', '[TCP Window Full]'],
  ['keep_alive', '[TCP Keep-Alive]'],
  ['keep_alive_ack', '[TCP Keep-Alive ACK]'],
  ['duplicate_ack', '[TCP Dup ACK]'],
  ['zero_window_probe', '[TCP ZeroWindowProbe]'],
  ['zero_window', '[TCP ZeroWindow]'],
  ['zero_window_probe_ack', '[TCP ZeroWindowProbeAck]'],
];

/**
 * What each analysis flag actually means, for the expert categories.
 *
 * The split that matters is between **Loss** and **CaptureGap**, and Wireshark
 * does not make it: it files "Previous segment not captured" and "ACKed unseen
 * segment" under Sequence alongside real retransmissions, so a capture that
 * dropped frames reads as a network that dropped packets. They are different
 * problems with different owners - one is the wire, the other is the sniffer -
 * and on the inwire fixture the second is 2,427 frames against the first's
 * ~190. Reading those as network loss is the single most misleading thing the
 * expert system did.
 *
 * **FlowControl** is the other rescue. A zero window, a window-full and a
 * keep-alive are a peer applying back-pressure, which is TCP working, not TCP
 * failing - they were `warn` and `note` before and drew the eye for nothing.
 */
export const CATEGORY_BY_FLAG: Record<TcpAnalysisFlag, ExpertCategory> = {
  retransmission: 'Loss',
  fast_retransmission: 'Loss',
  spurious_retransmission: 'Loss',
  out_of_order: 'Loss',
  duplicate_ack: 'Loss',

  // The sniffer missed frames. Nothing here says the network did.
  lost_segment: 'CaptureGap',
  ack_lost_segment: 'CaptureGap',

  window_update: 'FlowControl',
  window_full: 'FlowControl',
  keep_alive: 'FlowControl',
  keep_alive_ack: 'FlowControl',
  zero_window: 'FlowControl',
  zero_window_probe: 'FlowControl',
  zero_window_probe_ack: 'FlowControl',

  // A port reused while the old connection is still live ends that connection
  // as surely as a RST does, and from the reader's side it is the same event.
  reused_ports: 'Reset',
};

export function analyzeTcpSegment(conn: TcpConnectionState, direction: 'a' | 'b', s: TcpSegment): TcpAnalysis {
  const fwd = direction === 'a' ? conn.a : conn.b;
  const rev = direction === 'a' ? conn.b : conn.a;
  const flags = new Set<TcpAnalysisFlag>();
  const out: TcpAnalysis = { flags: [], tags: [], nextSeq: 0 };
  const { seq, ack, segLen: seglen, window } = s;
  const plain = !s.syn && !s.fin && !s.rst;
  const synOrFin = s.syn || s.fin;

  if (s.syn && s.windowScaleOption !== undefined) fwd.winScale = s.windowScaleOption;
  if (s.syn) {
    if (!s.ack_ && fwd.synSeen && fwd.nextSeq !== 0 && seq !== add(fwd.nextSeq, -1)) flags.add('reused_ports');
    fwd.synSeen = true;
    if (!s.ack_) fwd.synTimeUs = s.timeUs;
  }

  // The forward checks, in the source's order. `finishedFwd` is its
  // `goto finished_fwd`.
  let finishedFwd = false;

  // ZERO WINDOW PROBE
  // `rev.windowSeen` and not just `rev.window === 0`: a window nobody has
  // advertised is unknown, and calling it zero turns every one-byte segment on
  // a half-captured stream into a probe (and its answer into a probe-ack).
  if (seglen === 1 && seq === fwd.nextSeq && rev.windowSeen && rev.window === 0) {
    flags.add('zero_window_probe');
    finishedFwd = true;
  }
  // ZERO WINDOW
  if (!finishedFwd && window === 0 && plain) flags.add('zero_window');
  // LOST PACKET
  if (!finishedFwd && fwd.nextSeq !== 0 && gt(seq, fwd.nextSeq) && !s.rst) flags.add('lost_segment');
  // KEEP ALIVE
  if (!finishedFwd && (seglen === 0 || seglen === 1) && seq === add(fwd.nextSeq, -1) && plain) flags.add('keep_alive');
  // A zero-length segment carrying a SACK block is reporting a HOLE - which is
  // what a duplicate ACK is - so whatever window it happens to advertise does
  // not make it a window update. Measured rather than read off the source: two
  // frames identical but for the option read `[TCP Window Update]` without it
  // and `[TCP Dup ACK 2#2]` with it, on a segment whose window had changed.
  //
  // It is worth the line because without it one keep-alive poisons everything
  // after it. A keep-alive DOES update the remembered window (also measured),
  // so a direction that sends one at a smaller window makes its next ordinary
  // ACK look like a change - and inwire frame 9379 read as a window update
  // 1,332 frames after two keep-alives at 131072 pulled the remembered window
  // down from 131584. It was the last mismatched analysis count in either
  // fixture, and fixing it took inwire's colour-rule column to 100%.
  const hasSack = (s.sackBlocks ?? []).length > 0;
  // WINDOW UPDATE
  if (!finishedFwd && seglen === 0 && window !== 0 && window !== fwd.window
    && seq === fwd.nextSeq && ack === fwd.lastAck && plain && !hasSack) {
    flags.add('window_update');
  }
  // WINDOW FULL
  if (!finishedFwd && seglen > 0 && rev.winScale !== -1 && plain
    && add(seq, seglen) === add(rev.lastAck, rev.window << Math.max(0, rev.winScale))) flags.add('window_full');
  // KEEP ALIVE ACK
  if (!finishedFwd && seglen === 0 && window !== 0 && window === fwd.window && seq === fwd.nextSeq
    && ack === fwd.lastAck && rev.lastWasKeepAlive && plain) {
    flags.add('keep_alive_ack');
    finishedFwd = true;
  }
  // ZERO WINDOW PROBE ACK
  if (!finishedFwd && seglen === 0 && window === 0 && window === fwd.window && seq === fwd.nextSeq
    && (ack === fwd.lastAck || ack === add(fwd.lastAck, 1)) && rev.lastWasZeroWindowProbe && plain) {
    flags.add('zero_window_probe_ack');
    if (ack === add(fwd.lastAck, 1)) { rev.nextSeq = ack; rev.maxSeqToBeAcked = ack; }
    finishedFwd = true;
  }
  // DUPLICATE ACK. The window must match UNLESS the segment carries a SACK
  // block, which reports the hole on its own - see the note above.
  if (!finishedFwd && seglen === 0 && window !== 0 && (hasSack || window === fwd.window)
    && seq === fwd.nextSeq && ack === fwd.lastAck && plain) {
    fwd.dupAckNum++;
    flags.add('duplicate_ack');
    out.dupAckNum = fwd.dupAckNum;
    out.dupAckFrame = fwd.lastNonDupAckFrame;
  }

  // finished_fwd:
  if (ack !== fwd.lastAck) {
    fwd.lastNonDupAckFrame = s.frame;
    fwd.dupAckNum = 0;
  }

  // ACKED LOST PACKET
  if (rev.maxSeqToBeAcked !== 0 && gt(ack, rev.maxSeqToBeAcked) && s.ack_) {
    if (ack === add(fwd.lastAck, 1) && seq === fwd.nextSeq && rev.lastWasZeroWindowProbe) {
      rev.nextSeq = ack;
      rev.maxSeqToBeAcked = ack;
      flags.add('window_update');
    } else {
      // The peer may have sent a contiguous run starting exactly at `ack`
      // that was seen; if so the next unseen byte is at that run's end.
      let tailLe = 0, tailRe = 0;
      for (const u of rev.segments) {
        if (tailLe === tailRe) { tailLe = u.seq; tailRe = u.nextSeq; }
        if (ge(u.seq, ack)) {
          if (u.nextSeq === tailLe) tailLe = u.seq;
          else { tailLe = u.seq; tailRe = u.nextSeq; }
        }
      }
      rev.maxSeqToBeAcked = ack === tailLe && gt(tailRe, ack) ? tailRe : ack;
      flags.add('ack_lost_segment');
    }
  }

  // RETRANSMISSION / FAST / SPURIOUS / OUT-OF-ORDER
  let seqNotAdvanced = fwd.nextSeq !== 0 && lt(seq, fwd.nextSeq);
  if (seglen > 0 || synOrFin) {
    let decided = flags.has('keep_alive');
    if (!decided && seglen > 1 && add(fwd.nextSeq, -1) === seq) seqNotAdvanced = false;
    if (!decided && seglen > 0 && rev.lastAck !== 0 && le(add(seq, seglen), rev.lastAck)) {
      flags.add('spurious_retransmission');
      decided = true;
    }
    if (!decided && !seqNotAdvanced) decided = true;
    if (!decided) {
      const t = Math.max(0, s.timeUs - rev.lastAckTimeUs);
      // Fast retransmission has precedence by default.
      if (t < FAST_RETRANSMISSION_WINDOW_US && rev.dupAckNum >= 2 && rev.lastAck === seq) {
        flags.add('fast_retransmission');
        decided = true;
      }
      // Also fast: after duplicate ACKs that SACKed other ranges, data the
      // peer did NOT report as received.
      if (!decided && t < FAST_RETRANSMISSION_WINDOW_US && rev.dupAckNum >= 2 && rev.sackRanges.length > 0) {
        const segEnd = add(seq, seglen);
        const sacked = rev.sackRanges.some((r) => ge(seq, r.left) && le(segEnd, r.right));
        if (!sacked) {
          flags.add('fast_retransmission');
          decided = true;
        }
      }
      if (!decided) {
        const oooThreshold = conn.initialRttUs ?? OUT_OF_ORDER_THRESHOLD_US;
        const segEnd = add(seq, seglen);
        const alreadySeen = fwd.segments.some((u) => ge(seq, u.seq) && le(segEnd, u.nextSeq));
        if (t < oooThreshold && !alreadySeen) {
          if (fwd.nextSeq !== add(segEnd, synOrFin ? 1 : 0)) {
            flags.add('out_of_order');
            decided = true;
          } else if (fwd.lastAckLen === 0) {
            flags.add('out_of_order');
            decided = true;
          }
        }
      }
      if (!decided) {
        flags.add('retransmission');
        out.rtoUs = s.timeUs - fwd.nextSeqTimeUs;
        out.rtoFrame = fwd.nextSeqFrame;
        for (const u of fwd.segments) {
          if (ge(u.seq, seq)) { out.rtoUs = s.timeUs - u.timeUs; out.rtoFrame = u.frame; }
        }
      }
    }
  }

  // Initial RTT: the handshake's third segment acknowledges the SYN-ACK.
  if (conn.initialRttUs === null && s.ack_ && !s.syn && fwd.synTimeUs !== null && rev.synSeen
    && fwd.nextSeq !== 0 && seq === fwd.nextSeq && ack === rev.nextSeq) {
    conn.initialRttUs = s.timeUs - fwd.synTimeUs;
    out.initialRttUs = conn.initialRttUs;
  }

  // --- bookkeeping ------------------------------------------------------------------
  let nextSeq = add(seq, seglen);
  const retransmitted = flags.has('retransmission') || flags.has('fast_retransmission') || flags.has('spurious_retransmission');
  if ((seglen > 0 || synOrFin) && fwd.segments.length < MAX_UNACKED_SEGMENTS) {
    if (synOrFin) nextSeq = add(nextSeq, 1);
    fwd.segments.unshift({ seq, nextSeq, frame: s.frame, timeUs: s.timeUs });
  } else if (synOrFin) {
    nextSeq = add(nextSeq, 1);
  }
  if (fwd.nextSeq === 0 || gt(nextSeq, add(fwd.nextSeq, synOrFin ? 1 : 0))) fwd.lastAckLen = seglen;
  /**
   * `|| fwd.nextSeq === 0` is a DELIBERATE divergence from the reference, which
   * wraps this whole update in `seglen != 0 || SYN || FIN` so that a segment
   * carrying nothing never seeds the next expected sequence number.
   *
   * Transplanting that guard was tried and reverted. It cost **63 -> 563
   * Info mismatches on inwire and 107 -> 2,142 on bulk**, nearly all of them
   * a lost `[TCP Window Update]`: that check needs `seq === fwd.nextSeq`, and
   * the direction it fires on is a pure receiver that sends only bare ACKs, so
   * under the reference's rule its `nextSeq` is seeded by the SYN or never.
   *
   * Never, here. **bulk holds 30 TCP streams and exactly one SYN** - these
   * are captures of traffic already in flight, which is the normal case for
   * somebody who starts capturing to look at a problem. The reference gets away
   * with the stricter rule because it is usually handed a capture that opens
   * with a handshake.
   *
   * The divergence is not free and the price is known: 4 frames across both
   * fixtures where a bare ACK seeds `nextSeq` and the NEXT segment then looks
   * like it landed exactly where one was expected - a 1-byte payload read as a
   * zero-window probe (bulk #959), the ACK of it as acknowledging a segment
   * never seen (#974), and two Dup ACKs read as Window Updates (inwire #9379,
   * bulk #1707). Four frames against two thousand is the trade, and it is
   * the right way round.
   */
  if (gt(nextSeq, fwd.nextSeq) || fwd.nextSeq === 0) {
    if (!flags.has('zero_window_probe')) {
      fwd.nextSeq = nextSeq;
      fwd.nextSeqFrame = s.frame;
      fwd.nextSeqTimeUs = s.timeUs;
    }
  }
  if (seq === fwd.maxSeqToBeAcked || fwd.maxSeqToBeAcked === 0) {
    if (!flags.has('zero_window_probe')) fwd.maxSeqToBeAcked = fwd.nextSeq;
  }
  fwd.window = window;
  fwd.windowSeen = true;
  fwd.lastAck = ack;
  fwd.lastAckTimeUs = s.timeUs;
  fwd.sackRanges = s.sackBlocks ?? [];
  fwd.lastWasKeepAlive = flags.has('keep_alive');
  fwd.lastWasZeroWindowProbe = flags.has('zero_window_probe');

  // What this ACK acknowledges in the other direction, and the RTT to it.
  if (s.ack_) {
    const remaining: UnackedSegment[] = [];
    for (const u of rev.segments) {
      if (ack === u.nextSeq) {
        out.ackOfFrame = u.frame;
        out.ackRttUs = s.timeUs - u.timeUs;
        out.partialAck = false;
      } else if (gt(ack, u.seq) && le(ack, u.nextSeq)) {
        u.seq = ack;
        out.ackOfFrame = u.frame;
        out.ackRttUs = s.timeUs - u.timeUs;
        out.partialAck = true;
        remaining.push(u);
        continue;
      } else if (gt(u.nextSeq, ack)) {
        remaining.push(u);
        continue;
      }
      // fully acknowledged: dropped
    }
    rev.segments = remaining;
  }
  if (seglen > 0 && rev.lastAck !== 0 && !retransmitted) {
    const inFlight = (fwd.nextSeq - rev.lastAck) | 0;
    if (inFlight > 0) out.bytesInFlight = inFlight;
  }

  out.nextSeq = fwd.nextSeq;
  out.flags = [...flags];
  const printed: string[] = [];
  for (const [flag, tag] of PRINT_ORDER) {
    if (!flags.has(flag)) continue;
    printed.push(flag === 'duplicate_ack' ? `[TCP Dup ACK ${out.dupAckFrame}#${out.dupAckNum}]` : tag);
  }
  out.tags = printed.reverse();
  return out;
}
