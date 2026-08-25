/**
 * Tracks TCP conversations across packets so a single-pass decode can still
 * detect cross-packet behavior: which stream a segment belongs to (for
 * "Follow Stream"), and whether a segment's sequence number has already been
 * seen on that stream (retransmission) or arrives behind the highest
 * contiguous sequence seen so far (out-of-order). This is a lightweight
 * heuristic, not full TCP reassembly - no SACK, no sequence-wraparound
 * handling, no reordering-window tolerance.
 *
 * One instance represents one capture session; call reset() when the packet
 * buffer is cleared or a new file is imported so streams don't bleed across
 * unrelated captures.
 */
export class TcpStreamTracker {
  private streamIds = new Map<string, number>();
  private nextStreamId = 0;
  private highWaterSeq = new Map<string, number>();
  private baseSeq = new Map<string, number>();
  private packetCountByStream = new Map<number, number>();
  private connState = new Map<number, { sawSyn: boolean; sawSynAck: boolean; sawFinOrRst: boolean }>();
  private lastWasKeepAlive = new Map<string, boolean>();
  private windowScaleShift = new Map<string, number>();

  private connectionKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    const a = `${srcIp}:${srcPort}`;
    const b = `${dstIp}:${dstPort}`;
    return a <= b ? `${a}|${b}` : `${b}|${a}`;
  }

  /**
   * Keys one *direction* of a connection: the (symmetric) connection key plus
   * the sending endpoint, so the two halves of a conversation track their
   * sequence state independently.
   */
  private directionKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    return `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
  }

  /**
   * Returns a stable, zero-based ID shared by both directions of a TCP
   * conversation, assigning a new one the first time a connection is seen.
   */
  public getStreamId(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const key = this.connectionKey(srcIp, srcPort, dstIp, dstPort);
    let id = this.streamIds.get(key);
    if (id === undefined) {
      id = this.nextStreamId++;
      this.streamIds.set(key, id);
    }
    return id;
  }

  /**
   * Classifies a TCP segment against the highest sequence number already
   * seen going in that same direction on this connection. Pure ACKs (no
   * payload) never trip retransmit/out-of-order, since they legitimately
   * reuse the current sequence number.
   */
  public checkSequence(
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    seqNum: number,
    payloadLength: number
  ): 'ok' | 'retransmit' | 'out-of-order' {
    const directionKey = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    const seenThrough = this.highWaterSeq.get(directionKey);

    if (seenThrough === undefined) {
      this.highWaterSeq.set(directionKey, seqNum + payloadLength);
      return 'ok';
    }

    if (payloadLength > 0 && seqNum < seenThrough) {
      const result = seqNum + payloadLength <= seenThrough ? 'retransmit' : 'out-of-order';
      return result;
    }

    this.highWaterSeq.set(directionKey, Math.max(seenThrough, seqNum + payloadLength));
    return 'ok';
  }

  /**
   * Returns the sequence number relative to this direction's base (Wireshark's
   * default display), establishing that base the first time a direction is
   * seen. Wraparound-safe: uses unsigned modular subtraction rather than naive
   * arithmetic, since raw TCP sequence numbers legitimately wrap past 2**32 on
   * long-lived connections.
   *
   * The base depends on whether the handshake was captured, and getting this
   * wrong shifts every Seq= and Ack= in the stream by one:
   *
   *   - SYN seen: base = the SYN's own sequence number, so the SYN reports
   *     Seq=0 and the first byte of data reports Seq=1.
   *   - Mid-stream capture (no SYN): base = first seen sequence *minus one*,
   *     so the first observed segment also reports Seq=1. Wireshark does this
   *     so that a capture started mid-connection reads the same way as one
   *     that caught the handshake.
   */
  public getRelativeSeq(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    seqNum: number, isSyn: boolean = false
  ): number {
    const directionKey = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    let base = this.baseSeq.get(directionKey);
    if (base === undefined) {
      base = isSyn ? seqNum : (seqNum - 1 + 2 ** 32) % 2 ** 32;
      this.baseSeq.set(directionKey, base);
    }
    return ((seqNum - base) + 2 ** 32) % 2 ** 32;
  }

  /**
   * Records the window scale shift negotiated by this direction's SYN. Scaling
   * only applies once *both* ends have advertised support, which is why this
   * is stored per direction and checked pairwise in getWindowScaleShift().
   */
  public setWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number, shift: number): void {
    this.windowScaleShift.set(this.directionKey(srcIp, srcPort, dstIp, dstPort), shift);
  }

  /**
   * Returns the shift to apply to this direction's advertised window, or 0
   * when scaling isn't in effect. A mid-stream capture never saw either SYN,
   * so nothing scales and the raw window value is displayed as-is - matching
   * what Wireshark shows when it can't observe the negotiation.
   */
  public getWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const own = this.windowScaleShift.get(this.directionKey(srcIp, srcPort, dstIp, dstPort));
    const peer = this.windowScaleShift.get(this.directionKey(dstIp, dstPort, srcIp, srcPort));
    return own !== undefined && peer !== undefined ? own : 0;
  }

  /**
   * True when this segment's sequence number is ahead of where the sender left
   * off, meaning the capture missed whatever filled the gap - Wireshark's
   * "[TCP Previous segment not captured]". Skipped for the first segment of a
   * direction, which has no predecessor to be missing.
   */
  public isPreviousSegmentMissing(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number
  ): boolean {
    const expectedNext = this.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
    if (expectedNext === undefined) return false;
    // 32-bit signed comparison, so a sequence space that has wrapped past
    // 2**32 doesn't read as an enormous backwards jump.
    return ((seqNum - expectedNext) | 0) > 0;
  }

  /**
   * True when this packet acknowledges data the capture never contained -
   * Wireshark's "[TCP ACKed unseen segment]". Compares against how far the
   * *peer* direction has actually been seen to send.
   */
  public isAckingUnseenSegment(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number, ackNum: number
  ): boolean {
    const peerExpectedNext = this.getExpectedNext(dstIp, dstPort, srcIp, srcPort);
    if (peerExpectedNext === undefined) return false;
    return ((ackNum - peerExpectedNext) | 0) > 0;
  }

  /**
   * Returns the raw sequence number expected in the next segment from this
   * direction (i.e. the current high-water mark), or undefined if no segment
   * from this direction has been through checkSequence() yet.
   */
  public getExpectedNext(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number | undefined {
    const directionKey = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    return this.highWaterSeq.get(directionKey);
  }

  /** Returns this packet's 1-based position within its stream, recording it. */
  public recordStreamPacket(streamId: number): number {
    const count = (this.packetCountByStream.get(streamId) ?? 0) + 1;
    this.packetCountByStream.set(streamId, count);
    return count;
  }

  public updateConnectionState(streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean): void {
    const state = this.connState.get(streamId) ?? { sawSyn: false, sawSynAck: false, sawFinOrRst: false };
    if (syn && !ack) state.sawSyn = true;
    if (syn && ack) state.sawSynAck = true;
    if (fin || rst) state.sawFinOrRst = true;
    this.connState.set(streamId, state);
  }

  /**
   * A plain-English summary of handshake progress - deliberately not
   * Wireshark's internal numeric completeness bitmask, since that's an
   * implementation detail nobody reading this UI needs to decode.
   */
  public getConversationCompleteness(streamId: number): string {
    const state = this.connState.get(streamId);
    if (!state) return 'Incomplete';
    if (state.sawSyn && state.sawSynAck && state.sawFinOrRst) return 'Complete, WITH_DATA';
    if (state.sawSyn && state.sawSynAck) return 'Established, no close seen';
    if (state.sawSyn) return 'SYN sent, no reply seen';
    return 'Incomplete';
  }

  /**
   * A classic TCP Keep-Alive resends 0-1 bytes at (expected next seq - 1),
   * purely to provoke an ACK - without this check, checkSequence() would
   * misread it as a retransmission, since its sequence number is
   * deliberately behind the high-water mark.
   */
  public checkKeepAlive(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    seqNum: number, payloadLength: number, syn: boolean, fin: boolean, rst: boolean
  ): boolean {
    // The flag must be *cleared* as well as set: if a keep-alive goes
    // unanswered and the sender then transmits real data, the peer's ordinary
    // ACK of that data would otherwise still be labeled a Keep-Alive ACK.
    const directionKey = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    if (syn || fin || rst || payloadLength > 1) {
      this.lastWasKeepAlive.set(directionKey, false);
      return false;
    }
    const expectedNext = this.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
    if (expectedNext === undefined) {
      this.lastWasKeepAlive.set(directionKey, false);
      return false;
    }
    const isKeepAlive = seqNum === ((expectedNext - 1 + 2 ** 32) % 2 ** 32);
    this.lastWasKeepAlive.set(directionKey, isKeepAlive);
    return isKeepAlive;
  }

  /**
   * Checks (and clears) whether the peer direction just sent a keep-alive
   * that this ACK is replying to - one-shot, so the same ACK isn't
   * re-labeled on a later unrelated lookup.
   */
  public consumeKeepAliveAck(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    // Swapped arguments address the peer's direction; connectionKey is
    // symmetric, so the resulting key is identical either way round.
    const peerDirectionKey = this.directionKey(dstIp, dstPort, srcIp, srcPort);
    const wasKeepAlive = this.lastWasKeepAlive.get(peerDirectionKey) === true;
    if (wasKeepAlive) this.lastWasKeepAlive.set(peerDirectionKey, false);
    return wasKeepAlive;
  }

  public reset(): void {
    this.streamIds.clear();
    this.highWaterSeq.clear();
    this.baseSeq.clear();
    this.packetCountByStream.clear();
    this.connState.clear();
    this.lastWasKeepAlive.clear();
    this.windowScaleShift.clear();
    this.nextStreamId = 0;
  }
}
