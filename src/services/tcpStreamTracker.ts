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

  private connectionKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    const a = `${srcIp}:${srcPort}`;
    const b = `${dstIp}:${dstPort}`;
    return a <= b ? `${a}|${b}` : `${b}|${a}`;
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
    const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
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
   * Returns the sequence number relative to the first one seen in this
   * direction (Wireshark's default display), establishing that base the
   * first time a direction is seen. Wraparound-safe: uses unsigned modular
   * subtraction rather than naive arithmetic, since raw TCP sequence numbers
   * legitimately wrap past 2**32 on long-lived connections.
   */
  public getRelativeSeq(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number): number {
    const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
    let base = this.baseSeq.get(directionKey);
    if (base === undefined) {
      base = seqNum;
      this.baseSeq.set(directionKey, base);
    }
    return ((seqNum - base) + 2 ** 32) % 2 ** 32;
  }

  /**
   * Returns the raw sequence number expected in the next segment from this
   * direction (i.e. the current high-water mark), or undefined if no segment
   * from this direction has been through checkSequence() yet.
   */
  public getExpectedNext(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number | undefined {
    const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
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
    if (syn || fin || rst || payloadLength > 1) return false;
    const expectedNext = this.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
    if (expectedNext === undefined) return false;
    const isKeepAlive = seqNum === ((expectedNext - 1 + 2 ** 32) % 2 ** 32);
    if (isKeepAlive) {
      const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
      this.lastWasKeepAlive.set(directionKey, true);
    }
    return isKeepAlive;
  }

  /**
   * Checks (and clears) whether the peer direction just sent a keep-alive
   * that this ACK is replying to - one-shot, so the same ACK isn't
   * re-labeled on a later unrelated lookup.
   */
  public consumeKeepAliveAck(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    const peerDirectionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${dstIp}:${dstPort}`;
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
    this.nextStreamId = 0;
  }
}
