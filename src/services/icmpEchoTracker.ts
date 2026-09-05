/**
 * Correlates ICMP echo request/reply pairs across packets so each side's
 * Info column can reference the other by frame number, mirroring the reference analyzer's
 * "(reply in #N)" / "(request in #N)" annotations. Keyed by the unordered
 * pair of endpoints plus the echo id/sequence, since a request and its reply
 * swap source/destination but keep the same id and sequence number.
 */

/**
 * How many unanswered requests are remembered.
 *
 * An entry is only held while a request has no reply, so an ordinary ping
 * leaves at most one - but a **ping sweep leaves one per probe**, for the
 * length of the capture, and nothing was ever removing them. Measured at 275 B
 * a probe (`scripts/perf/tracker-cost.ts`), which is 51 MB for a /16 swept
 * once: state whose only purpose is to answer a reply that is never coming.
 *
 * Losing the oldest is the right thing to lose. A reply whose request has been
 * evicted simply does not get its "(request in N)" cross-reference - the frame
 * is still dissected, still filtered, still exported. The alternative is to
 * grow without limit on exactly the traffic that produces the most entries.
 */
const MAX_PENDING = 4096;

export class IcmpEchoTracker {
  /**
   * Insertion-ordered, which is what makes the eviction below free: a Map
   * iterates in insertion order, so `keys().next()` is the oldest pending
   * request and no second structure has to be kept in step with this one.
   */
  private pendingRequests = new Map<string, number>();

  private conversationKey(ipA: string, ipB: string, icmpId: number, icmpSeq: number): string {
    const pair = ipA <= ipB ? `${ipA}|${ipB}` : `${ipB}|${ipA}`;
    return `${pair}:${icmpId}:${icmpSeq}`;
  }

  /** Records an unanswered echo request so a later matching reply can find it. */
  public recordRequest(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number, frameId: number): void {
    const key = this.conversationKey(srcIp, dstIp, icmpId, icmpSeq);
    // Delete before setting, so a repeated probe moves to the back of the
    // queue rather than keeping the position of its first attempt.
    this.pendingRequests.delete(key);
    this.pendingRequests.set(key, frameId);
    while (this.pendingRequests.size > MAX_PENDING) {
      const oldest = this.pendingRequests.keys().next();
      if (oldest.done) break;
      this.pendingRequests.delete(oldest.value);
    }
  }

  /**
   * Looks up (and consumes) the request frame matching this reply, if any.
   * Returns undefined when no matching request has been seen.
   */
  public matchReply(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number): number | undefined {
    const key = this.conversationKey(srcIp, dstIp, icmpId, icmpSeq);
    const requestFrameId = this.pendingRequests.get(key);
    if (requestFrameId !== undefined) this.pendingRequests.delete(key);
    return requestFrameId;
  }

  /** How many requests are still waiting for a reply. */
  public get pendingCount(): number {
    return this.pendingRequests.size;
  }

  public reset(): void {
    this.pendingRequests.clear();
  }
}
