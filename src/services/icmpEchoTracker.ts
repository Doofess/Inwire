/**
 * Correlates ICMP echo request/reply pairs across packets so each side's
 * Info column can reference the other by frame number, mirroring the reference analyzer's
 * "(reply in #N)" / "(request in #N)" annotations. Keyed by the unordered
 * pair of endpoints plus the echo id/sequence, since a request and its reply
 * swap source/destination but keep the same id and sequence number.
 */
export class IcmpEchoTracker {
  private pendingRequests = new Map<string, number>();

  private conversationKey(ipA: string, ipB: string, icmpId: number, icmpSeq: number): string {
    const pair = ipA <= ipB ? `${ipA}|${ipB}` : `${ipB}|${ipA}`;
    return `${pair}:${icmpId}:${icmpSeq}`;
  }

  /** Records an unanswered echo request so a later matching reply can find it. */
  public recordRequest(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number, frameId: number): void {
    this.pendingRequests.set(this.conversationKey(srcIp, dstIp, icmpId, icmpSeq), frameId);
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

  public reset(): void {
    this.pendingRequests.clear();
  }
}
