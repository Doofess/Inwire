/**
 * Pairs DNS queries with their responses across frames.
 *
 * The same shape as `IcmpEchoTracker`, and for the same reason: a single-pass
 * dissector cannot see the future, so the response records the link and the
 * request is patched afterwards. Wireshark shows `[Request In: 10]` and
 * `[Time: 4.3 ms]` on the response and `[Response In: 14]` on the query, and
 * those two numbers are how anyone answers "was the resolver slow, or did it
 * never answer at all".
 *
 * Keyed by transaction id, the client's address and its port: a resolver
 * handles many queries at once and transaction ids are only unique per client.
 * mDNS uses transaction id 0 for everything, so multicast messages are keyed
 * on the question name too, and are only paired within a short window.
 */

export interface DnsPending {
  frameId: number;
  tsUs: number;
}

/** How long a query waits for its answer before it is considered unanswered. */
const QUERY_TIMEOUT_US = 5_000_000;

/** Bounds memory on a capture full of queries that were never answered. */
const MAX_PENDING = 4096;

export class DnsTracker {
  private pending = new Map<string, DnsPending>();
  /** Queries still waiting, oldest first, for the unanswered sweep. */
  private order: string[] = [];

  private key(transactionId: number, clientIp: string, clientPort: number, questionName: string, multicast: boolean): string {
    // mDNS transaction ids are all zero, so the question name is the only
    // distinguishing part - and the address cannot be, because the answer
    // comes from whichever host owns the name, not from the one that asked.
    // Unicast DNS pairs on the id and the client, which is what a resolver
    // echoes back and the only thing that makes an id unique.
    return multicast
      ? `m|${questionName.toLowerCase()}`
      : `u|${clientIp}:${clientPort}|${transactionId}`;
  }

  recordQuery(
    transactionId: number, clientIp: string, clientPort: number, questionName: string,
    multicast: boolean, frameId: number, tsUs: number,
  ): void {
    const k = this.key(transactionId, clientIp, clientPort, questionName, multicast);
    if (!this.pending.has(k)) this.order.push(k);
    this.pending.set(k, { frameId, tsUs });
    if (this.order.length > MAX_PENDING) {
      const evicted = this.order.shift();
      if (evicted !== undefined) this.pending.delete(evicted);
    }
  }

  /**
   * The query this response answers, and how long it took. Consumed on match,
   * so a retransmitted response does not claim the same query twice - the
   * second one is a response with no request, which is itself worth seeing.
   */
  matchResponse(
    transactionId: number, clientIp: string, clientPort: number, questionName: string,
    multicast: boolean, tsUs: number,
  ): { frameId: number; elapsedUs: number } | undefined {
    const k = this.key(transactionId, clientIp, clientPort, questionName, multicast);
    const hit = this.pending.get(k);
    if (hit === undefined) return undefined;
    // A multicast answer far removed from the question is a fresh
    // announcement, not a reply to it.
    if (multicast && tsUs - hit.tsUs > QUERY_TIMEOUT_US) return undefined;
    this.pending.delete(k);
    const at = this.order.indexOf(k);
    if (at >= 0) this.order.splice(at, 1);
    return { frameId: hit.frameId, elapsedUs: tsUs - hit.tsUs };
  }

  /** Queries with no answer after the timeout, for the expert list. */
  unanswered(nowUs: number): number[] {
    const out: number[] = [];
    for (const k of this.order) {
      const p = this.pending.get(k);
      if (p && nowUs - p.tsUs > QUERY_TIMEOUT_US) out.push(p.frameId);
    }
    return out;
  }

  reset(): void {
    this.pending.clear();
    this.order = [];
  }
}
