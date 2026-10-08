/**
 * Everything a capture numbers in arrival order ACROSS its conversations, in
 * one place (ADR 0053, phase 2).
 *
 * Most cross-frame state in this build belongs to one conversation: a TCP
 * connection's sequence analysis, a DNS query and its answer, a QUIC
 * connection's keys. That state can be kept by whoever dissects that
 * conversation, because no other conversation's frames move it. What is here
 * is the opposite - numbers whose value depends on the order of frames from
 * EVERY conversation:
 *
 *   - each frame's two clocks (`FrameClock`);
 *   - `eth.stream`, `ip.stream`, `ipv6.stream` and `udp.stream`, each the
 *     order in which a conversation was first seen (`ConversationIndex`);
 *   - `tcp.stream` and `tls.stream`, and which TCP connection is forgotten
 *     when more than 16,384 are open (`TcpOrder`).
 *
 * They lived inside the trackers, which was right while one Worker saw every
 * frame in order. Dissection on several cores (ADR 0053 phase 3) splits
 * conversations across Workers, and then a number like these is only right
 * if one stage hands it out in frame order. This is that stage. With one
 * Worker the trackers hold a `Sequencer` and ask it, so the output is byte for
 * byte what it was (`scripts/pipeline/sequencer.ts`), and the multi-core build
 * is the same code with one shard.
 *
 * **Nothing here reaches a dissector directly.** The trackers keep their
 * methods (`ethStream`, `getStreamId`, ...), so `dissect/trackerApi.ts` and
 * every frame record are unchanged; the Sequencer is what answers them.
 *
 * **What is not here, each for a stated reason:**
 *   - counters that start again per conversation (TCP's relative sequence
 *     numbers, a stream's packet number): whoever dissects the conversation
 *     owns those, because only its own frames move them;
 *   - first-use numbers on protocols that stay on the sequential lane:
 *     WireGuard's and DTLS's stream numbers and QUIC's connection number.
 *     Phase 3 shards TCP only;
 *   - the HTTP/1 body budget every connection shares, which ADR 0053 accepts
 *     splitting across shards rather than numbering.
 *
 * Frame ids are not here either: the live Worker's ordering window and the
 * import loop already assign them, in order, on the stage that will become the
 * coordinator - moving the counter would move nothing.
 */

/**
 * How many conversations each per-layer index remembers.
 *
 * Matches `MAX_TCP_CONNECTIONS` below deliberately: these are the same kind of
 * object bounded for the same reason (docs/decisions/0014), and two different
 * caps would only invite the question of which was right.
 */
export const MAX_CONVERSATIONS = 16384;

/** What a conversation index knows about one conversation. */
export interface ConversationFacts {
  /** Assigned in order of first appearance, and never reused. */
  index: number;
  /** This frame's position in the conversation, counting from 1. */
  pnum: number;
  /** Seconds since the conversation's first frame. */
  sinceFirst: number;
  /** Seconds since the conversation's previous frame. */
  sincePrev: number;
}

interface ConversationRecord {
  index: number;
  packets: number;
  firstTsUs: number;
  lastTsUs: number;
}

/**
 * A conversation index: the thing that turns an endpoint pair into the small
 * integer the reference analyzer calls `eth.stream`, `ip.stream`, `ipv6.stream`
 * or `udp.stream`.
 *
 * ## Why this is an arrival-order counter and not a hash
 *
 * A hash of the tuple would be tempting: it needs no state, it is stable
 * across a replay with no seeding, and it would pass every assertion in this
 * repository. It is also wrong in the one way that matters. These numbers are
 * the reference's numbers - somebody reads `ip.stream == 3` off Wireshark and
 * types it here - so an index that is internally consistent but disagrees with
 * Wireshark answers a different question while looking like the same one.
 * Arrival order is not an implementation detail of this field; it IS the
 * field. That is also why it has to be handed out by one stage in frame order
 * once conversations are dissected on several cores.
 *
 * That choice is what forces `seedNext`, and through it the five stream
 * indices into `Packet.fields`: a replay rebuilds one conversation from a
 * five-tuple bundle and would otherwise call it 0. See
 * `L3Tracker.seedNextIndices`.
 *
 * Bounded like every other tracker here. An index is never reused: evicting a
 * conversation forgets it, and if it comes back it is a new one with a new
 * number, which is what `TcpOrder` does and for the same reason - the
 * alternative is two conversations answering to one id. Unlike `TcpOrder`, the
 * oldest conversation FIRST SEEN goes, not the least recently seen: the record
 * is not moved on a hit.
 */
export class ConversationIndex {
  private readonly seen = new Map<string, ConversationRecord>();
  private next = 0;
  private evictedCount = 0;
  /**
   * The last conversation looked up, remembered by its ENDPOINTS rather than
   * by its key.
   *
   * Consecutive frames share a conversation almost always - overwhelmingly so
   * for the MAC pair, which is consulted on every frame. Both orders are
   * checked because a conversation's two directions arrive interleaved, and
   * they are the same conversation.
   *
   * **Comparing the endpoints rather than a composed key was an optimisation
   * that did not work, and saying so is the point.** The reasoning was that a
   * hit should not have to build the key string at all; three runs each side
   * measured 27,315 f/s against 27,499 for the composed-key version, which is
   * no better and inside the noise. So the ~2.8% these indices cost is not the
   * concatenation, and whoever tries to buy it back should look at the Map
   * probe, the per-conversation record, or the four extra tree rows - not
   * here. This form is kept only because it allocates less for the same
   * speed; it is not the reason anything got faster, because nothing did.
   */
  private lastA?: string;
  private lastB?: string;
  private lastRecord?: ConversationRecord;

  observe(a: string, b: string, tsUs: number): ConversationFacts {
    let record: ConversationRecord | undefined;
    if (this.lastRecord !== undefined
      && ((this.lastA === a && this.lastB === b) || (this.lastA === b && this.lastB === a))) {
      record = this.lastRecord;
    } else {
      const key = a < b ? `${a}|${b}` : `${b}|${a}`;
      record = this.seen.get(key);
      if (record === undefined) {
        if (this.seen.size >= MAX_CONVERSATIONS) {
          const oldest = this.seen.keys().next();
          if (!oldest.done) { this.seen.delete(oldest.value); this.evictedCount++; }
        }
        record = { index: this.next++, packets: 0, firstTsUs: tsUs, lastTsUs: tsUs };
        this.seen.set(key, record);
      }
      this.lastA = a;
      this.lastB = b;
      this.lastRecord = record;
    }

    record.packets++;
    const sinceFirst = (tsUs - record.firstTsUs) / 1_000_000;
    // The first frame of a conversation has no previous one, and the reference
    // prints 0 rather than omitting the row.
    const sincePrev = record.packets === 1 ? 0 : (tsUs - record.lastTsUs) / 1_000_000;
    record.lastTsUs = tsUs;
    return { index: record.index, pnum: record.packets, sinceFirst, sincePrev };
  }

  /** See `L3Tracker.seedNextIndices`. */
  seedNext(index: number): void {
    if (this.next === 0) this.next = index;
  }

  get evicted(): number { return this.evictedCount; }

  reset(): void {
    this.seen.clear();
    this.next = 0;
    this.evictedCount = 0;
    this.lastA = undefined;
    this.lastB = undefined;
    this.lastRecord = undefined;
  }
}

/** The four conversation indexes, each numbered across the whole capture. */
export class ConversationIndexes {
  readonly eth = new ConversationIndex();
  readonly ip = new ConversationIndex();
  readonly ipv6 = new ConversationIndex();
  readonly udp = new ConversationIndex();

  /** Conversations forgotten to the cap, per index - the counter ADR 0014 wants. */
  get evicted(): { eth: number; ip: number; ipv6: number; udp: number } {
    return { eth: this.eth.evicted, ip: this.ip.evicted, ipv6: this.ipv6.evicted, udp: this.udp.evicted };
  }

  reset(): void {
    this.eth.reset();
    this.ip.reset();
    this.ipv6.reset();
    this.udp.reset();
  }
}

/**
 * How many TCP connections hold state at once; past it the least recently
 * seen one is forgotten (docs/decisions/0014). Forgetting is what makes a
 * connection that comes back a new one, with a new `tcp.stream`.
 */
export const MAX_TCP_CONNECTIONS = 16384;

/** What the order knows of one connection: its numbers, once it has them. */
interface TcpSlot {
  streamId?: number;
  tlsStreamId?: number;
}

const NO_KEYS: readonly string[] = [];

/**
 * The global half of TCP: which connections are remembered, in what order they
 * were last seen, and the two sequences numbered across them.
 *
 * `TcpStreamTracker` keeps each connection's STATE; this keeps its place. Every
 * lookup that moved a connection to the back of the tracker's
 * least-recently-used map calls `locate` here instead, at exactly the same
 * points, so the connection forgotten past the cap is the same one.
 *
 * Keys are the tracker's own (`tcpConnectionKey`), so the two can never
 * disagree about which connection a frame belongs to.
 */
export class TcpOrder {
  /** Connection keys in least-recently-used order: a Map iterates in insertion order. */
  private readonly slots = new Map<string, TcpSlot>();
  private nextStreamId = 0;
  private nextTlsStreamId = 0;
  /** The key the last lookup found, which a repeat need not move again. */
  private lastKey: string | undefined;
  private evictedCount = 0;

  /**
   * Finds a connection's place - created at the back on first sight, moved
   * there when it is not already the last one seen - and returns the keys
   * forgotten to stay inside the cap, never the one just created. The caller
   * drops its own state for each.
   */
  locate(key: string): readonly string[] {
    const slot = this.slots.get(key);
    let evicted: string[] | undefined;
    if (slot === undefined) {
      this.slots.set(key, {});
      while (this.slots.size > MAX_TCP_CONNECTIONS) {
        const oldest = this.slots.keys().next();
        if (oldest.done) break;
        this.slots.delete(oldest.value);
        if (this.lastKey === oldest.value) this.lastKey = undefined;
        (evicted ??= []).push(oldest.value);
        this.evictedCount += 1;
      }
    } else if (key !== this.lastKey) {
      // Deleted and re-set rather than left alone: that is what moves it to
      // the back of the eviction order.
      this.slots.delete(key);
      this.slots.set(key, slot);
    }
    this.lastKey = key;
    return evicted ?? NO_KEYS;
  }

  /**
   * `tcp.stream`: this connection's place among the connections, assigned the
   * first time it is asked - not when the connection is created - and never
   * reused. Only for a connection `locate` has placed.
   */
  streamId(key: string): number {
    const slot = this.slots.get(key)!;
    slot.streamId ??= this.nextStreamId++;
    return slot.streamId;
  }

  /**
   * `tls.stream`: as `streamId`, numbering only the connections that produced
   * a TLS record.
   *
   * **The one number here a header cannot predict.** A connection takes it on
   * its first TLS record, which only dissecting the payload finds. Phase 3
   * cannot hand it to a shard ahead of time the way it hands `tcp.stream`;
   * ADR 0053 records what it needs instead.
   */
  tlsStreamId(key: string): number {
    const slot = this.slots.get(key)!;
    slot.tlsStreamId ??= this.nextTlsStreamId++;
    return slot.tlsStreamId;
  }

  /** A replay's tracker meets one connection and must number it as the capture did. */
  seedNextStreamId(id: number): void {
    this.nextStreamId = id;
  }

  seedNextTlsStreamId(next: number): void {
    if (this.nextTlsStreamId === 0) this.nextTlsStreamId = next;
  }

  /** Connections forgotten to the cap. */
  get evicted(): number {
    return this.evictedCount;
  }

  /** Connections currently remembered. */
  get size(): number {
    return this.slots.size;
  }

  reset(): void {
    this.slots.clear();
    this.nextStreamId = 0;
    this.nextTlsStreamId = 0;
    this.lastKey = undefined;
    this.evictedCount = 0;
  }
}

/**
 * The key a TCP connection is known by, for both of its directions, and which
 * of the two the sender is.
 *
 * One function for the tracker and for the Sequencer's header parse, so the
 * two can never disagree about which connection a frame belongs to.
 */
export function tcpConnectionKey(
  srcIp: string, srcPort: number, dstIp: string, dstPort: number,
): { key: string; senderIsA: boolean } {
  const from = `${srcIp}:${srcPort}`;
  const to = `${dstIp}:${dstPort}`;
  const senderIsA = from <= to;
  return { key: senderIsA ? `${from}|${to}` : `${to}|${from}`, senderIsA };
}

/**
 * A frame's two clocks: seconds since the capture's first frame, and since the
 * frame before it.
 *
 * Two forms, because the two paths that number frames are handed time in two
 * forms, and each keeps the arithmetic it had, digit for digit:
 *
 *   - an import has the stamp as epoch nanoseconds, and subtracts in `bigint`
 *     before converting, which keeps nanosecond precision: the difference is a
 *     small number of seconds and lands well inside float64's exact range, even
 *     though the absolute epoch-nanosecond value does not;
 *   - the live Worker has microseconds and the nanoseconds past them, and its
 *     delta is clamped at zero, because frames from two adapters can arrive out
 *     of stamp order and a negative gap between frames is not a gap.
 */
export class FrameClock {
  private baseNanos: bigint | null = null;
  private previousNanos: bigint | null = null;
  private startUs: number | null = null;
  private startNsRem = 0;
  private lastUs: number | null = null;
  private lastNsRem = 0;

  fromNanos(tsNanos: bigint): { relativeTime: number; timeDelta: number } {
    if (this.baseNanos === null) this.baseNanos = tsNanos;
    const relativeTime = Number(tsNanos - this.baseNanos) / 1e9;
    const timeDelta = this.previousNanos === null ? 0 : Number(tsNanos - this.previousNanos) / 1e9;
    this.previousNanos = tsNanos;
    return { relativeTime, timeDelta };
  }

  fromLive(tsUs: number, tsNsRem: number): { relativeTime: number; timeDelta: number } {
    if (this.startUs === null) {
      this.startUs = tsUs;
      this.startNsRem = tsNsRem;
      this.lastUs = null;
    }
    // In nanoseconds, then seconds: a difference of two stamps is small enough
    // that its nanosecond count is exact in a double where the stamps are not.
    const relativeTime = ((tsUs - this.startUs) * 1000 + tsNsRem - this.startNsRem) / 1e9;
    const timeDelta = this.lastUs !== null
      ? Math.max(0, ((tsUs - this.lastUs) * 1000 + tsNsRem - this.lastNsRem) / 1e9)
      : 0;
    this.lastUs = tsUs;
    this.lastNsRem = tsNsRem;
    return { relativeTime, timeDelta };
  }

  reset(): void {
    this.baseNanos = null;
    this.previousNanos = null;
    this.startUs = null;
    this.startNsRem = 0;
    this.lastUs = null;
    this.lastNsRem = 0;
  }
}

/**
 * The one stage that numbers across conversations.
 *
 * Its parts are separate objects because each is asked through a different
 * tracker - the conversation indexes through `L3Tracker`, the TCP order
 * through `TcpStreamTracker` - and a tracker built without one makes its own,
 * which is the same thing: no part reads another. The Worker builds one and
 * hands it to both, which is what phase 3's coordinator will hold.
 */
export class Sequencer {
  readonly clock = new FrameClock();
  readonly conversations = new ConversationIndexes();
  readonly tcp = new TcpOrder();

  reset(): void {
    this.clock.reset();
    this.conversations.reset();
    this.tcp.reset();
  }
}
