/**
 * A shard's stand-ins for the Sequencer (ADR 0053 phase 3).
 *
 * A shard dissects only some of the capture's TCP connections, so it cannot
 * number anything that is counted across all of them - `eth.stream`,
 * `ip.stream`, `tcp.stream`, which connection is forgotten past the cap. The
 * coordinator numbers each frame before it sends it, in frame order, and these
 * hand those numbers to the shard's own trackers when they ask - the way
 * `FrameRevisit` hands a record's answers to the same unchanged dissector.
 *
 * **A question the coordinator did not answer is a bug, and it throws.** The
 * header parse that decides which frames may be sharded (`frameLane.ts`) is
 * held by `scripts/pipeline/sequencer.ts` to ask exactly what each frame's
 * dissection asks, so a frame that asked something else would have been
 * numbered by guesswork. `ShardMiss` names the question; the frame fails to
 * dissect and says so, rather than drawing a number nobody assigned.
 */
import {
  DeferredTlsNumbers, NO_KEYS,
  type ConversationFacts, type ConversationIndexApi, type ConversationIndexesApi, type TcpOrderApi,
} from './sequencer';
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

export class ShardMiss extends Error {
  constructor(message: string) {
    super(`shard numbering: ${message}`);
    this.name = 'ShardMiss';
  }
}

/** One conversation index's answer for the frame being dissected. */
class ReplayIndex implements ConversationIndexApi {
  private a: string | undefined;
  private b: string | undefined;
  private facts: ConversationFacts | undefined;

  constructor(private readonly name: string) {}

  /** What the coordinator numbered for this frame; cleared by asking. */
  give(a: string, b: string, facts: ConversationFacts): void {
    this.a = a;
    this.b = b;
    this.facts = facts;
  }

  observe(a: string, b: string): ConversationFacts {
    const facts = this.facts;
    if (facts === undefined) throw new ShardMiss(`${this.name}.stream asked of a frame it was not numbered for`);
    if (!((a === this.a && b === this.b) || (a === this.b && b === this.a))) {
      throw new ShardMiss(`${this.name}.stream asked for ${a} and ${b}, numbered for ${this.a} and ${this.b}`);
    }
    this.facts = undefined;
    return facts;
  }

  /** Nothing is left over from a frame that dissected differently. */
  clear(): void {
    this.facts = undefined;
  }

  seedNext(): void {}
  get evicted(): number { return 0; }
  reset(): void { this.clear(); }
}

/** The four indexes, answering from what the coordinator sent. */
export class ShardConversations implements ConversationIndexesApi {
  readonly eth = new ReplayIndex('eth');
  readonly ip = new ReplayIndex('ip');
  readonly ipv6 = new ReplayIndex('ipv6');
  readonly udp = new ReplayIndex('udp');
  get evicted() { return { eth: 0, ip: 0, ipv6: 0, udp: 0 }; }
  clear(): void {
    this.eth.clear();
    this.ip.clear();
    this.ipv6.clear();
    this.udp.clear();
  }
  reset(): void { this.clear(); }
}

/** What the coordinator knows of a fragment it could not number ahead. */
export interface BarrierHint {
  /** `tcp.stream` for a connection the reassembled segment would create. */
  nextStreamId: number;
  /** The connection creating one would forget, or null when there is room. */
  forgets: string | null;
}

/** What a barrier frame's dissection did to the TCP order, for the coordinator to do too. */
export interface BarrierReport {
  /** The connection the reassembled segment belongs to; absent when nothing reassembled. */
  key?: string;
  created: boolean;
  /** It asked for its `tcp.stream` for the first time. */
  streamAsked: boolean;
}

interface Slot {
  streamId?: number;
  tlsStreamId?: number;
}

/**
 * The TCP order as a shard sees it: its own connections only, each placed and
 * numbered by the coordinator, and `tls.stream` as a placeholder until the
 * merge numbers it (`DeferredTlsNumbers`).
 *
 * Forgetting is the coordinator's decision too: a connection it forgets is
 * dropped here by `drop` before the next frame, which is where the sequential
 * build forgot it - inside the lookup of the frame that pushed it out.
 */
export class ShardTcpOrder implements TcpOrderApi {
  private readonly slots = new Map<string, Slot>();
  readonly tls = new DeferredTlsNumbers();
  /** The frame being dissected: its connection and that connection's number. */
  private frame: { key: string; streamId: number } | null = null;
  private barrier: BarrierHint | null = null;
  private report: BarrierReport = { created: false, streamAsked: false };

  /** Before a TCP-lane frame. */
  numbered(key: string, streamId: number): void {
    this.frame = { key, streamId };
    this.barrier = null;
  }

  /** Before a fragment, which only its own dissection can number. */
  fragment(hint: BarrierHint): void {
    this.frame = null;
    this.barrier = hint;
    this.report = { created: false, streamAsked: false };
  }

  /** After the frame: what a barrier did, or null for any other frame. */
  done(): BarrierReport | null {
    const report = this.barrier === null ? null : this.report;
    this.frame = null;
    this.barrier = null;
    return report;
  }

  locate(key: string): readonly string[] {
    if (this.frame !== null) {
      if (key !== this.frame.key) throw new ShardMiss(`a TCP lookup on ${key}, numbered for ${this.frame.key}`);
      if (!this.slots.has(key)) this.slots.set(key, {});
      return NO_KEYS;
    }
    if (this.barrier !== null) {
      if (this.report.key !== undefined && this.report.key !== key) {
        throw new ShardMiss(`a fragment looked up ${key} after ${this.report.key}`);
      }
      this.report.key = key;
      if (this.slots.has(key)) return NO_KEYS;
      this.slots.set(key, {});
      this.report.created = true;
      const gone = this.barrier.forgets;
      if (gone === null) return NO_KEYS;
      // Forgotten here as the sequential build would, inside this lookup; the
      // coordinator forgets it on whichever shard holds it once told.
      this.slots.delete(gone);
      return [gone];
    }
    throw new ShardMiss(`a TCP lookup on ${key} the coordinator did not number`);
  }

  streamId(key: string): number {
    const slot = this.slots.get(key);
    if (slot === undefined) throw new ShardMiss(`tcp.stream for ${key}, which was never located`);
    if (slot.streamId !== undefined) return slot.streamId;
    if (this.frame !== null) {
      slot.streamId = this.frame.streamId;
    } else if (this.barrier !== null) {
      slot.streamId = this.barrier.nextStreamId;
      this.report.streamAsked = true;
    } else {
      throw new ShardMiss(`tcp.stream for ${key} outside a numbered frame`);
    }
    return slot.streamId;
  }

  tlsStreamId(key: string): number {
    const slot = this.slots.get(key);
    if (slot === undefined) throw new ShardMiss(`tls.stream for ${key}, which was never located`);
    slot.tlsStreamId ??= this.tls.assign();
    return this.tls.resolve(slot.tlsStreamId);
  }

  /** The coordinator forgot this connection. */
  drop(key: string): void {
    this.slots.delete(key);
  }

  seedNextStreamId(): void {
    throw new ShardMiss('a shard is never seeded');
  }

  seedNextTlsStreamId(): void {
    throw new ShardMiss('a shard is never seeded');
  }

  get evicted(): number { return 0; }
  get size(): number { return this.slots.size; }

  reset(): void {
    this.slots.clear();
    this.tls.reset();
    this.frame = null;
    this.barrier = null;
  }
}

/**
 * A cached tree's `tls.stream` rows with their placeholders replaced, in
 * place: the tree was built before the merge numbered its connection.
 */
export function settleTreeTls(layers: readonly ProtocolLayer[], resolve: (placeholder: number) => number): void {
  const walk = (fields: readonly ProtocolField[]): void => {
    for (const field of fields) {
      if (field.abbrev === 'tls.stream' && typeof field.value === 'number' && field.value < 0) {
        field.value = resolve(field.value);
      }
      if (field.children) walk(field.children);
    }
  };
  for (const layer of layers) walk(layer.fields);
}

/** A shard's Sequencer: the two parts its trackers ask. */
export class ShardSequencer {
  readonly conversations = new ShardConversations();
  readonly tcp = new ShardTcpOrder();
}
