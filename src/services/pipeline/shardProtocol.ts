/**
 * What the pipeline Worker and its TCP shards say to each other (ADR 0053
 * phase 3). Every message is a structured clone.
 *
 * **A batch of frames is packed, not a list of objects.** It was a list: each
 * frame an object holding its numbers, two conversation answers and their
 * endpoints, each one more object - and a shard spent 6 us a frame
 * deserializing them, a fifth of its time, before dissecting anything
 * (`scripts/perf/parallel-threads.ts`). Now every number a frame carries is a
 * slot in one `Float64Array`, every string is an index into one list that
 * holds each string once per batch, and the frames' bytes are one slab beside
 * them: copied in as each frame is written, and cut by `ends`. A batch is then
 * three transferred buffers however many frames it holds, where a buffer a
 * frame cost a transfer apiece (#17).
 *
 * **The bytes go one way.** A shard keeps no frame for the merge: the
 * coordinator still holds each frame's own bytes, because the shard was given
 * a copy, and the row comes back as a pack without them (`ShardResult`).
 */
import type { ConversationFacts } from '../dissect/sequencer';
import type { BarrierHint, BarrierReport } from '../dissect/shardNumbering';
import type { InfoPatch } from '../dissect/types';
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { RowPack } from './rowPack';
import type { RowSide } from './rowSteps';
import type { FlowAnnotationStore } from '../flowAnnotations';

/** A frame, as a lane dissects it. */
export interface WireFrame {
  id: number;
  bytes: Uint8Array;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  origLen: number;
  linktype: number;
  /** The agent's adapter index, looked up in the shard's copy of the table. */
  iface?: number;
  /**
   * `holeBefore`: the frames the live stream skipped just before this one,
   * which `markLiveGap` writes into the row. A shard writes it because it is
   * the one packing the row.
   */
  facts?: { nanosRemainder?: number; holeBefore?: number };
}

/** One conversation index's answer, and the two endpoints it was asked for. */
export interface Numbered {
  a: string;
  b: string;
  facts: ConversationFacts;
}

export const OP_TCP = 0;
export const OP_FRAGMENT = 1;
export const OP_FORGET = 2;

// The slots of one op, in `OpBatch.nums`.
const KIND = 0;
const ID = 1;
const TS_US = 2;
const RELATIVE = 3;
const DELTA = 4;
const ORIG_LEN = 5;
const LINKTYPE = 6;
const IFACE = 7;
/** NaN: no facts object; -1: one without nanoseconds; else the nanoseconds. */
const NANOS = 8;
const FAMILY = 9;
const ETH = 10; // index, pnum, sinceFirst, sincePrev
const IP = 14; // the same four
/** `tcp.stream` for a segment; the next one, for a fragment. */
const STREAM = 18;
/** The connection's string; for a fragment, the one creating a connection would forget (-1: none). */
const KEY = 19;
const ETH_A = 20;
const ETH_B = 21;
const IP_A = 22;
const IP_B = 23;
/** The frames skipped just before this one; -1: none (a hole is always at least 1). */
const HOLE = 24;
const SLOTS = 25;

/** A batch of ops for one shard, as it travels. */
export interface OpBatch {
  nums: Float64Array;
  strings: string[];
  /**
   * Every frame's bytes, end to end in the order the frames were written. A
   * buffer of its own, exactly sized: it is transferred whole.
   */
  bytes: Uint8Array;
  /** One per frame op, in order: where that frame's bytes end in `bytes`. A frame begins where the one before ended. */
  ends: Uint32Array;
}

/** Builds one batch, op by op, in frame order. */
export class OpWriter {
  private nums = new Float64Array(SLOTS * 64);
  private count = 0;
  private readonly strings: string[] = [];
  private readonly stringAt = new Map<string, number>();
  /** The frames' bytes so far; grows by doubling. */
  private slab = new Uint8Array(16384);
  private used = 0;
  private ends = new Uint32Array(64);
  /** Frame ops written - what a batch is sized by. */
  frames = 0;

  private intern(s: string): number {
    let at = this.stringAt.get(s);
    if (at === undefined) {
      at = this.strings.length;
      this.strings.push(s);
      this.stringAt.set(s, at);
    }
    return at;
  }

  private slot(): number {
    if ((this.count + 1) * SLOTS > this.nums.length) {
      const grown = new Float64Array(this.nums.length * 2);
      grown.set(this.nums);
      this.nums = grown;
    }
    return this.count++ * SLOTS;
  }

  private frame(kind: number, frame: WireFrame, family: 'ip' | 'ipv6', eth: Numbered, ip: Numbered): number {
    const at = this.slot();
    const nums = this.nums;
    nums[at + KIND] = kind;
    nums[at + ID] = frame.id;
    nums[at + TS_US] = frame.tsUs;
    nums[at + RELATIVE] = frame.relativeTime;
    nums[at + DELTA] = frame.timeDelta;
    nums[at + ORIG_LEN] = frame.origLen;
    nums[at + LINKTYPE] = frame.linktype;
    nums[at + IFACE] = frame.iface ?? -1;
    nums[at + NANOS] = frame.facts === undefined ? Number.NaN : frame.facts.nanosRemainder ?? -1;
    nums[at + HOLE] = frame.facts?.holeBefore ?? -1;
    nums[at + FAMILY] = family === 'ip' ? 0 : 1;
    writeFacts(nums, at + ETH, eth.facts);
    writeFacts(nums, at + IP, ip.facts);
    nums[at + ETH_A] = this.intern(eth.a);
    nums[at + ETH_B] = this.intern(eth.b);
    nums[at + IP_A] = this.intern(ip.a);
    nums[at + IP_B] = this.intern(ip.b);
    this.append(frame.bytes);
    return at;
  }

  /** Copies one frame's bytes onto the slab: the caller keeps its own view, whole. */
  private append(bytes: Uint8Array): void {
    const end = this.used + bytes.length;
    if (end > this.slab.length) {
      const grown = new Uint8Array(Math.max(end, this.slab.length * 2));
      grown.set(this.slab.subarray(0, this.used));
      this.slab = grown;
    }
    if (this.frames === this.ends.length) {
      const grown = new Uint32Array(this.ends.length * 2);
      grown.set(this.ends);
      this.ends = grown;
    }
    this.slab.set(bytes, this.used);
    this.used = end;
    this.ends[this.frames++] = end;
  }

  /** A plain TCP segment, numbered whole. */
  tcp(frame: WireFrame, family: 'ip' | 'ipv6', eth: Numbered, ip: Numbered, key: string, streamId: number): void {
    const at = this.frame(OP_TCP, frame, family, eth, ip);
    this.nums[at + STREAM] = streamId;
    this.nums[at + KEY] = this.intern(key);
  }

  /** A fragment of a TCP datagram: numbered as far as its headers go, the rest on report. */
  fragment(frame: WireFrame, family: 'ip' | 'ipv6', eth: Numbered, ip: Numbered, hint: BarrierHint): void {
    const at = this.frame(OP_FRAGMENT, frame, family, eth, ip);
    this.nums[at + STREAM] = hint.nextStreamId;
    this.nums[at + KEY] = hint.forgets === null ? -1 : this.intern(hint.forgets);
  }

  /** The coordinator's order forgot this connection. */
  forget(key: string): void {
    const at = this.slot();
    this.nums[at + KIND] = OP_FORGET;
    this.nums[at + KEY] = this.intern(key);
  }

  get empty(): boolean {
    return this.count === 0;
  }

  /**
   * The batch, ready to send: its numbers, bytes and ends are what a transfer
   * list moves. Each is copied out to a buffer of its own, exactly sized - the
   * growing ones are larger than what they hold, and a transfer moves a buffer
   * whole.
   */
  seal(): OpBatch {
    return {
      nums: this.nums.slice(0, this.count * SLOTS),
      strings: this.strings,
      bytes: this.slab.slice(0, this.used),
      ends: this.ends.slice(0, this.frames),
    };
  }
}

function writeFacts(nums: Float64Array, at: number, facts: ConversationFacts): void {
  nums[at] = facts.index;
  nums[at + 1] = facts.pnum;
  nums[at + 2] = facts.sinceFirst;
  nums[at + 3] = facts.sincePrev;
}

function readFacts(nums: Float64Array, at: number): ConversationFacts {
  return { index: nums[at], pnum: nums[at + 1], sinceFirst: nums[at + 2], sincePrev: nums[at + 3] };
}

/** One op of a received batch, read in place. */
export interface ReadOp {
  kind: number;
  key: string | null;
  frame?: WireFrame;
  family?: 'ip' | 'ipv6';
  eth?: Numbered;
  ip?: Numbered;
  streamId?: number;
  hint?: BarrierHint;
}

/** Every op of a batch, in order. */
export function* readOps(batch: OpBatch): Generator<ReadOp> {
  const { nums, strings, bytes, ends } = batch;
  let frame = 0;
  for (let at = 0; at < nums.length; at += SLOTS) {
    const kind = nums[at + KIND];
    if (kind === OP_FORGET) {
      yield { kind, key: strings[nums[at + KEY]] };
      continue;
    }
    const nanos = nums[at + NANOS];
    const iface = nums[at + IFACE];
    const hole = nums[at + HOLE];
    // A view into the slab, not a copy: it is the frame's own bytes to the
    // dissector, and the slab lives as long as the batch does.
    const from = frame === 0 ? 0 : ends[frame - 1];
    const to = ends[frame++];
    const wire: WireFrame = {
      id: nums[at + ID], bytes: bytes.subarray(from, to), tsUs: nums[at + TS_US], relativeTime: nums[at + RELATIVE],
      timeDelta: nums[at + DELTA], origLen: nums[at + ORIG_LEN], linktype: nums[at + LINKTYPE],
      ...(iface >= 0 ? { iface } : {}),
      ...(Number.isNaN(nanos) && hole < 0 ? {} : {
        facts: {
          ...(Number.isNaN(nanos) ? {} : { nanosRemainder: nanos < 0 ? undefined : nanos }),
          ...(hole >= 0 ? { holeBefore: hole } : {}),
        },
      }),
    };
    const eth: Numbered = { a: strings[nums[at + ETH_A]], b: strings[nums[at + ETH_B]], facts: readFacts(nums, at + ETH) };
    const ip: Numbered = { a: strings[nums[at + IP_A]], b: strings[nums[at + IP_B]], facts: readFacts(nums, at + IP) };
    const family = nums[at + FAMILY] === 0 ? 'ip' : 'ipv6';
    if (kind === OP_TCP) {
      yield { kind, key: strings[nums[at + KEY]], frame: wire, family, eth, ip, streamId: nums[at + STREAM] };
    } else {
      const forgets = nums[at + KEY];
      yield {
        kind, key: null, frame: wire, family, eth, ip,
        hint: { nextStreamId: nums[at + STREAM], forgets: forgets < 0 ? null : strings[forgets] },
      };
    }
  }
}

/**
 * An adapter, as a shard dissects its frames. `tsPrecision` is the adapter's
 * clock, which the merge would otherwise write onto every row it is given - an
 * overlay per row on the way to the window and the store (`rowOverlay.ts`).
 * A shard that knows it writes it into the row it packs instead.
 */
export interface ShardInterface { name: string; label: string; tsPrecision?: number }

export type ToShard =
  /** The first message a shard Worker is sent. */
  | { type: 'init'; shards: number; cacheFrames: number }
  | {
    type: 'batch';
    epoch: number;
    /** Empty when the batch only carries what the merge owes the shard. */
    ops: OpBatch | null;
    /** `tls.stream` placeholders the merge has numbered. */
    settle?: [number, number][];
    /** Rows the merge added to a frame's Frame layer: the process, a live gap, a fingerprint. */
    rows?: [number, ProtocolField[]][];
    /** Later frames' links into cached trees this shard holds. */
    patches?: InfoPatch[];
  }
  | { type: 'reset'; epoch: number }
  | {
    type: 'host'; macs: string[]; addresses: string[];
    inferred: boolean; confidence: number; basis?: string;
  }
  | { type: 'interfaces'; interfaces: [number, ShardInterface][] }
  | { type: 'keylog'; text: string }
  | { type: 'keylogClear' }
  /**
   * A `socket_table` message, applied to the shard's own annotation store with
   * the Worker's clock (`nowUs`), never the shard's: a shard annotates every
   * frame with the table the single Worker would have had at that frame. The
   * coordinator sends it in dispatch order, behind every frame already given
   * to the shard.
   */
  | { type: 'flows'; table: Parameters<FlowAnnotationStore['apply']>[0]; nowUs: number }
  /** The Worker's annotation store was cleared: a new capture, or a lost link. */
  | { type: 'flowsClear' }
  | { type: 'detail'; requestId: number; id: number };

/** What one frame's dissection on a shard produced. */
export interface ShardResult {
  id: number;
  /** This frame's index in the batch's pack. Absent when it failed to dissect. */
  row?: number;
  /**
   * What the merge needs from this row without decoding it: the fingerprint's
   * and facts' inputs, a `tls.stream` still a placeholder (`rowSteps.ts`).
   * Absent when every key would be.
   */
  side?: RowSide;
  record?: Uint8Array;
  derived?: Uint8Array | null;
  deferredAt?: readonly number[];
  /** `tls.stream` placeholders this frame took, for the merge to number. */
  tls?: number[];
  icmpMatchedRequestFrameId?: number;
  infoPatches?: InfoPatch[];
  /** Why it failed to dissect, as the single Worker would have said. */
  error?: string;
  /** A fragment's report: what it did to the TCP order. */
  barrier?: BarrierReport;
  /** Its tree as dissected - only for the equality test (`withTrees`). */
  layers?: ProtocolLayer[];
}

export type FromShard =
  | {
    type: 'results'; epoch: number; results: ShardResult[];
    /** Every result's row, encoded once; null when no frame of the batch dissected. */
    pack: RowPack | null;
  }
  | { type: 'detail'; requestId: number; layers: ProtocolLayer[] | null }
  | { type: 'failure'; message: string };
