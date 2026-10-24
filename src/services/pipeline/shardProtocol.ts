/**
 * What the pipeline Worker and its TCP shards say to each other (ADR 0053
 * phase 3). Every message is a structured clone; a frame's bytes are
 * transferred both ways - into the shard to be dissected, and back with its
 * row - so the only copy of a frame is the one the store needs.
 *
 * **A batch of frames is packed, not a list of objects.** It was a list: each
 * frame an object holding its numbers, two conversation answers and their
 * endpoints, each one more object - and a shard spent 6 us a frame
 * deserializing them, a fifth of its time, before dissecting anything
 * (`scripts/perf/parallel-threads.ts`). Now every number a frame carries is a
 * slot in one `Float64Array`, every string is an index into one list that
 * holds each string once per batch, and the bytes ride beside them.
 */
import type { ConversationFacts } from '../dissect/sequencer';
import type { BarrierHint, BarrierReport } from '../dissect/shardNumbering';
import type { InfoPatch } from '../dissect/types';
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { RowPack } from './rowPack';

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
  facts?: { nanosRemainder?: number };
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
const SLOTS = 24;

/** A batch of ops for one shard, as it travels. */
export interface OpBatch {
  nums: Float64Array;
  strings: string[];
  /** One per frame op, in order. */
  bytes: Uint8Array[];
}

/** Builds one batch, op by op, in frame order. */
export class OpWriter {
  private nums = new Float64Array(SLOTS * 64);
  private count = 0;
  private readonly strings: string[] = [];
  private readonly stringAt = new Map<string, number>();
  private readonly bytes: Uint8Array[] = [];
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
    nums[at + FAMILY] = family === 'ip' ? 0 : 1;
    writeFacts(nums, at + ETH, eth.facts);
    writeFacts(nums, at + IP, ip.facts);
    nums[at + ETH_A] = this.intern(eth.a);
    nums[at + ETH_B] = this.intern(eth.b);
    nums[at + IP_A] = this.intern(ip.a);
    nums[at + IP_B] = this.intern(ip.b);
    this.bytes.push(frame.bytes);
    this.frames += 1;
    return at;
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

  /** The batch, ready to send: its numbers and bytes are what a transfer list moves. */
  seal(): OpBatch {
    return { nums: this.nums.slice(0, this.count * SLOTS), strings: this.strings, bytes: this.bytes };
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
  const { nums, strings, bytes } = batch;
  let frame = 0;
  for (let at = 0; at < nums.length; at += SLOTS) {
    const kind = nums[at + KIND];
    if (kind === OP_FORGET) {
      yield { kind, key: strings[nums[at + KEY]] };
      continue;
    }
    const nanos = nums[at + NANOS];
    const iface = nums[at + IFACE];
    const wire: WireFrame = {
      id: nums[at + ID], bytes: bytes[frame++], tsUs: nums[at + TS_US], relativeTime: nums[at + RELATIVE],
      timeDelta: nums[at + DELTA], origLen: nums[at + ORIG_LEN], linktype: nums[at + LINKTYPE],
      ...(iface >= 0 ? { iface } : {}),
      ...(Number.isNaN(nanos) ? {} : { facts: { nanosRemainder: nanos < 0 ? undefined : nanos } }),
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

export interface ShardInterface { name: string; label: string }

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
  | { type: 'detail'; requestId: number; id: number };

/** What one frame's dissection on a shard produced. */
export interface ShardResult {
  id: number;
  /** This frame's index in the batch's pack. Absent when it failed to dissect. */
  row?: number;
  /** The frame's bytes, which travel beside the pack rather than in its row. */
  bytes?: Uint8Array;
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
