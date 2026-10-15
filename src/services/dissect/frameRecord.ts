/**
 * What one frame's first dissection learned from the past, kept so its tree
 * can be built again from that frame alone (ADR 0049).
 *
 * A frame's tree is not a function of its own bytes: its relative sequence
 * numbers, its stream index, its "[Response In]", whether it is a
 * retransmission - all of that is what the frames before it built up in the
 * trackers. Rebuilding a tree used to mean rebuilding that past, by replaying
 * the frame's conversation from its first frame. Wireshark does not do that:
 * its first pass stores what each frame needed (`p_add_proto_data`), and a
 * frame shown later is dissected once, from that.
 *
 * This is the same idea at the one seam every dissector already goes through,
 * `dissect/trackerApi.ts`. At arrival a `FrameRecorder` stands in front of the
 * real trackers and writes down, in call order, every answer they give. On
 * revisit a `FrameRevisit` stands in their place and gives the same answers
 * back, in the same order, to the same unchanged dissector code. **The
 * dissector is never told which one it is talking to.**
 *
 * The record is a call log: a method id per call, and the answer when the call
 * has one. Replaying it checks the method id at every step, so a revisit that
 * asks a different question from the one arrival asked - which would mean the
 * dissector is not a pure function of its bytes and its answers - throws
 * `RecordMiss` rather than handing back an answer to some other question. A
 * miss is never a wrong tree; it is a tree built another way.
 *
 * Four kinds of call:
 * - **answer** - the return value is recorded and handed back;
 * - **effect** - the call changes tracker state and returns nothing a
 *   dissector reads; recorded as its id alone, so the order is still checked,
 *   and a no-op on revisit;
 * - **peek** - returns a live object the dissector only tests; recorded as
 *   the part that is tested;
 * - **decryptor** - returns a function (QUIC's Initial decryptor), whose own
 *   calls are logged as answers in the same stream;
 * - **derived** - an answer that can carry DECRYPTED content (HTTP/3 frames
 *   read from a 1-RTT stream, a packet opened with a key-log key). Decrypted
 *   content is never written to a record (the owner's rule: plaintext stays in
 *   memory). An empty answer carries none and is recorded like any other;
 *   a full one is not recordable yet, and a revisit misses there;
 * - **snapshot** - returns live state the dissector goes on to mutate (the TLS
 *   record cursor and conversation, LDAP/SMB2/BGP state). Recorded as it stood
 *   when it was handed over; a revisit is handed a fresh copy, changes it, and
 *   the copy is thrown away. A TLS conversation is recorded WITHOUT its keys:
 *   a revisit derives them again from the key log held at that moment, which is
 *   also what lets a key log loaded later open a frame that arrived opaque. A
 *   decrypting connection's HTTP state was built from plaintext, so it is
 *   derived content and not recorded.
 */
import type {
  TcpTrackerApi, QuicTrackerApi, DnsTrackerApi, IcmpTrackerApi, L3TrackerApi,
} from './trackerApi';
import { LIVE_ENV, type DissectEnv } from './dissectEnv';
import { ValueReader, ValueWriter, registerRecordClass } from './valueCodec';
import {
  FRAME_RECORD_VERSION, readRecordHeader, recordRefs, writeRecordHeader,
} from './recordHeader';
import { HpackTable } from '../dissectors/hpack';
import type { TlsConversationState, TlsRecordCursor } from '../tcpStreamTracker';
import { RecordMiss } from './recordMiss';
import { keyLabels } from '../tls/decrypt';
import type { KeyLogWitness } from '../dissectors/quic';

// Every HTTP/2-capable direction carries one, even on an HTTP/1 connection.
registerRecordClass(HpackTable);

/**
 * `checked`: an env answer that must not be replayed from the record, because
 * it is key material or leads to it. Arrival records a projection of it
 * (`projectChecked`); a revisit asks `LIVE_ENV` again and misses if the
 * projection differs.
 */
type Kind = 'answer' | 'effect' | 'peek' | 'decryptor' | 'derived' | 'snapshot' | 'checked';

const TCP = {
  setWindowScaleShift: 'effect', getWindowScaleShift: 'answer', getRelativeSeq: 'answer',
  getStreamId: 'answer', recordStreamPacket: 'answer', updateConnectionState: 'effect',
  noteFin: 'answer', isAtOrPastExpected: 'answer', analyze: 'answer', noteGap: 'effect',
  getConversationCompleteness: 'answer', getCompletenessMask: 'answer',
  ldapConversation: 'snapshot', smb2Conversation: 'snapshot', peekBgpDirection: 'peek',
  bgpDirection: 'snapshot', peekTlsCursor: 'peek', tlsCursor: 'snapshot',
  tlsConversation: 'snapshot', getTlsStreamId: 'answer', sshConversation: 'snapshot', dcerpcConversation: 'snapshot',
} as const satisfies Record<keyof TcpTrackerApi, Kind>;

const QUIC = {
  isKnownFlow: 'answer', matchConnectionId: 'answer', createInitialDecryptor: 'decryptor',
  addCryptoFragments: 'answer', noteLongHeader: 'answer', connectionNumberForFlow: 'answer',
  readStreams: 'derived',
} as const satisfies Record<keyof QuicTrackerApi, Kind>;

const DNS = {
  recordQuery: 'effect', matchResponse: 'answer',
} as const satisfies Record<keyof DnsTrackerApi, Kind>;

const ICMP = {
  recordRequest: 'effect', matchReply: 'answer',
} as const satisfies Record<keyof IcmpTrackerApi, Kind>;

const L3 = {
  ethStream: 'answer', ipStream: 'answer', ipv6Stream: 'answer', udpStream: 'answer',
  fragment: 'answer', forgetFragments: 'effect', arpClaim: 'answer', wireguard: 'answer',
  espSequence: 'answer', dtlsConversation: 'snapshot', cldapConversation: 'snapshot',
  flowTemplate: 'answer', defineFlowTemplate: 'effect', flowSequence: 'answer',
  rtpStream: 'answer', rtpDescription: 'effect',
} as const satisfies Record<keyof L3TrackerApi, Kind>;

const ENV = {
  now: 'answer', sharedBodyRoom: 'answer', takeBodyBytes: 'effect', releaseBodyBytes: 'effect',
  direction: 'answer', keyLogSecrets: 'checked', keyLogEmpty: 'checked',
} as const satisfies Record<keyof DissectEnv, Kind>;

const GROUPS = { tcp: TCP, quic: QUIC, dns: DNS, icmp: ICMP, l3: L3, env: ENV } as const;
type Group = keyof typeof GROUPS;

/**
 * Method ids: one byte each, assigned in table order, 0 reserved. Named
 * `group:method` rather than with a dot, because a dotted literal in a
 * dissection source reads as a field name to `scripts/dissect/registry.ts`.
 */
const IDS = new Map<string, number>();
const NAMES: string[] = ['(none)'];
const KINDS: (Kind | undefined)[] = [undefined];
for (const [group, table] of Object.entries(GROUPS)) {
  for (const [method, kind] of Object.entries(table) as [string, Kind][]) {
    IDS.set(`${group}:${method}`, NAMES.length);
    NAMES.push(`${group}:${method}`);
    KINDS.push(kind);
  }
}
/** A call to the function `createInitialDecryptor` returned. */
const DECRYPT_CALL = NAMES.length;
NAMES.push('quic:decrypt');
KINDS.push('answer');
/**
 * A call that needed the key log and opened nothing: recorded with the
 * connection's client random and the labels the log held for it, so a revisit
 * whose log now holds different ones misses instead of leaving it shut.
 */
const DECRYPT_UNOPENED = NAMES.length;
NAMES.push('quic:decrypt-unopened');
KINDS.push('answer');
/** An answer that carried decrypted content, which a record does not hold. */
const DERIVED = NAMES.length;
NAMES.push('(decrypted content)');
KINDS.push(undefined);
if (NAMES.length > 255) throw new Error('frameRecord: more methods than one byte can name');
/** The one answer a record may be written with a placeholder for (`deferredAnswers`). */
const TLS_STREAM = IDS.get('tcp:getTlsStreamId')!;
const NO_OFFSETS: number[] = [];

/**
 * A record with its placeholder answers replaced by the numbers they stand for
 * (ADR 0053 phase 3). `at` is `FrameRecorder.deferredAnswers` for this record;
 * each is the offset of one encoded integer, rewritten through `resolve`. The
 * call log has no lengths or offsets of its own, so a value that encodes to a
 * different length splices in cleanly.
 */
export function settleDeferredAnswers(
  record: Uint8Array, at: readonly number[], resolve: (placeholder: number) => number,
): Uint8Array {
  if (at.length === 0) return record;
  const parts: Uint8Array[] = [];
  let from = 0;
  let length = 0;
  for (const offset of at) {
    const reader = new ValueReader(record, offset);
    const placeholder = reader.value() as number;
    const end = record.length - reader.remaining;
    const writer = new ValueWriter();
    writer.value(resolve(placeholder));
    const before = record.subarray(from, offset);
    const value = writer.bytes();
    parts.push(before, value);
    length += before.length + value.length;
    from = end;
  }
  const tail = record.subarray(from);
  parts.push(tail);
  length += tail.length;
  const out = new Uint8Array(length);
  let i = 0;
  for (const part of parts) {
    out.set(part, i);
    i += part.length;
  }
  return out;
}

export { FRAME_RECORD_VERSION, recordRefs };

/** The call log's reader, positioned past the header; null for a record this build does not read. */
function openLog(record: Uint8Array): { reader: ValueReader; refs: number[] } | null {
  const header = readRecordHeader(record);
  if (header === null) return null;
  return { reader: new ValueReader(record, header.logStart), refs: header.refs };
}

/** FNV-1a, 32 bits: whether a referenced piece is still the piece it was. */
export function fnv1a(bytes: Uint8Array): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export { RecordMiss };

/** The five trackers and the environment, as one dissection sees them. */
export interface FrameSources {
  tcp: TcpTrackerApi;
  quic: QuicTrackerApi;
  dns: DnsTrackerApi;
  icmp: IcmpTrackerApi;
  l3: L3TrackerApi;
  env: DissectEnv;
}

type AnyFn = (...args: unknown[]) => unknown;

/** Whether a derived answer carries nothing - no frames, no packet. */
function carriesNothing(value: unknown): boolean {
  return value === undefined || value === null || (Array.isArray(value) && value.length === 0);
}

/**
 * Whether one call to the QUIC decryptor could have used a key-log key. Only
 * Initial packets are opened with keys derived from the packet itself; every
 * other kind needs the key log, and what it opens is plaintext.
 */
function decryptsWithKeyLog(call: unknown[]): boolean {
  return call[5] !== 'initial';
}

/**
 * What a TLS conversation snapshot records, or `null` when its state is
 * derived from plaintext and so is not recorded at all.
 */
/** What a snapshot leaves out of a conversation, and the one field it empties. */
const CONVERSATION_OMITS = ['keys', 'keyGeneration', 'keyLabelsAtArrival'] as const;
const NOTHING: readonly never[] = [];

/** How a snapshot is written: straight from the live object, into the log. */
type SnapshotWriter = (out: ValueWriter) => void;

function snapshotConversation(conv: TlsConversationState): SnapshotWriter | null {
  // Keys present means this connection is being decrypted, so whatever its
  // HTTP directions hold was read out of plaintext.
  if (conv.keys && (conv.appClient !== undefined || conv.appServer !== undefined)) return null;
  // Never the keys, nor the verdict and note that came with them - a revisit
  // asks the key log again. A key in a record would be key material on disk.
  // What IS kept is which key log labels the keys came from, which is not key
  // material: a revisit whose key log disagrees - keys that came later, or
  // were cleared, or only some of them - misses rather than drawing a record
  // opened, or left shut, differently from arrival (`ensureRevisitKeys`).
  // The note is kept: it is prose about the key log, not a key, and it is what
  // a rebuilt conversation's "[Not decrypted]" row must go on saying.
  //
  // `pendingVersionFrames` is emptied, not copied. It names the frames to
  // relabel once the ServerHello settles the version - patches to OTHER
  // frames, which a revisit discards - so no tree reads it. And on a
  // connection first seen mid-stream the version is never settled, so it
  // grows by one id every frame for the life of the connection: copied, it was
  // half of every record on the bulk fixture.
  const labels = keyLabels(conv.keys);
  return (out) => out.objectWith(conv, CONVERSATION_OMITS,
    { pendingVersionFrames: NOTHING, keyLabelsAtArrival: labels });
}

/**
 * A decrypting conversation, for the memory-only log: its HTTP state was read
 * out of plaintext, which is exactly why the record cannot hold it. Still no
 * keys - a revisit derives them from the key log as it does for any other
 * rebuilt conversation, and `keyLabelsAtArrival` says which it must find.
 */
function plaintextConversation(conv: TlsConversationState): SnapshotWriter {
  const labels = keyLabels(conv.keys);
  return (out) => out.objectWith(conv, CONVERSATION_OMITS,
    { pendingVersionFrames: NOTHING, keyLabelsAtArrival: labels });
}

/** What a `checked` answer is recorded as, and compared by: never the secrets themselves. */
function projectChecked(method: string, value: unknown): unknown {
  // The labels the log holds for the connection, never the secrets under them.
  if (method === 'keyLogSecrets') return value === undefined ? null : [...(value as Map<string, unknown>).keys()].sort();
  return value;
}

/** The labels the live key log holds for a connection, as `projectChecked` would record them. */
function liveLabels(clientRandom: Uint8Array | null): string[] | null {
  return clientRandom === null ? null : projectChecked('keyLogSecrets', LIVE_ENV.keyLogSecrets(clientRandom)) as string[] | null;
}

/** What a peek records: only the part of the live object the dissector tests. */
function projectPeek(method: string, value: unknown): unknown {
  if (value === undefined || value === null) return value;
  if (method === 'peekTlsCursor') return { unknown: (value as { unknown: boolean }).unknown };
  return {};
}

/**
 * Stands in front of the real trackers for a dissection, and writes down what
 * they said. `begin` before a frame, `end` after it.
 */
export class FrameRecorder {
  readonly sources: FrameSources;
  private readonly out = new ValueWriter();
  private derived = 0;
  /**
   * The answers the record refuses, in the order it refused them: decrypted
   * content, which the owner's rule keeps in memory and never on disk. Handed
   * out by `endDerived`, for whoever holds it in memory; a revisit given it
   * reads a refused answer from here instead of missing.
   */
  private readonly derivedOut = new ValueWriter();
  /** Something in this frame's derived answers could not be encoded. */
  private derivedLost = false;
  /** Frames this frame's record names bytes of. */
  private readonly refs = new Set<number>();
  /**
   * Each buffered piece's hash, computed once. A record spanning 45 segments
   * is snapshotted 45 times, and hashing its pieces every time was quadratic.
   */
  private readonly pieceHashes = new WeakMap<Uint8Array, number>();
  /**
   * Where in this frame's call log a `tls.stream` answer was a placeholder
   * (`DeferredTlsNumbers`, ADR 0053) - for the merge to put the real number
   * in with `settleDeferredAnswers`. Empty unless dissecting on several cores.
   */
  private deferredAt: number[] = [];
  private deferredOut: number[] = [];

  constructor(real: Omit<FrameSources, 'env'> & { env?: DissectEnv }) {
    const all = { ...real, env: real.env ?? LIVE_ENV } as unknown as Record<Group, Record<string, AnyFn>>;
    const sources = {} as Record<Group, Record<string, AnyFn>>;
    for (const group of Object.keys(GROUPS) as Group[]) {
      const target = all[group];
      const wrapped: Record<string, AnyFn> = {};
      for (const [method, kind] of Object.entries(GROUPS[group]) as [string, Kind][]) {
        const id = IDS.get(`${group}:${method}`)!;
        const fn = target[method].bind(target) as AnyFn;
        wrapped[method] = this.wrap(kind, id, method, fn);
      }
      sources[group] = wrapped;
    }
    this.sources = sources as unknown as FrameSources;
  }

  /**
   * What a snapshot records, or `null` when the state is derived from
   * plaintext and so is not recorded at all.
   */
  private snapshotOf(method: string, live: unknown): SnapshotWriter | null {
    if (method === 'tlsConversation') return snapshotConversation(live as TlsConversationState);
    if (method !== 'tlsCursor') return (out) => out.value(live);
    const cursor = live as TlsRecordCursor;
    if (cursor.buffer === null || cursor.buffer.length !== cursor.bufferSources.length) {
      return (out) => out.value(cursor);
    }
    // The buffered body is earlier frames' bytes, which the store already holds
    // as those frames. Named, not copied: frame, offset, length and a hash, so a
    // revisit that finds different bytes there misses instead of reading them.
    // A body that is not in its source any more - a segment carried inside a
    // reassembled IP datagram is cut from the datagram, not from a frame - is
    // caught by that hash too.
    const bufferRefs: number[] = [];
    cursor.bufferSources.forEach((source, i) => {
      const piece = cursor.buffer![i];
      let hash = this.pieceHashes.get(piece);
      if (hash === undefined) {
        hash = fnv1a(piece);
        this.pieceHashes.set(piece, hash);
      }
      bufferRefs.push(source.frame, source.at, source.length, hash);
      this.refs.add(source.frame);
    });
    return (out) => out.objectWith(cursor, NOTHING, { buffer: null, bufferSources: NOTHING, bufferRefs });
  }

  private wrap(kind: Kind, id: number, method: string, fn: AnyFn): AnyFn {
    const out = this.out;
    switch (kind) {
      case 'answer':
        return (...args) => {
          const answer = fn(...args);
          out.byte(id);
          if (id === TLS_STREAM && (answer as number) < 0) this.deferredAt.push(out.length);
          out.value(answer);
          return answer;
        };
      case 'effect':
        return (...args) => {
          out.byte(id);
          return fn(...args);
        };
      case 'peek':
        return (...args) => {
          const live = fn(...args);
          out.byte(id);
          out.value(projectPeek(method, live));
          return live;
        };
      case 'checked':
        return (...args) => {
          const live = fn(...args);
          out.byte(id);
          out.value(projectChecked(method, live));
          return live;
        };
      case 'decryptor':
        return (...args) => {
          const decrypt = fn(...args) as AnyFn;
          out.byte(id);
          return (...call: unknown[]) => {
            const result = decrypt(...call);
            const witness = (decrypt as { keyLogWitness?: () => KeyLogWitness }).keyLogWitness;
            if (decryptsWithKeyLog(call) && !carriesNothing(result)) {
              out.byte(DERIVED);
              this.derived += 1;
              this.keepDerived(result);
            } else if (decryptsWithKeyLog(call) && witness !== undefined) {
              const { random } = witness();
              out.byte(DECRYPT_UNOPENED);
              out.value({ random, labels: liveLabels(random) });
            } else {
              out.byte(DECRYPT_CALL);
              out.value(result);
            }
            return result;
          };
        };
      case 'derived':
        return (...args) => {
          const answer = fn(...args);
          if (carriesNothing(answer)) {
            out.byte(id);
            out.value(answer);
          } else {
            out.byte(DERIVED);
            this.derived += 1;
            this.keepDerived(answer);
          }
          return answer;
        };
      case 'snapshot':
        return (...args) => {
          const live = fn(...args);
          const snapshot = this.snapshotOf(method, live);
          if (snapshot === null) {
            out.byte(DERIVED);
            this.derived += 1;
            this.keepDerivedWith(plaintextConversation(live as TlsConversationState));
          } else {
            out.byte(id);
            snapshot(out);
          }
          return live;
        };
    }
  }

  begin(): void {
    this.out.reset();
    this.derivedOut.reset();
    this.derived = 0;
    this.derivedLost = false;
    this.refs.clear();
    if (this.deferredAt.length > 0) this.deferredAt = [];
  }

  /**
   * Encoded at once, because the live object goes on changing. A value the
   * codec cannot encode loses this frame's derived answers - a miss later,
   * never a failed arrival.
   */
  private keepDerived(value: unknown): void {
    this.keepDerivedWith((out) => out.value(value));
  }

  private keepDerivedWith(write: SnapshotWriter): void {
    if (this.derivedLost) return;
    try {
      write(this.derivedOut);
    } catch {
      this.derivedLost = true;
    }
  }

  /**
   * The frame's decrypted answers, for memory only: null when it had none, or
   * when one could not be kept. Read after `end`, before the next `begin`.
   */
  endDerived(): Uint8Array | null {
    return this.derived === 0 || this.derivedLost ? null : this.derivedOut.bytes();
  }

  /** The frame's record. */
  end(): Uint8Array {
    const head = writeRecordHeader([...this.refs]);
    const log = this.out.bytes();
    const record = new Uint8Array(head.length + log.length);
    record.set(head);
    record.set(log, head.length);
    this.deferredOut = this.deferredAt.length === 0 ? NO_OFFSETS : this.deferredAt.map((at) => at + head.length);
    return record;
  }

  /**
   * Where the record `end` just returned holds a placeholder answer, as offsets
   * into it - empty for nearly every frame. Read after `end`.
   */
  get deferredAnswers(): readonly number[] {
    return this.deferredOut;
  }

  /** How many answers the frame just recorded carried decrypted content. */
  get derivedCalls(): number {
    return this.derived;
  }
}

/**
 * Stands in the trackers' place for one revisit, answering from a record.
 * Call `finish` after the dissection: a record with answers left over is one
 * whose frame asked fewer questions the second time, which is a miss too.
 */
export class FrameRevisit {
  readonly sources: FrameSources;
  private readonly in: ValueReader;

  /**
   * `bytesOf` answers with another frame's stored bytes, for the frames
   * `recordRefs` names; a frame it cannot supply is a miss.
   */
  /** The memory-only answers (`FrameRecorder.endDerived`), when they are still held. */
  private readonly side: ValueReader | null;

  constructor(
    record: Uint8Array,
    private readonly bytesOf: (frame: number) => Uint8Array | undefined = () => undefined,
    derived: Uint8Array | null = null,
  ) {
    const log = openLog(record);
    if (log === null) throw new RecordMiss(`not a version ${FRAME_RECORD_VERSION} record`);
    this.in = log.reader;
    this.side = derived === null ? null : new ValueReader(derived);
    const sources = {} as Record<Group, Record<string, AnyFn>>;
    for (const group of Object.keys(GROUPS) as Group[]) {
      const answering: Record<string, AnyFn> = {};
      for (const [method, kind] of Object.entries(GROUPS[group]) as [string, Kind][]) {
        answering[method] = this.answer(kind, IDS.get(`${group}:${method}`)!, method);
      }
      sources[group] = answering;
    }
    this.sources = sources as unknown as FrameSources;
  }

  /**
   * Checks the next entry is this question, and says where its answer is: in
   * the record, or - for decrypted content - in the memory-only log.
   */
  private expect(id: number): ValueReader {
    if (this.in.done) throw new RecordMiss(`asked ${NAMES[id]} after the record ended`);
    const got = this.in.byte();
    if (got === DERIVED) {
      if (this.side === null || this.side.done) {
        throw new RecordMiss(`${NAMES[id]} answered with decrypted content, which is not held in memory`);
      }
      return this.side;
    }
    if (got !== id) throw new RecordMiss(`asked ${NAMES[id]} where arrival asked ${NAMES[got] ?? got}`);
    return this.in;
  }

  /** `expect`, for a question arrival may have answered in either of two ways. */
  private expectEither(a: number, b: number): [number, ValueReader] {
    if (this.in.done) throw new RecordMiss(`asked ${NAMES[a]} after the record ended`);
    const got = this.in.byte();
    if (got === DERIVED) {
      if (this.side === null || this.side.done) {
        throw new RecordMiss(`${NAMES[a]} answered with decrypted content, which is not held in memory`);
      }
      return [DERIVED, this.side];
    }
    if (got !== a && got !== b) throw new RecordMiss(`asked ${NAMES[a]} where arrival asked ${NAMES[got] ?? got}`);
    return [got, this.in];
  }

  /** A recorded TLS cursor, with its buffered body cut back out of its frames. */
  private hydrateCursor(state: Record<string, unknown>): unknown {
    const refs = state.bufferRefs as number[] | undefined;
    if (refs === undefined) return state;
    delete state.bufferRefs;
    const buffer: Uint8Array[] = [];
    const sources: { frame: number; at: number; length: number }[] = [];
    for (let i = 0; i < refs.length; i += 4) {
      const [frame, at, length, hash] = refs.slice(i, i + 4);
      const bytes = this.bytesOf(frame);
      if (bytes === undefined) throw new RecordMiss(`the bytes of frame ${frame} are not available`);
      const piece = bytes.slice(at, at + length);
      if (piece.length !== length || fnv1a(piece) !== hash) {
        throw new RecordMiss(`frame ${frame} no longer holds the bytes its record names`);
      }
      buffer.push(piece);
      sources.push({ frame, at, length });
    }
    state.buffer = buffer;
    state.bufferSources = sources;
    return state;
  }

  private answer(kind: Kind, id: number, method: string): AnyFn {
    switch (kind) {
      case 'checked':
        return (...args) => {
          const recorded = this.expect(id).value();
          const live = (LIVE_ENV as unknown as Record<string, AnyFn>)[method](...args);
          if (JSON.stringify(projectChecked(method, live)) !== JSON.stringify(recorded)) {
            throw new RecordMiss(`${NAMES[id]} answers differently now than when this frame arrived`);
          }
          return live;
        };
      case 'answer':
      case 'peek':
      case 'derived':
        return () => this.expect(id).value();
      case 'snapshot':
        return () => {
          const state = this.expect(id).value();
          return id === IDS.get('tcp:tlsCursor')
            ? this.hydrateCursor(state as Record<string, unknown>)
            : state;
        };
      case 'effect':
        return () => {
          this.expect(id);
          return undefined;
        };
      case 'decryptor':
        return () => {
          this.expect(id);
          return () => {
            const [got, from] = this.expectEither(DECRYPT_CALL, DECRYPT_UNOPENED);
            const value = from.value();
            if (got !== DECRYPT_UNOPENED) return value;
            // Normalised: the codec leaves a null field out of an object, so a
            // connection with no ClientHello seen comes back with neither.
            const { random, labels } = value as { random?: Uint8Array | null; labels?: string[] | null };
            if (JSON.stringify(liveLabels(random ?? null)) !== JSON.stringify(labels ?? null)) {
              throw new RecordMiss('the key log holds different secrets for this QUIC connection now');
            }
            return null;
          };
        };
    }
  }

  finish(): void {
    if (!this.in.done) throw new RecordMiss('the revisit asked fewer questions than arrival did');
    if (this.side !== null && !this.side.done) {
      throw new RecordMiss('the revisit used less decrypted content than arrival did');
    }
  }
}

/**
 * Where a record's bytes go, by question - for the gate's cost report, so a
 * record that grows says which answer grew rather than only that it did.
 */
export function recordComposition(record: Uint8Array): Map<string, number> {
  const out = new Map<string, number>();
  const log = openLog(record);
  if (log === null) return out;
  const reader = log.reader;
  let at = record.length - reader.remaining;
  out.set('(frames named)', at);
  while (!reader.done) {
    const id = reader.byte();
    if (id !== DERIVED && KINDS[id] !== 'effect' && KINDS[id] !== 'decryptor') reader.value();
    const end = record.length - reader.remaining;
    out.set(NAMES[id] ?? `#${id}`, (out.get(NAMES[id] ?? `#${id}`) ?? 0) + (end - at));
    at = end;
  }
  return out;
}

/** A record's entries, decoded - for diagnosing one record by hand. */
export function recordEntries(record: Uint8Array): [string, unknown][] {
  const out: [string, unknown][] = [];
  const log = openLog(record);
  if (log === null) return out;
  const reader = log.reader;
  out.push(['(frames named)', log.refs]);
  while (!reader.done) {
    const id = reader.byte();
    const carries = id !== DERIVED && KINDS[id] !== 'effect' && KINDS[id] !== 'decryptor';
    out.push([NAMES[id] ?? `#${id}`, carries ? reader.value() : undefined]);
  }
  return out;
}
