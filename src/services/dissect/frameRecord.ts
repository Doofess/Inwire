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
 * - **object** - returns live state the dissector mutates (the TLS cursor and
 *   conversation, LDAP/SMB2/BGP state). Not yet recordable: a revisit throws
 *   `RecordMiss` when it gets there.
 */
import type {
  TcpTrackerApi, QuicTrackerApi, DnsTrackerApi, IcmpTrackerApi, L3TrackerApi,
} from './trackerApi';
import { LIVE_ENV, type DissectEnv } from './dissectEnv';
import { ValueReader, ValueWriter } from './valueCodec';

type Kind = 'answer' | 'effect' | 'peek' | 'decryptor' | 'derived' | 'object';

const TCP = {
  setWindowScaleShift: 'effect', getWindowScaleShift: 'answer', getRelativeSeq: 'answer',
  getStreamId: 'answer', recordStreamPacket: 'answer', updateConnectionState: 'effect',
  noteFin: 'answer', isAtOrPastExpected: 'answer', analyze: 'answer', noteGap: 'effect',
  getConversationCompleteness: 'answer', getCompletenessMask: 'answer',
  ldapConversation: 'object', smb2Conversation: 'object', peekBgpDirection: 'peek',
  bgpDirection: 'object', peekTlsCursor: 'peek', tlsCursor: 'object',
  tlsConversation: 'object', getTlsStreamId: 'answer',
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
  fragment: 'answer', forgetFragments: 'effect', arpClaim: 'answer',
} as const satisfies Record<keyof L3TrackerApi, Kind>;

const ENV = {
  now: 'answer', sharedBodyRoom: 'answer', takeBodyBytes: 'effect', releaseBodyBytes: 'effect',
} as const satisfies Record<keyof DissectEnv, Kind>;

const GROUPS = { tcp: TCP, quic: QUIC, dns: DNS, icmp: ICMP, l3: L3, env: ENV } as const;
type Group = keyof typeof GROUPS;

/** Method ids: one byte each, assigned in table order, 0 reserved. */
const IDS = new Map<string, number>();
const NAMES: string[] = ['(none)'];
for (const [group, table] of Object.entries(GROUPS)) {
  for (const method of Object.keys(table)) {
    IDS.set(`${group}.${method}`, NAMES.length);
    NAMES.push(`${group}.${method}`);
  }
}
/** A call to the function `createInitialDecryptor` returned. */
const DECRYPT_CALL = NAMES.length;
NAMES.push('quic.decrypt');
/** An answer that carried decrypted content, which a record does not hold. */
const DERIVED = NAMES.length;
NAMES.push('(decrypted content)');
if (NAMES.length > 255) throw new Error('frameRecord: more methods than one byte can name');

/** The record format; a different leading byte reads as no record at all. */
export const FRAME_RECORD_VERSION = 1;

/** Why a revisit could not give the tree back from the record. */
export class RecordMiss extends Error {
  constructor(readonly reason: string) {
    super(`frame record: ${reason}`);
    this.name = 'RecordMiss';
  }
}

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
  private objects = 0;
  private derived = 0;

  constructor(real: Omit<FrameSources, 'env'> & { env?: DissectEnv }) {
    const all = { ...real, env: real.env ?? LIVE_ENV } as unknown as Record<Group, Record<string, AnyFn>>;
    const sources = {} as Record<Group, Record<string, AnyFn>>;
    for (const group of Object.keys(GROUPS) as Group[]) {
      const target = all[group];
      const wrapped: Record<string, AnyFn> = {};
      for (const [method, kind] of Object.entries(GROUPS[group]) as [string, Kind][]) {
        const id = IDS.get(`${group}.${method}`)!;
        const fn = target[method].bind(target) as AnyFn;
        wrapped[method] = this.wrap(kind, id, method, fn);
      }
      sources[group] = wrapped;
    }
    this.sources = sources as unknown as FrameSources;
  }

  private wrap(kind: Kind, id: number, method: string, fn: AnyFn): AnyFn {
    const out = this.out;
    switch (kind) {
      case 'answer':
        return (...args) => {
          const answer = fn(...args);
          out.byte(id);
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
      case 'decryptor':
        return (...args) => {
          const decrypt = fn(...args) as AnyFn;
          out.byte(id);
          return (...call: unknown[]) => {
            const result = decrypt(...call);
            if (decryptsWithKeyLog(call) && !carriesNothing(result)) {
              out.byte(DERIVED);
              this.derived += 1;
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
          }
          return answer;
        };
      case 'object':
        return (...args) => {
          out.byte(id);
          this.objects += 1;
          return fn(...args);
        };
    }
  }

  begin(): void {
    this.out.reset();
    this.out.byte(FRAME_RECORD_VERSION);
    this.objects = 0;
    this.derived = 0;
  }

  /** The frame's record. */
  end(): Uint8Array {
    return this.out.bytes();
  }

  /** How many live objects the frame just recorded was handed - 0 means fully recorded. */
  get objectCalls(): number {
    return this.objects;
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

  constructor(record: Uint8Array) {
    if (record.length === 0 || record[0] !== FRAME_RECORD_VERSION) {
      throw new RecordMiss(`not a version ${FRAME_RECORD_VERSION} record`);
    }
    this.in = new ValueReader(record, 1);
    const sources = {} as Record<Group, Record<string, AnyFn>>;
    for (const group of Object.keys(GROUPS) as Group[]) {
      const answering: Record<string, AnyFn> = {};
      for (const [method, kind] of Object.entries(GROUPS[group]) as [string, Kind][]) {
        answering[method] = this.answer(kind, IDS.get(`${group}.${method}`)!);
      }
      sources[group] = answering;
    }
    this.sources = sources as unknown as FrameSources;
  }

  private expect(id: number): void {
    if (this.in.done) throw new RecordMiss(`asked ${NAMES[id]} after the record ended`);
    const got = this.in.byte();
    if (got === DERIVED) {
      throw new RecordMiss(`${NAMES[id]} answered with decrypted content, which records do not hold`);
    }
    if (got !== id) throw new RecordMiss(`asked ${NAMES[id]} where arrival asked ${NAMES[got] ?? got}`);
  }

  private answer(kind: Kind, id: number): AnyFn {
    switch (kind) {
      case 'answer':
      case 'peek':
      case 'derived':
        return () => {
          this.expect(id);
          return this.in.value();
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
            this.expect(DECRYPT_CALL);
            return this.in.value();
          };
        };
      case 'object':
        return () => {
          this.expect(id);
          throw new RecordMiss(`${NAMES[id]} hands out live state, which records do not hold yet`);
        };
    }
  }

  finish(): void {
    if (!this.in.done) throw new RecordMiss('the revisit asked fewer questions than arrival did');
  }
}
