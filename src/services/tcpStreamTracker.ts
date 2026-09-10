/**
 * Tracks TCP conversations across packets so a single-pass decode can still
 * detect cross-packet behavior: which stream a segment belongs to (for
 * "Follow Stream"), relative sequence numbers, window scaling, the TLS record
 * cursor, and Wireshark's sequence analysis (retransmission, out-of-order,
 * duplicate ACK, window and keep-alive flags - see dissect/tcpAnalysis.ts).
 *
 * One instance represents one capture session; call reset() when the packet
 * buffer is cleared or a new file is imported so streams don't bleed across
 * unrelated captures.
 */
/**
 * Where one direction of a connection is inside the TLS record layer.
 *
 * A TLS record is a 5-byte header and a body of up to 16 KB, and a TCP
 * segment is ~1,400 bytes, so most records span several segments. Wireshark
 * labels the frame in which a record COMPLETES with the record's contents and
 * every earlier segment of it as plain TCP "[TCP PDU reassembled in N]"; doing
 * the same needs exactly this much memory per direction: how many bytes the
 * record in progress still owes, and which frames have carried it so far.
 * Handshake records are additionally buffered so a ClientHello that straddles
 * segments can still be parsed for its SNI and fingerprint.
 */
import { analyzeTcpSegment, freshConnection, type TcpAnalysis, type TcpConnectionState, type TcpSegment } from './dissect/tcpAnalysis';

import type { TlsDecryptionKeys } from './tls/decrypt';
import type { AppDirection } from './dissectors/appStream';
import { freshLdapConversation, type LdapConversationState } from './dissectors/ldap';
import { freshSmb2Conversation, type Smb2ConversationState } from './dissectors/smb2';
import { freshBgpDirection, type BgpDirectionState } from './dissectors/bgp';

export interface TlsRecordCursor {
  /** Bytes still owed to the record in progress; 0 means at a record boundary. */
  remaining: number;
  /** A record header that straddled a segment boundary, so far. */
  headerPartial: number[];
  contentType: number;
  version: number;
  recordLength: number;
  /**
   * Absolute TCP sequence number of the byte after the record in progress.
   * Reassembly follows sequence numbers, not a running byte count, so a lost
   * segment inside a record does not lose the record: Wireshark keeps the
   * PDU open across the gap and completes it when the end sequence arrives.
   */
  recordEndSeq: number;
  /**
   * True when a capture gap opened inside the record in progress and the bytes
   * it swallowed have not turned up since.
   *
   * The record's END is a sequence number and a gap does not move it, so a
   * holed record still knows exactly where it finishes - it just cannot be
   * shown, because part of its body was never captured. Keeping the two facts
   * apart is what lets the direction resynchronise at the right byte while
   * refusing to claim the record or the frames that carried it.
   */
  holed: boolean;
  /** Frames that carried the record in progress and completed nothing of their own. */
  contributors: number[];
  /** Byte counts per frame, for the "[Reassembled TCP segments]" note. */
  contributions: { frame: number; bytes: number }[];
  /** Handshake body collected so far, or null when the record is not buffered. */
  buffer: Uint8Array[] | null;
  bufferedBytes: number;
  /** True until this direction has shown a valid record header (mid-stream start). */
  unknown: boolean;
  /** TLS 1.2: set by Change Cipher Spec; every later handshake record in this direction is ciphertext. */
  encrypted: boolean;
  /**
   * Which end of the conversation this direction is, learned from whichever
   * hello it sent. Decryption needs it: the two directions have different keys
   * and a key log names them by role, not by address.
   */
  role: 'client' | 'server' | 'unknown';
  /**
   * True on the throwaway copy an out-of-order segment is read against. A
   * retransmission must not be decrypted: doing so would advance the AEAD
   * sequence number and feed the same bytes to the HTTP decoders a second
   * time, and both of those are state the real stream shares.
   */
  readOnly: boolean;
  /**
   * Index into this direction's list of epochs (TLS 1.3 handshake, then
   * application). A direction only ever moves forwards through it.
   */
  epoch: number;
  /**
   * The AEAD sequence number of the next record. It counts records, not bytes,
   * and restarts at zero on each epoch - which is why it lives here rather
   * than being derived from anything on the wire, where it does not appear.
   */
  recordSeq: number;
}

/** What both ends of a TLS conversation have agreed on so far. */
export interface TlsConversationState {
  /** From the ClientHello. The key log's join key, and 32 bytes sent in the clear. */
  clientRandom?: Uint8Array;
  /** From the ServerHello, for the TLS 1.2 key block. */
  serverRandom?: Uint8Array;
  /** The negotiated cipher suite, which decides the AEAD, the key sizes and the hash. */
  cipherSuite?: number;
  /**
   * Keys derived from the key log: undefined before the attempt, null when it
   * failed. `keyGeneration` records which version of the key log that verdict
   * came from, so loading a log part-way through a live capture retries the
   * connections that were opaque rather than staying opaque for ever.
   */
  keys?: TlsDecryptionKeys | null;
  keyGeneration?: number;
  /** Why decryption is not happening, when there is a reason worth showing. */
  keyNote?: string;
  /** The protocol ALPN settled on, which decides what the plaintext is read as. */
  alpn?: string;
  /** Application-layer state per direction, once there is plaintext to read. */
  appClient?: AppDirection;
  appServer?: AppDirection;
  /** From the ServerHello: supported_versions in 1.3, else server_version. */
  negotiatedVersion?: number;
  /** The ClientHello's legacy version - what its row is labelled before the server answers. */
  clientHelloVersion?: number;
  clientHelloSeen: boolean;
  serverHelloSeen: boolean;
  /** Set once the server's ServerHello has been seen in TLS 1.3: every later handshake record is encrypted. */
  encryptedHandshake: boolean;
  /** The ClientHello's server name, for the certificate name check. Unset for an ECH outer name. */
  sni?: string;
  /** The last record-layer version that was a real one, for labelling a record whose header carries junk. */
  lastRecordVersion?: number;
  /**
   * Frames labelled before the version was negotiated (the ClientHello and
   * anything else sent ahead of the ServerHello). Wireshark's two-pass view
   * labels those with the version the conversation ends up with, so when the
   * ServerHello arrives these get re-labelled.
   */
  pendingVersionFrames: number[];
}

export function freshTlsCursor(): TlsRecordCursor {
  return {
    remaining: 0, headerPartial: [], contentType: 0, version: 0, recordLength: 0,
    contributors: [], contributions: [], buffer: null, bufferedBytes: 0, unknown: true, encrypted: false, holed: false,
    recordEndSeq: 0, role: 'unknown', readOnly: false, epoch: 0, recordSeq: 0,
  };
}

/**
 * What a capture gap does to a record in progress.
 *
 * A record's end is a **sequence number**, and a gap does not move it - so the
 * question is not "did we lose bytes" but "did we lose the bytes this record
 * was still waiting for". If its end is still ahead of where the stream has
 * resumed, the record survives and only its buffered body is dropped, because
 * the bytes now missing from the middle can never be parsed. If its end is
 * behind, the gap swallowed it and there is nothing left to complete.
 *
 * Abandoning unconditionally instead costs seven frames on the inwire fixture,
 * where a record really did survive its gap - measured, not reasoned.
 *
 * `unknown`, `role`, `encrypted`, `epoch` and `recordSeq` are never touched
 * here. A gap loses this direction's PLACE in the record layer, not what the
 * conversation has established: it is still TLS, still the same role, still on
 * the same epoch and AEAD sequence.
 */
export function applyGapToCursor(cursor: TlsRecordCursor, segmentSeq: number): void {
  if (cursor.remaining > 0) {
    const owed = (cursor.recordEndSeq - segmentSeq) | 0;
    cursor.buffer = null;
    cursor.bufferedBytes = 0;
    if (owed <= 0) {
      cursor.remaining = 0;
      cursor.contributors = [];
      cursor.contributions = [];
      cursor.holed = false;
    } else {
      // The end is still ahead, so the record survives as a SPAN - this build
      // knows which byte finishes it and can resynchronise there. What it can
      // no longer do is show the record or credit the frames that carried it,
      // because the bytes in the hole were never captured. `holed` carries that
      // second fact; before it existed the record completed anyway and every
      // segment behind it was tagged as part of a PDU nobody could read.
      cursor.remaining = owed;
      cursor.holed = true;
    }
  } else if (cursor.headerPartial.length > 0) {
    cursor.headerPartial = [];
  }
}

export function freshTlsConversation(): TlsConversationState {
  return { clientHelloSeen: false, serverHelloSeen: false, encryptedHandshake: false, pendingVersionFrames: [] };
}

/**
 * One sender's half of a connection.
 *
 * These three used to be three separate maps keyed by a string built from the
 * connection key and the sending endpoint - so every connection stored six
 * copies of a ~40-character key just to describe its two directions.
 */
interface TcpDirection {
  /** This direction's reference sequence number; see `getRelativeSeq`. */
  baseSeq?: number;
  /** The shift this direction's SYN advertised, if it carried the option. */
  windowScaleShift?: number;
  /** Where this direction is inside the TLS record layer. */
  tlsCursor?: TlsRecordCursor;
  /**
   * Where this direction is inside the BGP message stream.
   *
   * Per direction rather than per connection, unlike LDAP's and SMB2's state:
   * the two halves of a peering are independent byte streams, so a message
   * boundary in one says nothing about where the other is.
   */
  bgp?: BgpDirectionState;
}

/**
 * Everything one TCP conversation carries, in one record.
 *
 * It was nine map entries: three keyed by the connection, three by the
 * direction and two by the stream index, each holding its own copy of the key
 * string. Measured at 2,269 B a connection, retained for the length of the
 * capture (`scripts/perf/tracker-cost.ts`).
 *
 * One record per connection stores that key once, and - the reason this matters
 * more than the bytes - makes forgetting a connection a single delete instead
 * of nine that could fall out of step.
 *
 * Every field is optional and created on first use, so a connection that never
 * carries TLS never allocates a TLS conversation, and one nothing has analysed
 * has no analysis state.
 */
interface TcpConnection {
  /** Assigned by `getStreamId` in order of first appearance, not on creation. */
  streamId?: number;
  /** Frames seen on this connection, which is `recordStreamPacket`'s answer. */
  packets: number;
  sawSyn: boolean;
  sawSynAck: boolean;
  sawFinOrRst: boolean;
  /** Wireshark's sequence analysis state, shared by both directions. */
  analysis?: TcpConnectionState;
  /** What both ends of the TLS conversation have agreed on. */
  tls?: TlsConversationState;
  /**
   * LDAP's per-connection counters, created only on a connection that speaks it.
   *
   * Optional for the reason `tls` is: the overwhelming majority of connections
   * are neither, and a field allocated on every one of them is 2,162 bytes a
   * connection of nothing (`docs/decisions/0014`).
   */
  ldap?: LdapConversationState;
  /** SMB2's per-connection state, on the same terms as `ldap` above. */
  smb2?: Smb2ConversationState;
  /** The endpoint that sorts first, and the other one. */
  a: TcpDirection;
  b: TcpDirection;
}

function freshTcpConnection(): TcpConnection {
  return { packets: 0, sawSyn: false, sawSynAck: false, sawFinOrRst: false, a: {}, b: {} };
}

/**
 * How many connections keep state.
 *
 * Nothing bounded this. The packet buffer is capped and trimmed - `trimToCap`
 * slices the array, trims the session store and evicts raw bytes - but it has
 * never touched a tracker, and `resetPipeline` only fires on events that mean
 * the buffer is *gone*. So a capture left running trimmed frames for hours
 * while this grew, and a browsing workload is precisely the shape that fills
 * it: thousands of short connections rather than one long one.
 *
 * **Least-recently-used, which is what makes a plain cap the right mechanism
 * here.** A connection that has closed stops receiving frames, so it stops
 * being touched and drifts to the front of the queue on its own - the entries
 * evicted first are the ones already finished, without a FIN needing to be
 * acted on or a sweep needing a clock. A long-lived idle connection is
 * protected by the same property in reverse, as far as the cap allows, which
 * is why the cap is generous.
 *
 * What eviction costs is real and worth naming: a frame arriving on an evicted
 * connection is a connection this tracker has not seen before, so it takes a
 * NEW stream index and a fresh relative-sequence base. That is the same thing
 * the tracker already does for a capture started mid-connection, and it is
 * counted (`evictedConnections`) rather than being silent.
 */
const MAX_CONNECTIONS = 16384;

export class TcpStreamTracker {
  /** One record per conversation, in least-recently-used order. */
  private connections = new Map<string, TcpConnection>();
  /** The same records by stream index, for the callers that hold only that. */
  private byStreamId = new Map<number, TcpConnection>();
  private nextStreamId = 0;
  /**
   * The connection the last lookup found. Every call made while dissecting one
   * frame asks about the same connection, so this is what keeps the
   * least-recently-used bookkeeping to one delete-and-reinsert per frame
   * rather than one per call.
   */
  private lastKey: string | undefined;
  private evicted = 0;

  /**
   * Finds one connection and the calling direction, creating both on first use.
   *
   * Builds the two endpoint strings once and derives everything from them: the
   * connection key, which half of the conversation the sender is, and the
   * peer's half. The previous shape built the same strings twice over, once for
   * the connection key and again for the direction key.
   */
  private locate(srcIp: string, srcPort: number, dstIp: string, dstPort: number): {
    conn: TcpConnection; dir: TcpDirection; peer: TcpDirection; senderIsA: boolean;
  } {
    const from = `${srcIp}:${srcPort}`;
    const to = `${dstIp}:${dstPort}`;
    const senderIsA = from <= to;
    const key = senderIsA ? `${from}|${to}` : `${to}|${from}`;

    let conn = this.connections.get(key);
    if (conn === undefined) {
      conn = freshTcpConnection();
      this.connections.set(key, conn);
      this.evictPastCap();
    } else if (key !== this.lastKey) {
      // Deleted and re-set rather than left alone: a Map iterates in insertion
      // order, so this is what moves the connection to the back of the
      // eviction queue.
      this.connections.delete(key);
      this.connections.set(key, conn);
    }
    this.lastKey = key;

    return {
      conn,
      dir: senderIsA ? conn.a : conn.b,
      peer: senderIsA ? conn.b : conn.a,
      senderIsA,
    };
  }

  /** The same lookup, without creating anything. */
  private peek(srcIp: string, srcPort: number, dstIp: string, dstPort: number): {
    conn: TcpConnection; dir: TcpDirection; peer: TcpDirection; senderIsA: boolean;
  } | undefined {
    const from = `${srcIp}:${srcPort}`;
    const to = `${dstIp}:${dstPort}`;
    const senderIsA = from <= to;
    const conn = this.connections.get(senderIsA ? `${from}|${to}` : `${to}|${from}`);
    if (conn === undefined) return undefined;
    return {
      conn,
      dir: senderIsA ? conn.a : conn.b,
      peer: senderIsA ? conn.b : conn.a,
      senderIsA,
    };
  }

  /** Forgets the least recently seen connections once the cap is exceeded. */
  private evictPastCap(): void {
    while (this.connections.size > MAX_CONNECTIONS) {
      const oldest = this.connections.keys().next();
      if (oldest.done) break;
      const conn = this.connections.get(oldest.value);
      this.connections.delete(oldest.value);
      // The stream index goes with it, or `byStreamId` becomes the leak this
      // eviction exists to stop. Indexes are never reused - `nextStreamId`
      // only ever counts up - so nothing can collide with the one just freed.
      if (conn?.streamId !== undefined) this.byStreamId.delete(conn.streamId);
      if (this.lastKey === oldest.value) this.lastKey = undefined;
      this.evicted += 1;
    }
  }

  /**
   * How many connections have been forgotten to stay inside the cap.
   *
   * Zero for every ordinary capture. Non-zero means some frames were given a
   * fresh stream index and relative-sequence base part-way through a
   * conversation, which is a thing to be able to say rather than to hide.
   */
  public get evictedConnections(): number {
    return this.evicted;
  }

  /** How many connections currently hold state. */
  public get connectionCount(): number {
    return this.connections.size;
  }

  /**
   * Numbers the next stream this tracker meets.
   *
   * A stream index is assigned in order of first appearance across the whole
   * capture, so a tracker that has only ever seen one conversation calls it 0
   * - which is wrong for a replay, where the point is to reproduce the tree of
   * a frame whose stream the real capture numbered something else
   * (services/pipeline/replay.ts). The frame already knows its own index; this
   * is how it tells a fresh tracker.
   */
  public seedNextStreamId(id: number): void {
    this.nextStreamId = id;
  }

  /**
   * Returns a stable, zero-based ID shared by both directions of a TCP
   * conversation, assigning a new one the first time a connection is seen.
   */
  public getStreamId(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    if (conn.streamId === undefined) {
      conn.streamId = this.nextStreamId++;
      this.byStreamId.set(conn.streamId, conn);
    }
    return conn.streamId;
  }

  /**
   * Runs Wireshark's sequence analysis for one segment and returns its flags.
   * The two directions of a connection share one state record; which half
   * this segment travels in is decided by the same ordering the connection
   * key uses, so both ends see the same `a`/`b`.
   */
  public analyze(srcIp: string, srcPort: number, dstIp: string, dstPort: number, segment: TcpSegment): TcpAnalysis {
    const { conn, senderIsA } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.analysis ??= freshConnection();
    return analyzeTcpSegment(conn.analysis, senderIsA ? 'a' : 'b', segment);
  }

  /**
   * Returns the sequence number relative to this direction's base (the reference analyzer's
   * default display), establishing that base the first time a direction is
   * seen. Wraparound-safe: uses unsigned modular subtraction rather than naive
   * arithmetic, since raw TCP sequence numbers legitimately wrap past 2**32 on
   * long-lived connections.
   *
   * The base depends on whether the handshake was captured, and getting this
   * wrong shifts every Seq= and Ack= in the stream by one:
   *
   *   - SYN seen: base = the SYN's own sequence number, so the SYN reports
   *     Seq=0 and the first byte of data reports Seq=1.
   *   - Mid-stream capture (no SYN): base = first seen sequence *minus one*,
   *     so the first observed segment also reports Seq=1. The reference analyzer does this
   *     so that a capture started mid-connection reads the same way as one
   *     that caught the handshake.
   */
  public getRelativeSeq(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    seqNum: number, isSyn: boolean = false
  ): number {
    const { dir } = this.locate(srcIp, srcPort, dstIp, dstPort);
    if (dir.baseSeq === undefined) {
      dir.baseSeq = isSyn ? seqNum : (seqNum - 1 + 2 ** 32) % 2 ** 32;
    }
    return ((seqNum - dir.baseSeq) + 2 ** 32) % 2 ** 32;
  }

  /**
   * Records the window scale shift negotiated by this direction's SYN. Scaling
   * only applies once *both* ends have advertised support, which is why this
   * is stored per direction and checked pairwise in getWindowScaleShift().
   */
  public setWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number, shift: number): void {
    this.locate(srcIp, srcPort, dstIp, dstPort).dir.windowScaleShift = shift;
  }

  /**
   * Returns the shift to apply to this direction's advertised window, or 0
   * when scaling isn't in effect. A mid-stream capture never saw either SYN,
   * so nothing scales and the raw window value is displayed as-is - matching
   * what the reference analyzer shows when it can't observe the negotiation.
   */
  public getWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const found = this.peek(srcIp, srcPort, dstIp, dstPort);
    if (found === undefined) return 0;
    const own = found.dir.windowScaleShift;
    const peer = found.peer.windowScaleShift;
    return own !== undefined && peer !== undefined ? own : 0;
  }

  /**
   * Whether a segment is at or beyond where this direction left off BEFORE
   * this segment was analysed - the cases in which the TLS record cursor may
   * be consulted. A segment behind that point (a retransmission, or data
   * arriving out of order) must not consume record bytes a second time; one
   * beyond it (after a gap) is read against the record's end sequence
   * number, which a gap does not move. Call before analyze().
   */
  public isAtOrPastExpected(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number): boolean {
    const found = this.peek(srcIp, srcPort, dstIp, dstPort);
    const analysis = found?.conn.analysis;
    if (found === undefined || analysis === undefined) return true;
    const fwd = found.senderIsA ? analysis.a : analysis.b;
    return fwd.nextSeq === 0 || ((seqNum - fwd.nextSeq) | 0) >= 0;
  }

  /** This direction's TLS record cursor, created on first use. */
  public tlsCursor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsRecordCursor {
    const { dir } = this.locate(srcIp, srcPort, dstIp, dstPort);
    dir.tlsCursor ??= freshTlsCursor();
    return dir.tlsCursor;
  }

  /** This direction's BGP reassembly state, created on first use. */
  public bgpDirection(srcIp: string, srcPort: number, dstIp: string, dstPort: number): BgpDirectionState {
    const { dir } = this.locate(srcIp, srcPort, dstIp, dstPort);
    dir.bgp ??= freshBgpDirection();
    return dir.bgp;
  }

  /**
   * This direction's BGP state if it has one, without creating it.
   *
   * The dispatch needs this before it knows whether the stream is BGP: a
   * segment in the middle of a long UPDATE carries no marker of its own, so
   * "is there a message in flight here" is the only thing that identifies it.
   */
  public peekBgpDirection(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
  ): BgpDirectionState | undefined {
    return this.peek(srcIp, srcPort, dstIp, dstPort)?.dir.bgp;
  }

  /** The cursor if this direction has one, without creating it. */
  public peekTlsCursor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsRecordCursor | undefined {
    return this.peek(srcIp, srcPort, dstIp, dstPort)?.dir.tlsCursor;
  }

  /**
   * Tells this direction's record cursor that bytes before this segment were
   * never captured.
   *
   * Only needed for a segment with **no payload**, because one with a payload
   * carries the same news into `dissectTlsSegment` as `ctx.gap`. Both end up
   * in `applyGapToCursor`, which is the point: the rule lives once.
   */
  public noteGap(srcIp: string, srcPort: number, dstIp: string, dstPort: number, segmentSeq: number): void {
    const cursor = this.peek(srcIp, srcPort, dstIp, dstPort)?.dir.tlsCursor;
    if (cursor !== undefined) applyGapToCursor(cursor, segmentSeq);
  }

  /** The TLS facts both directions share, created on first use. */
  public tlsConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.tls ??= freshTlsConversation();
    return conn.tls;
  }

  /** LDAP's per-connection counters, created on first use. */
  public ldapConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): LdapConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.ldap ??= freshLdapConversation();
    return conn.ldap;
  }

  /** SMB2's per-connection counters, created on first use. */
  public smb2Conversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): Smb2ConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.smb2 ??= freshSmb2Conversation();
    return conn.smb2;
  }

  /** Returns this packet's 1-based position within its stream, recording it. */
  public recordStreamPacket(streamId: number): number {
    const conn = this.byStreamId.get(streamId);
    // A stream index whose connection has been evicted counts from one again,
    // which is what a connection this tracker has not seen before looks like.
    if (conn === undefined) return 1;
    return ++conn.packets;
  }

  public updateConnectionState(streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean): void {
    const conn = this.byStreamId.get(streamId);
    if (conn === undefined) return;
    if (syn && !ack) conn.sawSyn = true;
    if (syn && ack) conn.sawSynAck = true;
    if (fin || rst) conn.sawFinOrRst = true;
  }

  /**
   * A plain-English summary of handshake progress - deliberately not
   * The reference analyzer's internal numeric completeness bitmask, since that's an
   * implementation detail nobody reading this UI needs to decode.
   */
  public getConversationCompleteness(streamId: number): string {
    const conn = this.byStreamId.get(streamId);
    if (!conn) return 'Incomplete';
    if (conn.sawSyn && conn.sawSynAck && conn.sawFinOrRst) return 'Complete, WITH_DATA';
    if (conn.sawSyn && conn.sawSynAck) return 'Established, no close seen';
    if (conn.sawSyn) return 'SYN sent, no reply seen';
    return 'Incomplete';
  }

  public reset(): void {
    this.connections.clear();
    this.byStreamId.clear();
    this.nextStreamId = 0;
    this.lastKey = undefined;
    this.evicted = 0;
  }
}
