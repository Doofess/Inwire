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
import { freshDcerpcConversation, type DcerpcConversationState } from './dissectors/dcerpc';
import { analyzeTcpSegment, freshConnection, type TcpAnalysis, type TcpConnectionState, type TcpSegment } from './dissect/tcpAnalysis';

import type { TlsDecryptionKeys } from './tls/decrypt';
import type { AppDirection } from './dissectors/appStream';
import { releaseHttp1Body } from './dissectors/http1';
import { LIVE_ENV, withDissectEnv } from './dissect/dissectEnv';
import { Sequencer, tcpConnectionKey, type TcpOrderApi } from './dissect/sequencer';
import { freshLdapConversation, type LdapConversationState } from './dissectors/ldap';
import { freshSmb2Conversation, type Smb2ConversationState } from './dissectors/smb2';
import { freshSshConversation, type SshConversationState } from './dissectors/ssh';
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
  /**
   * Where each piece of `buffer` was cut from: the frame, and the offset and
   * length in that frame's bytes. Kept beside the buffer, entry for entry, so a
   * record of this cursor can name the bytes instead of copying them - they are
   * already stored as those frames' own bytes (ADR 0049).
   */
  bufferSources: { frame: number; at: number; length: number }[];
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
  /**
   * Set only on a conversation rebuilt from a frame record (ADR 0049): the key
   * log labels its keys were built from when that frame arrived, empty for
   * none (`keyLabels`). The record holds no keys, so a revisit derives them
   * from the key log it has now, and misses unless they come from the same
   * labels. Never set on a live conversation.
   */
  keyLabelsAtArrival?: string[];
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
    contributors: [], contributions: [], buffer: null, bufferSources: [], bufferedBytes: 0, unknown: true, encrypted: false, holed: false,
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
    cursor.bufferSources = [];
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
  /**
   * When this stream's first frame arrived, and its most recent, in epoch
   * microseconds - the two clocks `tcp.time_relative` and `tcp.time_delta` are
   * measured against.
   *
   * Per connection rather than per direction, which is the reference's own
   * choice: both fields describe the conversation, so an ACK coming back
   * resets the delta just as a data segment going out does.
   *
   * Two numbers on a record that already exists, against ADR 0014's rule about
   * what a connection may cost. They are unconditional because every TCP frame
   * wants them, where `tls`/`ldap`/`smb2` beside them are allocated only on a
   * connection that speaks those.
   */
  firstTsUs?: number;
  lastTsUs?: number;
  sawSyn: boolean;
  sawSynAck: boolean;
  sawFinOrRst: boolean;
  /**
   * The rest of the reference's completeness bits.
   *
   * `sawFinOrRst` above answers "did this conversation end", which is what the
   * plain-English summary needs; these answer "which of the six things did
   * this capture actually contain", which is a different and more useful
   * question - it is how you find out that a stream you are about to analyse
   * is missing its handshake, and therefore that every relative sequence
   * number in it is relative to a guess.
   */
  sawAck: boolean;
  sawData: boolean;
  sawFin: boolean;
  sawRst: boolean;
  /**
   * Which endpoint sent the first FIN, so a later one on the other side reads
   * as the passive half of the close rather than a second active one.
   */
  finFrom?: 'a' | 'b';
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
  dcerpc?: DcerpcConversationState;
  ssh?: SshConversationState;
  /** The endpoint that sorts first, and the other one. */
  a: TcpDirection;
  b: TcpDirection;
}

function freshTcpConnection(): TcpConnection {
  return {
    packets: 0, sawSyn: false, sawSynAck: false, sawFinOrRst: false,
    sawAck: false, sawData: false, sawFin: false, sawRst: false, a: {}, b: {},
  };
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
 *
 * **The cap and the order live in the `Sequencer` now** (`MAX_TCP_CONNECTIONS`
 * and `TcpOrder` in `dissect/sequencer.ts`, ADR 0053), with `tcp.stream` and
 * `tls.stream`: which connection is forgotten, and what a connection is
 * numbered, both depend on the order of frames from every connection, and
 * once connections are dissected on several cores only one stage sees that
 * order. This tracker keeps each connection's state and asks the order at the
 * points it used to reorder its own map.
 */

/** One lookup's answer: the connection, the sender's half, and the key both directions share. */
interface Found {
  conn: TcpConnection; dir: TcpDirection; peer: TcpDirection; senderIsA: boolean; key: string;
}

export class TcpStreamTracker {
  /** One record per conversation, by key. Their order is the `TcpOrder`'s. */
  private connections = new Map<string, TcpConnection>();
  /** The same records by stream index, for the callers that hold only that. */
  private byStreamId = new Map<number, TcpConnection>();
  private readonly order: TcpOrderApi;

  constructor(sequencer: { tcp: TcpOrderApi } = new Sequencer()) {
    this.order = sequencer.tcp;
  }
  /**
   * The whole result of the last lookup, keyed by the four values that produced
   * it.
   *
   * The order's own last-key check saves the delete-and-reinsert (`TcpOrder`);
   * it does not save **building the strings to find out**. Each call makes
   * three - `srcIp:srcPort`,
   * `dstIp:dstPort` and the key joining them - which for a pair of IPv6
   * addresses is around 135 characters allocated and hashed, and one TCP frame
   * makes several such calls (the sequence analysis, the TLS cursor, the TLS
   * conversation, and whichever of LDAP/SMB2/BGP the port matched). A CPU
   * profile put `locate` and `peek` together at **8.6%** of the pipeline.
   *
   * One entry is the right size for two reasons that compound: every call
   * within a frame asks about the same connection, and consecutive frames
   * usually do too - a bulk transfer is one connection for its whole length.
   * The four-field comparison tests the ports first, so a miss is normally two
   * integer compares rather than a string compare.
   *
   * Only ever holds a connection that EXISTS. A `peek` that found nothing
   * stores nothing, or a later `locate` would hand back a memo of absence
   * instead of creating the connection it is supposed to create.
   */
  private lastLookup: {
    srcIp: string; srcPort: number; dstIp: string; dstPort: number;
    found: Found;
  } | undefined;

  /** True when the memo describes exactly this direction of this connection. */
  private memoHit(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    const m = this.lastLookup;
    return m !== undefined
      && m.srcPort === srcPort && m.dstPort === dstPort
      && m.srcIp === srcIp && m.dstIp === dstIp;
  }

  /**
   * Finds one connection and the calling direction, creating both on first use.
   *
   * Builds the two endpoint strings once and derives everything from them: the
   * connection key, which half of the conversation the sender is, and the
   * peer's half. The previous shape built the same strings twice over, once for
   * the connection key and again for the direction key.
   */
  private locate(srcIp: string, srcPort: number, dstIp: string, dstPort: number): Found {
    if (this.memoHit(srcIp, srcPort, dstIp, dstPort)) {
      // Nothing is skipped by returning here. The order's move-to-back is
      // already guarded on the key not being the last one it found, and a memo
      // hit is by construction the key that set it - so the slow path would
      // find the connection, leave it where it is, and return this.
      return this.lastLookup!.found;
    }
    const { key, senderIsA } = tcpConnectionKey(srcIp, srcPort, dstIp, dstPort);

    // The order decides which connection is forgotten past the cap, and it is
    // asked at exactly the point this map used to move the connection to the
    // back of its own queue - so the same connection goes (`TcpOrder`).
    for (const gone of this.order.locate(key)) this.forget(gone);
    let conn = this.connections.get(key);
    if (conn === undefined) {
      conn = freshTcpConnection();
      this.connections.set(key, conn);
    }

    const found: Found = {
      conn,
      dir: senderIsA ? conn.a : conn.b,
      peer: senderIsA ? conn.b : conn.a,
      senderIsA,
      key,
    };
    this.lastLookup = { srcIp, srcPort, dstIp, dstPort, found };
    return found;
  }

  /** The same lookup, without creating anything. */
  private peek(srcIp: string, srcPort: number, dstIp: string, dstPort: number): Found | undefined {
    if (this.memoHit(srcIp, srcPort, dstIp, dstPort)) return this.lastLookup!.found;
    const { key, senderIsA } = tcpConnectionKey(srcIp, srcPort, dstIp, dstPort);
    const conn = this.connections.get(key);
    // A miss is NOT memoised: this call creates nothing, so storing "absent"
    // would let the next `locate` return it instead of creating the connection.
    if (conn === undefined) return undefined;
    const found: Found = {
      conn,
      key,
      dir: senderIsA ? conn.a : conn.b,
      peer: senderIsA ? conn.b : conn.a,
      senderIsA,
    };
    this.lastLookup = { srcIp, srcPort, dstIp, dstPort, found };
    return found;
  }

  /**
   * Drops a connection the order forgot to stay inside the cap
   * (`TcpOrder.locate`, which decides which one) - from inside a lookup, or,
   * on a shard, because the coordinator's order forgot it (ADR 0053).
   */
  public forget(key: string): void {
    const conn = this.connections.get(key);
    this.connections.delete(key);
    // A half-collected HTTP body's bytes are charged against a budget
    // shared by every connection, and this is the one path where collecting
    // stops without the body finishing. Forgetting the connection without
    // giving them back would spend a slice of that budget permanently - and
    // enough evictions would stop body reassembly for the rest of the
    // capture with nothing saying why. See `liveBodyBytes` in
    // `dissectors/http1.ts`.
    // Both the TLS-decrypted and the cleartext HTTP paths hang their
    // `AppDirection` off `tls`, which is why one lookup covers both.
    //
    // Given back to the live budget directly, not through the environment the
    // frame being dissected reads: an eviction is a side effect of a lookup,
    // not an answer that frame asked for, and recorded into its record it sat
    // between two answers a revisit does ask for - so every frame that pushed
    // out a connection with HTTP state missed when rebuilt. It is also what
    // keeps that frame's record the same when the connection lived on another
    // core and was forgotten there (ADR 0053).
    if (conn?.tls?.appClient !== undefined || conn?.tls?.appServer !== undefined) {
      withDissectEnv(LIVE_ENV, () => {
        if (conn.tls?.appClient !== undefined) releaseHttp1Body(conn.tls.appClient.http1);
        if (conn.tls?.appServer !== undefined) releaseHttp1Body(conn.tls.appServer.http1);
      });
    }
    // The stream index goes with it, or `byStreamId` becomes the leak this
    // eviction exists to stop. Indexes are never reused - the order only
    // ever counts up - so nothing can collide with the one just freed.
    if (conn?.streamId !== undefined) this.byStreamId.delete(conn.streamId);
    // Defensive, and knowingly so: this runs inside `locate`, before the new
    // connection's memo is assigned at the end of that same call, so the
    // memo cannot presently be holding a connection this just dropped.
    // Removing this line fails no test, which was checked. It is here for
    // the caller that one day evicts from somewhere else - a shard told by
    // the coordinator to forget a connection (ADR 0053) - where the failure
    // would be a frame served another connection's state: silent, and not
    // the kind of thing to leave to a future reader noticing the ordering.
    this.lastLookup = undefined;
  }

  /**
   * How many connections have been forgotten to stay inside the cap.
   *
   * Zero for every ordinary capture. Non-zero means some frames were given a
   * fresh stream index and relative-sequence base part-way through a
   * conversation, which is a thing to be able to say rather than to hide.
   */
  public get evictedConnections(): number {
    return this.order.evicted;
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
    this.order.seedNextStreamId(id);
  }

  /**
   * Returns a stable, zero-based ID shared by both directions of a TCP
   * conversation, assigning a new one the first time a connection is seen.
   * The number is the order's (`TcpOrder.streamId`), because it is numbered
   * across every connection.
   */
  public getStreamId(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const { conn, key } = this.locate(srcIp, srcPort, dstIp, dstPort);
    if (conn.streamId === undefined) {
      conn.streamId = this.order.streamId(key);
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

  /**
   * `tls.stream`: this connection's place in the sequence of TLS conversations,
   * assigned on first use like `getStreamId` and for the same reason - a
   * connection that never speaks TLS must not consume a number. The reference
   * numbers TLS conversations in their own sequence: on this repo's fixture
   * `tcp.stream` 1, 2, 3 carry `tls.stream` 0, 1, 2, because the connections in
   * between never spoke TLS.
   *
   * Asked of the order on every call rather than cached on the connection: the
   * order keeps it per connection already, and when connections are dissected
   * on several cores its first answer is a placeholder that a later one
   * replaces (`DeferredTlsNumbers`, ADR 0053).
   */
  public getTlsStreamId(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const { key } = this.locate(srcIp, srcPort, dstIp, dstPort);
    return this.order.tlsStreamId(key);
  }

  /** As `seedNextStreamId`, for the TLS sequence. See `L3Tracker.seedNextIndices`. */
  public seedNextTlsStreamId(next: number): void {
    this.order.seedNextTlsStreamId(next);
  }

  /** LDAP's per-connection counters, created on first use. */
  public ldapConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): LdapConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.ldap ??= freshLdapConversation();
    return conn.ldap;
  }

  /** SSH's two directions and what each side offered, created on first use. */
  public sshConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): SshConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.ssh ??= freshSshConversation();
    return conn.ssh;
  }

  /** SMB2's per-connection counters, created on first use. */
  public smb2Conversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): Smb2ConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.smb2 ??= freshSmb2Conversation();
    return conn.smb2;
  }

  /** DCE/RPC's bound contexts and outstanding calls, created on first use. */
  public dcerpcConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): DcerpcConversationState {
    const { conn } = this.locate(srcIp, srcPort, dstIp, dstPort);
    conn.dcerpc ??= freshDcerpcConversation();
    return conn.dcerpc;
  }

  /**
   * This packet's 1-based position within its stream, and the two stream
   * clocks - recording all three.
   *
   * One call rather than three, because every one of them is a write and
   * splitting them would mean three lookups per frame on the hot path. The
   * memo in `locate` exists because that cost was measured at 8.6% of the
   * pipeline once already.
   */
  public recordStreamPacket(streamId: number, tsUs?: number): {
    packetNumber: number;
    /** Since the stream's first frame, in seconds. */
    sinceFirst?: number;
    /** Since the previous frame on this stream, in seconds. */
    sincePrevious?: number;
  } {
    const conn = this.byStreamId.get(streamId);
    // A stream index whose connection has been evicted counts from one again,
    // which is what a connection this tracker has not seen before looks like.
    if (conn === undefined) return { packetNumber: 1 };
    const packetNumber = ++conn.packets;
    if (tsUs === undefined) return { packetNumber };
    // **The first frame of a stream is 0.000000 on both clocks, not absent.**
    // That is the reference's answer and it is the right one: the stream
    // starts here, so nothing has elapsed - which is a measurement, where an
    // empty row would read as one that could not be taken.
    conn.firstTsUs ??= tsUs;
    const sinceFirst = (tsUs - conn.firstTsUs) / 1e6;
    const sincePrevious = (tsUs - (conn.lastTsUs ?? tsUs)) / 1e6;
    conn.lastTsUs = tsUs;
    return { packetNumber, sinceFirst, sincePrevious };
  }

  public updateConnectionState(
    streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean, hasData = false,
  ): void {
    const conn = this.byStreamId.get(streamId);
    if (conn === undefined) return;
    if (syn && !ack) conn.sawSyn = true;
    if (syn && ack) conn.sawSynAck = true;
    if (fin || rst) conn.sawFinOrRst = true;
    // The reference counts a bare ACK, not the ACK flag on a SYN-ACK - which
    // is already its own bit and would otherwise set two.
    if (ack && !syn) conn.sawAck = true;
    if (hasData) conn.sawData = true;
    if (fin) conn.sawFin = true;
    if (rst) conn.sawRst = true;
  }

  /**
   * Records which side sent the first FIN, and says whether this one is it.
   *
   * "Active" and "passive" close are the reference's words, and the
   * distinction is the useful half of a FIN: it is the difference between a
   * client that finished and a server that dropped it, which a flag alone
   * cannot tell you because both frames carry the same flag.
   *
   * Idempotent on purpose - a retransmitted FIN is the same direction, so it
   * still reads as the active one rather than becoming the passive close of
   * itself.
   */
  public noteFin(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
  ): 'active' | 'passive' {
    const found = this.locate(srcIp, srcPort, dstIp, dstPort);
    const side = found.senderIsA ? 'a' : 'b';
    if (found.conn.finFrom === undefined) found.conn.finFrom = side;
    return found.conn.finFrom === side ? 'active' : 'passive';
  }

  /**
   * A plain-English summary of handshake progress - deliberately not
   * The reference analyzer's internal numeric completeness bitmask, since that's an
   * implementation detail nobody reading this UI needs to decode.
   */
  /**
   * The reference's six completeness bits as its own bitmask.
   *
   * The plain-English summary beside this deliberately does not print the
   * number (see `getConversationCompleteness`), and that stands - but the
   * individual bits are not an implementation detail, they are six separate
   * facts about what the capture contains, and each one is a filter somebody
   * would type: `tcp.completeness.syn == 0` finds every stream whose
   * handshake was missed.
   */
  public getCompletenessMask(streamId: number): number {
    const conn = this.byStreamId.get(streamId);
    if (!conn) return 0;
    return (conn.sawSyn ? 1 : 0)
      | (conn.sawSynAck ? 2 : 0)
      | (conn.sawAck ? 4 : 0)
      | (conn.sawData ? 8 : 0)
      | (conn.sawFin ? 16 : 0)
      | (conn.sawRst ? 32 : 0);
  }

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
    this.order.reset();
    this.lastLookup = undefined;
  }
}
