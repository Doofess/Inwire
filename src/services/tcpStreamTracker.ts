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
    contributors: [], contributions: [], buffer: null, bufferedBytes: 0, unknown: true, encrypted: false,
    recordEndSeq: 0, role: 'unknown', readOnly: false, epoch: 0, recordSeq: 0,
  };
}

export function freshTlsConversation(): TlsConversationState {
  return { clientHelloSeen: false, serverHelloSeen: false, encryptedHandshake: false, pendingVersionFrames: [] };
}

export class TcpStreamTracker {
  private streamIds = new Map<string, number>();
  private tlsCursors = new Map<string, TlsRecordCursor>();
  private tlsConversations = new Map<string, TlsConversationState>();
  private nextStreamId = 0;
  private baseSeq = new Map<string, number>();
  private packetCountByStream = new Map<number, number>();
  private connState = new Map<number, { sawSyn: boolean; sawSynAck: boolean; sawFinOrRst: boolean }>();
  private windowScaleShift = new Map<string, number>();
  /** Sequence-analysis state per connection (docs: dissect/tcpAnalysis.ts). */
  private analysis = new Map<string, TcpConnectionState>();

  private connectionKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    const a = `${srcIp}:${srcPort}`;
    const b = `${dstIp}:${dstPort}`;
    return a <= b ? `${a}|${b}` : `${b}|${a}`;
  }

  /**
   * Keys one *direction* of a connection: the (symmetric) connection key plus
   * the sending endpoint, so the two halves of a conversation track their
   * sequence state independently.
   */
  private directionKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    return `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
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
    const key = this.connectionKey(srcIp, srcPort, dstIp, dstPort);
    let id = this.streamIds.get(key);
    if (id === undefined) {
      id = this.nextStreamId++;
      this.streamIds.set(key, id);
    }
    return id;
  }

  /**
   * Runs Wireshark's sequence analysis for one segment and returns its flags.
   * The two directions of a connection share one state record; which half
   * this segment travels in is decided by the same ordering the connection
   * key uses, so both ends see the same `a`/`b`.
   */
  public analyze(srcIp: string, srcPort: number, dstIp: string, dstPort: number, segment: TcpSegment): TcpAnalysis {
    const key = this.connectionKey(srcIp, srcPort, dstIp, dstPort);
    let conn = this.analysis.get(key);
    if (conn === undefined) {
      conn = freshConnection();
      this.analysis.set(key, conn);
    }
    const direction = `${srcIp}:${srcPort}` <= `${dstIp}:${dstPort}` ? 'a' : 'b';
    return analyzeTcpSegment(conn, direction, segment);
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
    const directionKey = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    let base = this.baseSeq.get(directionKey);
    if (base === undefined) {
      base = isSyn ? seqNum : (seqNum - 1 + 2 ** 32) % 2 ** 32;
      this.baseSeq.set(directionKey, base);
    }
    return ((seqNum - base) + 2 ** 32) % 2 ** 32;
  }

  /**
   * Records the window scale shift negotiated by this direction's SYN. Scaling
   * only applies once *both* ends have advertised support, which is why this
   * is stored per direction and checked pairwise in getWindowScaleShift().
   */
  public setWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number, shift: number): void {
    this.windowScaleShift.set(this.directionKey(srcIp, srcPort, dstIp, dstPort), shift);
  }

  /**
   * Returns the shift to apply to this direction's advertised window, or 0
   * when scaling isn't in effect. A mid-stream capture never saw either SYN,
   * so nothing scales and the raw window value is displayed as-is - matching
   * what the reference analyzer shows when it can't observe the negotiation.
   */
  public getWindowScaleShift(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number {
    const own = this.windowScaleShift.get(this.directionKey(srcIp, srcPort, dstIp, dstPort));
    const peer = this.windowScaleShift.get(this.directionKey(dstIp, dstPort, srcIp, srcPort));
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
    const conn = this.analysis.get(this.connectionKey(srcIp, srcPort, dstIp, dstPort));
    if (conn === undefined) return true;
    const fwd = `${srcIp}:${srcPort}` <= `${dstIp}:${dstPort}` ? conn.a : conn.b;
    return fwd.nextSeq === 0 || ((seqNum - fwd.nextSeq) | 0) >= 0;
  }

  /** This direction's TLS record cursor, created on first use. */
  public tlsCursor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsRecordCursor {
    const key = this.directionKey(srcIp, srcPort, dstIp, dstPort);
    let cursor = this.tlsCursors.get(key);
    if (cursor === undefined) {
      cursor = freshTlsCursor();
      this.tlsCursors.set(key, cursor);
    }
    return cursor;
  }

  /** The cursor if this direction has one, without creating it. */
  public peekTlsCursor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsRecordCursor | undefined {
    return this.tlsCursors.get(this.directionKey(srcIp, srcPort, dstIp, dstPort));
  }

  /** Forgets where this direction was in the record layer - after a gap, nothing about it is known. */
  public resetTlsCursor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): void {
    this.tlsCursors.set(this.directionKey(srcIp, srcPort, dstIp, dstPort), freshTlsCursor());
  }

  /** The TLS facts both directions share, created on first use. */
  public tlsConversation(srcIp: string, srcPort: number, dstIp: string, dstPort: number): TlsConversationState {
    const key = this.connectionKey(srcIp, srcPort, dstIp, dstPort);
    let state = this.tlsConversations.get(key);
    if (state === undefined) {
      state = freshTlsConversation();
      this.tlsConversations.set(key, state);
    }
    return state;
  }

  /** Returns this packet's 1-based position within its stream, recording it. */
  public recordStreamPacket(streamId: number): number {
    const count = (this.packetCountByStream.get(streamId) ?? 0) + 1;
    this.packetCountByStream.set(streamId, count);
    return count;
  }

  public updateConnectionState(streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean): void {
    const state = this.connState.get(streamId) ?? { sawSyn: false, sawSynAck: false, sawFinOrRst: false };
    if (syn && !ack) state.sawSyn = true;
    if (syn && ack) state.sawSynAck = true;
    if (fin || rst) state.sawFinOrRst = true;
    this.connState.set(streamId, state);
  }

  /**
   * A plain-English summary of handshake progress - deliberately not
   * The reference analyzer's internal numeric completeness bitmask, since that's an
   * implementation detail nobody reading this UI needs to decode.
   */
  public getConversationCompleteness(streamId: number): string {
    const state = this.connState.get(streamId);
    if (!state) return 'Incomplete';
    if (state.sawSyn && state.sawSynAck && state.sawFinOrRst) return 'Complete, WITH_DATA';
    if (state.sawSyn && state.sawSynAck) return 'Established, no close seen';
    if (state.sawSyn) return 'SYN sent, no reply seen';
    return 'Incomplete';
  }

  public reset(): void {
    this.streamIds.clear();
    this.baseSeq.clear();
    this.packetCountByStream.clear();
    this.connState.clear();
    this.windowScaleShift.clear();
    this.analysis.clear();
    this.tlsCursors.clear();
    this.tlsConversations.clear();
    this.nextStreamId = 0;
  }
}
