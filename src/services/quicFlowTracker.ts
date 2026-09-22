/**
 * Remembers which UDP flows have been observed carrying a QUIC long header,
 * and which connection IDs those headers named.
 *
 * This exists because a QUIC *short* header is nearly unidentifiable on its
 * own: it has no version field, and the destination connection ID that follows
 * the first byte has no length prefix - only the two endpoints know how long
 * it is. So a short-header packet can only be recognized as QUIC in the
 * context of a handshake seen earlier on the same flow, which is exactly what
 * The reference analyzer does. Without this, any UDP datagram on port 443 whose first byte
 * happens to have the right two bits set gets mislabeled QUIC - including the
 * datagrams that precede the handshake, which the reference analyzer reports as plain UDP.
 *
 * One instance represents one capture session; call reset() when the packet
 * buffer is cleared or a new file is imported.
 */
import {
  deriveInitialKeys, deriveTrafficKeys, saltForVersion, decryptQuicPacket,
  QUIC_VERSION_2, type DirectionKeys, type InitialKeys,
} from './dissectors/quicCrypto';
import type { CryptoFragment, PacketDecryptor, StreamFragment } from './dissectors/quic';
import { parseQuicHandshake, type HelloFacts, type ServerHelloFacts } from './dissectors/tls';
import { cipherSuiteSpec } from './tls/cipherSuites';
import { keyLog } from './tls/keyLog';
import { dissectHttp3Stream, freshHttp3Stream, type Http3Frame, type Http3Stream } from './dissectors/http3';

interface InitialSession {
  keys: InitialKeys;
  /** "ip:port" of whichever endpoint sent the connection's first Initial. */
  clientEndpoint: string;
}

/**
 * The TLS handshake being reassembled out of one direction's CRYPTO frames.
 *
 * QUIC carries the handshake as a byte stream with explicit offsets, and a
 * client is free to split and reorder it - the fixtures contain hellos
 * arriving as ten fragments across two Initial packets, in no useful order.
 * So fragments are filled into a sparse buffer and parsed once the stream is
 * contiguous from zero and long enough to hold the message it declares.
 */
interface CryptoStream {
  chunks: { offset: number; data: Uint8Array }[];
  /** Highest byte offset seen, which bounds the buffer. */
  extent: number;
  /** Set once parsed, so a retransmitted fragment does not reparse. */
  done: boolean;
}

/** What a completed handshake told us about the connection. */
export interface QuicHandshakeFacts {
  hello?: HelloFacts;
  serverHello?: ServerHelloFacts;
}

/** A handshake message longer than this is not one we can use. */
const MAX_CRYPTO_BYTES = 65536;

/** What a flow needs before a key log can open anything past its Initials. */
interface QuicSession {
  clientRandom?: Uint8Array;
  cipherSuite?: number;
  /**
   * The suites the ClientHello offered, kept for 0-RTT alone: its keys are
   * needed before the ServerHello has named one. See `earlyKeys`.
   */
  offeredCiphers?: number[];
  /** undefined before the attempt, null when the key log had nothing for it. */
  keys?: QuicSessionKeys | null;
  keyGeneration?: number;
  /** The ALPN the handshake settled on, so `h3` is not assumed. */
  alpn?: string;
}

interface QuicSessionKeys {
  handshake?: { client: DirectionKeys; server: DirectionKeys };
  application?: { client: DirectionKeys; server: DirectionKeys };
}

/** One QUIC stream being put back together, per direction. */
interface StreamAssembly {
  http3: Http3Stream;
  /** The offset the next byte handed to HTTP/3 must have. */
  nextOffset: number;
  /** Fragments that arrived ahead of the gap, by offset. */
  pending: Map<number, Uint8Array>;
  pendingBytes: number;
}

/**
 * The held fragment that carries the byte at `nextOffset`, trimmed to start
 * there, with everything the cursor has passed dropped from the budget.
 *
 * Returns what it released as well as what it took, because the same bytes are
 * charged against two budgets: this stream's, and the whole tracker's
 * (`MAX_TOTAL_PENDING_BYTES`). A release that settled only the first would
 * leak the second, which is the bug the per-stream budget already had once.
 *
 * An exact `pending.get(nextOffset)` was not enough. A fragment held at
 * offset 100 is stranded for ever the moment a larger fragment arrives at 50
 * and carries the cursor to 150 - never consumed, never subtracted, and so
 * charged against MAX_PENDING_STREAM_BYTES until the connection ends. The scan
 * is O(held fragments), which the budget bounds at a couple of hundred, and it
 * also lets a partially overlapping fragment contribute its new tail instead
 * of being discarded.
 */
function takePendingAt(assembly: StreamAssembly): { data?: Uint8Array; released: number } {
  let released = 0;
  let take: { offset: number; data: Uint8Array } | undefined;
  for (const [offset, data] of assembly.pending) {
    if (offset + data.length <= assembly.nextOffset) {
      assembly.pending.delete(offset);
      assembly.pendingBytes -= data.length;
      released += data.length;
      continue;
    }
    // The earliest fragment that reaches the cursor: it carries the most.
    if (offset <= assembly.nextOffset && (take === undefined || offset < take.offset)) {
      take = { offset, data };
    }
  }
  if (take === undefined) return { released };
  assembly.pending.delete(take.offset);
  assembly.pendingBytes -= take.data.length;
  released += take.data.length;
  const skip = assembly.nextOffset - take.offset;
  return { data: skip > 0 ? take.data.subarray(skip) : take.data, released };
}

/** A stream's bytes held while waiting for the gap before them to be filled. */
const MAX_PENDING_STREAM_BYTES = 256 * 1024;

/**
 * Held stream bytes across every stream of every flow.
 *
 * `MAX_PENDING_STREAM_BYTES` bounds one stream. Nothing bounded their sum, and
 * a QUIC connection opens a stream per request - so a browser talking HTTP/3 to
 * a site that loses packets could hold a quarter of a megabyte per stream with
 * no ceiling at all. This is the ceiling.
 */
const MAX_TOTAL_PENDING_BYTES = 8 * 1024 * 1024;

/**
 * How many flows keep state, and how many streams across all of them.
 *
 * Both are per *connection*, not per frame, so no packet-buffer cap touches
 * them: `trimToCap` drops frames and leaves every one of these behind
 * (`scripts/perf/tracker-cost.ts`). A browsing session is thousands of short
 * connections, which is the shape that fills them.
 *
 * Eviction is least-recently-used rather than oldest-first, which matters here:
 * a QUIC connection can be idle for minutes and then resume, and the flow that
 * has gone longest without a packet is the one whose loss costs least. What is
 * lost is a flow's decryption keys and reassembly cursor - so a later packet on
 * an evicted flow reads as an unrecognised one, which is what it looks like
 * from the wire without the handshake anyway.
 */
const MAX_FLOWS = 4096;
const MAX_STREAMS = 8192;

/**
 * Connection IDs remembered per flow.
 *
 * A peer may issue new connection IDs for the life of a connection - that is
 * how QUIC migrates between addresses without being linkable - and every one
 * was kept for ever. Capped, and oldest-first, because `matchConnectionId`
 * scans this set for every short-header packet: an unbounded set is a growing
 * per-packet cost as well as a growing one in memory.
 */
const MAX_CONNECTION_IDS_PER_FLOW = 32;

export class QuicFlowTracker {
  /** Connection IDs (hex) seen in long headers, keyed by normalized flow. */
  private flowConnectionIds = new Map<string, Set<string>>();
  /** Initial keys and client identity, keyed by normalized flow. */
  private initialSessions = new Map<string, InitialSession>();
  /** Highest packet number decrypted per sending direction. */
  private largestPacketNumber = new Map<string, number>();
  /** CRYPTO reassembly, per sending direction. */
  private cryptoStreams = new Map<string, CryptoStream>();
  /** The SNI this flow's ClientHello carried, for labelling later packets. */
  private flowSni = new Map<string, string>();
  /** Key material and handshake facts, keyed by normalized flow. */
  private sessions = new Map<string, QuicSession>();
  /** HTTP/3 stream state, keyed by flow, sender and stream id. */
  private streams = new Map<string, StreamAssembly>();
  /** Held bytes across every assembly above, against MAX_TOTAL_PENDING_BYTES. */
  private totalPendingBytes = 0;

  /** Order-independent key, so both directions of a flow share their state. */
  private flowKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    const a = `${srcIp}:${srcPort}`;
    const b = `${dstIp}:${dstPort}`;
    return a <= b ? `${a}|${b}` : `${b}|${a}`;
  }

  /**
   * Records that this flow carried a long header, along with any non-empty
   * connection IDs it advertised. Registering the flow at all is what makes
   * subsequent short-header packets recognizable.
   */
  public noteLongHeader(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    connectionIds: string[]
  ): void {
    const key = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    let ids = this.flowConnectionIds.get(key);
    if (!ids) ids = new Set<string>();
    for (const id of connectionIds) {
      if (id.length === 0) continue;
      ids.add(id);
      // Insertion-ordered, so the first key out is the id issued longest ago -
      // and a peer that has issued 32 since is not still using it.
      while (ids.size > MAX_CONNECTION_IDS_PER_FLOW) {
        const oldest = ids.values().next();
        if (oldest.done) break;
        ids.delete(oldest.value);
      }
    }
    // Re-inserted rather than updated in place: a Map iterates in insertion
    // order, so deleting and setting is what moves this flow to the back of
    // the eviction queue. `flowConnectionIds` is the flow registry - a flow
    // exists exactly when it has an entry here (`isKnownFlow`) - so it is the
    // one map whose order can stand for all of them.
    this.flowConnectionIds.delete(key);
    this.flowConnectionIds.set(key, ids);
    this.evictFlowsPastCap();
  }

  /**
   * Forgets every flow past the cap, least-recently-seen first.
   *
   * The seven maps are keyed three different ways - by flow, by flow and
   * sender, and by flow, sender and stream id - so forgetting one flow means
   * scanning the direction-keyed ones for its prefix. That is O(entries) per
   * eviction, which is why this only runs when the cap is actually exceeded
   * rather than on every packet.
   */
  private evictFlowsPastCap(): void {
    while (this.flowConnectionIds.size > MAX_FLOWS) {
      const oldest = this.flowConnectionIds.keys().next();
      if (oldest.done) break;
      this.forgetFlow(oldest.value);
    }
    // A flow can open many streams, so their total is bounded separately: one
    // busy HTTP/3 connection can exceed this while the flow count is fine.
    while (this.streams.size > MAX_STREAMS) {
      const oldest = this.streams.keys().next();
      if (oldest.done) break;
      const assembly = this.streams.get(oldest.value);
      if (assembly) this.totalPendingBytes -= assembly.pendingBytes;
      this.streams.delete(oldest.value);
    }
  }

  /** Drops everything held for one flow, across every map that keys by it. */
  private forgetFlow(flowKey: string): void {
    this.flowConnectionIds.delete(flowKey);
    this.initialSessions.delete(flowKey);
    this.flowSni.delete(flowKey);
    this.sessions.delete(flowKey);
    const prefix = flowKey + '>';
    for (const key of this.largestPacketNumber.keys()) {
      if (key.startsWith(prefix)) this.largestPacketNumber.delete(key);
    }
    for (const key of this.cryptoStreams.keys()) {
      if (key.startsWith(prefix)) this.cryptoStreams.delete(key);
    }
    for (const [key, assembly] of this.streams) {
      if (!key.startsWith(prefix)) continue;
      this.totalPendingBytes -= assembly.pendingBytes;
      this.streams.delete(key);
    }
  }

  public isKnownFlow(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    return this.flowConnectionIds.has(this.flowKey(srcIp, srcPort, dstIp, dstPort));
  }

  /**
   * Returns the connection ID a short header carries, if the bytes right after
   * its first byte match one this flow has already advertised. A zero-length
   * connection ID - which one peer commonly chooses - matches nothing and
   * correctly yields undefined, so the Info column simply omits it.
   */
  public matchConnectionId(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    bytes: Uint8Array, offset: number
  ): string | undefined {
    const ids = this.flowConnectionIds.get(this.flowKey(srcIp, srcPort, dstIp, dstPort));
    if (!ids) return undefined;

    for (const id of ids) {
      const byteLength = id.length / 2;
      if (offset + byteLength > bytes.length) continue;
      let matches = true;
      for (let i = 0; i < byteLength; i++) {
        if (bytes[offset + i] !== parseInt(id.slice(i * 2, i * 2 + 2), 16)) {
          matches = false;
          break;
        }
      }
      if (matches) return id;
    }
    return undefined;
  }

  /**
   * Builds a decryptor bound to one direction of one flow.
   *
   * All the per-connection state Initial decryption needs lives here rather
   * than in the dissector: which endpoint is the client (the one that sent the
   * first Initial), the original Destination Connection ID the keys derive
   * from, and the largest packet number seen per direction, which is what
   * resolves a truncated packet number back to its full value.
   */
  public createInitialDecryptor(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    bytes: Uint8Array
  ): PacketDecryptor {
    const flowKey = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    const senderKey = `${flowKey}>${srcIp}:${srcPort}`;

    return (packetStart, packetNumberOffset, packetEnd, version, destinationConnectionId, kind) => {
      if (kind !== 'initial') {
        // Handshake, 0-RTT and 1-RTT packets are opened only from key log
        // secrets. Each packet-number space numbers its packets from zero
        // independently, which is why the largest-seen number is tracked per
        // space and not per direction.
        // Usually exactly one key. More only for 0-RTT, where the suite is not
        // yet known and the tag is what decides - see `earlyKeys`.
        const candidates = this.trafficKeys(flowKey, srcIp, srcPort, kind);
        const spaceKey = `${senderKey}#${kind}`;
        const largestInSpace = this.largestPacketNumber.get(spaceKey) ?? -1;
        for (const keys of candidates) {
          const opened = decryptQuicPacket(
            bytes, packetStart, packetNumberOffset, packetEnd, keys, largestInSpace, kind !== '1rtt',
          );
          if (!opened) continue;
          if (opened.packetNumber > largestInSpace) this.largestPacketNumber.set(spaceKey, opened.packetNumber);
          return opened;
        }
        return null;
      }

      const salt = saltForVersion(version);
      if (!salt) return null;

      let session = this.initialSessions.get(flowKey);
      if (!session) {
        // The first Initial on a flow is the client's, and its Destination
        // Connection ID is the one RFC 9001 derives both directions' keys
        // from - including for every later Initial, whose DCID will have
        // changed to the server's chosen value.
        if (destinationConnectionId.length === 0) return null;
        session = {
          keys: deriveInitialKeys(destinationConnectionId, salt, version === QUIC_VERSION_2),
          clientEndpoint: `${srcIp}:${srcPort}`,
        };
        this.initialSessions.set(flowKey, session);
      }

      const isFromClient = session.clientEndpoint === `${srcIp}:${srcPort}`;
      const keys = isFromClient ? session.keys.client : session.keys.server;
      const largest = this.largestPacketNumber.get(senderKey) ?? -1;

      const decrypted = decryptQuicPacket(bytes, packetStart, packetNumberOffset, packetEnd, keys, largest, true);
      if (!decrypted) return null;

      if (decrypted.packetNumber > largest) {
        this.largestPacketNumber.set(senderKey, decrypted.packetNumber);
      }
      return decrypted;
    };
  }

  /**
   * Adds this datagram's CRYPTO fragments to the sending direction's stream
   * and returns the handshake facts if the stream is now complete.
   *
   * Contiguity is checked from offset 0: a handshake message is 4 bytes of
   * header and a declared length, so the stream is only readable once every
   * byte up to that length has arrived. Anything else would parse a hole as
   * data and produce a fingerprint that matches nothing.
   */
  public addCryptoFragments(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number, fragments: CryptoFragment[],
  ): QuicHandshakeFacts | undefined {
    if (fragments.length === 0) return undefined;
    const key = `${this.flowKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
    let stream = this.cryptoStreams.get(key);
    if (stream === undefined) {
      stream = { chunks: [], extent: 0, done: false };
      this.cryptoStreams.set(key, stream);
    }
    if (stream.done) return undefined;

    for (const f of fragments) {
      if (f.offset + f.data.length > MAX_CRYPTO_BYTES) continue;
      stream.chunks.push({ offset: f.offset, data: f.data });
      stream.extent = Math.max(stream.extent, f.offset + f.data.length);
    }

    const assembled = assemble(stream);
    if (assembled === null) return undefined;

    stream.done = true;
    stream.chunks = [];
    const facts = parseQuicHandshake(assembled);
    const flowKey = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    if (facts.hello?.sni) this.flowSni.set(flowKey, facts.hello.sni);

    // The two facts a key log needs come from opposite directions: the client
    // random from the ClientHello, the cipher suite from the ServerHello. Both
    // are in Initial packets, which is the only reason a passive observer can
    // decrypt a QUIC connection from a key log at all.
    if (facts.hello || facts.serverHello) {
      const session = this.session(flowKey);
      if (facts.hello) {
        session.clientRandom = facts.hello.random;
        session.offeredCiphers = facts.hello.ciphers;
        if (facts.hello.alpn.length > 0) session.alpn = facts.hello.alpn[0];
      }
      if (facts.serverHello) session.cipherSuite = facts.serverHello.cipher;
    }
    return facts.hello || facts.serverHello ? facts : undefined;
  }

  private session(flowKey: string): QuicSession {
    let session = this.sessions.get(flowKey);
    if (session === undefined) { session = {}; this.sessions.set(flowKey, session); }
    return session;
  }

  /**
   * The keys for one packet-number space in one direction, deriving them from
   * the key log the first time they are asked for.
   *
   * Re-derived whenever the key log changes, so loading one part-way through a
   * capture opens the connections that were opaque rather than leaving the
   * verdict cached for the life of the session.
   */
  private trafficKeys(
    flowKey: string, srcIp: string, srcPort: number, kind: 'handshake' | '0rtt' | '1rtt'
  ): DirectionKeys[] {
    const session = this.sessions.get(flowKey);
    if (session === undefined) return [];

    const initial = this.initialSessions.get(flowKey);
    if (initial === undefined) return [];
    const fromClient = initial.clientEndpoint === `${srcIp}:${srcPort}`;

    // 0-RTT is answered before the derivation below, not by it: the whole
    // point of 0-RTT is that it arrives before the server has spoken, so the
    // facts that block below are exactly the facts it will never have.
    if (kind === '0rtt') return this.earlyKeys(session, fromClient);

    // Derive only once the facts the derivation needs are actually known, and
    // never cache a verdict reached without them.
    //
    // The client random comes from the ClientHello and the cipher suite from
    // the ServerHello, so there is a window - every packet the client sends
    // before the server has said anything - where a derivation attempt is
    // guaranteed to fail for a reason that says nothing about the key log. A
    // `null` cached there stood for the life of the connection, because the
    // recompute guard only fires on `undefined` or a new key log.
    //
    // A single 0-RTT packet is enough to enter that window, and 0-RTT is
    // exactly the case that sends one: it is client data sent before the
    // handshake completes. Measured on a real Chrome capture, all three
    // connections carrying a 0-RTT packet read as wholly undecryptable, 1-RTT
    // included, while every connection without one decrypted normally.
    const derivable = session.clientRandom !== undefined && session.cipherSuite !== undefined;
    if (derivable && (session.keys === undefined || session.keyGeneration !== keyLog.generation)) {
      session.keyGeneration = keyLog.generation;
      session.keys = this.deriveSessionKeys(session);
    }
    if (session.keys === undefined || session.keys === null) return [];

    const pair = kind === 'handshake' ? session.keys.handshake : session.keys.application;
    if (pair === undefined) return [];
    return [fromClient ? pair.client : pair.server];
  }

  /**
   * The keys for a 0-RTT packet, which are the one case that cannot wait for
   * the ServerHello.
   *
   * 0-RTT carries the first request of a resumed connection - a GET, with its
   * URL, sent before the handshake finishes - so it is the most interesting
   * packet on the connection and the hardest one to key. Its secret is a key
   * log label of its own, `CLIENT_EARLY_TRAFFIC_SECRET`, which the parser has
   * always kept.
   *
   * The cipher suite is what makes it awkward: it is the *resumed* session's,
   * and the ServerHello that would name it has not been sent yet. So the
   * candidates are the suites the ClientHello offered, and the AEAD tag picks
   * between them - a wrong suite fails to authenticate, which is the same
   * outcome as having no key at all. Guessing is therefore free of the usual
   * hazard: it cannot produce plausible wrong plaintext, only no plaintext.
   * Chrome offers three, and GREASE entries fall out on `cipherSuiteSpec`.
   */
  private earlyKeys(session: QuicSession, fromClient: boolean): DirectionKeys[] {
    // A server never sends 0-RTT; only the client can.
    if (!fromClient || session.clientRandom === undefined) return [];
    const early = keyLog.secretsFor(session.clientRandom)?.get('CLIENT_EARLY_TRAFFIC_SECRET');
    if (early === undefined) return [];

    const candidates = session.cipherSuite !== undefined
      ? [session.cipherSuite]
      : session.offeredCiphers ?? [];
    const keys: DirectionKeys[] = [];
    for (const id of candidates) {
      const suite = cipherSuiteSpec(id);
      if (suite !== null) keys.push(deriveTrafficKeys(early, suite));
    }
    return keys;
  }

  private deriveSessionKeys(session: QuicSession): QuicSessionKeys | null {
    if (session.clientRandom === undefined || session.cipherSuite === undefined) return null;
    const suite = cipherSuiteSpec(session.cipherSuite);
    if (suite === null) return null;
    const secrets = keyLog.secretsFor(session.clientRandom);
    if (secrets === undefined) return null;

    const keys: QuicSessionKeys = {};
    const clientHandshake = secrets.get('CLIENT_HANDSHAKE_TRAFFIC_SECRET');
    const serverHandshake = secrets.get('SERVER_HANDSHAKE_TRAFFIC_SECRET');
    if (clientHandshake && serverHandshake) {
      keys.handshake = {
        client: deriveTrafficKeys(clientHandshake, suite),
        server: deriveTrafficKeys(serverHandshake, suite),
      };
    }
    const clientApp = secrets.get('CLIENT_TRAFFIC_SECRET_0');
    const serverApp = secrets.get('SERVER_TRAFFIC_SECRET_0');
    if (clientApp && serverApp) {
      keys.application = {
        client: deriveTrafficKeys(clientApp, suite),
        server: deriveTrafficKeys(serverApp, suite),
      };
    }
    return keys.handshake || keys.application ? keys : null;
  }

  /**
   * Feeds decrypted STREAM frames into their streams and reads HTTP/3 out of
   * them.
   *
   * Reassembly by offset is not optional here the way it is for TCP, where the
   * transport hands over an ordered stream: QUIC hands over fragments with
   * explicit offsets and no promise about order, so a frame ahead of a gap is
   * held until the gap is filled rather than being parsed where it landed.
   */
  public readStreams(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number, fragments: StreamFragment[],
  ): { streamId: number; frames: Http3Frame[]; streamTypeName?: string }[] {
    if (fragments.length === 0) return [];
    const flowKey = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    const out: { streamId: number; frames: Http3Frame[]; streamTypeName?: string }[] = [];

    for (const fragment of fragments) {
      // Stream id bit 1 says unidirectional; bit 0 says server-initiated.
      const bidirectional = (fragment.streamId & 0x02) === 0;
      const key = `${flowKey}>${srcIp}:${srcPort}#${fragment.streamId}`;
      let assembly = this.streams.get(key);
      if (assembly === undefined) {
        assembly = { http3: freshHttp3Stream(bidirectional), nextOffset: 0, pending: new Map(), pendingBytes: 0 };
        this.streams.set(key, assembly);
        this.evictFlowsPastCap();
      } else {
        // Touched, so the eviction queue orders by last use rather than by
        // when the stream was opened: a long-lived control stream is the one
        // that would otherwise be dropped first.
        this.streams.delete(key);
        this.streams.set(key, assembly);
      }

      if (fragment.offset > assembly.nextOffset) {
        const held = assembly.pending.get(fragment.offset);
        if (held !== undefined) {
          // A retransmission of a fragment already being held. Replacing it
          // has to settle the difference against the budget - `set` overwrites
          // silently, so charging the full length again leaked the whole
          // MAX_PENDING_STREAM_BYTES allowance one retransmission at a time,
          // after which every further out-of-order fragment on this stream was
          // dropped for the life of the connection.
          if (fragment.data.length > held.length) {
            assembly.pendingBytes += fragment.data.length - held.length;
            this.totalPendingBytes += fragment.data.length - held.length;
            assembly.pending.set(fragment.offset, fragment.data);
          }
        } else if (assembly.pendingBytes + fragment.data.length <= MAX_PENDING_STREAM_BYTES
          && this.totalPendingBytes + fragment.data.length <= MAX_TOTAL_PENDING_BYTES) {
          assembly.pending.set(fragment.offset, fragment.data);
          assembly.pendingBytes += fragment.data.length;
          this.totalPendingBytes += fragment.data.length;
        }
        continue;
      }

      // A fragment that starts before what has already been read overlaps a
      // retransmission; only the new tail of it is data we have not seen.
      let data = fragment.data;
      if (fragment.offset < assembly.nextOffset) {
        const skip = assembly.nextOffset - fragment.offset;
        if (skip >= data.length) continue;
        data = data.subarray(skip);
      }

      const frames: Http3Frame[] = [];
      let streamTypeName: string | undefined;
      for (;;) {
        const result = dissectHttp3Stream(data, assembly.http3, bidirectional);
        frames.push(...result.frames);
        streamTypeName ??= result.streamTypeName;
        assembly.nextOffset += data.length;

        const next = takePendingAt(assembly);
        this.totalPendingBytes -= next.released;
        if (next.data === undefined) break;
        data = next.data;
      }

      if (frames.length > 0 || streamTypeName !== undefined) {
        out.push({ streamId: fragment.streamId, frames, streamTypeName });
      }
    }

    return out;
  }

  /** The ALPN this flow's ClientHello offered first, when one was read. */
  public alpnFor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string | undefined {
    return this.sessions.get(this.flowKey(srcIp, srcPort, dstIp, dstPort))?.alpn;
  }

  /** The server name this flow's handshake named, once one has been read. */
  public sniFor(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string | undefined {
    return this.flowSni.get(this.flowKey(srcIp, srcPort, dstIp, dstPort));
  }

  public reset(): void {
    this.totalPendingBytes = 0;
    this.flowConnectionIds.clear();
    this.initialSessions.clear();
    this.largestPacketNumber.clear();
    this.cryptoStreams.clear();
    this.flowSni.clear();
    this.sessions.clear();
    this.streams.clear();
  }
}

/**
 * The handshake bytes, if the stream is contiguous from 0 and holds the whole
 * message its own header declares. Returns null while anything is missing.
 */
function assemble(stream: CryptoStream): Uint8Array | null {
  if (stream.extent < 4) return null;
  const buffer = new Uint8Array(stream.extent);
  const filled = new Uint8Array(stream.extent);
  for (const chunk of stream.chunks) {
    buffer.set(chunk.data, chunk.offset);
    filled.fill(1, chunk.offset, chunk.offset + chunk.data.length);
  }
  // The declared length of the first handshake message.
  for (let i = 0; i < 4; i++) if (filled[i] === 0) return null;
  const declared = 4 + ((buffer[1] << 16) | (buffer[2] << 8) | buffer[3]);
  if (declared > stream.extent) return null;
  for (let i = 4; i < declared; i++) if (filled[i] === 0) return null;
  return buffer.subarray(0, declared);
}
