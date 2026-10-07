/**
 * The little bit of cross-frame state the network layer needs.
 *
 * Two facts, both of which are invisible in any single frame and both of which
 * are the whole point of looking at a capture rather than at a packet:
 *
 *   * **IP fragments.** A datagram split across frames only makes sense as a
 *     set. Before this, a non-first fragment's payload was read as though it
 *     were a transport header - so the second fragment of a UDP datagram was
 *     reported with two invented port numbers and a length taken from what was
 *     really application data. That is the worst kind of wrong: it is specific,
 *     it is plausible, and nothing about it looks like a failure.
 *   * **ARP bindings.** One address answered by two different MACs is either a
 *     misconfiguration or someone spoofing, and it cannot be seen in either of
 *     the two frames alone.
 *
 * Order-dependent, like the TCP, ICMP, QUIC and DNS trackers, and reset the
 * same way. Deliberately free of React and the DOM (docs/decisions/0003): this
 * runs inside the pipeline Worker.
 */

/**
 * How many conversations each per-layer index remembers.
 *
 * Matches `tcpStreamTracker.ts`'s `MAX_CONNECTIONS` deliberately: these are the
 * same kind of object bounded for the same reason (docs/decisions/0014), and
 * two different caps would only invite the question of which was right.
 */
const MAX_CONVERSATIONS = 16384;

/** What a conversation index knows about one conversation. */
interface ConversationFacts {
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
 * field.
 *
 * That choice is what forces `seedNext`, and through it the five stream
 * indices into `Packet.fields`: a replay rebuilds one conversation from a
 * five-tuple bundle and would otherwise call it 0. See `seedNextIndices`.
 *
 * Bounded like every other tracker here. An index is never reused: evicting a
 * conversation forgets it, and if it comes back it is a new one with a new
 * number, which is what `tcpStreamTracker.ts`'s `evictPastCap` does and for
 * the same reason - the alternative is two conversations answering to one id.
 */
class ConversationIndex {
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

/** How many datagrams' worth of fragments are remembered at once. */
const MAX_TRACKED_DATAGRAMS = 2048;
/** How many ARP bindings are remembered. */
const MAX_ARP_BINDINGS = 4096;

/** ESP security associations whose last sequence number is kept. */
const MAX_ESP_SAS = 4096;

/** WireGuard sessions kept, newest last; the oldest is forgotten past this. */
const MAX_WIREGUARD_SESSIONS = 4096;

/**
 * One WireGuard handshake and what followed it: the two ends, the index each
 * chose, and the frame that opened it. `responder` is filled by the response.
 */
interface WireGuardSession {
  stream: number;
  initiatorFrame: number;
  initiator: string;
  initiatorIndex: number;
  responder: string;
  responderIndex?: number;
  responseFrame?: number;
}

/** What `L3Tracker.wireguard` knows of a datagram's session. */
export interface WireGuardSessionFacts {
  stream: number;
  /** On a handshake response or a cookie reply: the message it answers. */
  responseTo?: number;
}

/**
 * The largest datagram IPv4 can express, and therefore the most any one
 * reassembly can hold. A fragment claiming to reach past it is malformed or
 * hostile, and either way is not a reason to allocate.
 */
const MAX_DATAGRAM_BYTES = 65535;

/**
 * Fragment payload held across all in-flight datagrams. A capture full of
 * fragments nobody ever finishes - which is what a fragmentation-based evasion
 * attack looks like - would otherwise grow this without limit.
 */
const MAX_RETAINED_FRAGMENT_BYTES = 16 * 1024 * 1024;

/** One fragment's payload, and where in the datagram it goes. */
interface FragmentPart {
  offset: number;
  bytes: Uint8Array;
  frame: number;
}

export interface FragmentInfo {
  /** Frames of this datagram seen so far, in arrival order, this one last. */
  frames: number[];
  /** Bytes of payload seen so far, counting this fragment. */
  bytesSoFar: number;
  /** True once a fragment with More Fragments clear has arrived. */
  complete: boolean;
  /** The datagram's total payload length, known only once the last fragment lands. */
  totalLength?: number;
  /**
   * The datagram, stitched back together - present only on the fragment that
   * completed it, and only when every byte from 0 to `totalLength` arrived.
   * This is what the transport dissector runs on.
   */
  reassembled?: Uint8Array;
  /**
   * How much each frame contributed, in arrival order, for the tree's
   * `[Reassembled IPv4 fragments]` row.
   */
  contributions?: { frame: number; offset: number; bytes: number }[];
  /**
   * Two fragments claimed the same bytes. The first arrival is kept - which is
   * one of the two choices a reassembler can make, and the one that matters:
   * an attacker who can get the *second* copy used gets to show a firewall one
   * datagram and the host another.
   */
  overlapped?: boolean;
}

export interface ArpConflict {
  address: string;
  /** The MAC that claimed it before. */
  previousMac: string;
  /** The frame that claim was made in. */
  previousFrame: number;
}

export class L3Tracker {
  private readonly ethIndex = new ConversationIndex();
  private readonly ipIndex = new ConversationIndex();
  private readonly ipv6Index = new ConversationIndex();
  private readonly udpIndex = new ConversationIndex();
  private fragments = new Map<string, FragmentInfo>();
  private parts = new Map<string, FragmentPart[]>();
  private retainedBytes = 0;
  private arpBindings = new Map<string, { mac: string; frame: number }>();
  private wireguardSessions: WireGuardSession[] = [];
  private espSas = new Map<string, { seq: number; frame: number }>();
  private nextWireGuardStream = 0;

  /** `eth.stream`: the conversation between two MAC addresses. */
  ethStream(srcMac: string, dstMac: string, tsUs: number): ConversationFacts {
    return this.ethIndex.observe(srcMac, dstMac, tsUs);
  }

  /**
   * `ip.stream` / `ipv6.stream`: the conversation between two addresses.
   *
   * Keyed on the addresses alone, with no ports - which is the reference's
   * keying, and the reason a browser opening forty connections to one host
   * shows forty `tcp.stream` values and one `ip.stream`.
   */
  ipStream(src: string, dst: string, tsUs: number): ConversationFacts {
    return this.ipIndex.observe(src, dst, tsUs);
  }

  ipv6Stream(src: string, dst: string, tsUs: number): ConversationFacts {
    return this.ipv6Index.observe(src, dst, tsUs);
  }

  /** `udp.stream`, keyed on the unordered four-tuple. */
  udpStream(src: string, srcPort: number, dst: string, dstPort: number, tsUs: number): ConversationFacts {
    return this.udpIndex.observe(`${src}:${srcPort}`, `${dst}:${dstPort}`, tsUs);
  }

  /**
   * Starts each index where a replay says it should, mirroring
   * `TcpStreamTracker.seedNextStreamId`.
   *
   * A detail tree is rebuilt by replaying one conversation through fresh
   * trackers (`services/pipeline/replay.ts`), and the bundle is selected by a
   * five-tuple - so a fresh index sees exactly one conversation and would call
   * it 0, where the packet list says 37. `scripts/pipeline/replay.ts` holds the
   * replayed tree to exact string equality with the eager one, so that
   * disagreement is a build failure rather than a cosmetic one.
   *
   * Seeding sets the NEXT index rather than restoring the table, so it is exact
   * only while the bundle holds one conversation per index. For `ip`, `ipv6`
   * and `udp` it does, by construction. For `eth` it holds while the
   * conversation kept one MAC pair - a Wi-Fi roam or a NIC failover mid-stream
   * gives a wrong number on the frames after the change. That is the same
   * approximation `seedNextStreamId` already accepts, and it is written down
   * rather than fixed because the alternative is shipping the whole table into
   * every replay message.
   */
  seedNextIndices(seeds: { eth?: number; ip?: number; ipv6?: number; udp?: number }): void {
    if (seeds.eth !== undefined) this.ethIndex.seedNext(seeds.eth);
    if (seeds.ip !== undefined) this.ipIndex.seedNext(seeds.ip);
    if (seeds.ipv6 !== undefined) this.ipv6Index.seedNext(seeds.ipv6);
    if (seeds.udp !== undefined) this.udpIndex.seedNext(seeds.udp);
  }

  /** Conversations forgotten to the cap, per index - the counter ADR 0014 wants. */
  get evictedConversations(): { eth: number; ip: number; ipv6: number; udp: number } {
    return {
      eth: this.ethIndex.evicted, ip: this.ipIndex.evicted,
      ipv6: this.ipv6Index.evicted, udp: this.udpIndex.evicted,
    };
  }

  /**
   * Records one fragment and returns what is known about its datagram.
   *
   * A datagram is identified by source, destination, identification and
   * protocol - RFC 791's own tuple, and the reason `ip.id` exists at all.
   */
  fragment(
    src: string, dst: string, identification: number, protocol: number,
    offsetBytes: number, moreFragments: boolean, payload: Uint8Array, frame: number,
  ): FragmentInfo {
    const key = `${src}|${dst}|${identification}|${protocol}`;
    let info = this.fragments.get(key);
    if (info === undefined) {
      info = { frames: [], bytesSoFar: 0, complete: false };
      // A capture full of fragments from hosts that never finish them would
      // otherwise grow these maps for the length of the capture.
      if (this.fragments.size >= MAX_TRACKED_DATAGRAMS) {
        const oldest = this.fragments.keys().next();
        if (!oldest.done) this.drop(oldest.value);
      }
      this.fragments.set(key, info);
      this.parts.set(key, []);
    }
    info.frames.push(frame);
    info.bytesSoFar += payload.length;

    // The payload is copied out of the frame's buffer: the frame it came from
    // is a view over a WebSocket batch or a whole capture file, and holding one
    // fragment would hold all of it.
    const end = offsetBytes + payload.length;
    const parts = this.parts.get(key)!;
    if (end <= MAX_DATAGRAM_BYTES && this.retainedBytes + payload.length <= MAX_RETAINED_FRAGMENT_BYTES) {
      parts.push({ offset: offsetBytes, bytes: payload.slice(), frame });
      this.retainedBytes += payload.length;
    }

    if (!moreFragments) {
      // The last fragment is the only one that says how long the datagram is:
      // its offset plus its own length is the total.
      info.complete = true;
      info.totalLength = end;
    }

    if (info.complete && info.totalLength !== undefined) {
      const assembled = assemble(parts, info.totalLength);
      if (assembled) {
        info.reassembled = assembled.bytes;
        info.overlapped = assembled.overlapped;
        info.contributions = assembled.contributions;
      }
    }
    return info;
  }

  /** Forgets a datagram once its fragments have been accounted for. */
  forgetFragments(src: string, dst: string, identification: number, protocol: number): void {
    this.drop(`${src}|${dst}|${identification}|${protocol}`);
  }

  private drop(key: string): void {
    for (const part of this.parts.get(key) ?? []) this.retainedBytes -= part.bytes.length;
    this.parts.delete(key);
    this.fragments.delete(key);
  }

  /**
   * Records who claims an address, and reports it when somebody else already did.
   *
   * Only claims are recorded - an ARP reply's sender, or a gratuitous request's
   * - because the target fields of a request are a question rather than an
   * assertion and treating them as a binding would report every ARP scan as a
   * conflict.
   *
   * A host legitimately changing its MAC (a failover, a new NIC, a laptop
   * moving between docks) also shows up here. That is correct: the point is to
   * say "this address changed hands in frame N", not to accuse anybody.
   */
  arpClaim(address: string, mac: string, frame: number): ArpConflict | null {
    if (address === '0.0.0.0' || mac === '00:00:00:00:00:00') return null;
    const existing = this.arpBindings.get(address);
    if (existing && existing.mac !== mac) {
      // Replaced, not kept: the newest claim is the one the next frame will be
      // compared against, so a genuine change is reported once rather than on
      // every frame from then on.
      this.arpBindings.set(address, { mac, frame });
      return { address, previousMac: existing.mac, previousFrame: existing.frame };
    }
    if (!existing) {
      if (this.arpBindings.size >= MAX_ARP_BINDINGS) {
        const oldest = this.arpBindings.keys().next();
        if (!oldest.done) this.arpBindings.delete(oldest.value);
      }
      this.arpBindings.set(address, { mac, frame });
    }
    return null;
  }

  /**
   * The WireGuard session a datagram belongs to, as packet-wireguard.c finds
   * it. An initiation opens a new session, numbered in order; a response
   * joins the newest one whose initiator chose its receiver index and sits at
   * the other end; a cookie reply or data joins the newest session where its
   * receiver index is the far end's. Null when no session explains it - data
   * from a handshake before the capture began.
   *
   * `from` and `to` are the datagram's `address:port` endpoints.
   */
  wireguard(
    type: number, from: string, to: string, frame: number, sender?: number, receiver?: number,
  ): WireGuardSessionFacts | null {
    if (type === 1 && sender !== undefined) {
      if (this.wireguardSessions.length >= MAX_WIREGUARD_SESSIONS) this.wireguardSessions.shift();
      const stream = this.nextWireGuardStream++;
      this.wireguardSessions.push({ stream, initiatorFrame: frame, initiator: from, initiatorIndex: sender, responder: to });
      return { stream };
    }
    for (let i = this.wireguardSessions.length - 1; i >= 0; i--) {
      const s = this.wireguardSessions[i];
      if (type === 2) {
        if (s.initiatorIndex !== receiver || s.initiator !== to || s.responder !== from) continue;
        s.responderIndex = sender;
        s.responseFrame = frame;
        return { stream: s.stream, responseTo: s.initiatorFrame };
      }
      // A cookie reply answers the handshake message whose sender it names:
      // the initiation, or the response.
      const answers = (sent: number | undefined) => (type === 3 && sent !== undefined ? { responseTo: sent } : {});
      if (s.initiatorIndex === receiver && s.initiator === to && s.responder === from) {
        return { stream: s.stream, ...answers(s.initiatorFrame) };
      }
      if (s.responderIndex === receiver && s.responder === to && s.initiator === from) {
        return { stream: s.stream, ...answers(s.responseFrame) };
      }
    }
    return null;
  }

  /**
   * What ESP's sequence analysis compares a packet with: the sequence number
   * its SA should have carried next and the frame it was last seen in, or
   * null for the first packet of an SA. An SA is its SPI and its two ends.
   * Records this packet as the SA's latest, in or out of order, as the
   * reference does.
   */
  espSequence(src: string, dst: string, spi: number, seq: number, frame: number): { expected: number; previousFrame: number } | null {
    const key = `${src}>${dst}#${spi}`;
    const last = this.espSas.get(key);
    if (last === undefined && this.espSas.size >= MAX_ESP_SAS) {
      const oldest = this.espSas.keys().next();
      if (!oldest.done) this.espSas.delete(oldest.value);
    }
    this.espSas.set(key, { seq, frame });
    return last === undefined ? null : { expected: last.seq + 1, previousFrame: last.frame };
  }

  reset(): void {
    this.espSas.clear();
    this.wireguardSessions = [];
    this.nextWireGuardStream = 0;
    this.fragments.clear();
    this.parts.clear();
    this.retainedBytes = 0;
    this.arpBindings.clear();
    this.ethIndex.reset();
    this.ipIndex.reset();
    this.ipv6Index.reset();
    this.udpIndex.reset();
  }
}

/**
 * Stitches the parts into one datagram, or returns null when they do not cover
 * it.
 *
 * A hole means a fragment has not arrived (or was never captured), and a
 * datagram with a hole in it is not a datagram - handing the transport
 * dissector a buffer with a gap silently filled with zeros would produce a
 * confident reading of bytes nobody sent.
 *
 * Overlaps are resolved **first-arrival-wins**, which is the choice that
 * matters rather than an arbitrary one: overlapping fragments are the classic
 * evasion, where a sender arranges for a firewall and the host behind it to
 * reassemble different datagrams from the same frames. Whichever rule is
 * chosen, the overlap itself is reported.
 */
function assemble(parts: FragmentPart[], totalLength: number): {
  bytes: Uint8Array;
  overlapped: boolean;
  contributions: { frame: number; offset: number; bytes: number }[];
} | null {
  if (totalLength <= 0 || totalLength > MAX_DATAGRAM_BYTES) return null;

  const out = new Uint8Array(totalLength);
  // Which bytes have been written, so a hole is detectable and a later
  // fragment cannot overwrite an earlier one's claim.
  const filled = new Uint8Array(totalLength);
  const contributions: { frame: number; offset: number; bytes: number }[] = [];
  let overlapped = false;
  let covered = 0;

  // Arrival order, not offset order: first-arrival-wins is defined by when a
  // byte was claimed, not by where it sits.
  for (const part of parts) {
    if (part.offset >= totalLength) { overlapped = true; continue; }
    const end = Math.min(totalLength, part.offset + part.bytes.length);
    let wrote = 0;
    for (let i = part.offset; i < end; i++) {
      if (filled[i]) { overlapped = true; continue; }
      out[i] = part.bytes[i - part.offset];
      filled[i] = 1;
      covered++;
      wrote++;
    }
    if (wrote > 0) contributions.push({ frame: part.frame, offset: part.offset, bytes: wrote });
  }

  if (covered !== totalLength) return null; // a hole: not a datagram
  return { bytes: out, overlapped, contributions };
}
