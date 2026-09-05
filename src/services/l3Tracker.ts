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

/** How many datagrams' worth of fragments are remembered at once. */
const MAX_TRACKED_DATAGRAMS = 2048;
/** How many ARP bindings are remembered. */
const MAX_ARP_BINDINGS = 4096;

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
  private fragments = new Map<string, FragmentInfo>();
  private parts = new Map<string, FragmentPart[]>();
  private retainedBytes = 0;
  private arpBindings = new Map<string, { mac: string; frame: number }>();

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

  reset(): void {
    this.fragments.clear();
    this.parts.clear();
    this.retainedBytes = 0;
    this.arpBindings.clear();
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
