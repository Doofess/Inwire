/**
 * Anonymising a capture on the way out.
 *
 * A packet capture is one of the most revealing files a person can hand over.
 * Every address in it says who was talking, every SNI says what they were
 * looking at, and the payload says the rest. Sharing one - with a vendor, on a
 * ticket, in a bug report - normally means either sharing all of that or
 * sharing nothing.
 *
 * What makes an anonymised capture *useful* rather than merely safe is that
 * the structure survives. Three rules, each chosen because the obvious
 * alternative destroys the thing the capture was kept for:
 *
 *   * **Addresses are prefix-preserving.** Two addresses that shared an n-bit
 *     prefix still do afterwards, so subnets, routing boundaries and "these
 *     twelve hosts are on the same /24" all survive. Replacing each address
 *     with an unrelated random one would leave a file in which no two hosts
 *     appear related, which is not a network any more. This is Xu, Fan,
 *     Ammar and Moon's Crypto-PAn construction, over the AES this app already
 *     ships for QUIC, with one change to its block that `PrefixPreserving`
 *     explains.
 *   * **MACs keep their OUI.** The first three bytes name the manufacturer,
 *     which is how a capture tells you the printer from the phone from the
 *     access point; the last three identify the unit. So the vendor half is
 *     kept and the unit half is replaced.
 *   * **Everything above the transport header goes.** Not scrambled - zeroed.
 *     Payload is where the passwords, the cookies and the documents are, and
 *     no reversible transform of it is worth defending.
 *
 * **"Header-only" protocols are not.** The control protocols carry addresses
 * in their bodies, and for a long time this module assumed they did not:
 * ICMPv6 Neighbor Discovery names the target address and the real MAC in a
 * link-layer option, a Router Advertisement names the prefix, the DNS servers
 * and the router's MAC, MLD and IGMP name group sources, and every ICMP error
 * embeds the offending packet's own IP header. So those bodies are walked
 * (`icmpv4`, `icmpv6`, `igmp`, `ndOptions`, and the link-layer discovery
 * protocols) and every address in them goes through the SAME mapping as the
 * headers, which keeps the file self-consistent: a Neighbor Solicitation's
 * target is the pseudonym the host has everywhere else. **Anything that is not
 * understood is zeroed, never passed through** - an unknown option, an unknown
 * ethertype, a tunnel, a non-first fragment, the Ethernet trailer. The rule is
 * that a byte leaves the machine only when this module can say what it is.
 *
 * Every checksum over a rewritten region is recomputed - IPv4 headers, TCP,
 * UDP, ICMP, IGMP, and ICMPv6 over its pseudo-header - because a stale one
 * paints the frame as damaged and buries what the capture was shared to show.
 *
 * The mapping is deterministic within one export and different between them:
 * the key is random per run, so the same capture exported twice does not
 * produce the same addresses, and nobody can build a dictionary from a file
 * they were given earlier.
 */
import type { Packet } from '../types/packet';
import { LINKTYPE } from './dissect/types';
import { declaredPayloadEnd, dissectLinkLayer } from './dissectors/linkLayer';
import { expandKey128, encryptBlock128 } from './crypto/aes';
import { formatMac, formatIpv4Address, formatIpv6Address } from './addressFormat';

/**
 * The Crypto-PAn pseudorandom function.
 *
 * For each bit position, the anonymised bit is the real bit XOR one bit
 * derived from every bit *before* it. That is what makes it prefix-preserving:
 * two addresses agreeing on the first n bits produce the same n pad bits and
 * therefore agree on the first n bits of the output, and neither the pad nor
 * the output says anything about the bits that follow.
 *
 * **One departure from the paper, and it closes a leak.** The paper's block for
 * bit i is the address's first i bits followed by the pad's remaining bits. So
 * the blocks for bits i and i+1 differ only in bit i - the pad's in one, the
 * address's in the other - and whenever those agree, which is half the time,
 * both steps encrypt the same block and flip the same way. The 32 flips of an
 * IPv4 address come in runs rather than as 32 coins, and an address comes out
 * as itself about once in 15,000: measured, and caught by
 * `scripts/export/anonymise-wire.ts` as a real address left in a real export.
 * Here the block is the first i bits, then a 1, then zeros - a padding that
 * says where the prefix ends, so no two steps share a block - XORed with the
 * pad. Each flip is its own coin, and an address survives once in 2^32.
 * Prefix preservation and injectivity are untouched: bit i's flip still
 * depends on the first i bits and nothing else.
 */
class PrefixPreserving {
  private readonly roundKeys: Uint8Array;
  /** The pad block, from the second half of the key material. */
  private readonly pad: Uint8Array;

  constructor(key: Uint8Array) {
    this.roundKeys = expandKey128(key.subarray(0, 16));
    // The pad is the key's second half encrypted under its first, as the
    // paper derives it - independent of the address being anonymised.
    this.pad = encryptBlock128(this.roundKeys, key.subarray(16, 32));
  }

  /** Anonymises `bits` bits (at most 128) of a big-endian address, in place on a copy. */
  map(address: Uint8Array, bits: number): Uint8Array {
    const out = new Uint8Array(address.length);
    out.set(address);
    const block = new Uint8Array(16);

    for (let i = 0; i < bits; i++) {
      // The first i bits of the *real* address, then a 1, then zeros, XORed
      // with the pad: distinct for every (i, prefix), which the paper's
      // pad-filled block is not (see above). Using the real address rather
      // than the anonymised one is what keeps the map injective.
      block.fill(0);
      for (let b = 0; b < i; b++) {
        if ((address[b >> 3] >> (7 - (b & 7))) & 1) block[b >> 3] |= 1 << (7 - (b & 7));
      }
      block[i >> 3] |= 1 << (7 - (i & 7));
      for (let b = 0; b < 16; b++) block[b] ^= this.pad[b];
      const cipher = encryptBlock128(this.roundKeys, block);
      const padBit = (cipher[0] >> 7) & 1;
      if (padBit) out[i >> 3] ^= 1 << (7 - (i & 7));
    }
    return out;
  }
}

/** How an anonymised capture describes itself. */
export interface AnonymiseSummary {
  /** Distinct real addresses that were mapped. */
  addresses: number;
  /** Distinct real MACs that were mapped. */
  macs: number;
  /** Frames whose payload above the transport header was zeroed. */
  payloadsStripped: number;
  /** Bytes of payload removed. */
  bytesStripped: number;
}

export class Anonymiser {
  private readonly prf: PrefixPreserving;
  private readonly ipv4 = new Map<string, string>();
  private readonly ipv6 = new Map<string, string>();
  private readonly macs = new Map<string, string>();
  /**
   * The low 24 bits of a real unicast IPv6 address, to the low 24 bits of its
   * pseudonym - what a solicited-node multicast address is built from. See
   * `solicited`.
   */
  private readonly solicitedLow = new Map<number, number>();
  /** Entries in `solicitedLow` that were derived before their unicast was seen. */
  private readonly solicitedGuessed = new Set<number>();
  private stripped = 0;
  private strippedBytes = 0;
  /** Payload bytes zeroed in the frame being rewritten. */
  private frameStripped = 0;

  /**
   * `key` is 32 random bytes. Generated per export rather than stored: a
   * persistent key would let anyone holding two anonymised captures from this
   * machine correlate the hosts across them, which is most of what the
   * anonymisation is meant to prevent.
   */
  constructor(key: Uint8Array = randomKey()) {
    this.prf = new PrefixPreserving(key);
  }

  summary(): AnonymiseSummary {
    return {
      addresses: this.ipv4.size + this.ipv6.size,
      macs: this.macs.size,
      payloadsStripped: this.stripped,
      bytesStripped: this.strippedBytes,
    };
  }

  /**
   * An IPv4 address, prefix-preserved.
   *
   * Multicast, broadcast and the unspecified address are left alone: they are
   * not anybody's address, they are how the protocols address *everyone*, and
   * rewriting 224.0.0.251 would turn mDNS into traffic to a host that does not
   * exist. The point is to hide who was talking, not to break the file.
   */
  ipv4Address(address: string): string {
    const cached = this.ipv4.get(address);
    if (cached) return cached;
    const raw = parseIpv4(address);
    if (!raw || isReservedIpv4(raw)) return address;
    const mapped = formatIpv4Address(this.prf.map(raw, 32), 0);
    this.ipv4.set(address, mapped);
    return mapped;
  }

  ipv6Address(address: string): string {
    const cached = this.ipv6.get(address);
    if (cached) return cached;
    const raw = parseIpv6(address);
    if (!raw) return address;
    // A solicited-node group is not cached: its answer can improve once the
    // unicast address it was built from is seen (`solicited`).
    if (isSolicitedNode(raw)) return formatIpv6Address(this.prfIpv6(raw), 0);
    if (isReservedIpv6(raw)) return address;
    const mapped = formatIpv6Address(this.prfIpv6(raw), 0);
    this.ipv6.set(address, mapped);
    return mapped;
  }

  /**
   * A MAC, with its vendor half kept.
   *
   * A broadcast or multicast destination is left alone for the same reason a
   * multicast IP is: `ff:ff:ff:ff:ff:ff` is not a device.
   */
  mac(address: string): string {
    const cached = this.macs.get(address);
    if (cached) return cached;
    const raw = parseMac(address);
    if (!raw) return address;
    // The one group MAC that is somebody's: `33:33:ff:xx:xx:xx` is the
    // solicited-node group of an IPv6 address, and its low three bytes are
    // that address's - on an EUI-64 address, the unit half of the real MAC.
    if (raw[0] === 0x33 && raw[1] === 0x33 && raw[2] === 0xff) {
      const low = this.solicited((raw[3] << 16) | (raw[4] << 8) | raw[5]);
      return formatMac(new Uint8Array([0x33, 0x33, 0xff, low >> 16, (low >> 8) & 0xff, low & 0xff]));
    }
    if ((raw[0] & 0x01) !== 0) return address; // group bit: not a device
    // The OUI stays; the three bytes that identify the unit are replaced by a
    // keyed function of the whole address, so two frames from one device still
    // agree and two devices from one vendor still differ.
    const derived = this.prf.map(raw, 48);
    const out = new Uint8Array(6);
    out.set(raw.subarray(0, 3));
    out.set(derived.subarray(3, 6), 3);
    // Never hand back the address we were given.
    if (out[3] === raw[3] && out[4] === raw[4] && out[5] === raw[5]) out[5] ^= 0x01;
    const mapped = formatMac(out);
    this.macs.set(address, mapped);
    return mapped;
  }

  /**
   * Free text with every address in it mapped the way the frames are.
   *
   * For the prose a dissector writes about a frame - an expert message names
   * the address it is about ("Duplicate IP address configured (10.0.0.7)") -
   * and for anything a report prints from it. Mapped rather than blanked, so a
   * sentence about a host still names the same host the anonymised tables do.
   *
   * A token is rewritten only when it parses as an address: a clock reading
   * such as `12:30:45` has colons and is not one, and a version string such as
   * `1.2.3` has dots and is not one either.
   */
  text(s: string): string {
    return s.replace(ADDRESS_TOKEN, (token) => {
      if (MAC_TOKEN.test(token)) return this.mac(token.toLowerCase());
      // Windows writes a MAC with dashes (`ipconfig`, adapter names). Mapped
      // through the same table, so one device is one pseudonym in both
      // spellings, and handed back in the spelling it arrived in.
      if (DASHED_MAC_TOKEN.test(token)) return this.mac(token.toLowerCase().replace(/-/g, ':')).replace(/:/g, '-');
      if (token.includes(':')) return parseIpv6(token) ? this.ipv6Address(token) : token;
      return parseIpv4(token) ? this.ipv4Address(token) : token;
    });
  }

  /**
   * One frame, rewritten.
   *
   * The bytes are what an exported capture actually carries, so they are what
   * has to change: rewriting only the summary columns would produce a file
   * whose packet list looked anonymous and whose hex dump was not.
   */
  packet(packet: Packet): Packet {
    const bytes = packet.rawBytes.length > 0 ? packet.rawBytes.slice() : packet.rawBytes;
    if (bytes.length > 0) this.rewriteFrame(bytes, packet.linkType ?? LINKTYPE.ETHERNET);

    return {
      ...packet,
      rawBytes: bytes,
      source: this.rewriteDisplayAddress(packet.source),
      destination: this.rewriteDisplayAddress(packet.destination),
      // The tree, the field bag and the resolved names all describe the frame
      // this no longer is. A name learned from a DNS answer is exactly the
      // kind of thing being removed, so none of it is carried over.
      layers: [],
      fields: undefined,
      // Both halves of the bag. The dense fields - every address, port and
      // sequence number among them - live in a shared column block reached
      // through `cols` (`dissect/fieldSplit.ts`), so clearing `fields` alone
      // leaves all of them readable on a frame this has just called anonymous.
      // The block itself is not touched: it is shared with frames that are not
      // being anonymised, and dropping this frame's pointer is what removes it
      // from this one.
      cols: undefined,
      row: undefined,
      resolved: undefined,
      streamPayload: undefined,
      hexDump: undefined,
      asciiDump: undefined,
      info: '(anonymised)',
      // Findings survive, because they are what the frame is being shared to
      // show - but their messages are prose written about THIS frame, and some
      // of them name its addresses.
      expert: packet.expert?.map((e) => ({ ...e, message: this.text(e.message) })),
    };
  }

  /** Addresses as the columns show them - which may be a MAC, or a name. */
  private rewriteDisplayAddress(value: string): string {
    if (/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(value)) return this.mac(value);
    if (parseIpv4(value)) return this.ipv4Address(value);
    if (value.includes(':') && parseIpv6(value)) return this.ipv6Address(value);
    // A resolved host name, a vendor-shortened MAC, "Broadcast". None of these
    // is an address this can map, and a name is precisely what must not
    // survive - so it is replaced rather than passed through.
    return 'host';
  }

  /**
   * Rewrites a frame's bytes in place: addresses wherever they are, and
   * everything above L4.
   *
   * The link layer is read with the same dissector the packet list uses, so
   * this follows VLAN tags and LLC/SNAP rather than assuming an offset - an
   * anonymiser that writes 12 bytes at offset 26 into a VLAN-tagged frame
   * corrupts the payload and leaves the address intact, which is the worst of
   * both outcomes.
   */
  private rewriteFrame(bytes: Uint8Array, linkType: number): void {
    // **The frame's own link type, not Ethernet.** Hard-coding it here was the
    // same class of error this method's own comment warns about one paragraph
    // up: an offset assumed rather than dissected. On a `LINKTYPE.NULL` frame
    // the 14-byte Ethernet header this produced overlaps the IP header, so the
    // anonymiser wrote two MACs over the IP version, the TTL and the protocol -
    // corrupting the frame while leaving the addresses it was asked to remove
    // exactly where they were.
    const link = dissectLinkLayer(bytes, linkType);
    const l3 = link.l3Offset;
    const declared = declaredPayloadEnd(bytes, l3, link.etherType);
    const end = declared > l3 ? Math.min(declared, bytes.length) : bytes.length;

    if (link.etherType === 0x0800) {
      this.ipv4Datagram(bytes, l3, end);
    } else if (link.etherType === 0x86dd) {
      this.ipv6Datagram(bytes, l3, end);
    } else if (link.etherType === 0x0806) {
      this.arp(bytes, l3, end);
    } else if (link.etherType === 0x88cc) {
      this.lldp(bytes, l3, end);
    } else if (link.etherType === 0x893a) {
      this.ieee1905(bytes, l3, end);
    } else if (link.etherType <= 1500 && link.llcDsap === 0x42 && link.llcOffset !== undefined) {
      this.stp(bytes, link.llcOffset + 3, end);
    } else {
      // An ethertype or SAP this module cannot read. Its bytes may be anything
      // - CDP names the device, EAPOL the user, a tunnel carries whole
      // packets - so none of them leaves.
      // An LLC header is three bytes of SAP numbers and stays.
      const from = link.llcOffset !== undefined ? Math.max(l3, link.llcOffset + 3) : l3;
      this.zeroPayload(bytes, Math.min(from, bytes.length), end);
    }

    // Whatever sits past the payload the protocol declared: Ethernet padding,
    // which a driver is not obliged to zero, and trailers nobody decoded.
    if (declared > l3 && declared < bytes.length) bytes.fill(0, declared);

    // The MACs last, so a solicited-node destination (`33:33:ff:..`) is mapped
    // with what the IPv6 layer above has just learned about its target.
    const offsets = linkType === LINKTYPE.LINUX_SLL ? { src: 6 }
      : linkType === LINKTYPE.LINUX_SLL2 ? { src: 12 }
        : link.dstMac && link.srcMac ? { dst: 0, src: 6 } : {};
    if (offsets.dst !== undefined && link.dstMac) writeMac(bytes, offsets.dst, parseMac(this.mac(link.dstMac))!);
    if (offsets.src !== undefined && link.srcMac) writeMac(bytes, offsets.src, parseMac(this.mac(link.srcMac))!);

    if (this.frameStripped > 0) {
      this.stripped++;
      this.strippedBytes += this.frameStripped;
      this.frameStripped = 0;
    }
  }

  private prfIpv4(raw: Uint8Array): Uint8Array {
    if (isReservedIpv4(raw)) return raw;
    return this.prf.map(raw, 32);
  }

  private prfIpv6(raw: Uint8Array): Uint8Array {
    if (isSolicitedNode(raw)) {
      const low = this.solicited((raw[13] << 16) | (raw[14] << 8) | raw[15]);
      const out = raw.slice();
      out[13] = low >> 16; out[14] = (low >> 8) & 0xff; out[15] = low & 0xff;
      return out;
    }
    if (isReservedIpv6(raw)) return raw;
    const mapped = this.prf.map(raw, 128);
    // What this host's solicited-node group will be called from now on. A
    // guess made before the unicast was seen gives way to the real answer.
    const real = (raw[13] << 16) | (raw[14] << 8) | raw[15];
    if (!this.solicitedLow.has(real) || this.solicitedGuessed.has(real)) {
      this.solicitedLow.set(real, (mapped[13] << 16) | (mapped[14] << 8) | mapped[15]);
      this.solicitedGuessed.delete(real);
    }
    return mapped;
  }

  /**
   * The low 24 bits of a solicited-node group, mapped.
   *
   * `ff02::1:ffXX:XXXX` is built from the last three bytes of a unicast
   * address, which on an EUI-64 address are the last three bytes of the MAC -
   * exactly the unit half the MAC mapping replaces. Left alone, as a
   * multicast group otherwise is, it would hand them back. So the group is
   * rebuilt from the PSEUDONYM's last three bytes when the unicast has been
   * seen, which keeps a Neighbor Solicitation addressed to its target's group,
   * and from a keyed function of the real bits when it has not.
   */
  private solicited(real: number): number {
    const known = this.solicitedLow.get(real);
    if (known !== undefined) return known;
    const block = new Uint8Array(16);
    block[0] = 0xff; block[1] = 0x02; block[11] = 0x01; block[12] = 0xff;
    block[13] = real >> 16; block[14] = (real >> 8) & 0xff; block[15] = real & 0xff;
    const mapped = this.prf.map(block, 128);
    const low = (mapped[13] << 16) | (mapped[14] << 8) | mapped[15];
    this.solicitedLow.set(real, low);
    this.solicitedGuessed.add(real);
    return low;
  }

  private mapIpv4At(b: Uint8Array, at: number): void {
    if (at + 4 <= b.length) b.set(this.prfIpv4(b.subarray(at, at + 4)), at);
  }

  private mapIpv6At(b: Uint8Array, at: number): void {
    if (at + 16 <= b.length) b.set(this.prfIpv6(b.subarray(at, at + 16)), at);
  }

  private mapMacAt(b: Uint8Array, at: number): void {
    if (at + 6 <= b.length) writeMac(b, at, parseMac(this.mac(formatMac(b.subarray(at, at + 6))))!);
  }

  /**
   * An IPv6 prefix of `bits` bits at `at`: the bits past the prefix are
   * zeroed and the rest mapped exactly as an address inside it would be.
   * Crypto-PAn's n-th output bit depends only on the bits before it, so the
   * mapped prefix is the mapped addresses' prefix - an advertised /64 is still
   * the /64 its hosts are in.
   */
  private mapIpv6PrefixAt(b: Uint8Array, at: number, bits: number, bytes = 16): void {
    if (at + bytes > b.length) return;
    const raw = new Uint8Array(16);
    raw.set(b.subarray(at, at + bytes));
    const keep = Math.max(0, Math.min(bits, bytes * 8));
    maskBits(raw, keep);
    const out = isReservedIpv6(raw) || isSolicitedNode(raw) ? raw : this.prf.map(raw, keep);
    maskBits(out, keep);
    b.set(out.subarray(0, bytes), at);
  }

  /** Zeroes `[from, to)` as payload: counted, because it is what the summary reports. */
  private zeroPayload(b: Uint8Array, from: number, to: number): void {
    const stop = Math.min(to, b.length);
    if (stop <= from) return;
    b.fill(0, from, stop);
    this.frameStripped += stop - from;
  }

  // --- the network layer -------------------------------------------------------

  private ipv4Datagram(b: Uint8Array, l3: number, end: number): void {
    if (end < l3 + 20) {
      // Not even a whole header. Nothing here can be read with confidence, and
      // the addresses are what would be in it.
      this.zeroPayload(b, l3, end);
      return;
    }
    const ihl = (b[l3] & 0x0f) * 4;
    this.mapIpv4At(b, l3 + 12);
    this.mapIpv4At(b, l3 + 16);
    if (ihl < 20 || l3 + ihl > end) {
      this.zeroPayload(b, l3 + 20, end);
      return;
    }
    this.ipv4Options(b, l3 + 20, l3 + ihl);
    // The header changed, so its checksum has to. Leaving it stale would
    // paint every frame in the file as a checksum error and bury whatever
    // the capture was shared to show.
    writeIpv4Checksum(b, l3, ihl);

    const l4 = l3 + ihl;
    const flags = b[l3 + 6];
    const fragmentOffset = ((flags & 0x1f) << 8) | b[l3 + 7];
    // Zero is what a large-send offload writes on a segment the NIC has not
    // yet split - 63,942-byte TCP segments in the fixture - and the reference
    // then takes the length from the capture. So does this: taking the zero
    // at its word put a length of 0 in every such segment's pseudo-header.
    const statedLen = (b[l3 + 2] << 8) | b[l3 + 3];
    const totalLen = statedLen === 0 ? end - l3 : statedLen;
    if (fragmentOffset !== 0) {
      // A later fragment is the middle of something whose header is in
      // another frame: it cannot be read, so all of it goes. Zeroing every
      // later fragment is also what keeps the first fragment's checksum
      // computable - the reassembled message is that fragment plus zeros.
      this.zeroPayload(b, l4, end);
      return;
    }
    const fragmented = (flags & 0x20) !== 0;
    this.upper(b, b[l3 + 9], l4, end, {
      v6: false, srcAt: l3 + 12, dstAt: l3 + 16,
      length: fragmented ? null : Math.max(0, totalLen - ihl),
    });
  }

  /**
   * IPv4 options. Record Route and the two source routes are lists of
   * addresses, and Timestamp can be; each is mapped. Router Alert (on every
   * IGMP frame) says nothing about anybody. Anything else keeps its type and
   * length and loses its data.
   */
  private ipv4Options(b: Uint8Array, from: number, to: number): void {
    let p = from;
    while (p < to) {
      const type = b[p];
      if (type === 0) { b.fill(0, p, to); return; }   // End of Options List; the rest is padding
      if (type === 1) { p++; continue; }               // No Operation
      if (p + 1 >= to) { b.fill(0, p, to); return; }
      const len = b[p + 1];
      if (len < 2 || p + len > to) { b.fill(0, p, to); return; }
      if (type === 7 || type === 131 || type === 137) {
        for (let a = p + 3; a + 4 <= p + len; a += 4) this.mapIpv4At(b, a);
      } else if (type === 68) {
        // Timestamp: flag 1 and 3 interleave an address with each stamp.
        const flag = len >= 4 ? b[p + 3] & 0x0f : 0;
        if (flag === 1 || flag === 3) for (let a = p + 4; a + 8 <= p + len; a += 8) this.mapIpv4At(b, a);
      } else if (type !== 148) {
        b.fill(0, p + 2, p + len);
      }
      p += len;
    }
  }

  private ipv6Datagram(b: Uint8Array, l3: number, end: number): void {
    if (end < l3 + 40) {
      this.zeroPayload(b, Math.min(l3 + 8, end), end);
      return;
    }
    // Zero is a jumbogram or, far more often, a large-send segment; either
    // way the capture holds the length (see `ipv4Datagram`).
    const statedLen = (b[l3 + 4] << 8) | b[l3 + 5];
    const payloadLen = statedLen === 0 ? end - l3 - 40 : statedLen;
    // A Neighbor Solicitation is sent to its target's solicited-node group.
    // Mapping the target first means the header's group is rebuilt from the
    // target's pseudonym, so the two still agree afterwards.
    if (b[l3 + 6] === 58 && b[l3 + 40] === 135 && l3 + 64 <= end) this.prfIpv6(b.subarray(l3 + 48, l3 + 64));
    this.mapIpv6At(b, l3 + 8);
    this.mapIpv6At(b, l3 + 24);

    // Walk the extension headers to the upper layer. An anonymiser that took
    // the Next Header field at face value skipped every MLD report, whose
    // Hop-by-Hop Router Alert comes first.
    let next = b[l3 + 6];
    let p = l3 + 40;
    let dstAt = l3 + 24;
    let fragmented = false;
    for (let hops = 0; hops < 16; hops++) {
      if (next === 0 || next === 60 || next === 43) {
        if (p + 8 > end) { this.zeroPayload(b, p, end); return; }
        const len = (b[p + 1] + 1) * 8;
        if (p + len > end) { this.zeroPayload(b, p, end); return; }
        if (next === 43) {
          const final = this.routingHeader(b, p, len);
          if (final !== null) dstAt = final;
        } else {
          this.ipv6Options(b, p + 2, p + len);
        }
        next = b[p];
        p += len;
      } else if (next === 44) {
        if (p + 8 > end) { this.zeroPayload(b, p, end); return; }
        const offset = ((b[p + 2] << 8) | b[p + 3]) >> 3;
        const more = (b[p + 3] & 0x01) !== 0;
        next = b[p];
        p += 8;
        if (offset !== 0) { this.zeroPayload(b, p, end); return; }
        fragmented = more;
      } else if (next === 51) {
        // AH: its ICV is a keyed digest over the real addresses.
        if (p + 12 > end) { this.zeroPayload(b, p, end); return; }
        const len = (b[p + 1] + 2) * 4;
        if (p + len > end) { this.zeroPayload(b, p, end); return; }
        b.fill(0, p + 12, p + len);
        next = b[p];
        p += len;
      } else if (next === 50) {
        // ESP: the SPI and sequence number are the header; the rest is sealed.
        this.zeroPayload(b, Math.min(p + 8, end), end);
        return;
      } else {
        break;
      }
    }
    this.upper(b, next, p, end, {
      v6: true, srcAt: l3 + 8, dstAt,
      length: fragmented ? null : Math.max(0, l3 + 40 + payloadLen - p),
    });
  }

  /** Hop-by-Hop and Destination options. Home Address is an address; the rest keeps its shape. */
  private ipv6Options(b: Uint8Array, from: number, to: number): void {
    let p = from;
    while (p < to) {
      const type = b[p];
      if (type === 0) { p++; continue; }             // Pad1
      if (p + 2 > to) { b.fill(0, p, to); return; }
      const len = b[p + 1];
      if (p + 2 + len > to) { b.fill(0, p, to); return; }
      if (type === 0xc9 && len === 16) this.mapIpv6At(b, p + 2);
      // Router Alert and Jumbo Payload are numbers about the packet.
      else if (type !== 0x05 && type !== 0xc2) b.fill(0, p + 2, p + 2 + len);
      p += 2 + len;
    }
  }

  /**
   * A Routing header's addresses. Returns where the FINAL destination is when
   * it is not the header's own - the one the upper layer's pseudo-header uses.
   */
  private routingHeader(b: Uint8Array, p: number, len: number): number | null {
    const type = b[p + 2];
    const segmentsLeft = b[p + 3];
    if (type === 0 || type === 2) {
      let last = -1;
      for (let a = p + 8; a + 16 <= p + len; a += 16) { this.mapIpv6At(b, a); last = a; }
      return segmentsLeft > 0 && last >= 0 ? last : null;
    }
    if (type === 4) {
      // Segment Routing: the segment list, newest first, then TLVs.
      const segments = b[p + 4] + 1;
      let a = p + 8;
      for (let i = 0; i < segments && a + 16 <= p + len; i++, a += 16) this.mapIpv6At(b, a);
      b.fill(0, a, p + len);
      return segmentsLeft > 0 ? p + 8 : null;
    }
    b.fill(0, p + 4, p + len);
    return null;
  }

  // --- the upper layer ---------------------------------------------------------

  private upper(b: Uint8Array, protocol: number, l4: number, end: number, ip: UpperContext): void {
    switch (protocol) {
      case 6: this.tcp(b, l4, end, ip); return;
      case 17: this.udp(b, l4, end, ip); return;
      case 1: if (!ip.v6) { this.icmpv4(b, l4, end); return; } break;
      case 2: if (!ip.v6) { this.igmp(b, l4, end); return; } break;
      case 58: if (ip.v6) { this.icmpv6(b, l4, end, ip); return; } break;
    }
    // Every other protocol - GRE, a tunnelled IP packet, SCTP, OSPF - is
    // something this cannot read, and a tunnel is a whole second packet of
    // addresses. None of it leaves.
    this.zeroPayload(b, l4, end);
  }

  /**
   * TCP keeps its header - sequence numbers, window sizes, ports and the whole
   * of the TCP analysis still work - and loses its payload.
   */
  private tcp(b: Uint8Array, l4: number, end: number, ip: UpperContext): void {
    if (l4 + 20 > end) { this.zeroPayload(b, l4, end); return; }
    const headerLen = Math.max(20, (b[l4 + 12] >> 4) * 4);
    this.zeroPayload(b, Math.min(l4 + headerLen, end), end);
    b[l4 + 16] = 0;
    b[l4 + 17] = 0;
    // With the payload zeroed the segment's checksum is the pseudo-header and
    // the header alone, so it is computable from this frame. Unknown length
    // (a fragmented segment) leaves zero, which this app's offload policy
    // reads as Unverified rather than Bad.
    if (ip.length === null) return;
    writeChecksum(b, l4 + 16, pseudoHeader(b, ip, 6, ip.length) + sum16(b, l4, Math.min(l4 + headerLen, end)));
  }

  private udp(b: Uint8Array, l4: number, end: number, ip: UpperContext): void {
    if (l4 + 8 > end) { this.zeroPayload(b, l4, end); return; }
    this.zeroPayload(b, l4 + 8, end);
    b[l4 + 6] = 0;
    b[l4 + 7] = 0;
    // UDP's own length field covers the whole datagram, fragmented or not,
    // and everything after the header is zeros now.
    const length = (b[l4 + 4] << 8) | b[l4 + 5];
    if (length < 8) return;
    const sum = checksumOf(pseudoHeader(b, ip, 17, length) + sum16(b, l4, l4 + 8));
    // Zero means "no checksum"; a computed zero is sent as all ones.
    const value = sum === 0 ? 0xffff : sum;
    b[l4 + 6] = value >> 8;
    b[l4 + 7] = value & 0xff;
  }

  /**
   * ICMP. Echo keeps its identifier and sequence and loses its data; an error
   * keeps its code and has the packet it quotes rewritten like any other; a
   * redirect's gateway is an address. Anything else keeps type, code and
   * checksum only.
   */
  private icmpv4(b: Uint8Array, l4: number, end: number): void {
    if (l4 + 8 > end) { this.zeroPayload(b, Math.min(l4 + 4, end), end); this.icmpv4Checksum(b, l4, end); return; }
    const type = b[l4];
    switch (type) {
      case 0: case 8:                              // echo
        this.zeroPayload(b, l4 + 8, end);
        break;
      case 13: case 14:                            // timestamp: three clock readings
        this.zeroPayload(b, Math.min(l4 + 20, end), end);
        break;
      case 17: case 18:                            // address mask
        this.zeroPayload(b, Math.min(l4 + 12, end), end);
        break;
      case 3: case 11: case 12:                    // unreachable, time exceeded, parameter problem
        // RFC 4884's length: an extension would follow the quoted datagram,
        // and the extension is zeroed with everything else past it.
        b[l4 + 5] = 0;
        this.quotedIpv4(b, l4 + 8, end);
        break;
      case 4:                                      // source quench
        this.quotedIpv4(b, l4 + 8, end);
        break;
      case 5:                                      // redirect
        this.mapIpv4At(b, l4 + 4);
        this.quotedIpv4(b, l4 + 8, end);
        break;
      case 9: {                                    // router advertisement
        const count = b[l4 + 4];
        const step = Math.max(2, b[l4 + 5]) * 4;
        let a = l4 + 8;
        for (let i = 0; i < count && a + step <= end; i++, a += step) this.mapIpv4At(b, a);
        this.zeroPayload(b, a, end);
        break;
      }
      default:
        this.zeroPayload(b, l4 + 4, end);
    }
    this.icmpv4Checksum(b, l4, end);
  }

  /**
   * ICMP's checksum covers the message and nothing else. Every later fragment
   * is zeroed, so the reassembled message sums to what this frame holds - the
   * answer is right even for a ping larger than one frame.
   */
  private icmpv4Checksum(b: Uint8Array, l4: number, end: number): void {
    if (l4 + 4 > end) return;
    b[l4 + 2] = 0;
    b[l4 + 3] = 0;
    writeChecksum(b, l4 + 2, sum16(b, l4, end));
  }

  /**
   * The IPv4 header an ICMP error quotes, and the first eight bytes after it.
   *
   * Its addresses go through the same mapping, so an unreachable still names
   * the conversation it is about. The eight bytes are what RFC 792 promises
   * and are kept the way the transport header of any frame is: ports and a
   * sequence number, which this module never hides. The checksum they carry
   * covered data that is not in this file, so it goes. A router that quoted
   * more than eight bytes quoted payload, and that goes too.
   */
  private quotedIpv4(b: Uint8Array, at: number, end: number): void {
    if (at + 20 > end) { this.zeroPayload(b, at, end); return; }
    const ihl = (b[at] & 0x0f) * 4;
    this.mapIpv4At(b, at + 12);
    this.mapIpv4At(b, at + 16);
    if (ihl < 20 || at + ihl > end) { this.zeroPayload(b, at + 20, end); return; }
    this.ipv4Options(b, at + 20, at + ihl);
    writeIpv4Checksum(b, at, ihl);
    this.quotedTransport(b, b[at + 9], at + ihl, end, false);
  }

  private quotedIpv6(b: Uint8Array, at: number, end: number): void {
    if (at + 40 > end) { this.zeroPayload(b, at, end); return; }
    this.mapIpv6At(b, at + 8);
    this.mapIpv6At(b, at + 24);
    let next = b[at + 6];
    let p = at + 40;
    for (let hops = 0; hops < 16 && (next === 0 || next === 60 || next === 43); hops++) {
      if (p + 8 > end) { this.zeroPayload(b, p, end); return; }
      const len = (b[p + 1] + 1) * 8;
      if (p + len > end) { this.zeroPayload(b, p, end); return; }
      if (next === 43) this.routingHeader(b, p, len);
      else this.ipv6Options(b, p + 2, p + len);
      next = b[p];
      p += len;
    }
    this.quotedTransport(b, next, p, end, true);
  }

  /** The eight bytes after a quoted IP header: the transport header's first eight. */
  private quotedTransport(b: Uint8Array, protocol: number, at: number, end: number, v6: boolean): void {
    const stop = Math.min(at + 8, end);
    if (protocol === 6) {
      // Ports and the sequence number.
    } else if (protocol === 17) {
      if (at + 8 <= end) { b[at + 6] = 0; b[at + 7] = 0; }
    } else if (protocol === (v6 ? 58 : 1)) {
      // An ICMP message quoting an echo: type, code, identifier, sequence.
      if (at + 4 <= end) { b[at + 2] = 0; b[at + 3] = 0; }
      const echo = v6 ? b[at] === 128 || b[at] === 129 : b[at] === 0 || b[at] === 8;
      if (!echo) this.zeroPayload(b, Math.min(at + 4, end), stop);
    } else {
      this.zeroPayload(b, at, stop);
    }
    this.zeroPayload(b, stop, end);
  }

  /** IGMP: the group, and the sources of a v3 query or report. */
  private igmp(b: Uint8Array, l4: number, end: number): void {
    if (l4 + 8 > end) { this.zeroPayload(b, l4, end); return; }
    const u16 = (at: number) => (b[at] << 8) | b[at + 1];
    const type = b[l4];
    if (type === 0x11) {
      this.mapIpv4At(b, l4 + 4);
      let p = l4 + 8;
      if (l4 + 12 <= end) {
        const sources = u16(l4 + 10);
        p = l4 + 12;
        for (let i = 0; i < sources && p + 4 <= end; i++, p += 4) this.mapIpv4At(b, p);
      }
      this.zeroPayload(b, p, end);
    } else if (type === 0x12 || type === 0x16 || type === 0x17) {
      this.mapIpv4At(b, l4 + 4);
      this.zeroPayload(b, l4 + 8, end);
    } else if (type === 0x22) {
      const records = u16(l4 + 6);
      let p = l4 + 8;
      for (let r = 0; r < records; r++) {
        if (p + 8 > end) break;
        const aux = b[p + 1] * 4;
        const sources = u16(p + 2);
        this.mapIpv4At(b, p + 4);
        let s = p + 8;
        for (let i = 0; i < sources && s + 4 <= end; i++, s += 4) this.mapIpv4At(b, s);
        this.zeroPayload(b, s, Math.min(s + aux, end));
        p = s + aux;
      }
      this.zeroPayload(b, p, end);
    } else {
      this.zeroPayload(b, l4 + 4, end);
    }
    b[l4 + 2] = 0;
    b[l4 + 3] = 0;
    writeChecksum(b, l4 + 2, sum16(b, l4, end));
  }

  /**
   * ICMPv6, which is where an IPv6 network describes itself: Neighbor
   * Discovery, Router Advertisements, MLD, and the errors.
   */
  private icmpv6(b: Uint8Array, l4: number, end: number, ip: UpperContext): void {
    if (l4 + 8 > end) { this.zeroPayload(b, Math.min(l4 + 4, end), end); this.icmpv6Checksum(b, l4, end, ip); return; }
    const u16 = (at: number) => (b[at] << 8) | b[at + 1];
    const type = b[l4];
    switch (type) {
      case 1: case 3:                              // unreachable, time exceeded
        b[l4 + 4] = 0;                             // RFC 4884 length
        this.quotedIpv6(b, l4 + 8, end);
        break;
      case 2: case 4:                              // packet too big, parameter problem
        this.quotedIpv6(b, l4 + 8, end);
        break;
      case 128: case 129:                          // echo
        this.zeroPayload(b, l4 + 8, end);
        break;
      case 130: {                                  // MLD query
        if (l4 + 24 > end) { this.zeroPayload(b, l4 + 8, end); break; }
        this.mapIpv6At(b, l4 + 8);
        let p = l4 + 24;
        if (l4 + 28 <= end) {
          const sources = u16(l4 + 26);
          p = l4 + 28;
          for (let i = 0; i < sources && p + 16 <= end; i++, p += 16) this.mapIpv6At(b, p);
        }
        this.zeroPayload(b, p, end);
        break;
      }
      case 131: case 132:                          // MLDv1 report, done
        if (l4 + 24 > end) { this.zeroPayload(b, l4 + 8, end); break; }
        this.mapIpv6At(b, l4 + 8);
        this.zeroPayload(b, l4 + 24, end);
        break;
      case 143: {                                  // MLDv2 report
        const records = u16(l4 + 6);
        let p = l4 + 8;
        for (let r = 0; r < records; r++) {
          if (p + 20 > end) break;
          const aux = b[p + 1] * 4;
          const sources = u16(p + 2);
          this.mapIpv6At(b, p + 4);
          let s = p + 20;
          for (let i = 0; i < sources && s + 16 <= end; i++, s += 16) this.mapIpv6At(b, s);
          this.zeroPayload(b, s, Math.min(s + aux, end));
          p = s + aux;
        }
        this.zeroPayload(b, p, end);
        break;
      }
      case 133:                                    // router solicitation
        this.ndOptions(b, l4 + 8, end);
        break;
      case 134:                                    // router advertisement
        this.ndOptions(b, Math.min(l4 + 16, end), end);
        break;
      case 135: case 136:                          // neighbor solicitation, advertisement
        if (l4 + 24 > end) { this.zeroPayload(b, l4 + 8, end); break; }
        this.mapIpv6At(b, l4 + 8);
        this.ndOptions(b, l4 + 24, end);
        break;
      case 137:                                    // redirect
        if (l4 + 40 > end) { this.zeroPayload(b, l4 + 8, end); break; }
        this.mapIpv6At(b, l4 + 8);
        this.mapIpv6At(b, l4 + 24);
        this.ndOptions(b, l4 + 40, end);
        break;
      default:
        this.zeroPayload(b, l4 + 4, end);
    }
    this.icmpv6Checksum(b, l4, end, ip);
  }

  /**
   * ICMPv6's checksum is over a pseudo-header of the (now mapped) source,
   * the final destination and the upper-layer length, so it has to be
   * recomputed after every rewrite above. A fragmented message's length is not
   * in this frame; its checksum is zeroed rather than guessed.
   */
  private icmpv6Checksum(b: Uint8Array, l4: number, end: number, ip: UpperContext): void {
    if (l4 + 4 > end) return;
    b[l4 + 2] = 0;
    b[l4 + 3] = 0;
    if (ip.length === null) return;
    writeChecksum(b, l4 + 2, pseudoHeader(b, ip, 58, ip.length) + sum16(b, l4, end));
  }

  /**
   * Neighbor Discovery options (RFC 4861 and later): the link-layer address
   * options are MACs, a Prefix Information or Route Information option is a
   * prefix, RDNSS is a list of DNS servers, PREF64 is the NAT64 prefix. The
   * MTU and the nonce stay. Everything else - the DNS search list first among
   * them, which names the network's domain - keeps its type and length and
   * loses its data.
   */
  private ndOptions(b: Uint8Array, from: number, end: number): void {
    let p = from;
    while (p + 2 <= end) {
      const type = b[p];
      const len = b[p + 1] * 8;
      if (len === 0 || p + len > end) break;
      switch (type) {
        case 1: case 2:                            // source / target link-layer address
          if (len === 8) this.mapMacAt(b, p + 2);
          else b.fill(0, p + 2, p + len);
          break;
        case 3:                                    // prefix information
          if (len === 32) this.mapIpv6PrefixAt(b, p + 16, b[p + 2]);
          else b.fill(0, p + 2, p + len);
          break;
        case 24: {                                 // route information
          const bytes = Math.min(16, len - 8);
          if (bytes > 0) this.mapIpv6PrefixAt(b, p + 8, b[p + 2], bytes);
          break;
        }
        case 25:                                   // recursive DNS servers
          for (let a = p + 8; a + 16 <= p + len; a += 16) this.mapIpv6At(b, a);
          break;
        case 38: {                                 // PREF64: 13-bit lifetime, 3-bit length code
          if (len !== 16) { b.fill(0, p + 2, p + len); break; }
          const bits = [96, 64, 56, 48, 40, 32][b[p + 3] & 0x07] ?? 0;
          this.mapIpv6PrefixAt(b, p + 4, bits, 12);
          break;
        }
        case 5: case 14:                           // MTU, nonce
          break;
        default:
          b.fill(0, p + 2, p + len);
      }
      p += len;
    }
    this.zeroPayload(b, p, end);
  }

  // --- the link layer's own protocols ----------------------------------------

  /** ARP carries addresses of its own, in its own layout. */
  private arp(b: Uint8Array, l3: number, end: number): void {
    // Ethernet and IPv4 sizes are the only layout this reads. An anonymiser
    // that missed ARP would leave the whole local subnet in plain view.
    if (l3 + 28 > end || b[l3 + 4] !== 6 || b[l3 + 5] !== 4) {
      this.zeroPayload(b, Math.min(l3 + 8, end), end);
      return;
    }
    this.mapMacAt(b, l3 + 8);
    this.mapIpv4At(b, l3 + 14);
    this.mapMacAt(b, l3 + 18);
    this.mapIpv4At(b, l3 + 24);
  }

  /**
   * A spanning tree BPDU: the root and the sending bridge are each a priority
   * and a MAC, and the MAC is the switch's own - often the same device as a
   * frame's source. An MSTP BPDU's extension (a region name, MSTI records)
   * is zeroed.
   */
  private stp(b: Uint8Array, bpdu: number, end: number): void {
    const type = b[bpdu + 3];
    if ((type === 0x00 || type === 0x02) && bpdu + 35 <= end) {
      this.mapMacAt(b, bpdu + 7);
      this.mapMacAt(b, bpdu + 19);
      this.zeroPayload(b, bpdu + 36, end);
      return;
    }
    this.zeroPayload(b, Math.min(bpdu + 4, end), end);
  }

  /**
   * LLDP: what a device says about itself, which is a MAC, an address and -
   * in the Chassis ID's "locally assigned" form, the system name and the
   * description - the machine's own name. MACs and addresses are mapped;
   * names and descriptions are zeroed. The IEEE 802.3 TLVs and LLDP-MED's
   * capabilities and network policy are numbers about the link, and stay.
   */
  private lldp(b: Uint8Array, l3: number, end: number): void {
    let p = l3;
    while (p + 2 <= end) {
      const type = b[p] >> 1;
      const len = ((b[p] & 0x01) << 8) | b[p + 1];
      const value = p + 2;
      if (value + len > end) break;
      if (type === 0) { p = value; break; }
      if (type === 1 || type === 2) {
        // Chassis ID subtype 4 and Port ID subtype 3 are MACs; Chassis 5 and
        // Port 4 are network addresses.
        const subtype = b[value];
        const isMac = (type === 1 && subtype === 4) || (type === 2 && subtype === 3);
        const isAddress = (type === 1 && subtype === 5) || (type === 2 && subtype === 4);
        if (isMac && len === 7) this.mapMacAt(b, value + 1);
        else if (isAddress && len >= 2) this.lldpAddress(b, value + 1, value + len);
        else b.fill(0, value + 1, value + len);
      } else if (type === 8 && len >= 2) {
        // Management address: a length, a family and the address, then an
        // interface number (kept) and an OID (zeroed).
        const addrLen = b[value];
        const addrEnd = value + 1 + addrLen;
        if (addrLen >= 1 && addrEnd <= value + len) this.lldpAddress(b, value + 1, addrEnd);
        if (addrEnd + 5 < value + len) b.fill(0, addrEnd + 6, value + len);
      } else if (type === 127 && len >= 4) {
        const oui = (b[value] << 16) | (b[value + 1] << 8) | b[value + 2];
        const subtype = b[value + 3];
        const keep = oui === 0x00120f                                   // IEEE 802.3
          || (oui === 0x0012bb && (subtype === 1 || subtype === 2))     // LLDP-MED capabilities, policy
          || (oui === 0x0080c2 && (subtype === 1 || subtype === 2 || subtype === 7)); // 802.1 VLAN ids, link aggregation
        if (!keep) b.fill(0, value + 4, value + len);
      } else if (type !== 3 && type !== 7) {
        // Port description, system name, system description, and anything
        // newer: text written by a person about this machine.
        b.fill(0, value, value + len);
      }
      p = value + len;
    }
    this.zeroPayload(b, p, end);
  }

  /** An address family byte (IANA: 1 IPv4, 2 IPv6, 6 802 MAC) and the address after it. */
  private lldpAddress(b: Uint8Array, at: number, to: number): void {
    const family = b[at];
    if (family === 1 && at + 5 === to) this.mapIpv4At(b, at + 1);
    else if (family === 2 && at + 17 === to) this.mapIpv6At(b, at + 1);
    else if (family === 6 && at + 7 === to) this.mapMacAt(b, at + 1);
    else b.fill(0, at + 1, to);
  }

  /**
   * IEEE 1905.1 (and Wi-Fi EasyMesh on top of it): a home network's devices
   * describing their radios, neighbours and BSSIDs to each other. The AL MAC,
   * MAC and Device Information TLVs are mapped; every other TLV - EasyMesh
   * adds dozens, carrying SSIDs and neighbour lists - keeps its type and
   * length and loses its value.
   */
  private ieee1905(b: Uint8Array, l3: number, end: number): void {
    let p = l3 + 8;                                // the CMDU header is numbers
    while (p + 3 <= end) {
      const type = b[p];
      const len = (b[p + 1] << 8) | b[p + 2];
      const value = p + 3;
      if (value + len > end) break;
      if (type === 0) { p = value + len; break; }  // End of Message
      const stop = value + len;
      if ((type === 1 || type === 2) && len === 6) {
        this.mapMacAt(b, value);
      } else if (type === 6) {
        // Non-1905 neighbours: this interface's MAC, then theirs.
        let q = value;
        for (; q + 6 <= stop; q += 6) this.mapMacAt(b, q);
        b.fill(0, q, stop);
      } else if (type === 7 && len >= 6) {
        // 1905 neighbours: this interface's MAC, then each AL MAC and a flags byte.
        this.mapMacAt(b, value);
        let q = value + 6;
        for (; q + 7 <= stop; q += 7) this.mapMacAt(b, q);
        b.fill(0, q, stop);
      } else if (type === 0x80 || type === 0x81) {
        // Supported / searched services: a count and one byte per service. A
        // zeroed count leaves the reader inside the TLV, reading its bytes as
        // the next one's header.
      } else if (type === 0x83 && len >= 1) {
        // AP Operational BSS: per radio its id (a MAC) and each BSS's MAC and
        // SSID. The SSID is the network's name and is zeroed; its length stays.
        let q = value + 1;
        for (let r = 0, radios = b[value]; r < radios && q + 7 <= stop; r++) {
          this.mapMacAt(b, q);
          const count = b[q + 6];
          q += 7;
          for (let i = 0; i < count && q + 7 <= stop; i++) {
            this.mapMacAt(b, q);
            const ssid = b[q + 6];
            b.fill(0, q + 7, Math.min(q + 7 + ssid, stop));
            q += 7 + ssid;
          }
        }
        b.fill(0, Math.min(q, stop), stop);
      } else if (type === 0x84 && len >= 1) {
        // Associated Clients: per BSS its BSSID and each client's MAC and age.
        let q = value + 1;
        for (let s = 0, bss = b[value]; s < bss && q + 8 <= stop; s++) {
          this.mapMacAt(b, q);
          const clients = (b[q + 6] << 8) | b[q + 7];
          q += 8;
          for (let i = 0; i < clients && q + 8 <= stop; i++, q += 8) this.mapMacAt(b, q);
        }
        b.fill(0, Math.min(q, stop), stop);
      } else if (type === 3 && len >= 7) {
        this.mapMacAt(b, value);
        const count = b[value + 6];
        let q = value + 7;
        for (let i = 0; i < count && q + 9 <= value + len; i++) {
          this.mapMacAt(b, q);
          const info = b[q + 8];
          b.fill(0, q + 9, Math.min(q + 9 + info, value + len));
          q += 9 + info;
        }
        b.fill(0, Math.min(q, value + len), value + len);
      } else {
        b.fill(0, value, value + len);
      }
      p = value + len;
    }
    this.zeroPayload(b, p, end);
  }
}

/** Anonymises a whole capture, and says what it did. */
export function anonymiseCapture(packets: Packet[]): { packets: Packet[]; summary: AnonymiseSummary } {
  const anonymiser = new Anonymiser();
  const out = packets.map((p) => anonymiser.packet(p));
  return { packets: out, summary: anonymiser.summary() };
}

// --- helpers ---------------------------------------------------------------------

/**
 * Anything in prose that might be an address: a MAC, a run of hex and colons
 * with at least two colons (IPv6, compressed or not), or a dotted quad. The
 * candidates are then parsed, so the pattern only has to be generous.
 */
const ADDRESS_TOKEN = new RegExp([
  /(?<![0-9a-f:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![0-9a-f:])/.source,
  /(?<![0-9a-f-])[0-9a-f]{2}(?:-[0-9a-f]{2}){5}(?![0-9a-f-])/.source,
  /(?<![0-9a-z:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z:]|\.\d)/.source,
  /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)/.source,
].join('|'), 'gi');
const MAC_TOKEN = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
const DASHED_MAC_TOKEN = /^[0-9a-f]{2}(?:-[0-9a-f]{2}){5}$/i;

function randomKey(): Uint8Array {
  const key = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(key);
  else for (let i = 0; i < key.length; i++) key[i] = Math.floor(Math.random() * 256);
  return key;
}

export function parseIpv4(address: string): Uint8Array | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

export function parseIpv6(address: string): Uint8Array | null {
  if (!address.includes(':') || /[^0-9a-f:]/i.test(address)) return null;
  const [head, tail] = address.split('::');
  if (address.split('::').length > 2) return null;
  const headGroups = head === '' ? [] : head.split(':').filter((g) => g !== '');
  const tailGroups = tail === undefined || tail === '' ? [] : tail.split(':').filter((g) => g !== '');
  if (tail === undefined && headGroups.length !== 8) return null;
  if (headGroups.length + tailGroups.length > 8) return null;
  const out = new Uint8Array(16);
  const write = (groups: string[], at: number) => {
    for (let i = 0; i < groups.length; i++) {
      const v = parseInt(groups[i], 16);
      if (!Number.isInteger(v) || v < 0 || v > 0xffff) return false;
      out[at + i * 2] = v >> 8;
      out[at + i * 2 + 1] = v & 0xff;
    }
    return true;
  };
  if (!write(headGroups, 0)) return null;
  if (!write(tailGroups, 16 - tailGroups.length * 2)) return null;
  return out;
}

function parseMac(address: string): Uint8Array | null {
  const parts = address.split(':');
  if (parts.length !== 6) return null;
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    const v = parseInt(parts[i], 16);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    out[i] = v;
  }
  return out;
}

function writeMac(bytes: Uint8Array, at: number, mac: Uint8Array): void {
  bytes.set(mac, at);
}

/**
 * Addresses that are not anybody's address.
 *
 * Multicast, broadcast, the unspecified address and the loopback net are how
 * the protocols address everyone or themselves. Rewriting 224.0.0.251 would
 * turn mDNS into traffic to a host that does not exist, which destroys the
 * file's meaning without hiding anything: these values are the same on every
 * network on earth.
 */
function isReservedIpv4(raw: Uint8Array): boolean {
  if (raw[0] === 0) return true;                    // 0.0.0.0/8, unspecified
  if (raw[0] === 127) return true;                  // loopback
  if (raw[0] >= 224) return true;                   // multicast and broadcast
  return false;
}

function isReservedIpv6(raw: Uint8Array): boolean {
  if (raw[0] === 0xff) return true;                 // multicast
  if (raw.every((b) => b === 0)) return true;       // ::
  if (raw.slice(0, 15).every((b) => b === 0) && raw[15] === 1) return true; // ::1
  return false;
}

/**
 * `ff02::1:ffXX:XXXX`, the solicited-node group - the one multicast address
 * whose bits come from a unicast one.
 */
function isSolicitedNode(raw: Uint8Array): boolean {
  if (raw[0] !== 0xff || raw[1] !== 0x02 || raw[11] !== 0x01 || raw[12] !== 0xff) return false;
  for (let i = 2; i < 11; i++) if (raw[i] !== 0) return false;
  return true;
}

/** Clears every bit of `raw` from bit `keep` on. */
function maskBits(raw: Uint8Array, keep: number): void {
  for (let bit = keep; bit < raw.length * 8; bit++) raw[bit >> 3] &= ~(1 << (7 - (bit & 7)));
}

/** What the upper layer needs from the IP header it sits in. */
interface UpperContext {
  v6: boolean;
  /** Where the source and the FINAL destination are in the frame - already mapped. */
  srcAt: number;
  dstAt: number;
  /** The upper-layer length the header states; null when this frame cannot say (a fragment). */
  length: number | null;
}

/** The one's-complement sum of big-endian 16-bit words, unfolded; an odd last byte is padded. */
function sum16(bytes: Uint8Array, from: number, to: number): number {
  const stop = Math.min(to, bytes.length);
  let sum = 0;
  let i = from;
  for (; i + 1 < stop; i += 2) sum += (bytes[i] << 8) | bytes[i + 1];
  if (i < stop) sum += bytes[i] << 8;
  return sum;
}

function checksumOf(sum: number): number {
  let s = sum;
  while (s > 0xffff) s = (s % 0x10000) + Math.floor(s / 0x10000);
  return (~s) & 0xffff;
}

function writeChecksum(bytes: Uint8Array, at: number, sum: number): void {
  const checksum = checksumOf(sum);
  bytes[at] = checksum >> 8;
  bytes[at + 1] = checksum & 0xff;
}

/** The pseudo-header TCP, UDP and ICMPv6 checksums cover. */
function pseudoHeader(bytes: Uint8Array, ip: UpperContext, protocol: number, length: number): number {
  const size = ip.v6 ? 16 : 4;
  return sum16(bytes, ip.srcAt, ip.srcAt + size) + sum16(bytes, ip.dstAt, ip.dstAt + size)
    + protocol + Math.floor(length / 0x10000) + (length & 0xffff);
}

function writeIpv4Checksum(bytes: Uint8Array, at: number, headerLen: number): void {
  bytes[at + 10] = 0;
  bytes[at + 11] = 0;
  writeChecksum(bytes, at + 10, sum16(bytes, at, at + headerLen));
}
