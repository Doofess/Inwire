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
 *     ships for QUIC.
 *   * **MACs keep their OUI.** The first three bytes name the manufacturer,
 *     which is how a capture tells you the printer from the phone from the
 *     access point; the last three identify the unit. So the vendor half is
 *     kept and the unit half is replaced.
 *   * **Everything above the transport header goes.** Not scrambled - zeroed.
 *     Payload is where the passwords, the cookies and the documents are, and
 *     no reversible transform of it is worth defending.
 *
 * The mapping is deterministic within one export and different between them:
 * the key is random per run, so the same capture exported twice does not
 * produce the same addresses, and nobody can build a dictionary from a file
 * they were given earlier.
 */
import type { Packet } from '../types/packet';
import { LINKTYPE } from './dissect/types';
import { dissectLinkLayer } from './dissectors/linkLayer';
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
 */
class PrefixPreserving {
  private readonly roundKeys: Uint8Array;
  /** The pad block, from the second half of the key material. */
  private readonly pad: Uint8Array;

  constructor(key: Uint8Array) {
    this.roundKeys = expandKey128(key.subarray(0, 16));
    // The pad is the key's second half encrypted under its first, exactly as
    // the paper specifies - it must be independent of the address being
    // anonymised, and it must not be all zeros.
    this.pad = encryptBlock128(this.roundKeys, key.subarray(16, 32));
  }

  /** Anonymises `bits` bits of a big-endian address, in place on a copy. */
  map(address: Uint8Array, bits: number): Uint8Array {
    const out = new Uint8Array(address.length);
    out.set(address);
    const block = new Uint8Array(16);

    for (let i = 0; i < bits; i++) {
      // The block is the first i bits of the *real* address followed by the
      // pad's remaining bits. Using the real address here rather than the
      // anonymised one is what keeps the map injective.
      block.set(this.pad);
      for (let b = 0; b < i; b++) {
        const bit = (address[b >> 3] >> (7 - (b & 7))) & 1;
        const mask = 1 << (7 - (b & 7));
        if (bit) block[b >> 3] |= mask; else block[b >> 3] &= ~mask;
      }
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
  private stripped = 0;
  private strippedBytes = 0;

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
    if (!raw || isReservedIpv6(raw)) return address;
    const mapped = formatIpv6Address(this.prf.map(raw, 128), 0);
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
    if (!raw || (raw[0] & 0x01) !== 0) return address; // group bit: not a device
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
   * One frame, rewritten.
   *
   * The bytes are what an exported capture actually carries, so they are what
   * has to change: rewriting only the summary columns would produce a file
   * whose packet list looked anonymous and whose hex dump was not.
   */
  packet(packet: Packet): Packet {
    const bytes = packet.rawBytes.length > 0 ? packet.rawBytes.slice() : packet.rawBytes;
    if (bytes.length > 0) this.rewriteFrame(bytes);

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
      resolved: undefined,
      streamPayload: undefined,
      hexDump: undefined,
      asciiDump: undefined,
      info: '(anonymised)',
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
   * Rewrites a frame's bytes in place: addresses, then everything above L4.
   *
   * The link layer is read with the same dissector the packet list uses, so
   * this follows VLAN tags and LLC/SNAP rather than assuming an offset - an
   * anonymiser that writes 12 bytes at offset 26 into a VLAN-tagged frame
   * corrupts the payload and leaves the address intact, which is the worst of
   * both outcomes.
   */
  private rewriteFrame(bytes: Uint8Array): void {
    const link = dissectLinkLayer(bytes, LINKTYPE.ETHERNET);
    if (link.dstMac && link.srcMac && bytes.length >= 12) {
      writeMac(bytes, 0, parseMac(this.mac(link.dstMac))!);
      writeMac(bytes, 6, parseMac(this.mac(link.srcMac))!);
    }

    const l3 = link.l3Offset;
    if (link.etherType === 0x0800 && bytes.length >= l3 + 20) {
      const headerLen = (bytes[l3] & 0x0f) * 4;
      const src = this.prfIpv4(bytes.subarray(l3 + 12, l3 + 16));
      const dst = this.prfIpv4(bytes.subarray(l3 + 16, l3 + 20));
      bytes.set(src, l3 + 12);
      bytes.set(dst, l3 + 16);
      const protocol = bytes[l3 + 9];
      const totalLen = (bytes[l3 + 2] << 8) | bytes[l3 + 3];
      this.stripPayload(bytes, l3 + headerLen, Math.min(bytes.length, l3 + totalLen), protocol);
      // The header changed, so its checksum has to. Leaving it stale would
      // paint every frame in the file as a checksum error and bury whatever
      // the capture was shared to show.
      writeIpv4Checksum(bytes, l3, headerLen);
    } else if (link.etherType === 0x86dd && bytes.length >= l3 + 40) {
      bytes.set(this.prfIpv6(bytes.subarray(l3 + 8, l3 + 24)), l3 + 8);
      bytes.set(this.prfIpv6(bytes.subarray(l3 + 24, l3 + 40)), l3 + 24);
      const payloadLen = (bytes[l3 + 4] << 8) | bytes[l3 + 5];
      this.stripPayload(bytes, l3 + 40, Math.min(bytes.length, l3 + 40 + payloadLen), bytes[l3 + 6]);
    } else if (link.etherType === 0x0806 && bytes.length >= l3 + 28) {
      // ARP carries addresses of its own, in its own layout, and an anonymiser
      // that missed them would leave the whole local subnet in plain view.
      bytes.set(parseMac(this.mac(formatMac(bytes.subarray(l3 + 8, l3 + 14))))!, l3 + 8);
      bytes.set(this.prfIpv4(bytes.subarray(l3 + 14, l3 + 18)), l3 + 14);
      bytes.set(parseMac(this.mac(formatMac(bytes.subarray(l3 + 18, l3 + 24))))!, l3 + 18);
      bytes.set(this.prfIpv4(bytes.subarray(l3 + 24, l3 + 28)), l3 + 24);
    }
  }

  private prfIpv4(raw: Uint8Array): Uint8Array {
    if (isReservedIpv4(raw)) return raw;
    return this.prf.map(raw, 32);
  }

  private prfIpv6(raw: Uint8Array): Uint8Array {
    if (isReservedIpv6(raw)) return raw;
    return this.prf.map(raw, 128);
  }

  /**
   * Zeroes everything above the transport header, and blanks the transport
   * checksum that described it.
   *
   * Zeroed rather than scrambled: payload is where the passwords, the cookies
   * and the documents are, and there is no reversible transform of it worth
   * defending. The headers stay, so sequence numbers, window sizes, ports and
   * the whole of the TCP analysis still work.
   */
  private stripPayload(bytes: Uint8Array, l4: number, end: number, protocol: number): void {
    let payloadStart: number;
    let checksumAt: number;
    if (protocol === 6 && l4 + 20 <= end) {
      payloadStart = l4 + ((bytes[l4 + 12] >> 4) * 4);
      checksumAt = l4 + 16;
    } else if (protocol === 17 && l4 + 8 <= end) {
      payloadStart = l4 + 8;
      checksumAt = l4 + 6;
    } else {
      return; // ICMP, IGMP and the rest are header-only in practice
    }
    if (payloadStart >= end || payloadStart > bytes.length) return;
    const stop = Math.min(end, bytes.length);
    if (stop <= payloadStart) return;
    bytes.fill(0, payloadStart, stop);
    // The checksum covered bytes that are gone. Zero means "not computed" for
    // UDP, and for TCP it is what this app's own offload policy already reads
    // as Unverified rather than Bad - so neither shows up as damage.
    bytes[checksumAt] = 0;
    bytes[checksumAt + 1] = 0;
    this.stripped++;
    this.strippedBytes += stop - payloadStart;
  }
}

/** Anonymises a whole capture, and says what it did. */
export function anonymiseCapture(packets: Packet[]): { packets: Packet[]; summary: AnonymiseSummary } {
  const anonymiser = new Anonymiser();
  const out = packets.map((p) => anonymiser.packet(p));
  return { packets: out, summary: anonymiser.summary() };
}

// --- helpers ---------------------------------------------------------------------

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

function writeIpv4Checksum(bytes: Uint8Array, at: number, headerLen: number): void {
  bytes[at + 10] = 0;
  bytes[at + 11] = 0;
  let sum = 0;
  for (let i = at; i < at + headerLen; i += 2) sum += (bytes[i] << 8) | bytes[i + 1];
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  const checksum = (~sum) & 0xffff;
  bytes[at + 10] = checksum >> 8;
  bytes[at + 11] = checksum & 0xff;
}
