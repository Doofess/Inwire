/**
 * ERSPAN frames, built byte by byte for `dissect.ts`. A builder, not a test.
 *
 * The header layouts are Cisco's, as the IETF draft
 * (draft-foschiano-erspan) writes them down:
 *
 *   type I    GRE with no sequence number, protocol 0x88BE, and the mirrored
 *             frame straight after it - no ERSPAN header at all
 *   type II   GRE with a sequence number, protocol 0x88BE, then 8 bytes:
 *             Ver(4)=1 VLAN(12) | COS(3) En(2) T(1) Session(10) |
 *             Reserved(12) Index(20)
 *   type III  GRE with a sequence number, protocol 0x22EB, then 12 bytes:
 *             Ver(4)=2 VLAN(12) | COS(3) BSO(2) T(1) Session(10) |
 *             Timestamp(32) | SGT(16) | P(1) FT(5) HW(6) D(1) Gra(2) O(1)
 *             and, when O is set, an 8-byte platform-specific subheader
 */
import { Bytes, ethernet, internetChecksum, ipv4 } from '../parity/synthetic';

export interface Gre { seq?: number; key?: number; protocol: number }

export function gre({ seq, key, protocol }: Gre): number[] {
  let flags = 0;
  if (key !== undefined) flags |= 0x2000;
  if (seq !== undefined) flags |= 0x1000;
  const out = new Bytes().u16(flags, protocol);
  if (key !== undefined) out.u32(key);
  if (seq !== undefined) out.u32(seq);
  return Array.from(out.build());
}

export interface TypeII { vlan?: number; cos?: number; encap?: number; truncated?: boolean; session: number; index?: number; reserved?: number }

export function typeII(h: TypeII): number[] {
  return Array.from(new Bytes()
    .u16((1 << 12) | (h.vlan ?? 0))
    .u16(((h.cos ?? 0) << 13) | ((h.encap ?? 0) << 11) | (h.truncated ? 0x400 : 0) | h.session)
    .u32((((h.reserved ?? 0) << 20) | (h.index ?? 0)) >>> 0)
    .build());
}

export interface TypeIII {
  vlan?: number; cos?: number; bso?: number; truncated?: boolean; session: number;
  timestamp: number; sgt?: number; p?: boolean; ft?: number; hw?: number; d?: boolean; gra?: number;
  /** The platform subheader's two words, when there is one. */
  platform?: [number, number];
}

export function typeIII(h: TypeIII): number[] {
  const word = ((h.p ? 1 : 0) << 15) | ((h.ft ?? 0) << 10) | ((h.hw ?? 0) << 4)
    | ((h.d ? 1 : 0) << 3) | ((h.gra ?? 0) << 1) | (h.platform !== undefined ? 1 : 0);
  const out = new Bytes()
    .u16((2 << 12) | (h.vlan ?? 0))
    .u16(((h.cos ?? 0) << 13) | ((h.bso ?? 0) << 11) | (h.truncated ? 0x400 : 0) | h.session)
    .u32(h.timestamp >>> 0)
    .u16(h.sgt ?? 0, word);
  if (h.platform !== undefined) out.u32(h.platform[0] >>> 0, h.platform[1] >>> 0);
  return Array.from(out.build());
}

/** An ICMPv4 echo request with a correct checksum. */
export function icmpEcho(id: number, seq: number): Uint8Array {
  const b = new Bytes().u8(8, 0).u16(0).u16(id, seq).ascii('abcdefgh').build();
  const sum = internetChecksum(b);
  b[2] = (sum >> 8) & 0xff;
  b[3] = sum & 0xff;
  return b;
}

const MIRRORED_SRC = '02:00:00:00:00:0a';
const MIRRORED_DST = '02:00:00:00:00:0b';

/** The mirrored host's Ethernet frame: its own MACs, a tag if any, a type, and the rest. */
export function mirrored(etherType: number, payload: ArrayLike<number>, vlan?: number): number[] {
  const out = new Bytes().mac(MIRRORED_DST).mac(MIRRORED_SRC);
  if (vlan !== undefined) out.u16(0x8100, vlan);
  return Array.from(out.u16(etherType).raw(payload).build());
}

/** A mirrored TCP SYN between two hosts the capturing machine is neither of. */
export const tcpSyn = (src: string, dst: string): Uint8Array => ipv4(6, new Bytes()
  .u16(51000, 443).u32(1000).u32(0).u8(0x50, 0x02).u16(64240, 0, 0).build(), src, dst);

function ipv6Address(text: string): number[] {
  const [head, tail = ''] = text.split('::');
  const groups = (s: string) => (s === '' ? [] : s.split(':').map((g) => parseInt(g, 16)));
  const h = groups(head);
  const t = groups(tail);
  const all = [...h, ...Array<number>(8 - h.length - t.length).fill(0), ...t];
  return all.flatMap((g) => [(g >> 8) & 0xff, g & 0xff]);
}

function ipv6Header(next: number, payloadLength: number, src: string, dst: string): number[] {
  return Array.from(new Bytes().u32(0x60000000).u16(payloadLength).u8(next, 64)
    .raw(ipv6Address(src)).raw(ipv6Address(dst)).build());
}

/**
 * A mirrored IPv6/UDP datagram, with the checksum IPv6 requires (RFC 8200
 * 8.1) - a zero one is malformed to the reference.
 */
export function udp6(srcPort: number, dstPort: number, payload: ArrayLike<number>): number[] {
  const src = '2001:db8::10';
  const dst = '2001:db8::20';
  const datagram = new Bytes().u16(srcPort, dstPort, 8 + payload.length, 0).raw(payload).build();
  const pseudo = [...ipv6Address(src), ...ipv6Address(dst), 0, 0, 0, datagram.length, 0, 0, 0, 17];
  const sum = internetChecksum(Uint8Array.from([...pseudo, ...datagram]));
  datagram[6] = sum >> 8;
  datagram[7] = sum & 0xff;
  return [...ipv6Header(17, datagram.length, src, dst), ...datagram];
}

/** An ARP request, as the mirrored host sent it. */
export function arpRequest(): number[] {
  return Array.from(new Bytes().u16(1, 0x0800).u8(6, 4).u16(1)
    .mac(MIRRORED_SRC).ipv4('10.9.0.10').mac('00:00:00:00:00:00').ipv4('10.9.0.1').build());
}

/** The mirroring switch's GRE datagram, over IPv4. */
export function erspanFrame(greHeader: number[], body: ArrayLike<number>): Uint8Array {
  return Uint8Array.from([...ethernet(0x0800).build(),
    ...ipv4(47, Uint8Array.from([...greHeader, ...Array.from(body)]), '198.51.100.1', '198.51.100.2')]);
}

/** The same, over IPv6. */
export function erspanFrame6(greHeader: number[], body: ArrayLike<number>): Uint8Array {
  const payload = [...greHeader, ...Array.from(body)];
  return Uint8Array.from([...ethernet(0x86dd).build(),
    ...ipv6Header(47, payload.length, '2001:db8:1::1', '2001:db8:1::2'), ...payload]);
}
