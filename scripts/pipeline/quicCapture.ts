/**
 * A synthetic QUIC capture for ADR 0053 phase 5: the datagram shapes the
 * dissector, the lane router and the QUIC order must all agree on.
 *
 * Payload bytes after the headers are filler: nothing here is decrypted, only
 * classified. Addresses are RFC 5737 / RFC 3849 documentation ranges.
 *
 * Not an assertion script: it never calls `process.exit` and has no top-level
 * side effects, so `check.ts` does not run it. Other scripts import it.
 */
import { Bytes, ethernet, ipv4, pcapOf, udpFrame } from '../parity/synthetic';

/** More flows than `MAX_FLOWS` (4,096), each with one long header. */
export const QUIC_EVICTION_FLOWS = 4_200;

const V1 = 0x00000001;
const V2 = 0x6b3343cf;

type Kind = 'initial' | 'handshake' | 'retry' | 'zeroRtt' | 'vn' | 'short';
interface PayloadOptions { dcid: number[]; scid?: number[]; token?: number[]; payload?: number; v2?: boolean }

/** QUIC's variable-length integer, one or two bytes (values under 16,384). */
function varint(value: number): number[] {
  return value < 64 ? [value] : [0x40 | (value >> 8), value & 0xff];
}

function filler(n: number, seed: number): number[] {
  return Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);
}

/** One QUIC packet, headers real, protected payload filler. */
export function quicPayload(kind: Kind, o: PayloadOptions): Uint8Array {
  const scid = o.scid ?? [];
  const size = o.payload ?? 32;
  const version = o.v2 === true ? V2 : V1;
  if (kind === 'short') return Uint8Array.from([0x40 | 0x05, ...o.dcid, ...filler(size, 0x21)]);
  const b = new Bytes();
  if (kind === 'vn') {
    b.u8(0xc0 | 0x0a).u32(0).u8(o.dcid.length).raw(o.dcid).u8(scid.length).raw(scid).u32(V1, V2);
    return b.build();
  }
  const type = o.v2 === true
    ? { retry: 0, initial: 1, zeroRtt: 2, handshake: 3 }[kind]
    : { initial: 0, zeroRtt: 1, handshake: 2, retry: 3 }[kind];
  b.u8(0xc0 | (type << 4)).u32(version).u8(o.dcid.length).raw(o.dcid).u8(scid.length).raw(scid);
  if (kind === 'retry') return b.raw(filler(size, 0x55)).build();
  if (kind === 'initial') {
    const token = o.token ?? [];
    b.raw(varint(token.length)).raw(token);
  }
  b.raw(varint(size)).raw(filler(size, 0x33));
  return b.build();
}

/** Packets back to back in one datagram. */
export function coalesce(...packets: Uint8Array[]): Uint8Array {
  return Uint8Array.from(packets.flatMap((p) => Array.from(p)));
}

function ipv6Bytes(text: string): number[] {
  const [head, tail] = text.split('::');
  const left = head === '' ? [] : head.split(':');
  const right = tail === undefined || tail === '' ? [] : tail.split(':');
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.flatMap((g) => { const v = parseInt(g, 16); return [(v >> 8) & 0xff, v & 0xff]; });
}

/** An Ethernet frame carrying one UDP datagram; `udpLength` overrides the header's length field. */
export function quicFrame(
  src: string, srcPort: number, dst: string, dstPort: number, payload: Uint8Array,
  o: { qinq?: boolean; ipv6?: boolean; udpLength?: number } = {},
): Uint8Array {
  const datagram = Uint8Array.from([
    ...new Bytes().u16(srcPort, dstPort, o.udpLength ?? 8 + payload.length, 0).build(), ...payload,
  ]);
  const etherType = o.ipv6 === true ? 0x86dd : 0x0800;
  const link = o.qinq === true
    ? Uint8Array.from([
      ...ethernet(0x88a8).build(), ...new Bytes().u16(0x0064, 0x8100, 0x00c8, etherType).build(),
    ])
    : ethernet(etherType).build();
  const network = o.ipv6 === true
    ? Uint8Array.from([
      ...new Bytes().u32(0x60000000).u16(datagram.length).u8(17, 64).raw(ipv6Bytes(src)).raw(ipv6Bytes(dst)).build(),
      ...datagram,
    ])
    : ipv4(17, datagram, src, dst);
  return Uint8Array.from([...link, ...network]);
}

/** A connection id unique to n: n's bytes first, so 4,200 eviction flows do not share ids. */
const id = (n: number, len = 8): number[] =>
  Array.from({ length: len }, (_, i) => (i < 4 ? (n >>> (8 * (3 - i))) : (n * 31 + i * 17 + 1)) & 0xff);

const SERVER = '198.51.100.1';
const SERVER6 = '2001:db8::1';

/** The capture, as pcap bytes (linktype 1). */
export function quicCapture(): Uint8Array {
  const frames: Uint8Array[] = [];
  const add = (f: Uint8Array) => { frames.push(f); };

  // (1) Handshakes on IPv4 and IPv6: client Initial, server Initial whose DCID
  // is empty (the flowConnection fallback), then short headers to the server SCID.
  const oneConnection = (client: string, server: string, ipv6: boolean, port: number, n: number) => {
    const c = id(n), s = id(n + 100);
    const o = { ipv6 };
    add(quicFrame(client, port, server, 443, quicPayload('initial', { dcid: c }), o));
    add(quicFrame(server, 443, client, port, quicPayload('initial', { dcid: [], scid: s }), o));
    add(quicFrame(client, port, server, 443, quicPayload('short', { dcid: s }), o));
    add(quicFrame(client, port, server, 443, quicPayload('short', { dcid: s, payload: 90 }), o));
    add(quicFrame(server, 443, client, port, quicPayload('short', { dcid: [] }), o));
    return { c, s };
  };
  const first = oneConnection('192.0.2.10', SERVER, false, 50000, 1);
  oneConnection('2001:db8::10', SERVER6, true, 50000, 2);

  // (2) One flow, two connections: a second client Initial with a new DCID.
  const second = id(3);
  add(quicFrame('192.0.2.10', 50000, SERVER, 443, quicPayload('initial', { dcid: second }), {}));
  add(quicFrame('192.0.2.10', 50000, SERVER, 443, quicPayload('short', { dcid: first.s }), {}));
  add(quicFrame('192.0.2.10', 50000, SERVER, 443, quicPayload('short', { dcid: second }), {}));

  // (3) Coalescing and odd long headers, each on its own flow.
  const h = '192.0.2.11';
  const c4 = id(4), s4 = id(104);
  add(quicFrame(h, 50001, SERVER, 443, quicPayload('initial', { dcid: c4, scid: s4 }), {}));
  add(quicFrame(h, 50001, SERVER, 443, coalesce(
    quicPayload('initial', { dcid: c4, scid: s4, payload: 20 }),
    quicPayload('handshake', { dcid: c4, scid: s4, payload: 20 }),
    quicPayload('short', { dcid: s4 }),
  ), {}));
  add(quicFrame(h, 50002, SERVER, 443, coalesce(
    quicPayload('initial', { dcid: id(5), scid: id(105), payload: 20 }),
    Uint8Array.from([0xc0, 0, 0, 0, 1, 21, ...filler(40, 9)]),   // dcidLen 21
  ), {}));
  add(quicFrame(h, 50003, SERVER, 443, coalesce(
    ...Array.from({ length: 9 }, (_, i) => quicPayload('handshake', { dcid: id(6), scid: id(106 + i), payload: 10 })),
  ), {}));
  add(quicFrame(h, 50004, SERVER, 443, quicPayload('retry', { dcid: id(7), scid: id(107), payload: 24 }), {}));
  add(quicFrame(h, 50005, SERVER, 443, quicPayload('initial', { dcid: id(8), scid: id(108), v2: true }), {}));

  // (4) Version Negotiation on a fresh flow, then a short header on it.
  add(quicFrame(SERVER, 443, '192.0.2.12', 50006, quicPayload('vn', { dcid: [], scid: [] }), {}));
  add(quicFrame('192.0.2.12', 50006, SERVER, 443, quicPayload('short', { dcid: id(9) }), {}));
  add(quicFrame('192.0.2.12', 50006, SERVER, 443, quicPayload('short', { dcid: id(9), payload: 70 }), {}));

  // (5) Malformed and unclaimed.
  add(quicFrame('192.0.2.13', 50007, SERVER, 443, quicPayload('short', { dcid: id(10) }), {}));   // unseen flow
  add(quicFrame('192.0.2.10', 50000, SERVER, 443, Uint8Array.from([0x30, ...id(11), ...filler(30, 3)]), {}));   // fixed bit clear
  add(quicFrame('192.0.2.14', 50008, SERVER, 443, Uint8Array.from([0xc0, 0, 0, 0, 1]), {}));   // 5-byte long header
  // Initial whose token length varint points past the end of the datagram.
  add(quicFrame('192.0.2.15', 50009, SERVER, 443,
    Uint8Array.from([0xc0, 0, 0, 0, 1, 8, ...id(12), 0, 0x3f]), {}));
  const udpOdd = quicPayload('initial', { dcid: id(13), scid: id(113) });
  add(quicFrame('192.0.2.16', 50010, SERVER, 443, udpOdd, { udpLength: 4 }));
  add(quicFrame('192.0.2.17', 50011, SERVER, 443, udpOdd, { udpLength: 8 + udpOdd.length + 1 }));

  // (6) 443 paired with ports whose protocols outrank or share QUIC.
  const lookalike = quicPayload('initial', { dcid: id(14), scid: id(114) });
  add(quicFrame('192.0.2.18', 443, SERVER, 53, lookalike, {}));
  add(quicFrame('192.0.2.18', 443, SERVER, 5353, lookalike, {}));
  const search = new Bytes().ascii('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n\r\n').build();
  add(quicFrame('192.0.2.18', 443, SERVER, 1900, search, {}));
  const inner = udpFrame(5000, 5001, Uint8Array.from([1, 2, 3, 4]));
  const vxlan = Uint8Array.from([...new Bytes().u8(0x08, 0, 0, 0).u8(0, 0, 42, 0).build(), ...inner]);
  add(quicFrame('192.0.2.18', 443, SERVER, 4789, vxlan, {}));

  // (7) A QinQ long header for flow Q, then plain short headers on Q.
  const cq = id(15), sq = id(115);
  add(quicFrame('192.0.2.19', 50012, SERVER, 443, quicPayload('initial', { dcid: cq, scid: sq }), { qinq: true }));
  add(quicFrame('192.0.2.19', 50012, SERVER, 443, quicPayload('short', { dcid: sq }), {}));
  add(quicFrame('192.0.2.19', 50012, SERVER, 443, quicPayload('short', { dcid: cq }), {}));

  // (8) Enough flows to evict the first, which then must be plain UDP; then a
  // new long header on it takes a fresh number.
  const flow = (i: number) => ({ src: `10.100.${Math.floor(i / 250)}.${(i % 250) + 1}`, port: 51000 });
  for (let i = 0; i < QUIC_EVICTION_FLOWS; i++) {
    const f = flow(i);
    add(quicFrame(f.src, f.port, SERVER, 443, quicPayload('initial', { dcid: id(1000 + i), scid: id(5000 + i), payload: 16 }), {}));
  }
  const f0 = flow(0);
  add(quicFrame(f0.src, f0.port, SERVER, 443, quicPayload('short', { dcid: id(5000) }), {}));
  add(quicFrame(f0.src, f0.port, SERVER, 443, quicPayload('initial', { dcid: id(9000), scid: id(9100), payload: 16 }), {}));
  add(quicFrame(f0.src, f0.port, SERVER, 443, quicPayload('short', { dcid: id(9100) }), {}));

  return pcapOf(frames);
}
