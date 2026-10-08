/**
 * A capture of TCP carried in IP fragments - the one TCP frame ADR 0053's
 * coordinator cannot number from its headers, because which connection a
 * fragment belongs to is known only when its datagram reassembles.
 *
 * None of the real fixtures holds one, so this builds them, byte for byte:
 *
 *   - a connection whose TLS segment is split into three IPv4 fragments, in
 *     order, beside a sibling connection on the same pair that is not;
 *   - a connection on another pair whose FIRST frame is a fragmented segment,
 *     its fragments out of order - so the connection is created, and numbered,
 *     by a fragment that is not the first;
 *   - the same over IPv6, with a fragment header;
 *   - a datagram whose first fragment was never captured, which never
 *     reassembles;
 *   - UDP between them, so the conversation indexes are numbered across it.
 *
 * Not an assertion script; `scripts/pipeline/parallel.ts` and
 * `scripts/pipeline/sequencer.ts` use it.
 */
import { Bytes, ethernet, internetChecksum, pcapOf, udp, ipv4 } from '../parity/synthetic';

const SYN = 0x02;
const ACK = 0x10;
const PSH_ACK = 0x18;

function tcpSegment(srcPort: number, dstPort: number, seq: number, ack: number, flags: number, payload: Uint8Array): Uint8Array {
  const header = new Bytes().u16(srcPort, dstPort).u32(seq).u32(ack).u8(0x50, flags).u16(64240, 0, 0).build();
  return Uint8Array.from([...header, ...payload]);
}

function ipv4Header(src: string, dst: string, length: number, id: number, flagsOffset: number, protocol = 6): Uint8Array {
  const bytes = new Bytes().u8(0x45, 0).u16(20 + length).u16(id).u16(flagsOffset).u8(64, protocol).u16(0)
    .ipv4(src).ipv4(dst).build();
  const sum = internetChecksum(bytes);
  bytes[10] = (sum >> 8) & 0xff;
  bytes[11] = sum & 0xff;
  return bytes;
}

function whole(src: string, dst: string, segment: Uint8Array): Uint8Array {
  return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, segment, src, dst)]);
}

/** A segment as IPv4 fragments of `piece` bytes (a multiple of 8), in order. */
function fragments(src: string, dst: string, id: number, segment: Uint8Array, piece: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let at = 0; at < segment.length; at += piece) {
    const part = segment.subarray(at, Math.min(segment.length, at + piece));
    const more = at + piece < segment.length ? 0x2000 : 0;
    out.push(Uint8Array.from([
      ...ethernet(0x0800).build(), ...ipv4Header(src, dst, part.length, id, more | (at / 8)), ...part,
    ]));
  }
  return out;
}

function address6(text: string): number[] {
  return text.split(':').flatMap((group) => {
    const value = parseInt(group, 16);
    return [(value >> 8) & 0xff, value & 0xff];
  });
}

/** The same over IPv6: a fixed header and a fragment header per piece. */
function fragments6(src: string, dst: string, id: number, segment: Uint8Array, piece: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let at = 0; at < segment.length; at += piece) {
    const part = segment.subarray(at, Math.min(segment.length, at + piece));
    const more = at + piece < segment.length ? 1 : 0;
    const header = new Bytes().u32(0x60000000).u16(8 + part.length).u8(44, 64)
      .raw(address6(src)).raw(address6(dst))
      .u8(6, 0).u16((at / 8) << 3 | more).u32(id)
      .build();
    out.push(Uint8Array.from([...ethernet(0x86dd).build(), ...header, ...part]));
  }
  return out;
}

/** A TLS application-data record of `n` bytes. */
function tlsRecord(n: number): Uint8Array {
  return Uint8Array.from([0x17, 0x03, 0x03, (n >> 8) & 0xff, n & 0xff, ...Array.from({ length: n }, (_, i) => (i * 7) & 0xff)]);
}

function datagram(c: number): Uint8Array {
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...ipv4(17, udp(5353 + c, 53, Uint8Array.from([c, 1, 2])), '10.9.0.1', '10.9.0.53'),
  ]);
}

/** The capture, as pcap bytes. */
export function fragmentCapture(): Uint8Array {
  const A = '10.9.0.1';
  const B = '10.9.0.2';
  const C = '10.9.1.1';
  const frames: Uint8Array[] = [];
  // Connection 1, A:40000 -> B:443, and its sibling A:40001 on the same pair.
  frames.push(whole(A, B, tcpSegment(40000, 443, 1000, 0, SYN, new Uint8Array())));
  frames.push(whole(B, A, tcpSegment(443, 40000, 9000, 1001, SYN | ACK, new Uint8Array())));
  frames.push(whole(A, B, tcpSegment(40000, 443, 1001, 9001, ACK, new Uint8Array())));
  frames.push(whole(A, B, tcpSegment(40001, 443, 5000, 0, SYN, new Uint8Array())));
  frames.push(datagram(1));
  const record = tlsRecord(1200);
  // In order, with the sibling and a datagram between the pieces.
  const pieces = fragments(A, B, 0x1234, tcpSegment(40000, 443, 1001, 9001, PSH_ACK, record), 512);
  frames.push(pieces[0]);
  frames.push(whole(B, A, tcpSegment(443, 40001, 7000, 5001, SYN | ACK, new Uint8Array())));
  frames.push(pieces[1]);
  frames.push(datagram(2));
  frames.push(pieces[2]);
  frames.push(whole(B, A, tcpSegment(443, 40000, 9001, 1001 + record.length, ACK, new Uint8Array())));
  frames.push(whole(A, B, tcpSegment(40000, 443, 1001 + record.length, 9001, PSH_ACK, tlsRecord(40))));
  // Connection 3: first seen as a fragmented segment, out of order.
  const late = fragments(C, B, 0x0101, tcpSegment(50000, 80, 300, 400, PSH_ACK, new Uint8Array(900).fill(0x41)), 400);
  frames.push(late[2], late[0], datagram(3), late[1]);
  frames.push(whole(B, C, tcpSegment(80, 50000, 400, 1200, ACK, new Uint8Array())));
  // IPv6: a connection whose first frame is a fragmented TLS segment.
  const six = fragments6('2001:0db8:0000:0000:0000:0000:0000:0001', '2001:0db8:0000:0000:0000:0000:0000:0002', 0xabcdef,
    tcpSegment(40002, 443, 70, 80, PSH_ACK, tlsRecord(600)), 304);
  frames.push(...six);
  // A datagram whose first fragment never arrived: never reassembles.
  const orphan = fragments(A, B, 0x7777, tcpSegment(40001, 443, 5001, 7001, PSH_ACK, new Uint8Array(700).fill(0x42)), 320);
  frames.push(orphan[1], orphan[2]);
  frames.push(whole(A, B, tcpSegment(40001, 443, 5001, 7001, PSH_ACK, tlsRecord(20))));
  frames.push(datagram(4));
  return pcapOf(frames);
}
