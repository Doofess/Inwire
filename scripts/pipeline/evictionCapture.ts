/**
 * A capture with more TCP connections than the tracker keeps, built so the
 * eviction path decides real stream numbers.
 *
 * 20,000 connections, one segment each, so the first 3,616 are forgotten;
 * then a recent one is touched (which must move it to the back of the
 * eviction order), then the oldest dozen come back - each a new connection
 * with a new `tcp.stream`, and each evicting another. Spread over 64 address
 * pairs and a UDP flow between them, so `ip.stream` and `udp.stream` are
 * numbered across it too.
 *
 * Not an assertion script; `scripts/pipeline/sequencer.ts` uses it.
 */
import { ethernet, ipv4, tcp, udp, pcapOf } from '../parity/synthetic';

export const EVICTION_CONNECTIONS = 20_000;

function segment(c: number, round: number): Uint8Array {
  const src = `10.1.${(c >> 6) & 0xff}.${(c & 63) + 1}`;
  const dst = `10.2.0.${(c % 64) + 1}`;
  const srcPort = 1024 + (c % 50_000);
  const dstPort = 443 + (c % 3);
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...ipv4(6, tcp(srcPort, dstPort, 1000 + round * 10, 5000, Uint8Array.from([c & 0xff, round])), src, dst),
  ]);
}

function datagram(c: number): Uint8Array {
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...ipv4(17, udp(5000 + (c % 7), 53, Uint8Array.from([1, 2, 3])), `10.1.0.${(c % 64) + 1}`, '10.2.0.1'),
  ]);
}

/** The capture, as pcap bytes. */
export function evictionCapture(): Uint8Array {
  const frames: Uint8Array[] = [];
  for (let c = 0; c < EVICTION_CONNECTIONS; c++) {
    frames.push(segment(c, 0));
    if (c % 997 === 0) frames.push(datagram(c));
  }
  // The newest-but-one touched again: it moves to the back of the order.
  frames.push(segment(EVICTION_CONNECTIONS - 2, 1));
  // The oldest come back, long forgotten: new connections, new numbers.
  for (let c = 0; c < 12; c++) frames.push(segment(c, 2));
  // And one that was still remembered when they returned, now evicted by them.
  frames.push(segment(3616, 3));
  return pcapOf(frames);
}
