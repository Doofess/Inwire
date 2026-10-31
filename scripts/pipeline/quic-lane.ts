/**
 * The QUIC lane's router held to the dissector it predicts (ADR 0053 phase 5).
 *
 *   npx tsx scripts/pipeline/quic-lane.ts
 *
 * The coordinator will number a QUIC datagram ahead of its dissection, so what
 * it reads off the headers - which branch of `dissectUdpTransport` takes the
 * datagram, what `dissectQuicDatagram` will ask the QUIC order and when - must
 * be exactly what the dissection does. Three sections:
 *
 *   1. **The walk against the dissector.** `walkQuicDatagram` and
 *      `dissectQuicDatagram` read every crafted datagram, every truncation and
 *      first byte of the shapes below, and 20,000 seeded random ones, and must
 *      agree on: claimed or not, long header, the connection ids, a zero-length
 *      DCID, the packet count, and where (if anywhere) the resolver is asked.
 *   2. **The branch against the dissection.** `frameLane` reads a frame onto the
 *      QUIC lane exactly where `dissectUdpTransport` reaches its QUIC branch,
 *      across 443 paired with every port that outranks or shares it, over IPv4,
 *      IPv6 and one VLAN tag.
 *   3. **The route's gate** (`readQuicRoute`): a short header on an unknown flow,
 *      a clear fixed bit, a UDP length below 8, QinQ and fragments.
 *
 * `scripts/pipeline/sequencer.ts` holds the same router to the dissection of
 * every frame of the fixtures. A synthetic datagram does not need them.
 */
import { dissectQuicDatagram, walkQuicDatagram } from '../../src/services/dissectors/quic';
import { udpBranch } from '../../src/services/dissectors/udpBranch';
import { frameLane } from '../../src/services/dissect/frameLane';
import { readQuicRoute } from '../../src/services/dissect/quicRoute';
import { QuicOrder } from '../../src/services/dissect/sequencer';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { Bytes } from '../parity/synthetic';
import { coalesce, quicFrame, quicPayload } from './quicCapture';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`);
}

/** The same generator `virtualShards.ts` seeds its runs with. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

const ids = (n: number, seed = 1): number[] => Array.from({ length: n }, (_, i) => (seed * 37 + i * 11 + 3) & 0xff);
const hexOf = (b: ArrayLike<number>): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// --- (1) the walk against the dissector --------------------------------------

/** Where the dissector's resolver was asked, and what it read. */
function dissected(bytes: Uint8Array, start: number, end: number) {
  const asked: number[] = [];
  const result = dissectQuicDatagram(bytes, start, end, (_b, at) => { asked.push(at); return undefined; });
  return { result, asked };
}

/** Why the walk and the dissector disagree about this datagram, or null when they do not. */
function walkDisagreement(bytes: Uint8Array, start: number, end: number): string | null {
  const { result, asked } = dissected(bytes, start, end);
  const walk = walkQuicDatagram(bytes, start, end);
  const same = walk.claimed === (result !== null)
    && (result === null || (walk.long === result.isLongHeader
      && JSON.stringify(walk.connectionIds) === JSON.stringify(result.connectionIds)
      && walk.emptyDcid === result.packets.some((x) => x.headerForm === 'long' && (x.dcidLength ?? 0) === 0)
      && walk.packets === result.packets.length))
    && asked.length <= 1 && walk.resolveAt === (asked[0] ?? -1);
  if (same) return null;
  return `[${start},${end}) of ${hexOf(bytes.subarray(0, Math.min(bytes.length, 48)))}: walk ${JSON.stringify(walk)}, `
    + `dissector ${result === null ? 'null' : JSON.stringify({
      long: result.isLongHeader, ids: result.connectionIds, packets: result.packets.length,
    })} asked ${JSON.stringify(asked)}`;
}

const KINDS = ['initial', 'handshake', 'zeroRtt', 'retry', 'vn', 'short'] as const;

/** A QUIC varint with the given two-bit length prefix, value truncated to what the prefix holds. */
function varintOf(prefix: number, value: number): number[] {
  const size = 1 << prefix;
  const out = new Array<number>(size).fill(0);
  let v = value;
  for (let i = size - 1; i >= 0; i--) { out[i] = v & 0xff; v = Math.floor(v / 256); }
  out[0] = (out[0] & 0x3f) | (prefix << 6);
  return out;
}

function crafted(): Uint8Array[] {
  const out: Uint8Array[] = [];
  // Every kind, both versions, empty and full connection ids.
  const lens = [0, 1, 8, 20];
  const base: Uint8Array[] = [];
  for (const kind of KINDS) {
    for (const dl of lens) {
      for (const sl of lens) {
        for (const v2 of [false, true]) {
          base.push(quicPayload(kind, { dcid: ids(dl, 2), scid: ids(sl, 5), v2, payload: 12, token: kind === 'initial' ? ids(3, 9) : undefined }));
        }
      }
    }
  }
  out.push(...base);

  // Every pair coalesced, and the handshake trio.
  const sample = KINDS.map((kind) => quicPayload(kind, { dcid: ids(8, 2), scid: ids(8, 5), payload: 10 }));
  for (const a of sample) for (const b of sample) out.push(coalesce(a, b));
  for (const a of sample) for (const b of sample) for (const c of sample) out.push(coalesce(a, b, c));
  const initial = quicPayload('initial', { dcid: ids(8, 2), scid: ids(8, 5), payload: 20 });
  const handshake = quicPayload('handshake', { dcid: ids(8, 2), scid: ids(8, 5), payload: 20 });
  const short = quicPayload('short', { dcid: ids(8, 5) });
  const trio = coalesce(initial, handshake, short);
  out.push(trio, coalesce(handshake, short), coalesce(short, initial), coalesce(initial, Uint8Array.from([0x30, 1, 2, 3])));

  // Nine coalesced, in the shapes that reach and pass the cap of eight.
  const nine = (kind: typeof KINDS[number]) => Array.from({ length: 9 }, (_, i) => quicPayload(kind, { dcid: ids(6, 2), scid: ids(6, 40 + i), payload: 10 }));
  out.push(coalesce(...nine('handshake')), coalesce(...nine('initial')), coalesce(...nine('zeroRtt')));
  out.push(coalesce(...nine('handshake').slice(0, 8), short), coalesce(...nine('handshake').slice(0, 7), short), coalesce(...nine('retry')));

  // Every length of each connection id, 0 to 25, past the cap of 20.
  for (const kind of ['initial', 'handshake', 'zeroRtt', 'retry'] as const) {
    for (let dl = 0; dl <= 25; dl++) {
      for (let sl = 0; sl <= 25; sl++) {
        out.push(quicPayload(kind, { dcid: ids(dl, 2), scid: ids(sl, 5), payload: 6 }));
        if (kind === 'initial') out.push(quicPayload(kind, { dcid: ids(dl, 2), scid: ids(sl, 5), payload: 6, v2: true }));
      }
    }
  }

  // Every first byte over a header of each form.
  for (const template of [initial, handshake, short, quicPayload('vn', { dcid: ids(8, 2), scid: ids(4, 3) }), trio]) {
    for (let first = 0; first < 256; first++) {
      const copy = template.slice();
      copy[0] = first;
      out.push(copy);
    }
  }

  // An Initial's token and Length varints, every prefix, with the value short of, at and past the end.
  for (const dl of [0, 8]) {
    const head = [0xc0, 0, 0, 0, 1, dl, ...ids(dl, 2), 4, ...ids(4, 5)];
    for (let tp = 0; tp < 4; tp++) {
      for (const token of [0, 1, 3, 40, 63]) {
        for (let lp = 0; lp < 4; lp++) {
          for (const filler of [0, 1, 7, 30]) {
            const tokenBytes = [...varintOf(tp, token), ...ids(Math.min(token, 12), 7)];
            for (const length of [0, 1, filler, filler + 1, filler + 100]) {
              out.push(Uint8Array.from([...head, ...tokenBytes, ...varintOf(lp, length), ...ids(filler, 11)]));
            }
          }
        }
      }
    }
    // A token that points past the end, and an 8-byte token length of the largest value.
    out.push(Uint8Array.from([...head, 0x3f]), Uint8Array.from([...head, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]));
    out.push(Uint8Array.from([...head, 0x40]), Uint8Array.from([...head, 0x80, 0, 0]), Uint8Array.from([...head, 0xc0, 0, 0, 0, 0, 0, 0]));
  }
  // The same for the other long types, which have a Length and no token.
  for (const first of [0xe0, 0xd0, 0xf0]) {
    const head = [first, 0, 0, 0, 1, 4, ...ids(4, 2), 4, ...ids(4, 5)];
    for (let lp = 0; lp < 4; lp++) {
      for (const filler of [0, 1, 7]) {
        for (const length of [0, filler, filler + 1, 4000]) out.push(Uint8Array.from([...head, ...varintOf(lp, length), ...ids(filler, 3)]));
      }
    }
  }

  // Every truncation of the shapes that carry the most.
  for (const whole of [trio, coalesce(...nine('handshake').slice(0, 3), short), sample[0], sample[4], quicPayload('initial', { dcid: ids(20, 2), scid: ids(20, 5), token: ids(30, 9), payload: 40 })]) {
    for (let n = 0; n <= whole.length; n++) out.push(whole.slice(0, n));
  }
  return out;
}

/** Datagrams of every shape a header can be wrong in, from a seed. */
function randomDatagram(r: () => number): Uint8Array {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  const byte = () => Math.floor(r() * 256);
  const length = (max: number) => Math.floor(r() * max);
  const mode = Math.floor(r() * 5);
  if (mode === 0) return Uint8Array.from({ length: length(60) }, byte);
  const packet = (): Uint8Array => {
    const first = pick([0xc0, 0xd0, 0xe0, 0xf0, 0x80, 0xcf, 0x40, 0x41, 0x7f, byte()]) | (r() < 0.9 ? 0 : byte());
    const version = pick([0, 1, 1, 1, 0x6b3343cf, 0xff00001d, Math.floor(r() * 0x100000000)]);
    const dl = r() < 0.8 ? length(21) : length(40);
    const sl = r() < 0.8 ? length(21) : length(40);
    const b = new Bytes().u8(first).u32(version).u8(dl);
    for (let i = 0; i < dl; i++) b.u8(byte());
    b.u8(sl);
    for (let i = 0; i < sl; i++) b.u8(byte());
    if (r() < 0.9) b.u8(...varintOf(Math.floor(r() * 4), length(70)));
    if (r() < 0.9) b.u8(...varintOf(Math.floor(r() * 4), length(70)));
    const tail = length(40);
    for (let i = 0; i < tail; i++) b.u8(byte());
    return b.build();
  };
  if (mode === 1) return packet();
  if (mode === 2) return coalesce(...Array.from({ length: 1 + length(10) }, packet));
  // A well-formed datagram, cut and mutated.
  const kinds = Array.from({ length: 1 + length(4) }, () => quicPayload(pick(KINDS), {
    dcid: ids(length(21), byte()), scid: ids(length(21), byte()), payload: length(30), v2: r() < 0.3, token: ids(length(10), 3),
  }));
  const out = coalesce(...kinds);
  const cut = r() < 0.5 ? out.slice(0, length(out.length + 1)) : out;
  if (cut.length > 0 && r() < 0.6) cut[length(cut.length)] = byte();
  return cut;
}

function walkVersusDissector(): void {
  const all = crafted();
  const r = rng(53_005);
  for (let i = 0; i < 20_000; i++) all.push(randomDatagram(r));

  let wrong: string | null = null;
  let claimed = 0;
  for (const p of all) {
    // Bare, and in the middle of a larger buffer with junk either side, which is
    // how a datagram sits in a frame: the walk and the dissector get an offset and an end.
    wrong ??= walkDisagreement(p, 0, p.length);
    const padded = Uint8Array.from([0xa5, 0x5a, 0xc3, ...p, 0x99, 0x11, 0x22, 0x33, 0x44]);
    wrong ??= walkDisagreement(padded, 3, 3 + p.length);
    if (walkQuicDatagram(p, 0, p.length).claimed) claimed++;
  }
  check(`walk: ${all.length.toLocaleString()} crafted and mutated datagrams read exactly as dissectQuicDatagram reads them`,
    wrong === null && claimed > 1000, wrong ?? `only ${claimed} claimed: the corpus is not reaching the walk`);

  const vn = quicPayload('vn', { dcid: ids(8, 2), scid: ids(4, 3) });
  const walkVn = walkQuicDatagram(vn, 0, vn.length);
  check('walk: Version Negotiation is a long header with no ids and emptyDcid',
    walkVn.claimed && walkVn.long && walkVn.connectionIds.length === 0 && walkVn.emptyDcid && walkVn.packets === 1 && walkVn.resolveAt === -1
      && walkDisagreement(vn, 0, vn.length) === null, JSON.stringify(walkVn));

  const initial = quicPayload('initial', { dcid: ids(8, 2), scid: ids(8, 5), payload: 20 });
  const handshake = quicPayload('handshake', { dcid: ids(8, 2), scid: ids(8, 5), payload: 20 });
  const trio = coalesce(initial, handshake, quicPayload('short', { dcid: ids(8, 5) }));
  const walkTrio = walkQuicDatagram(trio, 0, trio.length);
  const askedTrio = dissected(trio, 0, trio.length).asked;
  check('walk: Initial+Handshake+short asks the resolver once, at the short header',
    walkTrio.packets === 3 && walkTrio.long && walkTrio.resolveAt === initial.length + handshake.length + 1
      && askedTrio.length === 1 && askedTrio[0] === walkTrio.resolveAt, JSON.stringify({ walkTrio, askedTrio }));

  const nine = coalesce(...Array.from({ length: 9 }, (_, i) => quicPayload('handshake', { dcid: ids(6, 2), scid: ids(6, 40 + i), payload: 10 })));
  const walkNine = walkQuicDatagram(nine, 0, nine.length);
  check('walk: a ninth coalesced packet is not read',
    walkNine.packets === 8 && walkNine.connectionIds.length === 16 && walkDisagreement(nine, 0, nine.length) === null, JSON.stringify(walkNine));
}

// --- (2) the branch against the dissection -----------------------------------

/** Reports whether `isKnownFlow` - the QUIC branch's first question - was asked while a frame was dissected. */
function reachesQuicBranch(frame: Uint8Array, quic: QuicFlowTracker, tcp: TcpStreamTracker, icmp: IcmpEchoTracker, dns: DnsTracker, l3: L3Tracker): boolean {
  let asked = false;
  const spy = new Proxy(quic, {
    get(t, prop, receiver) {
      const value = Reflect.get(t, prop, receiver);
      if (prop !== 'isKnownFlow' || typeof value !== 'function') return typeof value === 'function' ? value.bind(t) : value;
      return (...args: unknown[]) => { asked = true; return (value as (...a: unknown[]) => unknown).apply(t, args); };
    },
  });
  decodeRawEthernetPacket(frame.slice(), 1, 1_700_000_000_000_000, 0, 0, frame.length, tcp, icmp, spy, dns, undefined, 1, l3, undefined);
  return asked;
}

/** The frame with one 802.1Q tag after its MACs. */
function withVlan(frame: Uint8Array): Uint8Array {
  return Uint8Array.from([...frame.subarray(0, 12), 0x81, 0x00, 0x00, 0x64, ...frame.subarray(12)]);
}

function branchVersusDissection(): void {
  const tcp = new TcpStreamTracker();
  const icmp = new IcmpEchoTracker();
  const dns = new DnsTracker();
  const l3 = new L3Tracker();
  const quic = new QuicFlowTracker();

  const initial = quicPayload('initial', { dcid: ids(8, 2), scid: ids(8, 5), payload: 20 });
  const short = quicPayload('short', { dcid: ids(8, 5) });
  const ldap = Uint8Array.from([0x30, 0x08, 0x02, 0x01, 0x01, 0x63, 0x03, 0x04, 0x01, 0x00, 0, 0, 0, 0, 0, 0]);
  const innerFrame = quicFrame('192.0.2.1', 5000, '192.0.2.2', 5001, Uint8Array.from([1, 2, 3, 4]), {});
  const vxlan = Uint8Array.from([0x08, 0, 0, 0, 0, 0, 42, 0, ...innerFrame]);
  const ssdp = new Bytes().ascii('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n').build();
  const payloads = [initial, short, ldap, vxlan, ssdp, Uint8Array.from([1, 2, 3])];

  const ports = [...Array.from({ length: 1101 }, (_, p) => p), 1985, 2029, 2055, 3478, 3702, 4739, 4784, 4789, 5004, 5060, 5353, 5355, 6343, 9996,
    17500, 37008, 50000, 51820, 65535];
  let frames = 0;
  let onLane = 0;
  let wrong: string | null = null;
  const consider = (frame: Uint8Array, label: string, dstIp: string) => {
    frames++;
    const lane = frameLane(frame, 1);
    const reached = reachesQuicBranch(frame, quic, tcp, icmp, dns, l3);
    if (lane.lane === 'quic') onLane++;
    if ((lane.lane === 'quic') !== reached) wrong ??= `${label}: lane ${lane.lane}, QUIC branch ${reached ? 'reached' : 'not reached'}`;
    if (lane.lane === 'quic') {
      const branch = udpBranch(frame, lane.payloadStart, lane.payloadEnd, lane.srcPort, lane.dstPort, dstIp);
      if (branch !== 'quic') wrong ??= `${label}: lane quic, branch ${branch}`;
    }
  };
  for (const port of ports) {
    for (const [i, payload] of payloads.entries()) {
      if (i > 1 && port !== 389 && port !== 4789 && port !== 1900 && i !== 5) continue;
      for (const [sp, dp] of [[443, port], [port, 443]] as const) {
        const v4 = quicFrame('192.0.2.7', sp, '198.51.100.1', dp, payload, {});
        consider(v4, `v4 ${sp}>${dp} #${i}`, '198.51.100.1');
        if (i <= 1 || port === 4789 || port === 53) {
          consider(quicFrame('2001:db8::7', sp, '2001:db8::1', dp, payload, { ipv6: true }), `v6 ${sp}>${dp} #${i}`, '2001:db8::1');
          consider(withVlan(v4), `vlan ${sp}>${dp} #${i}`, '198.51.100.1');
        }
      }
    }
  }
  // HSRP reads the destination address, not only the port.
  for (const dst of ['224.0.0.2', '224.0.0.102', '198.51.100.1']) {
    consider(quicFrame('192.0.2.7', 443, dst, 1985, initial, {}), `hsrp to ${dst}`, dst);
    consider(quicFrame('192.0.2.7', 1985, dst, 443, initial, {}), `hsrp from ${dst}`, dst);
  }
  check(`branch: frameLane reads the QUIC lane exactly where udpTransport reaches the QUIC branch (${frames.toLocaleString()} frames, ${onLane.toLocaleString()} on it)`,
    wrong === null && onLane > 100 && onLane < frames, wrong ?? `${onLane} of ${frames}`);
}

// --- (3) the route's gate ----------------------------------------------------

function routeGate(): void {
  const sid = ids(8, 5);
  const cid = ids(8, 2);
  const frame = (payload: Uint8Array, o: { qinq?: boolean; ipv6?: boolean; udpLength?: number } = {}) =>
    quicFrame('192.0.2.7', 50000, '198.51.100.1', 443, payload, o);
  const laneOf = (f: Uint8Array) => {
    const lane = frameLane(f, 1);
    if (lane.lane !== 'quic') throw new Error(`expected the QUIC lane, got ${lane.lane}`);
    return lane;
  };

  const unknown = new QuicOrder();
  const shortFrame = frame(quicPayload('short', { dcid: sid }));
  check('route: a short header on an unknown flow stays on lane 0',
    readQuicRoute(shortFrame, laneOf(shortFrame), unknown) === null);

  const known = new QuicOrder();
  const lane = laneOf(shortFrame);
  known.noteLongHeader(lane.flow, [hexOf(sid)], false);
  const routed = readQuicRoute(shortFrame, lane, known);
  check('route: on a known flow it is claimed, matched at payload + 1',
    routed !== null && routed.known && routed.walk.claimed && !routed.walk.long && routed.walk.resolveAt === lane.payloadStart + 1
      && routed.matched === hexOf(sid), JSON.stringify(routed));
  const unmatched = frame(quicPayload('short', { dcid: ids(8, 77) }));
  const routedUnmatched = readQuicRoute(unmatched, laneOf(unmatched), known);
  check('route: a short header whose id the flow never showed is claimed, matched to nothing',
    routedUnmatched !== null && routedUnmatched.known && routedUnmatched.matched === undefined);

  const longFrame = frame(quicPayload('initial', { dcid: cid, scid: sid }));
  const routedLong = readQuicRoute(longFrame, laneOf(longFrame), unknown);
  check('route: a long header on an unknown flow is claimed, not known, with its ids',
    routedLong !== null && !routedLong.known && routedLong.walk.long
      && JSON.stringify(routedLong.walk.connectionIds) === JSON.stringify([hexOf(cid), hexOf(sid)]) && routedLong.matched === undefined);

  const clearBit = frame(Uint8Array.from([0x30, ...sid, ...ids(30, 3)]));
  const longClear = frame(Uint8Array.from([0x80, 0, 0, 0, 1, 4, ...ids(4, 2), 4, ...ids(4, 5), 0, 4, 1, 2, 3, 4]));
  check('route: a first byte with the fixed bit clear stays on lane 0',
    readQuicRoute(clearBit, laneOf(clearBit), known) === null && readQuicRoute(clearBit, laneOf(clearBit), unknown) === null
      && readQuicRoute(longClear, laneOf(longClear), known) === null);

  const tiny = frame(quicPayload('initial', { dcid: cid, scid: sid }), { udpLength: 4 });
  const tinyLane = laneOf(tiny);
  const exact = frame(quicPayload('initial', { dcid: cid, scid: sid }), { udpLength: 8 });
  check('route: a UDP length below 8 stays on lane 0',
    tinyLane.payloadEnd === tinyLane.payloadStart && readQuicRoute(tiny, tinyLane, known) === null
      && readQuicRoute(exact, laneOf(exact), known) === null);

  const qinq = frame(quicPayload('initial', { dcid: cid, scid: sid }), { qinq: true });
  const fragment = frame(quicPayload('initial', { dcid: cid, scid: sid }));
  fragment[14 + 6] |= 0x20;    // More Fragments
  const later = frame(quicPayload('initial', { dcid: cid, scid: sid }));
  later[14 + 7] = 0x10;        // a non-zero fragment offset
  const shortHeaderLength = frame(quicPayload('initial', { dcid: cid, scid: sid }));
  shortHeaderLength[14] = 0x44;    // IHL 4: a header shorter than the minimum
  const extension = frame(quicPayload('initial', { dcid: cid, scid: sid }), { ipv6: true });
  extension[14 + 6] = 0;           // a hop-by-hop header first
  const zeroPayload = frame(quicPayload('initial', { dcid: cid, scid: sid }), { ipv6: true });
  zeroPayload[14 + 4] = 0; zeroPayload[14 + 5] = 0;
  const stacked = withVlan(withVlan(frame(quicPayload('initial', { dcid: cid, scid: sid }))));
  const cut = frame(quicPayload('initial', { dcid: cid, scid: sid })).subarray(0, 14 + 20 + 7);
  check('route: QinQ and an IP fragment are never the QUIC lane',
    [qinq, fragment, later, shortHeaderLength, extension, zeroPayload, stacked, cut].every((f) => frameLane(f, 1).lane !== 'quic'),
    JSON.stringify([qinq, fragment, later, shortHeaderLength, extension, zeroPayload, stacked, cut].map((f) => frameLane(f, 1).lane)));
  const vlan = withVlan(frame(quicPayload('initial', { dcid: cid, scid: sid })));
  check('route: one VLAN tag is the QUIC lane, with the flow both directions share',
    frameLane(vlan, 1).lane === 'quic' && laneOf(vlan).flow === lane.flow
      && laneOf(quicFrame('198.51.100.1', 443, '192.0.2.7', 50000, quicPayload('short', { dcid: sid }), {})).flow === lane.flow);
}

walkVersusDissector();
branchVersusDissection();
routeGate();

console.log(failures === 0 ? '\nAll QUIC lane checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
