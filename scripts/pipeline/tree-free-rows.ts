/**
 * A frame dissected without its tree is the same frame (ADR 0072).
 *
 *   npx tsx scripts/pipeline/tree-free-rows.ts
 *   INWIRE_BURST_PCAP=<capture> npx tsx scripts/pipeline/tree-free-rows.ts
 *
 * Every frame of every source is dissected twice, in order, by two fresh
 * `FrameDissector`s: one that builds the tree and one built with
 * `{ tree: false }`. The tree-on one is the reference. For each frame the two
 * must agree on whether it threw, on the frame's record bytes, on the expert
 * list, and on the packed row (the bytes `encodeChunk` writes, after
 * `layers = []` as a shard does). And every layer named in `TREE_FREE_NOW`
 * must hold only findings - an `expertInfo` and no children - apart from the
 * names `ALLOWED_PLAIN` lets through.
 *
 * Sources: the real fixtures `revisit.ts` uses (skipped when absent), a large
 * capture named by `INWIRE_BURST_PCAP` (its first 100,000 frames), and a
 * synthetic capture carrying the findings the hot-path layers can raise.
 * The synthetic set checks itself: it must really produce each finding in
 * tree-on mode, or it has gone blind.
 */
import { existsSync, openAsBlob } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { FrameClock } from '../../src/services/dissect/sequencer';
import { SIZE_LIMITED } from '../../src/services/dissect/captureShort';
import { FrameDissector, type DissectInput } from '../../src/services/pipeline/frameDissector';
import { packRows } from '../../src/services/pipeline/rowPack';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import type { HostIdentity } from '../../src/services/direction';
import type { Packet } from '../../src/types/packet';
import { Bytes, check, ethernet, finish, ipv4, udp, udpFrame } from '../parity/synthetic';
import { FIXED_ENV } from './virtualShards';
import { FIXTURES } from './arrival';

/** The layers a live shard's cost is mostly in; Tasks 2 and 3 make them tree-free. */
export const HOT_PATH_LAYERS: ReadonlySet<string> = new Set([
  'Frame', 'Ethernet II', 'Internet Protocol Version 4', 'Internet Protocol Version 6',
  'Transmission Control Protocol', 'User Datagram Protocol',
]);

/** The layers that are tree-free so far: each holds findings only. */
export const TREE_FREE_NOW: ReadonlySet<string> = new Set<string>([
  'Transmission Control Protocol', 'User Datagram Protocol',
]);

/** Field names a tree-free layer may hold without an `expertInfo`, by layer. */
export const ALLOWED_PLAIN: Record<string, ReadonlySet<string>> = {
  // `decodeRawEthernetPacket` hangs the size-limited marker on the deepest layer, which a cut frame makes one of these.
  'Transmission Control Protocol': new Set([SIZE_LIMITED]),
  'User Datagram Protocol': new Set([SIZE_LIMITED]),
};

const BURST_FRAMES = 100_000;
const MAX_FAILURES_SHOWN = 30;

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}

function lane(tree: boolean, host?: HostIdentity): FrameDissector {
  const d = new FrameDissector({
    tcp: new TcpStreamTracker(), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(),
  }, FIXED_ENV, null, { tree });
  if (host !== undefined) d.host = host;
  return d;
}

interface Outcome { error: boolean; record: string; expert: string; row: string; packet?: Packet }

function dissectOne(d: FrameDissector, input: DissectInput, keepTree: boolean): Outcome {
  try {
    const out = d.dissect(input);
    const packet = out.packet;
    const found = packet.layers;
    const expert = JSON.stringify(packet.expert ?? null);
    packet.layers = [];
    const pack = packRows(0, [packet], [packet.rawBytes.length]);
    return {
      error: false, record: hex(out.record), expert, row: hex(pack.prefix) + '|' + hex(pack.summary),
      packet: keepTree ? { ...packet, layers: found } : undefined,
    };
  } catch {
    return { error: true, record: '', expert: '', row: '' };
  }
}

interface Totals { frames: number; checks: number; failures: number }

function runSource(
  name: string, inputs: Iterable<DissectInput>, onReference?: (o: Outcome, id: number) => void, host?: HostIdentity,
): Totals {
  const on = lane(true, host);
  const off = lane(false, host);
  const totals: Totals = { frames: 0, checks: 0, failures: 0 };
  const same = (label: string, actual: unknown, expected: unknown) => {
    totals.checks++;
    if (JSON.stringify(actual) === JSON.stringify(expected)) return;
    totals.failures++;
    if (totals.failures <= MAX_FAILURES_SHOWN) check(label, actual, expected);
    else if (totals.failures === MAX_FAILURES_SHOWN + 1) console.log('        (further failures in this source not shown)');
  };
  for (const input of inputs) {
    // Each dissector gets its own copy: neither can see the other's bytes move.
    const a = dissectOne(on, { ...input, bytes: input.bytes.slice() }, true);
    const b = dissectOne(off, { ...input, bytes: input.bytes.slice() }, true);
    totals.frames++;
    const at = `${name} #${input.id}`;
    same(`${at}: same error-ness`, b.error, a.error);
    if (a.error || b.error) continue;
    onReference?.(a, input.id);
    same(`${at}: same record`, b.record, a.record);
    same(`${at}: same expert`, b.expert, a.expert);
    for (const layer of b.packet!.layers) {
      if (!TREE_FREE_NOW.has(layer.name)) continue;
      const allowed = ALLOWED_PLAIN[layer.name];
      const bad = layer.fields.filter((f) =>
        !((f.expertInfo !== undefined && f.children === undefined) || allowed?.has(f.name) === true));
      same(`${at} ${layer.name}: only findings`, bad.map((f) => f.name), []);
    }
    same(`${at}: same packed row`, b.row, a.row);
  }
  return totals;
}

// --- sources -------------------------------------------------------------------

async function* fileInputs(path: string, max: number): AsyncGenerator<DissectInput> {
  const walk = await PcapService.frameWalk(await openAsBlob(path));
  const clock = new FrameClock();
  let id = 0;
  for await (const frame of walk.frames(max)) {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    id += 1;
    yield {
      id, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
      facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
    };
  }
}

async function collect(path: string, max: number): Promise<DissectInput[]> {
  const all: DissectInput[] = [];
  for await (const input of fileInputs(path, max)) all.push(input);
  return all;
}

const FLAG = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };
const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';

/** A TCP segment with any flags and any checksum field (zero: offloaded, left alone). */
function segment(
  from: [string, number], to: [string, number], seq: number, ack: number, flags: number,
  payload: Uint8Array, checksum = 0,
): Uint8Array {
  const header = new Bytes()
    .u16(from[1], to[1]).u32(seq).u32(ack).u8(0x50, flags).u16(8192, checksum, 0).build();
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...ipv4(6, Uint8Array.from([...header, ...payload]), from[0], to[0]),
  ]);
}

function syntheticFrames(): { bytes: Uint8Array; origLen?: number }[] {
  const c: [string, number] = [CLIENT, 40000];
  const s: [string, number] = [SERVER, 80];
  const data = new Uint8Array(10).fill(0x41);
  const none = new Uint8Array(0);
  const frames: { bytes: Uint8Array; origLen?: number }[] = [];
  const add = (bytes: Uint8Array, origLen?: number) => { frames.push({ bytes, origLen }); };

  add(segment(c, s, 1000, 0, FLAG.SYN, none));                                   // a TCP SYN
  add(segment(s, c, 5000, 1001, FLAG.SYN | FLAG.ACK, none));
  add(segment(c, s, 1001, 5001, FLAG.ACK, none));
  add(segment(c, s, 1001, 5001, FLAG.PSH | FLAG.ACK, data));
  add(segment(c, s, 1011, 5001, FLAG.PSH | FLAG.ACK, data));
  add(segment(s, c, 5001, 1011, FLAG.ACK, none));                                // acks the first segment only
  add(segment(s, c, 5001, 1011, FLAG.ACK, none));                                // a duplicate ACK
  add(segment(s, c, 5001, 1011, FLAG.ACK, none));                                // and another
  add(segment(c, s, 1001, 5001, FLAG.PSH | FLAG.ACK, data));                     // a retransmission
  // RST + a bad TCP checksum + an analysis flag (a retransmission) in one frame.
  add(segment(c, s, 1011, 5001, FLAG.RST | FLAG.ACK, data, 0x1234));
  add(segment(c, s, 1021, 5001, FLAG.PSH | FLAG.ACK, data, 0x4321));             // bad checksum alone

  // A UDP frame with a bad checksum.
  const bad = udp(5000, 5001, new Uint8Array(12).fill(7));
  bad[6] = 0xbe; bad[7] = 0xef;
  add(Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(17, bad)]));
  add(udpFrame(5000, 5001, new Uint8Array(12).fill(7)));                         // and a good one

  // An IPv4 header with a bad checksum.
  const ipBad = udpFrame(5002, 5003, new Uint8Array(8));
  ipBad[24] ^= 0xff;
  add(ipBad);

  // A 1,600-byte frame (past the MTU).
  add(udpFrame(5004, 5005, new Uint8Array(1600 - 14 - 20 - 8).fill(9)));

  // IPv6 / TCP, with a good checksum and with a bad one.
  for (const checksum of [0, 0x2222]) {
    const tcp6 = new Bytes().u16(40001, 443).u32(1).u32(0).u8(0x50, FLAG.SYN).u16(8192, checksum, 0).build();
    const v6 = new Bytes().u32(0x60000000).u16(tcp6.length).u8(6, 64)
      .u16(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).u16(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).build();
    add(Uint8Array.from([...ethernet(0x86dd).build(), ...v6, ...tcp6]));
  }

  // Cut mid-TCP-header: the capture holds 14 + 20 + 10 bytes of a longer frame.
  const whole = segment(c, s, 2000, 0, FLAG.SYN, none);
  add(whole.slice(0, 14 + 20 + 10), whole.length);
  // Cut mid-IPv4 header, and a runt Ethernet frame.
  add(whole.slice(0, 14 + 12), whole.length);
  add(whole.slice(0, 9), whole.length);
  return frames;
}

function syntheticInputs(): DissectInput[] {
  const clock = new FrameClock();
  return syntheticFrames().map(({ bytes, origLen }, i) => {
    const tsNanos = 1_700_000_000_000_000_000n + BigInt(i) * 1_000_000n;
    const { relativeTime, timeDelta } = clock.fromNanos(tsNanos);
    return {
      id: i + 1, bytes, tsUs: Number(tsNanos / 1000n), relativeTime, timeDelta,
      origLen: origLen ?? bytes.length, linktype: 1,
    };
  });
}

/**
 * What the synthetic set must raise in tree-on mode, by frame id, or it has
 * gone blind: the frame's expert list must hold a message matching each pattern.
 */
const INTENDED: [number, string, RegExp[]][] = [
  [9, 'a retransmission', [/retransmission/i]],
  [7, 'a duplicate ACK', [/dup ack/i]],
  [10, 'RST + bad checksum + an analysis flag', [/reset/i, /bad checksum/i, /retransmission/i]],
  [12, 'a bad UDP checksum', [/bad checksum/i]],
  [14, 'a bad IPv4 header checksum', [/bad checksum/i]],
  [15, 'the MTU finding', [/MTU/]],
  [17, 'a bad IPv6/TCP checksum', [/bad checksum/i]],
];

/**
 * A host identity that matches none of the synthetic frames' MACs: with no
 * identity at all the direction is undecided and a checksum is never called Bad.
 */
const SOME_OTHER_HOST: HostIdentity = {
  macs: new Set(['02:00:00:00:00:99']), addresses: new Set(['198.51.100.9']), inferred: false, confidence: 1,
};

// --- run -----------------------------------------------------------------------

function report(name: string, t: Totals): void {
  console.log(`${t.failures === 0 ? 'ok  ' : 'FAIL'}  ${name}: ${t.frames} frames, ${t.checks} checks, ${t.failures} failed`);
}

const sources: { name: string; inputs: Iterable<DissectInput> }[] = [];
for (const fixture of FIXTURES) {
  if (!existsSync(fixture.path)) {
    console.log(`SKIP  ${fixture.name}: ${fixture.path} not present`);
    continue;
  }
  sources.push({ name: fixture.name, inputs: await collect(fixture.path, Number.POSITIVE_INFINITY) });
}
const burst = process.env.INWIRE_BURST_PCAP;
if (burst !== undefined && burst !== '') {
  if (existsSync(burst)) sources.push({ name: 'burst', inputs: await collect(burst, BURST_FRAMES) });
  else console.log('SKIP  burst: INWIRE_BURST_PCAP names no file');
}

const messagesOf = new Map<number, string[]>();
const synthetic = runSource('synthetic', syntheticInputs(), (o, id) => {
  messagesOf.set(id, (JSON.parse(o.expert) as { message: string }[] | null ?? []).map((e) => e.message));
}, SOME_OTHER_HOST);
report('synthetic', synthetic);
for (const [id, what, patterns] of INTENDED) {
  const found = messagesOf.get(id) ?? [];
  for (const pattern of patterns) {
    check(`synthetic #${id} raises ${what}: ${pattern}`, found.some((m) => pattern.test(m)), true);
  }
}
for (const source of sources) report(source.name, runSource(source.name, source.inputs));

finish('tree-free rows');
