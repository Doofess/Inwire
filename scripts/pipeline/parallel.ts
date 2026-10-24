/**
 * Dissection on several cores, held to dissection on one (ADR 0053 phase 3).
 *
 *   npx tsx scripts/pipeline/parallel.ts [--burst some.pcapng]
 *
 * The equality test the ADR names. Every capture is dissected twice: the way
 * the single Worker does it, and through the coordinator with virtual shards -
 * the real `Coordinator` and `Shard` classes, every message between them put
 * through `structuredClone` with its buffers transferred, as a `postMessage`
 * does, and delivered in a shuffled order across the shards, as real threads
 * would. Each frame's columns, field bag, tree, record, decrypted answers and
 * patches are hashed and must agree, frame for frame, at:
 *
 *   - N = 1, 2 and 7, sharded by address pair (ADR 0053's routing);
 *   - N = 2 and 7, sharded by connection, which a real burst needs (one
 *     address pair carried more than half of it);
 *   - two adversarial assignments: every new connection to the next shard in
 *     turn, and everything on one shard but the first connection.
 *
 * Then every frame of the 7-shard run is rebuilt from its record, as the
 * detail pane would, and must draw the tree it drew at arrival.
 *
 * Captures: the real fixtures (untracked, test/fixtures/README.md - skipped
 * when absent), a capture of 20,000 connections that makes the TCP order forget
 * (`evictionCapture.ts`), and one of TCP in IP fragments (`fragmentCapture.ts`),
 * which the coordinator cannot number from its headers. `--burst` adds any
 * capture - the 300,000-frame download ADR 0053 was measured on.
 *
 * In one process, so two things a real shard has of its own are shared here:
 * the key log, which every shard is given whole anyway, and HTTP/1's body
 * counter - each shard's share of the budget is applied, against one counter.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { PcapService, decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { Sequencer, FrameClock } from '../../src/services/dissect/sequencer';
import { LIVE_ENV, withDissectEnv, type DissectEnv } from '../../src/services/dissect/dissectEnv';
import { FrameRevisit, RecordMiss, recordEntries } from '../../src/services/dissect/frameRecord';
import { keyLog } from '../../src/services/tls/keyLog';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import { Coordinator, WatchedTcpOrder, type CoordFrame, type Merged, type ShardRoute } from '../../src/services/pipeline/coordinator';
import { Shard, shardEnv } from '../../src/services/pipeline/shard';
import { unpackRows, type RowPack } from '../../src/services/pipeline/rowPack';
import type { FromShard, ToShard } from '../../src/services/pipeline/shardProtocol';
import { NO_HOST, type HostIdentity } from '../../src/services/direction';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet, ProtocolLayer } from '../../src/types/packet';
import { FIXTURES, render } from './arrival';
import { evictionCapture } from './evictionCapture';
import { fragmentCapture } from './fragmentCapture';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`);
}

/** The live environment with its clock stopped, so two runs' records can agree. */
const FIXED_ENV: DissectEnv = { ...LIVE_ENV, now: () => new Date(Date.UTC(2026, 9, 8)) };

interface Input {
  id: number; bytes: Uint8Array; tsUs: number; relativeTime: number; timeDelta: number;
  origLen: number; linktype: number; facts: { nanosRemainder?: number };
}

interface Capture { name: string; inputs: Input[]; host: HostIdentity | undefined; keys: string | null }

async function load(name: string, bytes: Uint8Array, keysPath?: string): Promise<Capture> {
  const file = new File([bytes], 'capture.pcap');
  const { frames } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames);
  const clock = new FrameClock();
  const inputs = frames.map((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    return {
      id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
      facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
    };
  });
  const keys = keysPath !== undefined && existsSync(keysPath) ? readFileSync(keysPath, 'utf8') : null;
  return { name, inputs, host, keys };
}

/** `--verbose`: keep each frame's description whole and print where a failing one differs. */
const VERBOSE = process.argv.includes('--verbose');

const hex = (bytes: Uint8Array | null | undefined) => (bytes == null ? '-' : Buffer.from(bytes).toString('hex'));

function digest(
  packet: Packet | undefined, layers: ProtocolLayer[] | undefined, record: Uint8Array | undefined,
  derived: Uint8Array | null | undefined, icmp: number | undefined, patches: InfoPatch[] | undefined, error?: string,
): string {
  if (packet === undefined) return `error ${error}`;
  const fields = packet.fields ?? {};
  const parts = [
    JSON.stringify([
      packet.id, packet.source, packet.destination, packet.sourcePort, packet.destPort,
      packet.protocol, packet.protocolLabel, packet.info, packet.status, packet.length,
      packet.frameProtocols, packet.analysisFlags, Object.keys(fields).map((k) => [k, fields[k]]),
    ]),
    render(layers ?? []),
    VERBOSE && record !== undefined
      ? recordEntries(record).map(([name, value]) => `${name} ${JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? hex(v) : v))}`).join('\n')
      : hex(record),
    hex(derived),
    JSON.stringify([icmp ?? null, patches ?? []]),
  ];
  // Kept whole rather than hashed, so a failure can say which row moved.
  if (VERBOSE) return parts.join('\n');
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part).update('\n');
  return hash.digest('hex');
}

function trackers(sequencer: Sequencer) {
  return {
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  };
}

/** The single Worker: one Sequencer, one recorder, every frame in order. */
function sequential(capture: Capture): string[] {
  const dissector = new FrameDissector(trackers(new Sequencer()), FIXED_ENV, null);
  dissector.host = capture.host ?? dissector.host;
  return capture.inputs.map((input) => {
    const bytes = input.bytes.slice();
    let out: string;
    try {
      const d = dissector.dissect({ ...input, bytes });
      out = digest(d.packet, d.packet.layers, d.record, d.derived, d.icmpMatchedRequestFrameId, d.infoPatches);
    } catch (err) {
      out = `error failed to dissect a captured frame: ${String(err)}`;
    }
    structuredClone(bytes.buffer, { transfer: [bytes.buffer as ArrayBuffer] });
    return out;
  });
}

/** A deterministic shuffle. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

interface Config {
  label: string;
  shards: number;
  route: ShardRoute;
  assign?: () => (key: string, shards: number) => number;
}

interface Run {
  digests: string[];
  merged: Merged[];
  lanes: number[];
  crossLane: number;
  barrierMismatch: number;
  ms: number;
}

/** The coordinator and its shards, every message through a structured clone, delivered shuffled. */
function parallel(capture: Capture, config: Config, keep = false): Run {
  const random = rng(capture.inputs.length * 31 + config.shards);
  const shardInbox: { message: ToShard }[][] = Array.from({ length: config.shards }, () => []);
  const coordInbox: { shard: number; message: FromShard }[] = [];
  const shards = Array.from({ length: config.shards }, (_, s) => new Shard((message, transfer) => {
    coordInbox.push({ shard: s, message: structuredClone(message, { transfer: transfer as ArrayBuffer[] }) });
  }, { shards: config.shards, cacheFrames: 64, env: FIXED_ENV, withTrees: true }));

  const digests: string[] = new Array(capture.inputs.length);
  const merged: Merged[] = [];
  const sequencer = new Sequencer(new WatchedTcpOrder());
  const coordinator = new Coordinator({
    shards: config.shards,
    route: config.route,
    ...(config.assign ? { assign: config.assign() } : {}),
    trackers: trackers(sequencer),
    sequencer,
    env: shardEnv(FIXED_ENV, config.shards),
    ifaceOf: () => undefined,
    withTrees: true,
    send: (shard, message, transfer) => {
      shardInbox[shard].push({ message: structuredClone(message, { transfer: transfer as ArrayBuffer[] }) });
    },
    emit: (m) => {
      const layers = m.lane === 0 ? m.packet?.layers : m.layers;
      digests[m.id - 1] = digest(m.packet, layers, m.record, m.derived, m.icmpMatchedRequestFrameId, m.infoPatches, m.error);
      if (keep) merged.push({ ...m, layers });
      const bytes = m.packet?.rawBytes;
      if (bytes && bytes.byteLength > 0 && !keep) structuredClone(bytes.buffer, { transfer: [bytes.buffer as ArrayBuffer] });
    },
  });
  coordinator.lane0.host = capture.host ?? coordinator.lane0.host;
  if (capture.host) {
    coordinator.broadcast({
      type: 'host', macs: [...capture.host.macs], addresses: [...capture.host.addresses],
      inferred: capture.host.inferred, confidence: capture.host.confidence, basis: capture.host.basis,
    });
  }

  const step = (): boolean => {
    const ready: number[] = [];
    for (let s = 0; s < config.shards; s++) if (shardInbox[s].length > 0) ready.push(s);
    if (coordInbox.length > 0) ready.push(-1);
    if (ready.length === 0) return false;
    const pick = ready[Math.floor(random() * ready.length)];
    if (pick === -1) {
      // Results from shards come back in any interleaving, but each shard's in its own order.
      const from = coordInbox[Math.floor(random() * coordInbox.length)].shard;
      const at = coordInbox.findIndex((m) => m.shard === from);
      const [{ shard, message }] = coordInbox.splice(at, 1);
      coordinator.receive(shard, message);
    } else {
      shards[pick].handle(shardInbox[pick].shift()!.message);
    }
    return true;
  };

  const t0 = performance.now();
  const CHUNK = 257;
  for (let i = 0; i < capture.inputs.length; i += CHUNK) {
    const chunk: CoordFrame[] = capture.inputs.slice(i, i + CHUNK).map((input) => ({ ...input, bytes: input.bytes.slice() }));
    coordinator.dispatch(chunk);
    const steps = Math.floor(random() * 6);
    for (let k = 0; k < steps; k++) if (!step()) break;
  }
  while (step()) { /* until every message is delivered */ }
  let idle = false;
  coordinator.whenIdle(() => { idle = true; });
  if (!idle) throw new Error(`${config.label}: the coordinator never went idle (backlog ${coordinator.backlog})`);
  return {
    digests, merged, lanes: [...coordinator.perLane], crossLane: coordinator.crossLane,
    barrierMismatch: coordinator.barrierMismatch, ms: performance.now() - t0,
  };
}

/** Every new connection to the next shard in turn. */
function scatter(): (key: string, shards: number) => number {
  const seen = new Map<string, number>();
  return (key, shards) => {
    let shard = seen.get(key);
    if (shard === undefined) {
      shard = seen.size % shards;
      seen.set(key, shard);
    }
    return shard;
  };
}

/** Everything on one shard, but the first connection. */
function lopsided(): (key: string, shards: number) => number {
  let first: string | undefined;
  return (key) => {
    first ??= key;
    return key === first ? 1 : 0;
  };
}

const CONFIGS: Config[] = [
  { label: 'N=1 by pair', shards: 1, route: 'pair' },
  { label: 'N=2 by pair', shards: 2, route: 'pair' },
  { label: 'N=7 by pair', shards: 7, route: 'pair' },
  { label: 'N=2 by connection', shards: 2, route: 'connection' },
  { label: 'N=7 by connection', shards: 7, route: 'connection' },
  { label: 'N=7, each connection to the next shard', shards: 7, route: 'connection', assign: scatter },
  { label: 'N=2, all but the first connection on one shard', shards: 2, route: 'connection', assign: lopsided },
];

function lineDiff(want: string, got: string | undefined): string {
  const a = want.split('\n');
  const b = (got ?? '(nothing)').split('\n');
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) return `line ${i + 1}: one core "${(a[i] ?? '(none)').slice(0, 300)}" / sharded "${(b[i] ?? '(none)').slice(0, 300)}"`;
  }
  return '(identical)';
}

function firstDiff(a: string[], b: string[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) return i;
  return -1;
}

async function equality(capture: Capture, configs: Config[]): Promise<void> {
  keyLog.clear();
  if (capture.keys !== null) keyLog.add(capture.keys);
  try {
    const t0 = performance.now();
    const want = sequential(capture);
    const oneCore = performance.now() - t0;
    for (const config of configs) {
      const run = parallel(capture, config);
      const at = firstDiff(want, run.digests);
      check(`${capture.name}, ${config.label}: all ${want.length.toLocaleString()} frames as one core dissects them`,
        at === -1 && run.crossLane === 0 && run.barrierMismatch === 0,
        at !== -1 ? `frame ${at + 1} differs${VERBOSE ? `: ${lineDiff(want[at], run.digests[at])}` : ''}`
          : `crossLane ${run.crossLane}, barrierMismatch ${run.barrierMismatch}`);
      console.log(`        lanes ${run.lanes.join(' / ')}; ${run.ms.toFixed(0)} ms in one process (one core: ${oneCore.toFixed(0)} ms)`);
    }
  } finally {
    keyLog.clear();
  }
}

/**
 * A row as the window would compare it: without the bytes and the tree, which
 * travel beside a pack, and with a key that is undefined on one side and absent
 * on the other the same (JSON drops it), a timestamp's bigint as a string.
 * `tls.stream` is left out: the merge numbers it after the shard packed the
 * row, so `tlsSettled` holds it instead.
 */
function rowJson(packet: Packet): string {
  const { rawBytes: _bytes, layers: _layers, fields, ...row } = packet;
  const { 'tls.stream': _tls, ...rest } = fields ?? {};
  return JSON.stringify({ ...row, fields: fields === undefined ? undefined : rest },
    (_, v) => (typeof v === 'bigint' ? `${v}n` : v));
}

/**
 * The pack holds the shard's `tls.stream` placeholder (negative); the merge
 * replaces it with the real number, which `Merged.packed` is not told of
 * (the row overlay carries it). Anything else must be unchanged.
 */
function tlsSettled(packed: Packet, merged: Packet): boolean {
  const was = packed.fields?.['tls.stream'];
  const now = merged.fields?.['tls.stream'];
  return was === now || (typeof was === 'number' && was < 0 && typeof now === 'number');
}

/**
 * Every row a shard sent is still in its pack, at the index the merge kept,
 * and decodes to the row the merge ran on: what the flush forwards instead of
 * the object is the object.
 */
function packedRows(capture: Capture, run: Run): void {
  let shardRows = 0;
  let unpacked = 0;
  let firstWrong = '';
  const decoded = new Map<RowPack, Packet[]>();
  for (const m of run.merged) {
    if (m.lane === 0 || m.error !== undefined || m.packet === undefined) continue;
    shardRows++;
    if (m.packed === undefined) {
      firstWrong ||= `frame ${m.id}: no pack`;
      continue;
    }
    let rows = decoded.get(m.packed.pack);
    if (rows === undefined) decoded.set(m.packed.pack, rows = unpackRows(m.packed.pack));
    const got = rows[m.packed.index];
    if (got !== undefined && rowJson(got) === rowJson(m.packet) && tlsSettled(got, m.packet)) unpacked++;
    else firstWrong ||= `frame ${m.id}: index ${m.packed.index} of pack ${m.packed.pack.key} differs`;
  }
  check(`${capture.name}: every row a 7-shard run took from a shard is in its pack, and the pack decodes to it`,
    shardRows === unpacked, firstWrong);
  console.log(`        ${unpacked.toLocaleString()} of ${shardRows.toLocaleString()} shard rows, in ${decoded.size.toLocaleString()} packs`);
}

/** Every frame of a sharded run rebuilt from its record: the tree it drew at arrival. */
function revisits(capture: Capture): void {
  keyLog.clear();
  if (capture.keys !== null) keyLog.add(capture.keys);
  try {
    const run = parallel(capture, { label: 'revisit', shards: 7, route: 'connection' }, true);
    const bytes = (id: number) => capture.inputs[id - 1]?.bytes;
    let rebuilt = 0;
    let missed = 0;
    let firstMiss = '';
    let wrong: string | null = null;
    for (const m of run.merged) {
      if (m.packet === undefined || m.record === undefined) continue;
      const input = capture.inputs[m.id - 1];
      try {
        const again = new FrameRevisit(m.record, bytes, m.derived ?? null);
        const rs = again.sources;
        const { packet } = withDissectEnv(rs.env, () => decodeRawEthernetPacket(
          input.bytes, m.id, input.tsUs, input.relativeTime, input.timeDelta, input.origLen,
          rs.tcp, rs.icmp, rs.quic, rs.dns, undefined, input.linktype, rs.l3, capture.host ?? NO_HOST, input.facts));
        again.finish();
        rebuilt++;
        if (wrong === null && render(packet.layers) !== render(m.layers ?? [])) wrong = `frame ${m.id}`;
      } catch (err) {
        if (!(err instanceof RecordMiss)) throw err;
        missed++;
        firstMiss ||= `frame ${m.id}: ${err.message}`;
      }
    }
    check(`${capture.name}: every frame a 7-shard arrival recorded is rebuilt from its record as it arrived`,
      wrong === null, wrong ?? '');
    packedRows(capture, run);
    console.log(`        ${rebuilt.toLocaleString()} rebuilt, ${missed.toLocaleString()} fell back to a replay`
      + `${firstMiss ? ` (first: ${firstMiss})` : ''}`);
  } finally {
    keyLog.clear();
  }
}

async function main(): Promise<void> {
  const captures: Capture[] = [];
  for (const fixture of FIXTURES) {
    if (!existsSync(fixture.path)) {
      if (!fixture.optional) console.log(`SKIP  ${fixture.name}: ${fixture.path} is not present - see test/fixtures/README.md`);
      continue;
    }
    captures.push(await load(fixture.name, new Uint8Array(readFileSync(fixture.path)), fixture.path.replace(/\.pcapng?$/, '.keys')));
  }
  captures.push(await load('eviction', evictionCapture()));
  captures.push(await load('fragments', fragmentCapture()));
  const burstAt = process.argv.indexOf('--burst');
  const burst = burstAt > 0 ? process.argv[burstAt + 1] : undefined;
  if (burst !== undefined) captures.push(await load('burst', new Uint8Array(readFileSync(burst))));

  const onlyAt = process.argv.indexOf('--only');
  if (onlyAt > 0) captures.splice(0, captures.length, ...captures.filter((c) => c.name === process.argv[onlyAt + 1]));
  for (const capture of captures) await equality(capture, capture.name === 'burst' ? CONFIGS.filter((c) => c.shards === 7 || c.shards === 1) : CONFIGS);
  for (const capture of captures) if (capture.name !== 'burst') revisits(capture);
}

main().then(() => {
  console.log(failures === 0 ? '\nAll parallel checks passed.' : `\n${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
