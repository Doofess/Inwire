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
 * would (`virtualShards.ts`). Each frame's columns, field bag, tree, record,
 * decrypted answers and patches are hashed and must agree, frame for frame, at:
 *
 *   - N = 1, 2 and 7, sharded by address pair (ADR 0053's routing);
 *   - N = 2 and 7, sharded by connection, which a real burst needs (one
 *     address pair carried more than half of it);
 *   - two adversarial assignments: every new connection to the next shard in
 *     turn, and everything on one shard but the first connection.
 *
 * Those runs are light: a shard row stays in its pack, and the digest rebuilds
 * it from the pack, its bytes and its overlay. A 7-shard run with `decodeRows`
 * (more than one interface) must agree too, and so must a run that is handed a
 * socket table a third of the way in, which a shard annotates with and the
 * single Worker's sequential path does at the same frame (ADR 0053 phase 6).
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
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { Sequencer } from '../../src/services/dissect/sequencer';
import { withDissectEnv } from '../../src/services/dissect/dissectEnv';
import { FrameRevisit, RecordMiss, recordEntries } from '../../src/services/dissect/frameRecord';
import { keyLog } from '../../src/services/tls/keyLog';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import type { Merged } from '../../src/services/pipeline/coordinator';
import { unpackRows, type RowPack } from '../../src/services/pipeline/rowPack';
import { applyOverlay } from '../../src/services/pipeline/rowOverlay';
import { OpWriter, readOps } from '../../src/services/pipeline/shardProtocol';
import { FlowAnnotationStore } from '../../src/services/flowAnnotations';
import { annotatePacket } from '../../src/services/dissect/processFields';
import { NO_HOST } from '../../src/services/direction';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet, ProtocolLayer } from '../../src/types/packet';
import { FIXTURES, render } from './arrival';
import { evictionCapture } from './evictionCapture';
import { fragmentCapture } from './fragmentCapture';
import { CONFIGS, FIXED_ENV, drive, load, trackers, type Capture, type Config, type Stats, type Table, type TableAt } from './virtualShards';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`);
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

/**
 * The single Worker: one Sequencer, one recorder, every frame in order. Each
 * row is annotated as `ingest` does, with the table as it stood at its index.
 */
function sequential(capture: Capture, table?: TableAt): string[] {
  const dissector = new FrameDissector(trackers(new Sequencer()), FIXED_ENV, null);
  dissector.host = capture.host ?? dissector.host;
  const annotations = new FlowAnnotationStore();
  return capture.inputs.map((input, index) => {
    if (table !== undefined && index === table.at) annotations.apply(table.table, 0);
    const bytes = input.bytes.slice();
    let out: string;
    try {
      const d = dissector.dissect({ ...input, bytes });
      annotatePacket(d.packet, annotations);
      out = digest(d.packet, d.packet.layers, d.record, d.derived, d.icmpMatchedRequestFrameId, d.infoPatches);
    } catch (err) {
      out = `error failed to dissect a captured frame: ${String(err)}`;
    }
    structuredClone(bytes.buffer, { transfer: [bytes.buffer as ArrayBuffer] });
    return out;
  });
}

interface Run extends Stats {
  digests: string[];
  merged: Merged[];
}

interface RunOptions {
  /** Keep every merged frame (the revisit and pack checks read them). */
  keep?: boolean;
  /** The coordinator's `decodeRows`: more than one interface. */
  decodeRows?: boolean;
  /** Broadcast this table once the frames before `at` are dispatched. */
  table?: TableAt;
  /** Broadcast a table and then `flowsClear` before any frame. */
  clearTable?: Table;
}

/** The coordinator and its shards (`virtualShards.ts`), each merged frame hashed. */
function parallel(capture: Capture, config: Config, options: RunOptions = {}): Run {
  const keep = options.keep ?? false;
  const digests: string[] = new Array(capture.inputs.length);
  const merged: Merged[] = [];
  // The Worker's own store: lane 0's rows are annotated at the merge, as `emitMerged` does.
  const annotations = new FlowAnnotationStore();
  let tableApplied = false;
  // A shard row that stayed in its pack, rebuilt as the window would: decoded
  // once per pack, its bytes beside it, the merge's overlay over it.
  const decodedPacks = new Map<RowPack, Packet[]>();
  const rebuilt = (m: Merged): Packet => {
    const ref = m.packed!;
    let rows = decodedPacks.get(ref.pack);
    if (rows === undefined) {
      if (decodedPacks.size >= 64) decodedPacks.delete(decodedPacks.keys().next().value!);
      decodedPacks.set(ref.pack, rows = unpackRows(ref.pack));
    }
    const row = rows[ref.index];
    row.rawBytes = m.bytes ?? new Uint8Array(0);
    if (m.overlay !== undefined) applyOverlay(row, m.overlay);
    return row;
  };
  const stats = drive(capture, config, {
    ...(options.decodeRows !== undefined ? { decodeRows: options.decodeRows } : {}),
    ...(options.table !== undefined ? { table: options.table } : {}),
    ...(options.clearTable !== undefined ? { clearTable: options.clearTable } : {}),
    emit: (m) => {
      if (options.table !== undefined && !tableApplied && m.id - 1 >= options.table.at) {
        annotations.apply(options.table.table, 0);
        tableApplied = true;
      }
      // A shard annotated its own rows; lane 0's are the Worker's to annotate.
      if (m.lane === 0 && m.packet !== undefined) annotatePacket(m.packet, annotations);
      const layers = m.lane === 0 ? m.packet?.layers : m.layers;
      const packet = m.packet ?? (m.packed !== undefined ? rebuilt(m) : undefined);
      // A shard sends no bytes back: the row's are the coordinator's own copy of
      // the frame, and they must be the frame the capture holds.
      const sent = capture.inputs[m.id - 1].bytes;
      const bytesAgree = packet === undefined || Buffer.from(packet.rawBytes).equals(sent);
      digests[m.id - 1] = digest(packet, layers, m.record, m.derived, m.icmpMatchedRequestFrameId, m.infoPatches, m.error)
        + (bytesAgree ? '' : '\nbytes differ from the frame');
      if (keep) merged.push({ ...m, layers });
      const bytes = packet?.rawBytes;
      if (bytes && bytes.byteLength > 0 && !keep) structuredClone(bytes.buffer, { transfer: [bytes.buffer as ArrayBuffer] });
    },
  });
  return { digests, merged, ...stats };
}

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

/** A socket table naming the capture's first `max` TCP flows' local-looking endpoints. */
function tableOf(capture: Capture, max: number): Table {
  const dissector = new FrameDissector(trackers(new Sequencer()), FIXED_ENV, null);
  dissector.host = capture.host ?? dissector.host;
  const endpoints = new Map<string, [string, string, number, number]>();
  for (const input of capture.inputs.slice(0, 8192)) {
    if (endpoints.size >= max) break;
    try {
      const { packet } = dissector.dissect({ ...input, bytes: input.bytes.slice() });
      if (!packet.frameProtocols?.includes('tcp') || packet.sourcePort === undefined) continue;
      const key = `${packet.source}|${packet.sourcePort}`;
      if (!endpoints.has(key)) endpoints.set(key, ['tcp', packet.source, packet.sourcePort, 1000 + endpoints.size]);
    } catch { /* a frame that fails to dissect names no flow */ }
  }
  const procs: Table['procs'] = {};
  for (const entry of endpoints.values()) procs[String(entry[3])] = { name: `proc${entry[3]}.exe`, exe: '' };
  return { full: true, procs, add: [...endpoints.values()], gone: [] };
}

/**
 * A socket table that arrives a third of the way in annotates what one core
 * annotates (Review Focus 1), and `flowsClear` empties a shard's table.
 */
async function tableRuns(capture: Capture, want: string[], withClear: boolean): Promise<void> {
  const table = tableOf(capture, 50);
  if (table.add.length === 0) {
    console.log(`SKIP  ${capture.name}: no TCP flow to name in a socket table`);
    return;
  }
  const at = Math.floor(capture.inputs.length / 3);
  const wantTable = sequential(capture, { at, table });
  let annotated = 0;
  for (let i = 0; i < want.length; i++) if (wantTable[i] !== want[i]) annotated++;
  const config: Config = { label: 'N=7 by connection', shards: 7, route: 'connection' };
  const run = parallel(capture, config, { table: { at, table } });
  const diff = firstDiff(wantTable, run.digests);
  check(`${capture.name}, ${config.label}: a socket table broadcast after frame ${at.toLocaleString()} annotates what one core annotates`,
    diff === -1 && annotated > 0,
    diff !== -1 ? `frame ${diff + 1} differs${VERBOSE ? `: ${lineDiff(wantTable[diff], run.digests[diff])}` : ''}`
      : 'the table annotated no row, so nothing was compared');
  console.log(`        ${table.add.length} flows in the table, ${annotated.toLocaleString()} rows annotated`);
  if (!withClear) return;
  const cleared = parallel(capture, config, { clearTable: table });
  const clearedAt = firstDiff(want, cleared.digests);
  check(`${capture.name}, ${config.label}: flowsClear empties a shard's table, so nothing is annotated`,
    clearedAt === -1 && annotated > 0,
    clearedAt !== -1 ? `frame ${clearedAt + 1} was annotated` : 'the table annotated no row, so the clear proved nothing');
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
      check(`${capture.name}, ${config.label}: a light run decodes only packs holding a needsRow row`,
        run.packsDecoded <= run.needsRowResults && (run.needsRowResults > 0 || run.packsDecoded === 0),
        `${run.packsDecoded} packs decoded, ${run.needsRowResults} results with needsRow`);
      console.log(`        ${run.packsDecoded.toLocaleString()} of ${run.packs.toLocaleString()} packs decoded,`
        + ` ${run.needsRowResults.toLocaleString()} needsRow results`);
    }
    if (capture.name === 'burst') {
      await tableRuns(capture, want, false);
    } else {
      const seven: Config = { label: 'N=7 by connection, decodeRows', shards: 7, route: 'connection' };
      const decoded = parallel(capture, seven, { decodeRows: true });
      const at = firstDiff(want, decoded.digests);
      check(`${capture.name}, ${seven.label}: all ${want.length.toLocaleString()} frames as one core dissects them`,
        at === -1 && decoded.crossLane === 0 && decoded.barrierMismatch === 0,
        at !== -1 ? `frame ${at + 1} differs${VERBOSE ? `: ${lineDiff(want[at], decoded.digests[at])}` : ''}` : '');
      check(`${capture.name}, ${seven.label}: every pack the shards sent was decoded`,
        decoded.packsDecoded === decoded.packs, `${decoded.packsDecoded} of ${decoded.packs}`);
      await tableRuns(capture, want, true);
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
    // Decoded, so every shard row is an object to compare against its pack.
    const run = parallel(capture, { label: 'revisit', shards: 7, route: 'connection' }, { keep: true, decodeRows: true });
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

/** A hole before a frame rides in its op, beside the nanoseconds, and is absent when there was none. */
function holeRidesInTheOp(): void {
  const facts = { index: 0, pnum: 1, sinceFirst: 0, sincePrev: 0 };
  const pair = { a: 'a', b: 'b', facts };
  const frame = (id: number, extra: { nanosRemainder?: number; holeBefore?: number } | undefined) => ({
    id, bytes: new Uint8Array(4), tsUs: id, relativeTime: 0, timeDelta: 0, origLen: 4, linktype: 1,
    ...(extra === undefined ? {} : { facts: extra }),
  });
  const writer = new OpWriter();
  writer.tcp(frame(1, { holeBefore: 7 }), 'ip', pair, pair, 'k', 0);
  writer.tcp(frame(2, undefined), 'ip', pair, pair, 'k', 0);
  writer.fragment(frame(3, { nanosRemainder: 250, holeBefore: 3 }), 'ip', pair, pair, { nextStreamId: 1, forgets: null });
  writer.tcp(frame(4, { nanosRemainder: 9 }), 'ip', pair, pair, 'k', 0);
  const ops = [...readOps(structuredClone(writer.seal()))].map((op) => op.frame!.facts);
  check('a hole rides in the op: holeBefore 7 comes back as 7, beside the nanoseconds when there are some',
    ops[0]?.holeBefore === 7 && ops[1] === undefined && ops[2]?.holeBefore === 3 && ops[2]?.nanosRemainder === 250
      && ops[3]?.holeBefore === undefined && ops[3]?.nanosRemainder === 9,
    JSON.stringify(ops));
}

/**
 * A batch's frame bytes travel as one slab: copied into the writer as written,
 * sealed to an exactly sized buffer of their own, transferred with the numbers,
 * and read back as views of it. The inputs are views at odd offsets into
 * larger buffers with junk around them, so a writer that took `.buffer` whole
 * (or transferred the input's) would carry the junk, or detach the sender's.
 */
function batchBytesAreOneSlab(): void {
  const facts = { index: 0, pnum: 1, sinceFirst: 0, sincePrev: 0 };
  const pair = { a: 'a', b: 'b', facts };
  const lengths = Array.from({ length: 50 }, (_, i) => (i % 9 === 4 ? 0 : (i * 97 + 13) % 1501));
  const inputs = lengths.map((length, i) => {
    const backing = new Uint8Array(length + 40).fill(0xa5);
    const at = 7 + (i % 13);
    const view = backing.subarray(at, at + length);
    for (let k = 0; k < length; k++) view[k] = (i * 31 + k * 7) & 0xff;
    return view;
  });
  const want = inputs.map((view) => Buffer.from(view).toString('hex'));
  const writer = new OpWriter();
  inputs.forEach((bytes, i) => {
    const frame = { id: i + 1, bytes, tsUs: i, relativeTime: 0, timeDelta: 0, origLen: bytes.length, linktype: 1 };
    if (i % 5 === 3) writer.fragment(frame, 'ip', pair, pair, { nextStreamId: 1, forgets: null });
    else writer.tcp(frame, 'ip', pair, pair, 'k', 0);
    // A forget between frames takes no entry in `ends`.
    if (i % 7 === 6) writer.forget('k');
  });
  const batch = writer.seal();
  const total = lengths.reduce((sum, length) => sum + length, 0);
  check('a shard batch carries its bytes as one slab: sealed exactly sized, from offset 0, one end per frame',
    batch.bytes instanceof Uint8Array && batch.bytes.byteOffset === 0
      && batch.bytes.byteLength === total && batch.bytes.buffer.byteLength === total
      && batch.ends instanceof Uint32Array && batch.ends.length === 50 && batch.ends[49] === total,
    `${batch.bytes instanceof Uint8Array ? `${batch.bytes.byteOffset}+${batch.bytes.byteLength} of ${batch.bytes.buffer.byteLength}` : 'not a Uint8Array'}, want ${total}`);
  let clone: typeof batch | undefined;
  let problem = '';
  try {
    const bytesBuffer = batch.bytes.buffer as ArrayBuffer;
    clone = structuredClone(batch, { transfer: [batch.nums.buffer as ArrayBuffer, bytesBuffer, batch.ends.buffer as ArrayBuffer] });
    if (bytesBuffer.byteLength !== 0) problem = 'the slab was copied, not transferred';
  } catch (err) {
    problem = String(err);
  }
  const got = clone === undefined ? [] : [...readOps(clone)].filter((op) => op.frame !== undefined)
    .map((op) => Buffer.from(op.frame!.bytes).toString('hex'));
  const wrong = got.findIndex((hex, i) => hex !== want[i]);
  check('a shard batch carries its bytes as one slab: every frame reads back equal after the transfer',
    problem === '' && got.length === 50 && wrong === -1,
    problem !== '' ? problem : `${got.length} frames read, first wrong ${wrong}`);
  const intact = inputs.findIndex((view, i) => view.byteLength !== lengths[i] || Buffer.from(view).toString('hex') !== want[i]);
  check('a shard batch carries its bytes as one slab: the sender\'s own views still read after the transfer',
    intact === -1 && inputs.every((view) => view.buffer.byteLength > 0),
    `first changed ${intact}`);
}

async function main(): Promise<void> {
  holeRidesInTheOp();
  batchBytesAreOneSlab();
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
