/**
 * Pack-native chunks read back what re-encoded ones did, on real captures
 * (ADR 0053 phase 6, pack-native store chunks).
 *
 *   npx tsx scripts/capture/pack-native-equality.ts
 *
 * The same store messages go into two `CaptureHost`s, one with the writer's
 * `packNative` off (a shard's rows decoded at the seal and written as version 2
 * chunks, as before) and one with it on (the packs kept as version 3
 * segments). Every capture is run through the virtual coordinator and shards
 * (`scripts/pipeline/virtualShards.ts`, the classes `parallel.ts` holds to one
 * core) at N = 1, 2 and 7 by connection, through the two adversarial
 * assignments, and with `decodeRows` (more than one interface, so rows are
 * packed and overlaid on decoded objects). What the merge emits is turned into
 * the messages the pipeline Worker posts to the store, in its order: a group's
 * bytes (filed into ring segments), its records, its rows as one
 * `appendPacked` (or an `append` when none went as a pack), its patches. Each
 * message is cloned with `v8.serialize` as it is sent, so no prototype and no
 * shared object crosses.
 *
 * Both hosts must agree on:
 *
 *   - `prefix.iwpfx`, `frames.iwbyt` and `records.iwrec`, byte for byte, in
 *     every segment. The index and `summary.iwsum` are expected to differ
 *     (version 2 against version 3) and are not compared;
 *   - every row read back, and every frame's bytes (also held to the capture);
 *   - the stream digest's snapshot and the writer's counters;
 *   - which versions the chunks are: the packNative host wrote version 3 and the
 *     other none.
 *
 * Then both are closed and reopened through recovery and must still agree, and
 * the packNative capture's last chunk has its summary cut mid-way: recovery
 * drops that chunk and reports it, and every earlier row reads back as the
 * other host's.
 *
 * Captures: the `inwire`, `bulk` and `keyLog` fixtures (untracked,
 * `test/fixtures/README.md`; each skipped when absent) and a synthetic one with
 * several TCP streams, TLS with a server name, DNS and ICMP echo, which produce
 * patches. Only counts are printed.
 *
 * ## The horizon
 *
 * The writer's horizon is set in frames (2,500) and never by time, with
 * ring files of 1,000 frames and groups of 700 posted at a time. A time horizon
 * of zero seals a ring file's chunk as soon as the next file's bytes are
 * staged, which can be before this group's rows have arrived: a placeholder,
 * written by both hosts alike but then proving nothing about rows. Rows here
 * trail their bytes by one group, as they do live, and the horizon keeps well
 * behind them. The ring files give many chunks, and the packs (at most 384
 * rows, over interleaved shards) cross every chunk boundary.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deserialize, serialize } from 'node:v8';
import { inflateSync } from 'fflate';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { CaptureIndex, recoverCapture, type ChunkRecord } from '../../src/services/capture/captureIndex';
import { dataFilesOf, type RawFrame } from '../../src/services/capture/captureWriter';
import { readExact, type BlockFile } from '../../src/services/capture/blockFile';
import { decodeDigest } from '../../src/services/conversation/digestCodec';
import { PackSender, PackedFlush, type RowPack } from '../../src/services/pipeline/rowPack';
import { overlayOf, type RowOverlay } from '../../src/services/pipeline/rowOverlay';
import { mergeRowSide } from '../../src/services/pipeline/rowSteps';
import { RingFiling } from '../../src/services/pipeline/ringFiling';
import type { Merged } from '../../src/services/pipeline/coordinator';
import { ClientFingerprintStore, learnOrLabelFingerprint } from '../../src/services/dissect/clientFingerprints';
import { NetworkFactsCollector } from '../../src/services/networkFacts';
import { keyLog } from '../../src/services/tls/keyLog';
import { NO_HOST } from '../../src/services/direction';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet } from '../../src/types/packet';
import { Bytes, ethernet, internetChecksum, ipv4, pcapOf, udpFrameTo } from '../parity/synthetic';
import { FIXTURES } from '../pipeline/arrival';
import { drive, load, lopsided, scatter, type Capture, type Config } from '../pipeline/virtualShards';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail) console.log(`        ${detail}`.slice(0, 400));
}

const FILE_FRAMES = 1_000;
const GROUP = 700;
const HORIZON_FRAMES = 2_500;
const CAPTURE_ID = 'cap-20261025-010000-0001';
const NO_BYTES = new Uint8Array(0);

const cross = <T>(message: T): T => deserialize(serialize(message)) as T;

/** A bigint-safe structural form: sorted keys, no undefined, typed arrays as lists. */
function canon(value: unknown): unknown {
  if (typeof value === 'bigint') return { big: value.toString() };
  if (value instanceof Uint8Array || value instanceof Int32Array) return Array.from(value);
  if (Array.isArray(value)) return value.map(canon);
  if (value instanceof Map) return { map: [...value.entries()].map(([k, v]) => [canon(k), canon(v)]) };
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = canon(v);
    }
    return out;
  }
  return value;
}
const same = (a: unknown, b: unknown) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));

/** Which top-level keys of two rows differ; names only, never values. */
function keysDiffering(a: Packet, b: Packet): string {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => !same((a as unknown as Record<string, unknown>)[k], (b as unknown as Record<string, unknown>)[k])).join(',');
}

/** The first id whose row differs between two lists, as a short description; '' when equal. */
function firstRowDiff(a: Packet[], b: Packet[]): string {
  if (a.length !== b.length) return `${a.length} rows against ${b.length}`;
  for (let i = 0; i < a.length; i++) {
    if (!same(a[i], b[i])) return `row ${i} (id ${a[i].id}) differs in: ${keysDiffering(a[i], b[i])}`;
  }
  return '';
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- the store messages, from what the merge emits -----------------------------------

interface Log {
  messages: ToCapture[];
  /** Packs sent, rows that travelled in one, rows that were objects, patches, frames. */
  packs: number;
  packedRows: number;
  objectRows: number;
  patches: number;
  frames: number;
}

/**
 * The messages the pipeline Worker posts to the store for a capture run through
 * the virtual shards: `emitMerged`'s queueing and `postFlushed`'s posting, per
 * group of ids. A light shard row stays in its pack and carries the merge's
 * overlay (`mergeRowSide`); a decoded one runs the Worker's order-dependent
 * steps and carries what `overlayOf` finds changed since unpacking; a lane-0
 * row is an object. Bytes travel ahead on their own message, so every row goes
 * without them (`sent`).
 */
function storeLog(capture: Capture, config: Config, decodeRows: boolean): Log {
  const merged: Merged[] = [];
  drive(capture, config, { withTrees: false, decodeRows, emit: (m) => { merged.push(m); } });
  if (merged.some((m, i) => m.id !== i + 1)) throw new Error(`${capture.name}: the merge did not emit every id in order`);

  const ctx = { fingerprints: new ClientFingerprintStore(), facts: new NetworkFactsCollector(), host: capture.host ?? NO_HOST };
  const filing = new RingFiling();
  const sender = new PackSender();
  const seen = new Map<number, RowPack>();
  const log: Log = { messages: [{ type: 'open', captureId: CAPTURE_ID }], packs: 0, packedRows: 0, objectRows: 0, patches: 0, frames: merged.length };

  for (let from = 0; from < merged.length; from += GROUP) {
    const group = merged.slice(from, from + GROUP);
    const frames: RawFrame[] = group.map((m) => {
      const seq = m.id - 1;
      if (seq % FILE_FRAMES === 0) filing.boundary(seq / FILE_FRAMES + 1, seq);
      const input = capture.inputs[seq];
      const part = filing.partOf(seq);
      return part === undefined
        ? { id: m.id, tsUs: input.tsUs, bytes: input.bytes.slice() }
        : { id: m.id, tsUs: input.tsUs, bytes: input.bytes.slice(), ring: part };
    });
    log.messages.push({ type: 'appendBytes', frames });

    const records = group.filter((m) => m.record !== undefined).map((m) => ({ id: m.id, record: m.record! }));
    if (records.length > 0) log.messages.push({ type: 'appendRecords', frames: records });

    const flush = new PackedFlush();
    const flags: number[] = [];
    const objects: Packet[] = [];
    const patches: InfoPatch[] = [];
    let anyPacked = false;
    const usePack = (m: Merged, overlay: RowOverlay | null) => {
      const ref = m.packed!;
      const known = seen.get(ref.pack.key);
      if (known !== undefined && known !== ref.pack) throw new Error(`two packs share key ${ref.pack.key}`);
      if (known === undefined) seen.set(ref.pack.key, ref.pack);
      flush.packed(ref.pack, ref.index, null, overlay);
      anyPacked = true;
      log.packedRows++;
    };
    for (const m of group) {
      if (m.error !== undefined || (m.packet === undefined && m.packed === undefined)) continue;
      if (m.packet === undefined) {
        // A light row: it stays in its pack, and the merge adds to it.
        const { overlay } = mergeRowSide(m.side, ctx, m.overlay ?? null);
        usePack(m, overlay);
      } else {
        const packet = m.packet;
        packet.tsPrecision = 6;
        const tree = m.lane === 0 ? packet.layers : null;
        packet.layers = tree ?? [{ name: 'Frame', summary: '', fields: [] }];
        learnOrLabelFingerprint(packet.fields, ctx.fingerprints, packet.layers);
        ctx.facts.observe(packet, ctx.host);
        packet.layers = [];
        if (m.packed !== undefined) {
          usePack(m, m.packed.mark === undefined ? null : overlayOf(packet, m.packed.mark));
        } else {
          const whole: Packet = { ...packet, rawBytes: NO_BYTES };
          flush.object(whole);
          objects.push(whole);
          log.objectRows++;
        }
      }
      flags.push(1);
      if (m.infoPatches) patches.push(...m.infoPatches);
    }
    if (flags.length > 0) {
      if (anyPacked) {
        const rows = sender.seal(flush);
        log.packs += rows.packs.length;
        log.messages.push({ type: 'appendPacked', rows, sent: Uint8Array.from(flags) });
      } else {
        log.messages.push({ type: 'append', packets: objects, bytesSent: true });
      }
    }
    if (patches.length > 0) {
      log.patches += patches.length;
      log.messages.push({ type: 'patches', patches });
    }
  }
  log.messages.push({ type: 'finish' });
  return log;
}

// --- a host, and everything a reader can ask of it ------------------------------------

function phost(packNative: boolean, volume = new MemoryVolume()) {
  const said: FromCapture[] = [];
  const store = new CaptureHost(volume, (message) => said.push(message), {
    writer: { packNative, horizonUs: Number.MAX_SAFE_INTEGER, horizonFrames: HORIZON_FRAMES },
  });
  return {
    volume, said, store,
    send: (message: ToCapture) => store.receive(message),
    of<T extends FromCapture['type']>(type: T): Extract<FromCapture, { type: T }>[] {
      return said.filter((m) => m.type === type) as Extract<FromCapture, { type: T }>[];
    },
  };
}
type PHost = ReturnType<typeof phost>;

async function replay(log: Log, packNative: boolean): Promise<PHost> {
  const h = phost(packNative);
  let n = 0;
  for (const message of log.messages) {
    h.send(cross(message));
    if (++n % 200 === 0) await h.store.drain();
  }
  await h.store.drain();
  return h;
}

let nextRequest = 1;

async function readChunks(h: PHost, chunks: number): Promise<Packet[][]> {
  const out: Packet[][] = [];
  for (let c = 0; c < chunks; c++) {
    h.said.length = 0;
    const requestId = nextRequest++;
    h.send({ type: 'chunk', requestId, chunk: c });
    await h.store.drain();
    const reply = h.of('rows').find((m) => m.requestId === requestId);
    if (reply === undefined) throw new Error(`chunk ${c} was not answered: ${h.of('failure').map((m) => m.message).join('; ')}`);
    out.push(reply.packets);
  }
  return out;
}

async function readBytes(h: PHost, ids: number[]): Promise<Map<number, Uint8Array>> {
  const out = new Map<number, Uint8Array>();
  for (let i = 0; i < ids.length; i += 1_000) {
    h.said.length = 0;
    const requestId = nextRequest++;
    h.send({ type: 'read', requestId, ids: ids.slice(i, i + 1_000) });
    await h.store.drain();
    const reply = h.of('bytes').find((m) => m.requestId === requestId);
    if (reply === undefined) throw new Error('a read was not answered');
    for (const [id, bytes] of reply.frames) out.set(id, bytes);
  }
  return out;
}

const dump = (file: BlockFile): Uint8Array => {
  const out = new Uint8Array(file.size());
  file.read(0, out);
  return out;
};

interface Files {
  /** Per segment: the three files that must match byte for byte. */
  data: Map<number, { pfx: Uint8Array; byt: Uint8Array; rec: Uint8Array }>;
  records: ChunkRecord[];
  versions: number[];
  digest: unknown;
}

/** The finished capture's files, as they are on the volume now. */
function filesOf(h: PHost): Files {
  const files = h.volume.open(CAPTURE_ID);
  try {
    const index = CaptureIndex.parse(dump(files.index));
    const records: ChunkRecord[] = [];
    const versions: number[] = [];
    for (let c = 0; c < index.chunkCount; c++) {
      const r = index.record(c);
      records.push(r);
      const sum = dataFilesOf(files, r.segment)!.sum;
      const summary = inflateSync(readExact(sum, r.sumOffset, r.sumLength));
      versions.push(summary[4] | (summary[5] << 8));
    }
    const data = new Map<number, { pfx: Uint8Array; byt: Uint8Array; rec: Uint8Array }>();
    for (const n of [0, ...(files.segments?.list() ?? [])]) {
      const d = dataFilesOf(files, n)!;
      data.set(n, { pfx: dump(d.pfx), byt: dump(d.byt), rec: dump(d.rec) });
    }
    const digest = decodeDigest(dump(files.digest), inflateSync);
    return { data, records, versions, digest };
  } finally {
    files.close();
  }
}

async function collect(h: PHost) {
  await h.store.drain();
  h.send({ type: 'stats' });
  await h.store.drain();
  const stats = h.of('stats').at(-1)!.stats;
  const files = filesOf(h);
  const rows = await readChunks(h, stats.chunksWritten);
  const ids = rows.flat().map((r) => r.id);
  const bytes = await readBytes(h, ids);
  return { stats, files, rows, bytes, failures: h.of('failure').map((m) => m.message) };
}
type Collected = Awaited<ReturnType<typeof collect>>;

// --- one capture, one configuration ----------------------------------------------------

async function equalityRun(capture: Capture, config: Config, decodeRows: boolean, deep: boolean): Promise<void> {
  const label = `${capture.name}, ${config.label}${decodeRows ? ', decodeRows' : ''}`;
  const log = storeLog(capture, config, decodeRows);
  const nativeHost = await replay(log, true);
  const plainHost = await replay(log, false);
  const native = await collect(nativeHost);
  const plain = await collect(plainHost);

  const total = native.rows.flat().length;
  const v3 = native.files.versions.filter((v) => v === 3).length;
  const segments = native.files.data.size;
  check(`${label}: both hosts stored every frame (${total.toLocaleString()} rows in ${native.rows.length} chunks, ${segments} segments)`,
    total === log.frames && plain.rows.flat().length === log.frames && native.failures.length === 0 && plain.failures.length === 0,
    `${total} and ${plain.rows.flat().length} of ${log.frames}; failures ${native.failures.length}/${plain.failures.length}`);
  console.log(`        ${log.packedRows.toLocaleString()} rows in ${log.packs.toLocaleString()} packs, ${log.objectRows.toLocaleString()} objects,`
    + ` ${log.patches.toLocaleString()} patches; ${v3} of ${native.files.versions.length} chunks are version 3`);

  let fileDiff = '';
  if (native.files.data.size !== plain.files.data.size) fileDiff = 'a different number of segments';
  for (const [n, a] of native.files.data) {
    const b = plain.files.data.get(n);
    for (const name of ['pfx', 'byt', 'rec'] as const) {
      if (b === undefined || !sameBytes(a[name], b[name])) fileDiff ||= `segment ${n} ${name}`;
    }
  }
  const chunkShape = (f: Files) => f.records.map((r) => [r.firstId, r.lastId, r.frameCount, r.segment, r.pfxLength, r.bytLength, r.recLength]);
  check(`${label}: prefix, bytes and records files are byte-identical in every segment`, fileDiff === '' && same(chunkShape(native.files), chunkShape(plain.files)), fileDiff);

  const rowDiff = firstRowDiff(native.rows.flat(), plain.rows.flat());
  check(`${label}: every row reads back as the re-encoded one does`, rowDiff === '', rowDiff);

  let bytesWrong = 0;
  for (const side of [native, plain]) {
    if (side.bytes.size !== log.frames) bytesWrong++;
    for (const [id, got] of side.bytes) if (!sameBytes(got, capture.inputs[id - 1].bytes)) bytesWrong++;
  }
  check(`${label}: every frame's bytes read back, in both, as the capture's`, bytesWrong === 0, `${bytesWrong} wrong`);

  check(`${label}: the digest snapshot is the same, and holds streams`,
    same(native.files.digest, plain.files.digest) && native.files.digest !== null,
    'digests differ or are missing');
  check(`${label}: the writer's counters are the same`, same(native.stats, plain.stats), `${JSON.stringify(native.stats)} / ${JSON.stringify(plain.stats)}`.replace(/\d{6,}/g, '#'));
  check(`${label}: packNative wrote version 3 chunks and the other only version 2`,
    v3 > 0 && plain.files.versions.every((v) => v === 2), `${v3} version 3; the other ${[...new Set(plain.files.versions)].join(',')}`);
  if (capture.name === 'synthetic') {
    check(`${label}: patches were applied and some were missed (${native.stats.patchesApplied}/${native.stats.patchesMissed})`,
      native.stats.patchesApplied > 0 && log.patches > 0, 'no patch was applied');
  }

  if (deep) await reopenRuns(label, nativeHost, plainHost, native, plain);
  nativeHost.store.close();
  plainHost.store.close();
}

/** Close both, reopen through recovery, then tear the packNative capture's last summary. */
async function reopenRuns(label: string, nativeHost: PHost, plainHost: PHost, native: Collected, plain: Collected): Promise<void> {
  nativeHost.store.close();
  plainHost.store.close();

  const planOf = (h: PHost) => {
    const files = h.volume.open(CAPTURE_ID);
    try {
      const { plan } = recoverCapture(files.index, (n) => dataFilesOf(files, n));
      return plan;
    } finally {
      files.close();
    }
  };
  const clean = [planOf(nativeHost), planOf(plainHost)];
  check(`${label}: recovery of a closed capture loses nothing`, clean.every((p) => p.framesLost === 0 && p.keepRecords === native.rows.length),
    clean.map((p) => `${p.framesLost} lost, ${p.keepRecords} kept`).join(' / '));

  const reopened = [phost(true, nativeHost.volume), phost(false, plainHost.volume)];
  for (const h of reopened) {
    h.send({ type: 'open', captureId: CAPTURE_ID });
    await h.store.drain();
  }
  const [rn, rp] = await Promise.all(reopened.map(async (h) => {
    const ready = h.of('ready').at(-1)!;
    return { ready, rows: await readChunks(h, ready.chunkCount), failures: h.of('failure').map((m) => m.message) };
  }));
  const wantRows = native.rows.flat();
  check(`${label}: reopened, ${rn.ready.frameCount.toLocaleString()} rows read back, as before and as the other host's`,
    rn.ready.frameCount === wantRows.length && rn.failures.length === 0 && rp.failures.length === 0
      && firstRowDiff(rn.rows.flat(), wantRows) === '' && firstRowDiff(rp.rows.flat(), plain.rows.flat()) === ''
      && firstRowDiff(rn.rows.flat(), rp.rows.flat()) === '',
    `${rn.ready.frameCount} frames; ${firstRowDiff(rn.rows.flat(), wantRows)} ${firstRowDiff(rn.rows.flat(), rp.rows.flat())}`);
  for (const h of reopened) h.store.close();

  // Cut the last chunk's summary in half, inside the chunk and not at a boundary.
  const records = native.files.records;
  const last = records.length - 1;
  const tornAt = native.files.versions.lastIndexOf(3);
  check(`${label}: the last chunk is version 3, so the tear is inside one`, tornAt === last, `last version 3 chunk ${tornAt} of ${records.length}`);
  const victim = records[tornAt];
  const volumeFiles = nativeHost.volume.open(CAPTURE_ID);
  dataFilesOf(volumeFiles, victim.segment)!.sum.truncate(victim.sumOffset + Math.floor(victim.sumLength / 2));
  const torn = (() => {
    try {
      return recoverCapture(volumeFiles.index, (n) => dataFilesOf(volumeFiles, n)).plan;
    } finally {
      volumeFiles.close();
    }
  })();
  const keepFrames = records.slice(0, tornAt).reduce((n, r) => n + r.frameCount, 0);
  check(`${label}: recovery drops the torn chunk only (${victim.frameCount} frames) and says so`,
    torn.keepRecords === tornAt && torn.framesLost === records.slice(tornAt).reduce((n, r) => n + r.frameCount, 0),
    `${torn.keepRecords} kept, ${torn.framesLost} lost`);

  const again = phost(true, nativeHost.volume);
  again.send({ type: 'open', captureId: CAPTURE_ID });
  await again.store.drain();
  const ready = again.of('ready').at(-1)!;
  const said = again.of('failure').map((m) => m.message);
  check(`${label}: ...the host reports ${victim.frameCount} frames lost to a torn tail, and keeps ${tornAt} chunks`,
    ready.chunkCount === tornAt && ready.frameCount === keepFrames && ready.lastId === records[tornAt - 1].lastId
      && said.length === 1 && said[0].includes('torn tail') && said[0].includes(`${victim.frameCount} frames`),
    `${ready.chunkCount} chunks, ${ready.frameCount} frames; said ${said.length}`);
  const kept = await readChunks(again, ready.chunkCount);
  const wantKept = plain.rows.slice(0, tornAt).flat();
  check(`${label}: ...and every earlier row reads back as the other host's`,
    firstRowDiff(kept.flat(), wantKept) === '' && kept.flat().length === keepFrames,
    firstRowDiff(kept.flat(), wantKept));
  again.store.close();
}

// --- a synthetic capture --------------------------------------------------------------

function tcpSegment(srcPort: number, dstPort: number, seq: number, ack: number, flags: number, payload: Uint8Array): Uint8Array {
  const header = new Bytes().u16(srcPort, dstPort).u32(seq).u32(ack).u8(0x50, flags).u16(64240, 0, 0).build();
  return Uint8Array.from([...header, ...payload]);
}

const tcpFrameBetween = (src: string, dst: string, segment: Uint8Array): Uint8Array =>
  Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, segment, src, dst)]);

function tlsRecord(type: number, version: number, body: Uint8Array): Uint8Array {
  return Uint8Array.from([type, version >> 8, version & 0xff, body.length >> 8, body.length & 0xff, ...body]);
}

function handshake(type: number, body: Uint8Array): Uint8Array {
  return Uint8Array.from([type, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]);
}

function clientHello(sni: string, seed: number): Uint8Array {
  const name = Buffer.from(sni, 'utf8');
  const extensions = [
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x00, 0x00, name.length + 5, 0x00, name.length + 3, 0x00, 0x00, name.length, ...name,
  ];
  const random = Array.from({ length: 32 }, (_, i) => (seed * 7 + i) & 0xff);
  const body = Uint8Array.from([
    0x03, 0x03, ...random, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
    extensions.length >> 8, extensions.length & 0xff, ...extensions,
  ]);
  return tlsRecord(22, 0x0301, handshake(1, body));
}

function serverHello(seed: number): Uint8Array {
  const extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
  const random = Array.from({ length: 32 }, (_, i) => (seed * 11 + i) & 0xff);
  const body = Uint8Array.from([0x03, 0x03, ...random, 0x00, 0x13, 0x01, 0x00, 0x00, extensions.length, ...extensions]);
  return tlsRecord(22, 0x0303, handshake(2, body));
}

function dnsMessage(id: number, name: string, response: boolean): Uint8Array {
  const labels = name.split('.').flatMap((l) => [l.length, ...Buffer.from(l, 'ascii')]);
  const question = [...labels, 0, 0, 1, 0, 1];
  const head = new Bytes().u16(id, response ? 0x8180 : 0x0100, 1, response ? 1 : 0, 0, 0).build();
  const answer = response ? [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, id & 0xff, 1] : [];
  return Uint8Array.from([...head, ...question, ...answer]);
}

function icmpEcho(type: number, id: number, seq: number): Uint8Array {
  const bytes = Uint8Array.from([type, 0, 0, 0, id >> 8, id & 0xff, seq >> 8, seq & 0xff, ...Array.from({ length: 16 }, (_, i) => (seq + i) & 0xff)]);
  const sum = internetChecksum(bytes);
  bytes[2] = sum >> 8;
  bytes[3] = sum & 0xff;
  return bytes;
}

/**
 * Seventy TCP connections interleaved (a third to port 443 with a Client Hello
 * naming a server, and its Server Hello), 300 DNS exchanges and 150 ICMP echoes.
 * Each exchange's reply comes a good many frames after its request, so the
 * request's row is patched when the reply arrives.
 */
function syntheticCapture(): Uint8Array {
  const items: { start: number; frames: Uint8Array[] }[] = [];
  const SYN = 0x02; const ACK = 0x10; const PSH_ACK = 0x18; const FIN_ACK = 0x11;
  // The last ten start late, so the capture ends on TCP rows (packs) and the torn
  // last chunk below is one that holds some.
  for (let s = 0; s < 70; s++) {
    const client = `10.0.${s >> 6}.${(s & 63) + 2}`;
    const server = `93.184.${s % 5}.${10 + (s % 7)}`;
    const cport = 40_000 + s;
    const sport = s % 3 === 0 ? 443 : s % 3 === 1 ? 80 : 8080;
    const out = (seq: number, ack: number, flags: number, payload: Uint8Array) => tcpFrameBetween(client, server, tcpSegment(cport, sport, seq, ack, flags, payload));
    const back = (seq: number, ack: number, flags: number, payload: Uint8Array) => tcpFrameBetween(server, client, tcpSegment(sport, cport, seq, ack, flags, payload));
    const frames: Uint8Array[] = [out(1000, 0, SYN, NO_BYTES), back(5000, 1001, SYN | ACK, NO_BYTES), out(1001, 5001, ACK, NO_BYTES)];
    let cseq = 1001;
    let sseq = 5001;
    if (sport === 443) {
      const hello = clientHello(`host${s}.example.test`, s);
      frames.push(out(cseq, sseq, PSH_ACK, hello));
      cseq += hello.length;
      const reply = serverHello(s);
      frames.push(back(sseq, cseq, PSH_ACK, reply));
      sseq += reply.length;
    }
    for (let i = 0; i < 80; i++) {
      const payload = Uint8Array.from({ length: 30 + ((s * 13 + i * 29) % 270) }, (_, k) => (s + i + k) & 0xff);
      if (i % 3 === 2) {
        frames.push(back(sseq, cseq, PSH_ACK, payload));
        sseq += payload.length;
      } else {
        frames.push(out(cseq, sseq, PSH_ACK, payload));
        cseq += payload.length;
      }
    }
    frames.push(out(cseq, sseq, FIN_ACK, NO_BYTES), back(sseq, cseq + 1, FIN_ACK, NO_BYTES));
    items.push({ start: s < 60 ? s * 3 : 1_150 + (s - 60) * 2, frames });
  }
  for (let i = 0; i < 300; i++) {
    const client = `10.0.0.${(i % 50) + 2}`;
    const name = `name${i % 40}.example.test`;
    items.push({
      start: i * 4,
      frames: [
        udpFrameTo(client, '10.0.0.1', 50_000 + i, 53, dnsMessage(i + 1, name, false)),
        udpFrameTo('10.0.0.1', client, 53, 50_000 + i, dnsMessage(i + 1, name, true)),
      ],
    });
  }
  for (let i = 0; i < 150; i++) {
    const a = `10.0.1.${(i % 30) + 2}`;
    const echo = (type: number, src: string, dst: string) => Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(1, icmpEcho(type, 7, i), src, dst)]);
    items.push({ start: i * 8 + 2, frames: [echo(8, a, '93.184.9.9'), echo(0, '93.184.9.9', a)] });
  }
  const timeline: Uint8Array[] = [];
  const at = items.map(() => 0);
  for (let round = 0; timeline.length < items.reduce((n, it) => n + it.frames.length, 0); round++) {
    items.forEach((item, k) => {
      if (item.start <= round && at[k] < item.frames.length) timeline.push(item.frames[at[k]++]);
    });
  }
  return pcapOf(timeline);
}

// --- main ------------------------------------------------------------------------------

const CONNECTION = (shards: number, label?: string, assign?: Config['assign']): Config => ({
  label: label ?? `N=${shards} by connection`, shards, route: 'connection', ...(assign ? { assign } : {}),
});

async function main(): Promise<void> {
  const captures: Capture[] = [];
  for (const name of ['inwire', 'bulk', 'keyLog']) {
    const fixture = FIXTURES.find((f) => f.name === name)!;
    if (!existsSync(fixture.path)) {
      console.log(`SKIP  ${name}: ${fixture.path} is not present - see test/fixtures/README.md`);
      continue;
    }
    captures.push(await load(name, new Uint8Array(readFileSync(fixture.path)), fixture.path.replace(/\.pcapng?$/, '.keys')));
  }
  captures.push(await load('synthetic', syntheticCapture()));

  for (const capture of captures) {
    keyLog.clear();
    if (capture.keys !== null) keyLog.add(capture.keys);
    try {
      console.log(`\n--- ${capture.name}: ${capture.inputs.length.toLocaleString()} frames ---\n`);
      // The reopen and the tear run once per capture, on the 7-shard run.
      await equalityRun(capture, CONNECTION(1), false, false);
      await equalityRun(capture, CONNECTION(2), false, false);
      await equalityRun(capture, CONNECTION(7), false, true);
      await equalityRun(capture, CONNECTION(7, 'N=7, each connection to the next shard', scatter), false, false);
      await equalityRun(capture, CONNECTION(2, 'N=2, all but the first connection on one shard', lopsided), false, false);
      await equalityRun(capture, CONNECTION(7), true, false);
    } finally {
      keyLog.clear();
    }
  }
}

main().then(() => {
  console.log(failures === 0 ? '\nAll pack-native equality checks passed.' : `\n${failures} pack-native equality check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
