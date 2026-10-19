/**
 * The collector on a real folder (ADR 0061): adoption, relocation and discard
 * through `openMonitoringVolume` and `openMonitoringFolder`, so what a discard
 * deletes is what `node:fs` deleted, not what a fake was told.
 *
 *   npx tsx scripts/monitoring/location.ts
 *
 * Plain tsx. Each case has its own temp folder; the socket and the timers are
 * fakes (no timer ever fires), the files are not.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Collector, type UdpSocket } from '../../electron/monitoring/collector';
import { openMonitoringFolder, openMonitoringVolume } from '../../electron/monitoring/volume';
import { DATASET_FILE, DATASET_SUBFOLDER, readDatasetFile } from '../../src/services/monitoring/datasetPlan';
import { isSegmentFileName } from '../../src/services/monitoring/segments';
import type { RpcPort } from '../../src/services/monitoring/runtimeRpc';
import type { SourceConfig } from '../../src/services/monitoring/types';

const MiB = 1024 * 1024;
const CFG: SourceConfig = { exporterIPv4: '10.0.0.1', bindIPv4: '192.168.1.5', port: 2055, storageLimitBytes: 16 * MiB };

let failures = 0;
let passes = 0;
async function test(name: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'inwire-location-'));
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      fn(dir),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('timed out: a promise never settled')), 10_000); }),
    ]);
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 7).join('\n        ')}`.slice(0, 1200));
  } finally {
    clearTimeout(timer);
    rmSync(dir, { recursive: true, force: true });
  }
}

async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise<void>((r) => setImmediate(r));
}

class FakeSocket implements UdpSocket {
  private msg: ((data: Uint8Array, from: { address: string; port: number }) => void) | null = null;
  onMessage(h: (data: Uint8Array, from: { address: string; port: number }) => void): void { this.msg = h; }
  onError(): void {}
  bind(): Promise<void> { return Promise.resolve(); }
  close(): void {}
  emit(data: Uint8Array): void { this.msg?.(data, { address: CFG.exporterIPv4, port: 2055 }); }
}

class FakePort implements RpcPort {
  private h: ((m: unknown) => void) | null = null;
  postMessage(m: unknown): void {
    if ((m as { type?: string }).type === 'live') queueMicrotask(() => this.h?.({ type: 'live-ack' }));
  }
  onMessage(h: (m: unknown) => void): void { this.h = h; }
  onClose(): void {}
  close(): void {}
}

class Disk {
  t = 1_700_000_000_000;
  sockets: FakeSocket[] = [];
  readonly collector = new Collector({
    openVolume: openMonitoringVolume,
    openFolder: openMonitoringFolder,
    createSocket: () => { const s = new FakeSocket(); this.sockets.push(s); return s; },
    now: () => this.t,
    randomBytes: (n) => new Uint8Array(randomBytes(n)),
    setTimer: () => () => {},
    defer: (fn) => { setImmediate(fn); },
    postStatus: () => {},
  });

  /** Opens `root`, attaches a Worker, starts, records `n` datagrams and, unless told not to, stops. */
  async record(root: string, opts: { n?: number; isDefaultLocation?: boolean; keepRunning?: boolean } = {}): Promise<void> {
    assert.deepEqual(await this.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: opts.isDefaultLocation ?? false }), { ok: true });
    this.collector.attach(new FakePort());
    assert.deepEqual(await this.collector.start(CFG), { ok: true });
    const socket = this.sockets[this.sockets.length - 1];
    for (let i = 0; i < (opts.n ?? 5); i++) {
      this.t += 1000;
      socket.emit(new Uint8Array(64).fill(i + 1));
    }
    await settle();
    if (opts.keepRunning !== true) assert.equal((await this.collector.stop('user')).ok, true);
  }

  async close(): Promise<void> { await this.collector.dispose(); }
}

const segmentsIn = (root: string): string[] => readdirSync(root).filter(isSegmentFileName);
const datasetFile = (root: string) => {
  const read = readDatasetFile(readFileSync(path.join(root, DATASET_FILE), 'utf8'));
  assert.equal(read.ok, true);
  return (read as { ok: true; file: ReturnType<typeof readDatasetFile> extends infer R ? R extends { ok: true; file: infer F } ? F : never : never }).file;
};

async function main(): Promise<void> {
  await test('a whole discard removes the dataset and leaves the folder the user picked, and what is in it', async (dir) => {
    const picked = path.join(dir, 'picked');
    const root = path.join(picked, DATASET_SUBFOLDER);
    mkdirSync(picked);
    writeFileSync(path.join(picked, 'keep-me.txt'), 'the user\'s');
    const disk = new Disk();
    try {
      await disk.record(root);
      assert.ok(segmentsIn(root).length > 0, 'the run wrote a segment');
      const before = datasetFile(root).generation;
      const result = await disk.collector.discard({ scope: 'all' });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.ok(result.ok && result.removedSegments >= 1);
      assert.equal(readFileSync(path.join(picked, 'keep-me.txt'), 'utf8'), 'the user\'s');
      assert.ok(existsSync(root), 'the dataset folder itself stays');
      const after = datasetFile(root);
      assert.notEqual(after.generation, before, 'the reopened dataset is a new one');
      assert.equal(after.replaced?.previousGeneration, before);
      assert.equal(after.discarding, null);
      assert.equal(disk.collector.status().snapshot?.throughEntryId, 0, 'nothing of the old journal is served');
    } finally { await disk.close(); }
  });

  await test('a whole discard leaves a foreign file that appeared in the dataset folder, and says the data went', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      await disk.record(root);
      writeFileSync(path.join(root, 'notes.txt'), 'not Inwire\'s');
      const result = await disk.collector.discard({ scope: 'all' });
      assert.equal(result.ok, false);
      assert.match(!result.ok ? result.message : '', /was discarded/);
      assert.equal(readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'not Inwire\'s');
      assert.deepEqual(segmentsIn(root), []);
      assert.deepEqual(readdirSync(root).sort(), [DATASET_FILE, 'notes.txt'], 'the dataset\'s names are gone and nothing was created beside the foreign file');
    } finally { await disk.close(); }
  });

  await test('a whole discard in the default location keeps the app\'s settings.json', async (dir) => {
    const root = path.join(dir, 'monitoring');
    mkdirSync(root);
    writeFileSync(path.join(root, 'settings.json'), '{"version":2}');
    const disk = new Disk();
    try {
      await disk.record(root, { isDefaultLocation: true });
      const result = await disk.collector.discard({ scope: 'all' });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(readFileSync(path.join(root, 'settings.json'), 'utf8'), '{"version":2}');
    } finally { await disk.close(); }
  });

  await test('a discard while collecting is busy and removes nothing', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      await disk.record(root, { keepRunning: true });
      const names = readdirSync(root).sort();
      for (const scope of [{ scope: 'all' as const }, { scope: 'before' as const, beforeMs: disk.t + 1 }]) {
        const result = await disk.collector.discard(scope);
        assert.equal(result.ok, false);
        assert.equal(!result.ok && result.reason, 'busy');
      }
      assert.deepEqual(readdirSync(root).sort(), names);
      assert.equal(disk.collector.status().listener, 'listening');
    } finally { await disk.close(); }
  });

  await test('an open that finds a discard marker finishes the discard before it serves anything', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const first = new Disk();
    await first.record(root);
    await first.close();
    const old = datasetFile(root);
    // As a crash leaves it: the marker written, the newest segment already gone, the rest still there.
    writeFileSync(path.join(root, DATASET_FILE), JSON.stringify({ ...old, discarding: { generation: old.generation, fromMs: 1, throughMs: 2 } }));
    const segs = segmentsIn(root).sort();
    unlinkSync(path.join(root, segs[segs.length - 1]));
    const second = new Disk();
    try {
      assert.deepEqual(await second.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      const after = datasetFile(root);
      assert.equal(after.discarding, null);
      assert.deepEqual(after.replaced && { g: after.replaced.previousGeneration, from: after.replaced.previousFromMs, through: after.replaced.previousThroughMs }, { g: old.generation, from: 1, through: 2 });
      assert.notEqual(after.generation, old.generation);
      assert.equal(second.collector.status().snapshot?.throughEntryId, 0);
    } finally { await second.close(); }
  });

  await test('an adopted read-only dataset refuses Start and writes nothing', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const first = new Disk();
    await first.record(root);
    await first.close();
    // dataset.json from another dataset: the journal and its note disagree.
    const other = { ...datasetFile(root), generation: 'f'.repeat(32) };
    writeFileSync(path.join(root, DATASET_FILE), JSON.stringify(other));
    const stamp = (): string => readdirSync(root).sort().map((n) => `${n}:${statSync(path.join(root, n)).size}:${statSync(path.join(root, n)).mtimeMs}`).join('|');
    const before = stamp();
    const disk = new Disk();
    try {
      assert.deepEqual(await disk.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      const status = disk.collector.status();
      assert.equal(status.storage, 'refused-corrupt');
      assert.match(status.storageError ?? '', /different dataset/);
      assert.ok((status.snapshot?.throughEntryId ?? 0) > 0, 'its history is still served');
      disk.collector.attach(new FakePort());
      const started = await disk.collector.start(CFG);
      assert.equal(started.ok, false);
      assert.match(!started.ok ? started.message : '', /read but not added to/);
      const discarded = await disk.collector.discard({ scope: 'before', beforeMs: disk.t + 1 });
      assert.equal(discarded.ok, false);
      await settle();
      assert.equal(stamp(), before, 'not a byte written, not even the cache or dataset.json');
    } finally { await disk.close(); }
  });

  await test('relocating while stopped moves nothing; relocating while collecting is refused', async (dir) => {
    const a = path.join(dir, 'a', DATASET_SUBFOLDER);
    const b = path.join(dir, 'b', DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      await disk.record(a, { keepRunning: true });
      const busy = await disk.collector.open(b, CFG.storageLimitBytes, { isDefaultLocation: false });
      assert.equal(busy.ok, false);
      assert.equal(existsSync(b), false, 'a refused relocation creates nothing');
      assert.equal((await disk.collector.stop('user')).ok, true);
      const aNames = readdirSync(a).sort();
      assert.deepEqual(await disk.collector.open(b, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      assert.deepEqual(readdirSync(a).sort(), aNames, 'the old dataset stays where it was');
      assert.equal(disk.collector.status().snapshot?.throughEntryId, 0, 'the new folder is a new dataset');
      assert.deepEqual(await disk.collector.open(a, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      assert.ok((disk.collector.status().snapshot?.throughEntryId ?? 0) > 0, 'and choosing it again adopts it');
    } finally { await disk.close(); }
  });

  await test('inspect writes nothing: a missing folder is new and is not created; a foreign file refuses by name', async (dir) => {
    const disk = new Disk();
    try {
      const missing = path.join(dir, 'nowhere', DATASET_SUBFOLDER);
      assert.deepEqual(disk.collector.inspect(missing, false), { ok: true, kind: 'new', truncatedTailBytes: null, problem: null, exporterIPv4: null });
      assert.equal(existsSync(path.join(dir, 'nowhere')), false);
      const cluttered = path.join(dir, 'cluttered');
      mkdirSync(cluttered);
      writeFileSync(path.join(cluttered, 'holiday.jpg'), 'x');
      const refused = disk.collector.inspect(cluttered, false);
      assert.equal(refused.ok, false);
      assert.equal(!refused.ok && refused.reason, 'foreign-files');
      assert.deepEqual(!refused.ok && refused.names, ['holiday.jpg']);
      assert.deepEqual(readdirSync(cluttered), ['holiday.jpg']);
    } finally { await disk.close(); }
  });

  await test('inspect of a recorded folder that is not open adopts it without touching it', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const first = new Disk();
    await first.record(root);
    await first.close();
    const names = readdirSync(root).sort();
    const disk = new Disk();
    try {
      const seen = disk.collector.inspect(root, false);
      assert.equal(seen.ok && seen.kind, 'adopt', JSON.stringify(seen));
      assert.deepEqual(readdirSync(root).sort(), names);
    } finally { await disk.close(); }
  });

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

void main();
