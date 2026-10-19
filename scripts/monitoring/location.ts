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
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Collector, type UdpSocket } from '../../electron/monitoring/collector';
import { openMonitoringFolder, openMonitoringVolume } from '../../electron/monitoring/volume';
import { ArchiveStore } from '../../src/services/monitoring/archive';
import { DATASET_FILE, DATASET_SUBFOLDER, readDatasetFile } from '../../src/services/monitoring/datasetPlan';
import { MonitoringJournal, type EvidenceInput } from '../../src/services/monitoring/journal';
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
  /** Every message the collector posted, in order. */
  readonly posts: string[] = [];
  postMessage(m: unknown): void {
    this.posts.push(String((m as { type?: string }).type));
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

  // ADR 0061: a dataset adopted read-only is served with nothing written. The classification has to come
  // before any open that can write, and a last cut may only come from the archive of the journal's own generation.
  await test('an archive of another generation adopts the folder read-only before anything is written to the journal', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const SESSION = 'a1'.repeat(16);
    const t0 = 1_700_000_000_000;
    {
      const volume = openMonitoringVolume(root);
      try {
        // Generation A: a start and datagrams, no stop (a crash), then a torn tail on the newest segment.
        const { journal } = MonitoringJournal.open(volume.segments, {
          limitBytes: CFG.storageLimitBytes, randomBytes: (n) => new Uint8Array(n).fill(0xaa), nowMs: () => t0,
        });
        const inputs: EvidenceInput[] = [{
          kind: 'boundary', sessionId: SESSION, receivedMs: t0, action: 'start', reason: '', droppedDatagrams: null,
          source: { exporterIPv4: CFG.exporterIPv4, bindIPv4: CFG.bindIPv4, port: CFG.port },
        }];
        for (let i = 0; i < 5; i++) {
          inputs.push({
            kind: 'datagram', receivedMs: t0 + 1000 * (i + 1), localIPv4: CFG.bindIPv4, localPort: CFG.port,
            remoteIPv4: CFG.exporterIPv4, remotePort: 50000, bytes: new Uint8Array(64).fill(i + 1),
          });
        }
        assert.equal(journal.append(inputs).appended, 6);
        journal.close();
        // Generation B: an archive whose last cut is far above anything A holds.
        const archive = ArchiveStore.open(volume.archive, { generation: new Uint8Array(16).fill(0xbb), createdMs: t0 });
        archive.store.append([], { fromEntryId: 1, throughEntryId: 1000, fromMs: t0, throughMs: t0 + 1, fragments: 0, reason: 'age', checkpoint: new Uint8Array(0) });
      } finally { volume.close(); }
    }
    const newest = segmentsIn(root).sort().at(-1)!;
    // The last entry loses its end: a torn tail, which an ordinary open would cut off.
    truncateSync(path.join(root, newest), statSync(path.join(root, newest)).size - 10);
    // The cache is derived and may be absent: opening must not be what makes one.
    unlinkSync(path.join(root, 'rollups.iwmr'));

    const snapshotOf = (): Map<string, string> => new Map(readdirSync(root).sort().map((n) => [n, readFileSync(path.join(root, n)).toString('base64')]));
    const before = snapshotOf();
    const names = [...before.keys()];
    assert.ok(segmentsIn(root).length >= 1 && !names.includes('rollups.iwmr') && !names.includes(DATASET_FILE));

    const disk = new Disk();
    try {
      assert.deepEqual(await disk.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      const status = disk.collector.status();
      assert.equal(status.storage, 'refused-corrupt');
      assert.match(status.storageError ?? '', /different dataset/);
      const after = snapshotOf();
      // Every way a look can write, named at once: a segment deleted or created is the worst of them.
      const wrote: string[] = [];
      for (const n of after.keys()) if (!before.has(n)) wrote.push(`${n} was created`);
      for (const [n, bytes] of before) {
        if (!after.has(n)) wrote.push(`${n} was deleted`);
        else if (after.get(n) !== bytes) wrote.push(`${n} changed (${Buffer.from(bytes, 'base64').length} -> ${Buffer.from(after.get(n)!, 'base64').length} bytes)`);
      }
      assert.deepEqual(wrote, [], 'an adopted read-only dataset was written to');
      disk.collector.attach(new FakePort());
      const started = await disk.collector.start(CFG);
      assert.equal(started.ok, false);
      assert.match(!started.ok ? started.message : '', /read but not added to/);
      const snapshot = await disk.collector.runtime.snapshot();
      assert.equal(snapshot.throughEntryId, 5, 'the journal answers up to its last whole entry');
      const page = await disk.collector.runtime.readPage(snapshot, 0, 100, 1 << 20);
      assert.equal(page.entries.length, 5);
      await settle();
      assert.deepEqual([...snapshotOf()], [...before], 'still not a byte written after Start and a read');
    } finally { await disk.close(); }
  });

  // The other half of the same rule: the archive of the journal's own generation does lend its last cut, so a
  // journal whose early segments went (its first id is above 1) is adopted and written, not read-only.
  await test('an archive of the journal\'s own generation lends its cut: a journal that starts after it adopts writable', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const t0 = 1_700_000_000_000;
    const volume = openMonitoringVolume(root);
    try {
      const generation = new Uint8Array(16).fill(0xcc);
      const { journal } = MonitoringJournal.open(volume.segments, {
        limitBytes: CFG.storageLimitBytes, randomBytes: () => generation, nowMs: () => t0, lastCutThroughEntryId: 1000,
      });
      assert.equal(journal.snapshot().firstEntryId, 1001, 'the journal begins after the cut');
      journal.close();
      const archive = ArchiveStore.open(volume.archive, { generation, createdMs: t0 });
      archive.store.append([], { fromEntryId: 1, throughEntryId: 1000, fromMs: t0, throughMs: t0 + 1, fragments: 0, reason: 'age', checkpoint: new Uint8Array(0) });
    } finally { volume.close(); }
    const disk = new Disk();
    try {
      assert.deepEqual(await disk.collector.inspect(root, false), { ok: true, kind: 'adopt', truncatedTailBytes: null, problem: null, exporterIPv4: null });
      assert.deepEqual(await disk.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      assert.equal(disk.collector.status().storage, 'open');
      assert.equal(disk.collector.status().snapshot?.firstEntryId, 1001);
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

  await test('a relocation and a whole discard each tell the Worker once, before the new dataset\'s live pushes; a first open tells nothing', async (dir) => {
    const a = path.join(dir, 'a', DATASET_SUBFOLDER);
    const b = path.join(dir, 'b', DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      // The first open has no port to tell, and attaching one afterwards is not a reopen.
      assert.deepEqual(await disk.collector.open(a, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      const port = new FakePort();
      disk.collector.attach(port);
      await settle();
      assert.equal(port.posts.filter((t) => t === 'reopened').length, 0, 'a first open posts no reopened');

      const recordMore = async (): Promise<void> => {
        assert.deepEqual(await disk.collector.start(CFG), { ok: true });
        const socket = disk.sockets[disk.sockets.length - 1];
        for (let i = 0; i < 3; i++) { disk.t += 1000; socket.emit(new Uint8Array(64).fill(i + 1)); }
        await settle();
        assert.equal((await disk.collector.stop('user')).ok, true);
      };
      const reopenedThenLive = (why: string): void => {
        assert.equal(port.posts.filter((t) => t === 'reopened').length, 1, `${why}: exactly one reopened`);
        const live = port.posts.indexOf('live');
        assert.ok(live > port.posts.indexOf('reopened'), `${why}: the notice precedes the live push (${port.posts.join(',')})`);
      };

      await recordMore();
      port.posts.length = 0;
      assert.deepEqual(await disk.collector.open(b, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      await recordMore();
      reopenedThenLive('a relocation');

      port.posts.length = 0;
      const discarded = await disk.collector.discard({ scope: 'all' });
      assert.equal(discarded.ok, true, JSON.stringify(discarded));
      await recordMore();
      reopenedThenLive('a whole discard');
    } finally { await disk.close(); }
  });

  // The dialog states a cut, so the cut must be the one that runs: both ask the same selection of segments.
  const BIG = 60_000;
  const recordSegments = async (disk: Disk, root: string, n: number): Promise<{ t0: number }> => {
    assert.deepEqual(await disk.collector.open(root, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
    disk.collector.attach(new FakePort());
    assert.deepEqual(await disk.collector.start(CFG), { ok: true });
    const t0 = disk.t;
    const socket = disk.sockets[disk.sockets.length - 1];
    for (let i = 0; i < n; i++) {
      disk.t += 1000;
      socket.emit(new Uint8Array(BIG).fill((i % 250) + 1));
      if (i % 10 === 9) await settle();
    }
    await settle();
    assert.equal((await disk.collector.stop('user')).ok, true);
    return { t0 };
  };
  const stampOf = (root: string): string => readdirSync(root).sort().map((n) => `${n}:${statSync(path.join(root, n)).size}:${statSync(path.join(root, n)).mtimeMs}`).join('|');
  const firstMs = async (disk: Disk): Promise<number> => {
    const snapshot = await disk.collector.runtime.snapshot();
    return (await disk.collector.runtime.readPage(snapshot, snapshot.firstEntryId - 1, 1, 1 << 20)).entries[0].receivedMs;
  };

  await test('a preview before a date states the cut the discard then makes, and writes nothing', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      const { t0 } = await recordSegments(disk, root, 60);
      const total = segmentsIn(root).length;
      assert.ok(total >= 3, `the run rolled segments (${total})`);
      const first = await firstMs(disk);
      const beforeMs = t0 + 40_000;
      const stamp = stampOf(root);
      const scope = { scope: 'before' as const, beforeMs };
      const preview = await disk.collector.discardPreview(scope);
      assert.equal(preview.ok, true, JSON.stringify(preview));
      if (!preview.ok) return;
      assert.equal(stampOf(root), stamp, 'a preview writes nothing: names, sizes and times are unchanged');
      assert.equal(preview.scope, 'before');
      assert.ok(preview.segments >= 1 && preview.segments < total, `some but not all go (${preview.segments} of ${total})`);
      assert.equal(preview.fromMs, first, 'it starts at the first entry of the first segment that goes');
      assert.ok(preview.cutMs !== null && preview.cutMs < beforeMs, 'the cut is before the date asked for');
      const discarded = await disk.collector.discard(scope);
      assert.deepEqual(discarded, { ok: true, removedSegments: preview.segments });
      assert.equal(segmentsIn(root).length, total - preview.segments);
      assert.ok((await firstMs(disk)) > preview.cutMs!, 'what remains starts after the cut');
      assert.deepEqual(await disk.collector.discardPreview(scope), { ok: true, scope: 'before', segments: 0, fromMs: null, throughMs: null, cutMs: null }, 'nothing is left to go');
    } finally { await disk.close(); }
  });

  await test('a whole preview reports the segments and the recorded range, and a whole discard removes that many', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      await recordSegments(disk, root, 30);
      const count = segmentsIn(root).length;
      const first = await firstMs(disk);
      const stamp = stampOf(root);
      const preview = await disk.collector.discardPreview({ scope: 'all' });
      assert.equal(stampOf(root), stamp, 'a preview writes nothing');
      assert.deepEqual(preview, { ok: true, scope: 'all', segments: count, fromMs: first, throughMs: disk.t, cutMs: null });
      const discarded = await disk.collector.discard({ scope: 'all' });
      assert.deepEqual(discarded, { ok: true, removedSegments: count });
    } finally { await disk.close(); }
  });

  await test('a preview is busy while collecting, and fails for a dataset a discard would refuse', async (dir) => {
    const root = path.join(dir, DATASET_SUBFOLDER);
    const disk = new Disk();
    try {
      await disk.record(root, { keepRunning: true });
      for (const scope of [{ scope: 'all' as const }, { scope: 'before' as const, beforeMs: disk.t + 1 }]) {
        const preview = await disk.collector.discardPreview(scope);
        assert.equal(preview.ok, false);
        assert.equal(!preview.ok && preview.reason, 'busy');
      }
      assert.equal((await disk.collector.stop('user')).ok, true);
    } finally { await disk.close(); }
    // Adopted read-only: a before-discard refuses, so its preview does too, and neither writes.
    const other = path.join(dir, 'ro', DATASET_SUBFOLDER);
    const first = new Disk();
    await first.record(other);
    await first.close();
    writeFileSync(path.join(other, DATASET_FILE), JSON.stringify({ ...datasetFile(other), generation: 'f'.repeat(32) }));
    const stamp = stampOf(other);
    const ro = new Disk();
    try {
      assert.deepEqual(await ro.collector.open(other, CFG.storageLimitBytes, { isDefaultLocation: false }), { ok: true });
      const preview = await ro.collector.discardPreview({ scope: 'before', beforeMs: ro.t + 1 });
      assert.equal(preview.ok, false);
      assert.equal(!preview.ok && preview.reason, 'failed');
      assert.equal(stampOf(other), stamp);
    } finally { await ro.close(); }
    // Never opened: nothing to preview.
    const unopened = new Disk();
    try {
      const preview = await unopened.collector.discardPreview({ scope: 'before', beforeMs: 1 });
      assert.equal(preview.ok, false);
      assert.equal(!preview.ok && preview.reason, 'failed');
    } finally { await unopened.close(); }
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
