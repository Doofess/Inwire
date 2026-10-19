/**
 * Real monitoring datasets on disk for the sheet's UI drive and its screenshots. Not a test (it is in
 * `check.ts`'s NOT_TESTS) and it never starts Electron: each function builds one folder under a parent the
 * caller owns, through the pure journal and archive APIs (the same ones `scripts/monitoring/location.ts` and
 * `queries.ts` build their worlds with), then proves what the folder classifies as by asking the collector's own
 * read-only `inspect`, so a seed that drifts from what the app would say fails here and not in a screenshot.
 *
 * The folders are meant to be picked through the sheet's "Change..." button. A folder that holds a journal is
 * adopted where it is (`electron/monitoring/location.ts`), so these hold their segments directly; an empty
 * folder gets an `Inwire Monitoring` subfolder of its own, which is the `new` case.
 *
 * Time is relative to the wall clock the caller passes (`nowMs`), because the History presets always end at
 * now. An expiry here is an `age` expiry: the plan is made against a clock a day past the cut with a one-day
 * retention, then run with the real one, so the cut falls exactly where the seed wants it.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { ElectronApplication } from 'playwright';
import { Collector, type UdpSocket } from '../../electron/monitoring/collector';
import { openMonitoringFolder, openMonitoringVolume } from '../../electron/monitoring/volume';
import { ArchiveStore, runExpiry } from '../../src/services/monitoring/archive';
import type { InspectResult } from '../../src/services/monitoring/control';
import { MonitoringJournal, type EvidenceInput } from '../../src/services/monitoring/journal';
import { planExpiry } from '../../src/services/monitoring/retention';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { isSegmentFileName } from '../../src/services/monitoring/segments';
import { DECODER_POLICY_VERSION, LIMITS } from '../../src/services/monitoring/types';
import { dgram, deflate, MIN, S1, start, stop } from '../monitoring/queryRig';
import { EXPORTER } from '../monitoring/fixtures';

const MiB = 1024 * 1024;
const DAY = 86_400_000;
/** 32 MiB gives 1 MiB segments: the smallest a dataset has, so a few megabytes of datagrams seal several. */
const SEED_LIMIT = 32 * MiB;
const GENERATION = new Uint8Array(16).fill(0xcc);
const SOURCE = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055 };

/** A host present in every datagram's first flow, so it is in the tables and on both sides of any expiry cut. */
export const SEED_HOST = '10.9.0.1';
/** The name of the file `seedForeign` plants: no Inwire file is called this. */
export const FOREIGN_NAME = 'holiday.jpg';

export interface Seeded {
  /** The folder to pick: it holds the dataset's files directly (or nothing, for `seedEmpty`). */
  folder: string;
  /** What `Collector.inspect` says it is; the seed has already asserted it. */
  inspect: InspectResult;
}

export interface SeededExpired extends Seeded {
  host: typeof SEED_HOST;
  /** The newest instant whose raw evidence is gone. */
  expiredThroughMs: number;
  /** The oldest instant that still has raw evidence. */
  rawFromMs: number;
  /** The newest datagram's receive time. */
  lastMs: number;
}

export interface SeededIncomplete extends Seeded {
  /** The wide minute, as the minute's start. */
  minuteMs: number;
  expiredThroughMs: number;
  lastMs: number;
}

class NoSocket implements UdpSocket {
  onMessage(): void {}
  onError(): void {}
  bind(): Promise<void> { return Promise.resolve(); }
  close(): void {}
}

async function inspectFolder(folder: string): Promise<InspectResult> {
  const collector = new Collector({
    openVolume: openMonitoringVolume,
    openFolder: openMonitoringFolder,
    createSocket: () => new NoSocket(),
    now: () => Date.now(),
    randomBytes: (n) => new Uint8Array(randomBytes(n)),
    setTimer: () => () => {},
    defer: (fn) => { setImmediate(fn); },
    postStatus: () => {},
  });
  try {
    return await collector.inspect(folder, false);
  } finally {
    await collector.dispose();
  }
}

/** A datagram of `flows` flows from the one exporter; the first flow always has `SEED_HOST` as its source. */
function datagram(receivedMs: number, i: number, flows: number) {
  return dgram(receivedMs, Array.from({ length: flows }, (_, j) => ({
    src: j === 0 ? SEED_HOST : `10.${(i % 4) + 1}.${j}.${(i % 200) + 1}`,
    dst: `172.16.${j % 4}.${(i % 9) + 1}`,
    octets: j === 0 ? 50_000 + (i % 7) * 100 : 100 + j + (i % 13) * 10,
    packets: 1 + (j % 3),
    srcPort: 1000 + j,
    dstPort: 443,
  })), { engineId: 0, sequence: i });
}

interface Built {
  /** What the journal holds when the build ends: each sealed segment's last receive time, oldest first. */
  sealedThroughMs: number[];
}

/**
 * Writes `inputs` (sorted by time, after a `start` boundary and before a `stop`) into a new dataset in `folder`,
 * then, when `expireThrough` is given, expires every sealed segment that ends before it. Everything is closed.
 */
function build(folder: string, inputs: EvidenceInput[], expireThroughMs: number | null): Built {
  mkdirSync(folder, { recursive: true });
  const volume = openMonitoringVolume(folder);
  try {
    const first = inputs[0].receivedMs;
    const { journal } = MonitoringJournal.open(volume.segments, {
      limitBytes: SEED_LIMIT, randomBytes: () => GENERATION, nowMs: () => first, lastCutThroughEntryId: 0,
    });
    for (let at = 0; at < inputs.length; at += 100) {
      const r = journal.append(inputs.slice(at, at + 100));
      assert.equal(r.refused, 0, `the journal refused ${r.refused} entries (state ${r.state})`);
    }
    const sealed = journal.segments().filter((s) => s.sealed);
    assert.ok(sealed.length >= 2, `the seed seals at least two segments (it sealed ${sealed.length})`);
    const built: Built = { sealedThroughMs: sealed.map((s) => s.lastReceivedMs) };
    if (expireThroughMs !== null) {
      const snap = journal.snapshot();
      const archive = ArchiveStore.open(volume.archive, { generation: GENERATION, createdMs: first });
      const cache = RollupStore.open(
        volume.rollups,
        { generation: snap.generation, throughEntryId: snap.throughEntryId, policyVersion: DECODER_POLICY_VERSION },
        { nowMs: () => first },
      );
      // An age plan: a one-day retention judged on a clock a day past the cut drops exactly what ends before it.
      const plan = planExpiry(
        journal.segments(), { keepRawDays: 1, atLimit: 'stop' }, expireThroughMs + DAY, 0, SEED_LIMIT,
      );
      assert.ok(plan !== null, 'the cut reaches at least one sealed segment');
      assert.equal(plan.reason, 'age');
      assert.ok(plan.segments.length < journal.segments().length, 'the newest segment keeps its raw evidence');
      assert.equal(runExpiry(journal, cache.store, archive.store, plan, { nowMs: Date.now(), deflate }), 'done');
    }
    journal.close();
    return built;
  } finally {
    volume.close();
  }
}

const segmentNames = (folder: string): string[] => readdirSync(folder).filter(isSegmentFileName).sort();

/**
 * About two hours of v5 from one exporter, from three hours ago to one hour ago (a datagram every two seconds,
 * thirty flows each, a few megabytes), with an `age` expiry over the oldest part. A History range of six hours
 * has aggregate-only buckets for the old part and raw ones after; a Focus on `SEED_HOST` over the old part is
 * refused as `evidence-expired`. `age` is the policy's own reason, and the sentence it says is "under the
 * retention policy"; the discard path has its own wording and its own check.
 */
export async function seedExpired(dir: string, opts: { nowMs: number }): Promise<SeededExpired> {
  const folder = path.join(dir, 'seed-expired');
  const t0 = Math.floor((opts.nowMs - 3 * 60 * MIN) / MIN) * MIN;
  const timed: EvidenceInput[] = [];
  for (let i = 0; i < 3600; i++) timed.push(datagram(t0 + 1000 + i * 2000, i, 30));
  const lastMs = timed[timed.length - 1].receivedMs;
  const inputs = [{ ...start(t0, S1), source: SOURCE } as never as EvidenceInput, ...timed, stop(lastMs + 1000, S1)];

  // Two passes over the same sorted data: the first learns where the segments end, the second cuts at the
  // third seal so the old part is the oldest few segments and the newer part is whole segments after it.
  const probe = path.join(dir, 'seed-expired-probe');
  const ends = build(probe, inputs, null).sealedThroughMs;
  rmSync(probe, { recursive: true, force: true });
  assert.ok(ends.length >= 4, `the probe sealed ${ends.length} segments, and the seed needs four to keep raw evidence after a cut`);
  const cut = ends[2] + 1;
  const built = build(folder, inputs, cut);
  const expiredThroughMs = built.sealedThroughMs[2];
  assert.ok(expiredThroughMs >= ends[2] - 1, 'the cut is the third segment');

  const inspect = await inspectFolder(folder);
  assert.equal(inspect.ok && inspect.kind, 'adopt', JSON.stringify(inspect));
  assert.ok(segmentNames(folder).length >= 1, 'raw segments remain');
  return { folder, inspect, host: SEED_HOST, expiredThroughMs, rawFromMs: expiredThroughMs + 1, lastMs };
}

/**
 * One minute with more distinct address pairs than a minute may keep (`LIMITS.minuteKeyBudget`), then hours of
 * ordinary traffic, then an `age` expiry over the first segments. The tables, over a range holding that minute,
 * answer `evidence-expired` with `incomplete: true`: its pairs are not in the archive, because the minute
 * overflowed its key budget when it was rolled up.
 */
export async function seedIncomplete(dir: string, opts: { nowMs: number }): Promise<SeededIncomplete> {
  const folder = path.join(dir, 'seed-incomplete');
  const minuteMs = Math.floor((opts.nowMs - 3 * 60 * MIN) / MIN) * MIN;
  const timed: EvidenceInput[] = [];
  // 600 datagrams of 30 flows, each flow a pair nobody else has: 18,000 pairs, past the budget.
  const wide = 600;
  assert.ok(wide * 30 > LIMITS.minuteKeyBudget, 'the wide minute exceeds the key budget');
  for (let k = 0; k < wide; k++) {
    timed.push(dgram(minuteMs + 100 + k * 50, Array.from({ length: 30 }, (_, j) => ({
      src: `11.${k >> 8}.${k & 255}.${j}`, dst: '172.31.0.1', octets: 7 + j, packets: 1, srcPort: 2000 + j, dstPort: 80,
    })), { engineId: 0, sequence: k }));
  }
  // Ordinary traffic after it, from the next minute on, enough to seal several more segments.
  for (let i = 0; i < 2400; i++) timed.push(datagram(minuteMs + 2 * MIN + i * 2000, i, 30));
  timed.sort((a, b) => a.receivedMs - b.receivedMs);
  const lastMs = timed[timed.length - 1].receivedMs;
  const inputs = [{ ...start(minuteMs - 1000, S1), source: SOURCE } as never as EvidenceInput, ...timed, stop(lastMs + 1000, S1)];

  const probe = path.join(dir, 'seed-incomplete-probe');
  const ends = build(probe, inputs, null).sealedThroughMs;
  rmSync(probe, { recursive: true, force: true });
  // The wide minute is first, so the first segment holds it; cut after the second to be sure it is wholly inside.
  assert.ok(ends.length >= 3, `the probe sealed ${ends.length} segments`);
  assert.ok(ends[0] >= minuteMs + 100 + (wide - 1) * 50 || ends[1] >= minuteMs + 100 + (wide - 1) * 50, 'the wide minute is inside the first two segments');
  const built = build(folder, inputs, ends[1] + 1);

  const inspect = await inspectFolder(folder);
  assert.equal(inspect.ok && inspect.kind, 'adopt', JSON.stringify(inspect));
  return { folder, inspect, minuteMs, expiredThroughMs: built.sealedThroughMs[1], lastMs };
}

/** A small plain dataset with at least two sealed segments and an open one: raw material for the next two seeds. */
function plainDataset(folder: string, nowMs: number): void {
  const t0 = Math.floor((nowMs - 2 * 60 * MIN) / MIN) * MIN;
  const timed: EvidenceInput[] = [];
  for (let i = 0; i < 2400; i++) timed.push(datagram(t0 + 1000 + i * 1000, i, 30));
  const lastMs = timed[timed.length - 1].receivedMs;
  build(folder, [{ ...start(t0, S1), source: SOURCE } as never as EvidenceInput, ...timed, stop(lastMs + 1000, S1)], null);
}

/**
 * Interior corruption: a byte flipped inside the first of several segments. Adopted read-only
 * (`adopt-read-only`): history up to the damage is shown, Start is off, nothing in the folder is changed.
 */
export async function seedReadOnly(dir: string, opts: { nowMs?: number } = {}): Promise<Seeded> {
  const folder = path.join(dir, 'seed-read-only');
  plainDataset(folder, opts.nowMs ?? Date.now());
  const first = path.join(folder, segmentNames(folder)[0]);
  const bytes = readFileSync(first);
  // Well inside the second entry's body, past the 128-byte header and the first (boundary) entry.
  bytes[4096] ^= 0xff;
  writeFileSync(first, bytes);
  const inspect = await inspectFolder(folder);
  assert.equal(inspect.ok && inspect.kind, 'adopt-read-only', JSON.stringify(inspect));
  return { folder, inspect };
}

/** A dataset beside a file Inwire did not write: refused untouched as `foreign-files`, naming the file. */
export async function seedForeign(dir: string, opts: { nowMs?: number } = {}): Promise<Seeded> {
  const folder = path.join(dir, 'seed-foreign');
  plainDataset(folder, opts.nowMs ?? Date.now());
  writeFileSync(path.join(folder, FOREIGN_NAME), 'not an Inwire file');
  const inspect = await inspectFolder(folder);
  assert.ok(!inspect.ok && inspect.reason === 'foreign-files' && inspect.names?.includes(FOREIGN_NAME), JSON.stringify(inspect));
  return { folder, inspect };
}

export interface Dialogs {
  /** The folder main's open dialog answers with from now on. */
  pick(folder: string): Promise<void>;
  /** How many message boxes main has shown since the stub went in, and the options of the last. */
  boxes(): Promise<{ n: number; last: Record<string, unknown> | undefined }>;
  /** The file main's save dialog answers with from now on. */
  saveTo(file: string): Promise<void>;
}

/**
 * Replaces `dialog.showOpenDialog`, `dialog.showSaveDialog` and `dialog.showMessageBox` in main (the sheet sends
 * intents, never paths, so the dialogs are main's). The open dialog answers with the folder `pick` names and the
 * save dialog with the file `saveTo` names; the message box records its options, answers button 1 (the
 * "Discard" of main's confirmation, whose Cancel is the default) and counts.
 * Main calls each with or without a window first, so each accepts both. Main's own code looks `dialog.x` up at
 * the call, which is why replacing the property is enough.
 */
export async function stubDialogs(app: ElectronApplication): Promise<Dialogs> {
  await app.evaluate(({ dialog }) => {
    const g = globalThis as unknown as { __pick: string; __saveTo: string; __boxes: unknown[]; __lastMessageBox: unknown };
    g.__pick = '';
    g.__saveTo = '';
    g.__boxes = [];
    dialog.showOpenDialog = (async () => ({ canceled: false, filePaths: [g.__pick] })) as unknown as typeof dialog.showOpenDialog;
    dialog.showSaveDialog = (async () => ({ canceled: g.__saveTo === '', filePath: g.__saveTo })) as unknown as typeof dialog.showSaveDialog;
    dialog.showMessageBox = (async (first: unknown, second?: unknown) => {
      g.__lastMessageBox = second ?? first;
      g.__boxes.push(second ?? first);
      return { response: 1, checkboxChecked: false };
    }) as unknown as typeof dialog.showMessageBox;
  });
  return {
    pick: (folder) => app.evaluate((_main, f) => { (globalThis as unknown as { __pick: string }).__pick = f; }, folder),
    boxes: () => app.evaluate(() => {
      const g = globalThis as unknown as { __boxes: unknown[]; __lastMessageBox: unknown };
      return { n: g.__boxes.length, last: g.__lastMessageBox as Record<string, unknown> | undefined };
    }),
    saveTo: (file) => app.evaluate((_main, f) => { (globalThis as unknown as { __saveTo: string }).__saveTo = f; }, file),
  };
}

/** An empty folder: picked, it becomes `<it>/Inwire Monitoring` and is `new`. */
export async function seedEmpty(dir: string): Promise<Seeded> {
  const folder = path.join(dir, 'seed-empty');
  mkdirSync(folder, { recursive: true });
  assert.deepEqual(readdirSync(folder), []);
  // Inspected where the sheet would put it, the subfolder `resolveDatasetFolder` makes.
  const inspect = await inspectFolder(path.join(folder, 'Inwire Monitoring'));
  assert.equal(inspect.ok && inspect.kind, 'new', JSON.stringify(inspect));
  return { folder, inspect };
}
