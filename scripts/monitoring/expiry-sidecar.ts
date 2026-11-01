/**
 * What an expiry does to the rollup sidecar (ADRs 0062, 0071), through a `MonitoringWorkerHost` over the real journal,
 * sidecar, archive and `runExpiry`.
 *
 *   npx tsx scripts/monitoring/expiry-sidecar.ts
 *
 * An expiry trims the sidecar: the entries the archive now holds are left out of a copy, and the copy is renamed in
 * (here, handed over by a memory `replaceSidecar`; the Electron volume does it with a file). The Worker is not told,
 * and its next post continues. The reset an expiry used to be is the fallback, taken when the trim cannot be done or
 * the process dies before the rename (found by drive scenario 16, `scripts/electron/monitoring-drive.ts`, which saw
 * `rollups.iwmr` at 64 bytes, the header alone, for the whole run).
 *
 * The equality test is the heart of it: a trimmed sidecar must hold what a sidecar rebuilt from the retained
 * journal holds, fragment for fragment and checkpoint for checkpoint, at every segment start in turn.
 *
 * Plain `tsx`; the generator and the host rig are `queryRig.ts`.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { resumeExpiry, runExpiry, type RunExpiryOptions } from '../../src/services/monitoring/archive';
import { FILE_HEADER_BYTES } from '../../src/services/monitoring/journalCodec';
import { MonitoringJournal, type EvidenceInput } from '../../src/services/monitoring/journal';
import { LocalArchiveSource, LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { planExpiry, type RetentionPolicy } from '../../src/services/monitoring/retention';
import { decodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { RollupStore, type SidecarReplace } from '../../src/services/monitoring/rollupStore';
import { sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import { type Evidence } from '../../src/services/monitoring/types';
import { COLLECTOR, EXPORTER, v9DataOnly, v9Sample, type SampleFlow } from './fixtures';
import {
  BASE, HostRig, MIN, NOW, Rig, S1, SRC, askBoth, deflate, dgram, inflate, rollUp, runAll, spec, start, stop, test, waitTick, withoutProvenance,
} from './queryRig';

const MiB = 1 << 20;
const POLICY: RetentionPolicy = { keepRawDays: null, atLimit: 'expire-oldest' };
const V9 = sourceKeyFor('v9', EXPORTER, 1);
const RECORDS = 2000;

/** A Rig whose journal counts the sidecar and the archive against its limit, as the collector's journal does. */
class LimitRig extends Rig {
  override openJournal(): void {
    this.journal = MonitoringJournal.open(this.jdir, {
      limitBytes: this.limitBytes, randomBytes: (n) => Uint8Array.from({ length: n }, (_, i) => (this.seed + i) & 0xff), nowMs: () => BASE,
      lastCutThroughEntryId: this.archive.lastCut()?.throughEntryId ?? 0,
      otherBytes: () => (this.store?.size() ?? 0) + (this.archive?.bytes() ?? 0),
    }).journal;
  }
}

const FLOWS: SampleFlow[] = Array.from({ length: RECORDS }, (_, i) => ({
  src: `10.0.0.${1 + (i % 8)}`, dst: `10.0.1.${1 + (i % 8)}`, octets: 1000 + (i % 5000), packets: 10 + (i % 90),
}));

/** About 58 KB each: the template with the first, data only after, as drive scenario 16 sends them. */
function v9Datagram(receivedMs: number, n: number): EvidenceInput {
  const h = { uptime: 1_000_000 + n * 100, secs: Math.floor(receivedMs / 1000), sequence: n, sourceId: 1 };
  const bytes = n === 0 ? v9Sample(h, FLOWS, null) : v9DataOnly(h, FLOWS);
  return { kind: 'datagram', receivedMs, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}

/** What the Electron volume's `replaceRollups` does with a file, done with a memory one: the new file becomes the rig's sidecar. */
function memoryReplace(rig: Rig): SidecarReplace {
  return (write) => {
    const fresh = new MemoryBlockFile();
    write(fresh);
    rig.sfile = fresh;
    return fresh;
  };
}

/** The collector's `expireStep`: one sealed segment through `runExpiry` when the policy says the oldest is due. */
function expireStep(rig: Rig, nowMs: number, over: RunExpiryOptions = { replaceSidecar: memoryReplace(rig) }): boolean {
  const segments = rig.journal.segments();
  let used = rig.store.size() + rig.archive.bytes();
  for (const s of segments) used += s.bytes;
  const plan = planExpiry(segments, POLICY, nowMs, used, rig.limitBytes);
  if (plan === null) return false;
  const first = segments[0];
  const one = { segments: [first.name], throughEntryId: first.lastEntryId, throughMs: first.lastReceivedMs, reason: plan.reason };
  const done = runExpiry(rig.journal, rig.store, rig.archive, one, { nowMs, deflate, ...over }) === 'done';
  if (rig.journal.state === 'storage-limit') rig.journal.setLimit(rig.limitBytes);
  return done;
}

/** The oldest segment, expired whatever the limit says; the cut is its last entry. */
function expireFirst(rig: Rig, over: RunExpiryOptions = { replaceSidecar: memoryReplace(rig) }): { cut: number; cutMs: number; result: ReturnType<typeof runExpiry> } {
  const first = rig.journal.segments()[0];
  const plan = { segments: [first.name], throughEntryId: first.lastEntryId, throughMs: first.lastReceivedMs, reason: 'age' as const };
  return { cut: first.lastEntryId, cutMs: first.lastReceivedMs, result: runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate, ...over }) };
}

function readFrom(rig: Rig, after: number): Evidence[] {
  const snap = rig.journal.snapshot();
  const out: Evidence[] = [];
  for (;;) {
    const page = rig.journal.readPage(snap, after, 256, 1 << 20);
    out.push(...page.entries);
    after = page.nextAfterId;
    if (page.done) return out;
  }
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await waitTick();
}

// --- the journals and the comparison ------------------------------------------------------------------

const SEGMENT_BYTES = 1 * MiB;

/** Appends until the journal holds `segments` segments, then a few more entries and a stop. */
function fillSegments(rig: Rig, segments: number, next: (n: number) => EvidenceInput): void {
  let n = 0;
  while (rig.journal.segments().length < segments) rig.append([next(n++)]);
  for (let i = 0; i < 5; i++) rig.append([next(n++)]);
}

/** A closed v9 run over five 1 MiB segments, one datagram every nine seconds, so a minute straddles a segment start. */
async function v9Journal(): Promise<Rig> {
  const rig = new Rig(0xa0, 32 * SEGMENT_BYTES);
  rig.append([start(BASE + 1000)]);
  fillSegments(rig, 5, (n) => v9Datagram(BASE + 2000 + n * 9000, n));
  rig.append([stop(BASE + 2000 + 9000 * 200, S1, 'user')]);
  return rig;
}

/** A closed v5 run over four segments from two engines, a datagram every 1.5 s. */
async function v5Journal(): Promise<Rig> {
  const rig = new Rig(0xa1, 32 * SEGMENT_BYTES);
  rig.append([start(BASE + 1000)]);
  const flows = Array.from({ length: 30 }, (_, i) => ({ octets: 100 + i, packets: 1 + (i % 7), srcPort: 1000 + i }));
  fillSegments(rig, 4, (n) => dgram(BASE + 2000 + n * 1500, flows, { engineId: n % 2, sequence: n }));
  rig.append([stop(BASE + 2000 + 1500 * 5000, S1, 'user')]);
  return rig;
}

const hash = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex').slice(0, 24);

/** (source, minute, policy, through entry, rollup) of every fragment the sidecar holds, sorted: what the equality compares. */
function fragmentsOf(store: RollupStore): string[] {
  const out: string[] = [];
  for (const key of store.sources()) {
    for (const m of store.readMinutes(key, 0, Number.MAX_SAFE_INTEGER, 1 << 30)) {
      const policy = new DataView(m.bytes.buffer, m.bytes.byteOffset, m.bytes.byteLength).getUint16(0, true);
      out.push(`${key} ${m.minuteMs} p${policy} through ${m.throughEntryId} ${hash(m.bytes)}`);
    }
  }
  return out.sort();
}

function assertSame(mine: string[], theirs: string[], what: string): void {
  if (mine.length === theirs.length && mine.every((x, i) => x === theirs[i])) return;
  const have = new Set(theirs);
  const held = new Set(mine);
  const extra = mine.filter((x) => !have.has(x));
  const missing = theirs.filter((x) => !held.has(x));
  assert.fail(`${what}: ${mine.length} against ${theirs.length}; only in the trimmed sidecar: ${JSON.stringify(extra.slice(0, 4))} (${extra.length}); only in the rebuild: ${JSON.stringify(missing.slice(0, 4))} (${missing.length})`);
}

/**
 * A runtime that does not see the journal past `limit`. A rebuild batches a fragment's watermark by the entries it
 * reads, and an expiry appends its own `expired` boundary, which the sidecar being compared never read; clipped at
 * the entry that sidecar was built through, the rebuild reads what it read, and the watermarks can be compared as
 * they stand.
 */
class ClippedRuntime extends LocalRuntime {
  limit = Infinity;
  override async snapshot() {
    const s = await super.snapshot();
    return { ...s, throughEntryId: Math.min(s.throughEntryId, this.limit) };
  }
}

/** A sidecar rebuilt from the retained journal, the archive's cut and an empty file: what a reset and the Worker's catch-up make. */
async function rebuiltFrom(rig: Rig, clipThrough = Infinity): Promise<{ store: RollupStore; runtime: LocalRuntime }> {
  const snap = rig.journal.snapshot();
  const r = RollupStore.open(new MemoryBlockFile(), { generation: snap.generation, throughEntryId: snap.throughEntryId }, { nowMs: () => NOW });
  const runtime = new ClippedRuntime(
    rig.journal, r.store, { status: r.status }, new LocalArchiveSource(rig.archive), { generation: snap.generation, createdMs: NOW, replaced: null },
  );
  runtime.limit = clipThrough;
  const host = new HostRig(runtime);
  const reply = await host.connect();
  assert.ok(reply.type === 'connect-reply' && reply.ok, 'the rebuild connected');
  assert.equal(host.phases().at(-1), 'live', 'the rebuild finished');
  // Built clipped; asked whole, as the sidecar it is compared with is.
  runtime.limit = Infinity;
  return { store: r.store, runtime };
}

/** The answer over `[fromMs, toMs)`, from the rollups of whichever runtime the rig holds, and the raw scan's. */
async function answerOver(rig: Rig, runtime: LocalRuntime, key: string, fromMs: number, toMs: number) {
  const saved = rig.runtime;
  rig.runtime = runtime;
  try {
    return await askBoth(rig, spec(fromMs, toMs, 24, { sourceKey: key }));
  } finally {
    rig.runtime = saved;
  }
}

/** The keys two answers differ in, each side cut short: a failing deepEqual of two whole answers is unreadable. */
function sameAnswer(a: object, b: object, what: string): void {
  const out: string[] = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = JSON.stringify((a as Record<string, unknown>)[k], (_, v) => (typeof v === 'bigint' ? `${v}n` : v));
    const y = JSON.stringify((b as Record<string, unknown>)[k], (_, v) => (typeof v === 'bigint' ? `${v}n` : v));
    if (x !== y) out.push(`${k}: ${x?.slice(0, 300)} <> ${y?.slice(0, 300)}`);
  }
  assert.deepEqual(out, [], what);
}

/**
 * The trimmed sidecar against a rebuild: the same fragments and checkpoints, the same answer over the whole range
 * (the archive's part included), and over the retained part the rollups' answer equals the raw scan's. The raw scan
 * does not read the archive, so it is asked only about what the journal still holds: from the minute after the cut.
 */
async function equalToRebuild(rig: Rig, builtThrough: number, key: string, cutMs: number, toMs: number, label: string): Promise<void> {
  const other = await rebuiltFrom(rig, builtThrough);
  assertSame(fragmentsOf(rig.store), fragmentsOf(other.store), `${label}: fragments`);
  assert.deepEqual(rig.store.checkpoints(), other.store.checkpoints(), `${label}: checkpoints`);
  const retainedFrom = Math.ceil((cutMs + 1) / MIN) * MIN;
  const mine = await answerOver(rig, rig.runtime, key, retainedFrom, toMs);
  sameAnswer(withoutProvenance(mine.fast), withoutProvenance(mine.raw), `${label}: over the retained part the trimmed rollups answer as the raw scan does`);
  const whole = await answerOver(rig, rig.runtime, key, BASE, toMs);
  const theirs = await answerOver(rig, other.runtime, key, BASE, toMs);
  sameAnswer(withoutProvenance(whole.fast), withoutProvenance(theirs.fast), `${label}: the same answer over the whole range as the rebuild's`);
}

// --- tests -----------------------------------------------------------------------------------------------

test('trim: an expiry during a v9 run keeps the retained minutes, and the Worker\'s next post continues', async () => {
  const rig = new LimitRig(0xa0, 16 * MiB);
  const host = new HostRig(rig.runtime);
  const posts: { watermark: number; after: number; refusal: string | null }[] = [];
  const inner = rig.runtime.appendMinutes.bind(rig.runtime);
  rig.runtime.appendMinutes = async (minutes, watermark, after, checkpoints) => {
    const post = { watermark: watermark.throughEntryId, after, refusal: null as string | null };
    posts.push(post);
    try { await inner(minutes, watermark, after, checkpoints); } catch (e) { post.refusal = (e as Error).message; throw e; }
  };
  rig.append([start(BASE + 1000)]);
  const connected = await host.connect();
  assert.ok(connected.type === 'connect-reply' && connected.ok);
  const phasesAtConnect = host.phases().length;

  // 297 datagrams in six seconds, all inside one minute, with the collector's expiry check at most once a second.
  let now = BASE + 2000;
  let lastCheck = 0;
  let expiries = 0;
  const check = (): void => {
    while (expireStep(rig, now)) {
      expiries++;
      assert.equal(rig.store.trimmedThrough(), rig.journal.snapshot().firstEntryId - 1, 'the sidecar was trimmed to the cut');
    }
  };
  for (let sent = 0; sent < 297;) {
    const batch: EvidenceInput[] = [];
    for (let i = 0; i < 4 && sent < 297; i++) batch.push(v9Datagram(now, sent++));
    const before = rig.through;
    assert.equal(rig.journal.append(batch).state, 'open', 'the journal never stopped: expiring made room');
    host.wall = now;
    rig.runtime.publishLive(readFrom(rig, before));
    now += 80;
    if (now - lastCheck >= 1000) { lastCheck = now; check(); }
    host.tick();
    await settle();
  }
  // Then the quiet 30 s check (EXPIRY_CHECK_MS): the journal is still within two segments of its limit.
  now += 30_000;
  host.wall = now;
  check();
  host.tick();
  await settle();

  const firstRetained = rig.journal.snapshot().firstEntryId;
  assert.ok(expiries >= 2 && firstRetained > 1, `segments expired (${expiries}), the journal starts at entry ${firstRetained}`);
  assert.ok(posts.length > 0, 'fragments were posted while the run was live');
  assert.deepEqual(posts.filter((p) => p.refusal !== null), [], 'no post was refused: the trimmed sidecar continues from the Worker\'s watermark');
  assert.ok(!host.phases().slice(phasesAtConnect).includes('rebuilding'), 'the Worker never rebuilt');

  rig.runtime.publishLive(rig.add(stop(now + 1000, S1, 'user')));
  await settle();
  host.tick();
  await host.host.settled();
  await settle();
  assert.equal(host.phases().at(-1), 'live');
  assert.equal(rig.store.watermark()?.throughEntryId, rig.through, 'the sidecar is caught up to the journal');
  const minutes = rig.store.readMinutes(V9, 0, Number.MAX_SAFE_INTEGER, 1 << 30).map((m) => decodeMinuteRollup(m.bytes, inflate));
  const retainedDatagrams = readFrom(rig, firstRetained - 1).filter((e) => e.kind === 'datagram').length;
  assert.equal(minutes.reduce((n, m) => n + m.records, 0), retainedDatagrams * RECORDS, 'it holds exactly the retained journal; what expired is the archive\'s');
});

for (const [label, build, key] of [
  ['v9', v9Journal, V9],
  ['v5', v5Journal, SRC],
] as const) {
  test(`trim: equal to a rebuild, ${label}, at each segment start in turn`, async () => {
    const rig = await build();
    const host = await rollUp(rig);
    assert.equal(host.phases().at(-1), 'live');
    const segments = rig.journal.segments().length;
    assert.ok(segments >= 4, `${segments} segments`);
    const toMs = BASE + 5_000 * MIN;
    const builtThrough = rig.store.watermark()?.throughEntryId ?? 0;
    assert.equal(builtThrough, rig.through, 'the sidecar covers the journal');
    let trims = 0;
    while (rig.journal.segments().length > 1 && rig.journal.segments()[0].sealed) {
      const { cut, cutMs, result } = expireFirst(rig);
      assert.equal(result, 'done');
      assert.equal(rig.store.trimmedThrough(), cut, 'trimmed to the cut');
      trims++;
      await equalToRebuild(rig, builtThrough, key, cutMs, toMs, `${label} after the expiry through entry ${cut}`);
    }
    assert.ok(trims >= 3, `${trims} expiries`);
  });
}

test('trim: a crash before the rename leaves the old file, and reopen resets it', async () => {
  const rig = await v9Journal();
  await rollUp(rig);
  const before = rig.sidecarBytes();
  const first = rig.journal.segments()[0];

  // The trim itself: the replace throws after the copy was written, and the old sidecar is as it was.
  const crashed: SidecarReplace = (write) => { write(new MemoryBlockFile()); throw new Error('the process died before the rename'); };
  const mark = rig.store.watermark();
  assert.throws(() => rig.store.trim(first.lastEntryId, crashed), /died before the rename/);
  assert.deepEqual(rig.sidecarBytes(), before, 'the old sidecar is byte-identical');
  assert.deepEqual(rig.store.watermark(), mark, 'and the store still holds it');
  assert.equal(rig.store.trimmedThrough(), 0);

  // The process died there: the journal and the archive moved on, the sidecar did not. Reopen finishes it by resetting.
  const { cut, cutMs } = expireFirst(rig, { replaceSidecar: crashed });
  assert.equal(cut, first.lastEntryId);
  assert.equal(rig.store.watermark(), null, 'a trim that fails falls back to the reset, in the same process');
  // runExpiry fell back to the reset in its own process; put the untouched file back, as a death would have left it.
  rig.sfile.truncate(0);
  rig.sfile.write(0, before);
  rig.reopen();
  assert.equal(rig.sidecarStatus, 'ok', 'the old file opens: it is a good sidecar of the journal as it was');
  assert.equal(rig.store.trimmedThrough(), 0);
  assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive, NOW), 'resumed');
  assert.equal(rig.store.watermark(), null, 'the untrimmed cache was never served beside the archive');
  assert.equal(rig.store.trimmedThrough(), rig.journal.snapshot().firstEntryId - 1);

  await rollUp(rig);
  const other = await rebuiltFrom(rig);
  assertSame(fragmentsOf(rig.store), fragmentsOf(other.store), 'the rebuild after the reset');
  const toMs = BASE + 5_000 * MIN;
  const mine = await answerOver(rig, rig.runtime, V9, Math.ceil((cutMs + 1) / MIN) * MIN, toMs);
  sameAnswer(withoutProvenance(mine.fast), withoutProvenance(mine.raw), 'the rebuilt rollups answer as the raw scan does');
});

test('trim: a Worker that connects over the untrimmed old file wipes it, as before', async () => {
  const rig = await v9Journal();
  await rollUp(rig);
  const before = rig.sidecarBytes();
  expireFirst(rig, { replaceSidecar: () => { throw new Error('no room to copy'); } });
  assert.equal(rig.store.watermark(), null, 'a failed trim falls back to the reset');
  rig.sfile.truncate(0);
  rig.sfile.write(0, before);
  rig.reopen();
  let resets = 0;
  const inner = rig.runtime.resetRollups.bind(rig.runtime);
  rig.runtime.resetRollups = async () => { resets++; await inner(); };
  await rollUp(rig);
  assert.equal(resets, 1, 'the connect check saw a sidecar behind the expired boundary');
  assert.equal(rig.store.watermark()?.throughEntryId, rig.through);
});

test('trim: the Worker keeps a trimmed sidecar at connect', async () => {
  const rig = await v9Journal();
  await rollUp(rig);
  const { cut } = expireFirst(rig);
  const mark = rig.store.watermark();
  assert.equal(mark?.trimmedThroughEntryId, cut, 'the watermark the store reports carries the trim');
  const size = rig.store.size();
  assert.ok(size > FILE_HEADER_BYTES, 'the trimmed sidecar holds the retained minutes');
  let resets = 0;
  const inner = rig.runtime.resetRollups.bind(rig.runtime);
  rig.runtime.resetRollups = async () => { resets++; await inner(); };
  await rollUp(rig);
  assert.equal(resets, 0, 'the Worker did not wipe it');
  assert.equal(rig.store.size(), size, 'and did not append over it');
  assert.deepEqual(rig.store.watermark(), mark);
  // The same after a restart of the process: the file is read back, and still not wiped.
  rig.reopen();
  assert.equal(rig.sidecarStatus, 'ok');
  assert.equal(rig.store.trimmedThrough(), cut);
  resets = 0;
  const again = rig.runtime.resetRollups.bind(rig.runtime);
  rig.runtime.resetRollups = async () => { resets++; await again(); };
  await rollUp(rig);
  assert.equal(resets, 0);
  assert.equal(rig.store.size(), size);
});

test('trim: a sidecar with nothing after the cut is emptied and the retry rebuilds from the cut', async () => {
  const rig = new Rig(0xa0, 32 * SEGMENT_BYTES);
  rig.append([start(BASE + 1000)]);
  let n = 0;
  for (; n < 10; n++) rig.append([v9Datagram(BASE + 2000 + n * 9000, n)]);
  const host = await rollUp(rig);
  // The Worker follows the journal live up to the entry that rolls it; that entry, the new segment's first, it has not seen.
  let rolled: Evidence[] = [];
  for (;;) {
    const before = rig.through;
    rig.append([v9Datagram(BASE + 2000 + n * 9000, n)]);
    n++;
    const entries = readFrom(rig, before);
    if (rig.journal.segments().length > 1) { rolled = entries; break; }
    host.wall = BASE + 2000 + n * 9000;
    rig.runtime.publishLive(entries);
    await settle();
  }
  const first = rig.journal.segments()[0];
  assert.equal(first.lastEntryId, rolled[0].ref.entryId - 1);
  const held = rig.store.watermark();
  assert.ok(held !== null && held.throughEntryId < first.lastEntryId, 'a minute is open: the sidecar covers less than the segment');
  const { result, cut } = expireFirst(rig);
  assert.equal(result, 'done');
  assert.equal(cut, first.lastEntryId);
  assert.equal(rig.store.watermark(), null, 'emptied');
  assert.equal(rig.store.trimmedThrough(), cut);
  assert.equal(rig.store.size(), FILE_HEADER_BYTES, 'the file is the header alone');

  // The Worker's next post continues from its old watermark, which is not the cut: refused, and the retry rebuilds.
  rig.runtime.publishLive(rolled);
  await settle();
  assert.equal(host.phases().at(-1), 'rebuilding', 'the post was refused');
  host.timers.fire();
  await host.waitFor(() => (host.phases().at(-1) === 'live' ? true : undefined), 'the rebuild after the retry');
  const other = await rebuiltFrom(rig);
  assert.ok(rig.store.watermark() !== null && rig.store.watermark()!.throughEntryId >= cut, 'caught up from the cut');
  assert.deepEqual(rig.store.watermark(), other.store.watermark(), 'to where a rebuild from the cut gets');
  assertSame(fragmentsOf(rig.store), fragmentsOf(other.store), 'the retry\'s rebuild');
});

test('trim: a read-only store refuses to trim', () => {
  const file = new MemoryBlockFile();
  const r = RollupStore.open(file, { generation: '00'.repeat(16), throughEntryId: 0 }, { readOnly: true });
  assert.throws(() => r.store.trim(1, () => file), /read-only/);
});

const failures = await runAll();
process.exit(failures === 0 ? 0 : 1);
