/**
 * What an expiry does to the rollup sidecar while a v9 run is live (ADR 0062), through a `MonitoringWorkerHost`
 * over the real journal, sidecar, archive and `runExpiry`, at the 16 MiB minimum limit with `expire-oldest`.
 *
 *   npx tsx scripts/monitoring/expiry-sidecar.ts
 *
 * Found by drive scenario 16 (`scripts/electron/monitoring-drive.ts`), which saw `rollups.iwmr` at 64 bytes, the
 * header alone, for the whole run and right after Stop. That is not a storage-limit refusal (the room the limit
 * leaves is megabytes). An expiry resets the sidecar to the journal's new start; the live Worker is not told, so
 * its next post, which comes when its minute is sealed (a later minute's datagram or a stop), continues from the
 * old watermark and is refused, and the retry a second later is what rebuilds. A drive that quits inside that
 * second leaves the 64 bytes behind, and the next open rebuilds them.
 *
 * Plain `tsx`; the generator and the host rig are `queryRig.ts`.
 */
import assert from 'node:assert/strict';
import { runExpiry } from '../../src/services/monitoring/archive';
import { MonitoringJournal, type EvidenceInput } from '../../src/services/monitoring/journal';
import { planExpiry, type RetentionPolicy } from '../../src/services/monitoring/retention';
import { decodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import { LIMITS, type Evidence } from '../../src/services/monitoring/types';
import { COLLECTOR, EXPORTER, v9DataOnly, v9Sample, type SampleFlow } from './fixtures';
import { BASE, HostRig, Rig, S1, deflate, inflate, runAll, start, stop, test, waitTick } from './queryRig';

const MiB = 1 << 20;
const POLICY: RetentionPolicy = { keepRawDays: null, atLimit: 'expire-oldest' };
const V9 = sourceKeyFor('v9', EXPORTER, 1);
const RECORDS = 2000;
const HEADER_ONLY = 64;

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

/** The collector's `expireStep`: one sealed segment through `runExpiry` when the policy says the oldest is due. */
function expireStep(rig: Rig, nowMs: number): boolean {
  const segments = rig.journal.segments();
  let used = rig.store.size() + rig.archive.bytes();
  for (const s of segments) used += s.bytes;
  const plan = planExpiry(segments, POLICY, nowMs, used, rig.limitBytes);
  if (plan === null) return false;
  const first = segments[0];
  const one = { segments: [first.name], throughEntryId: first.lastEntryId, throughMs: first.lastReceivedMs, reason: plan.reason };
  const done = runExpiry(rig.journal, rig.store, rig.archive, one, { nowMs, deflate }) === 'done';
  if (rig.journal.state === 'storage-limit') rig.journal.setLimit(rig.limitBytes);
  return done;
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

test('expiry during a v9 run: the sidecar stays the header, the first post is refused as "does not continue", and the retry rebuilds it exactly', async () => {
  const rig = new LimitRig(0xa0, 16 * MiB);
  const host = new HostRig(rig.runtime);
  const posts: { watermark: number; after: number; minutes: number; room: number; refusal: string | null }[] = [];
  const inner = rig.runtime.appendMinutes.bind(rig.runtime);
  rig.runtime.appendMinutes = async (minutes, watermark, after, checkpoints) => {
    const room = rig.limitBytes - LIMITS.closingReserveBytes - rig.journal.snapshot().writtenBytes - rig.store.size();
    const post = { watermark: watermark.throughEntryId, after, minutes: minutes.length, room, refusal: null as string | null };
    posts.push(post);
    try { await inner(minutes, watermark, after, checkpoints); } catch (e) { post.refusal = (e as Error).message; throw e; }
  };
  rig.append([start(BASE + 1000)]);
  const connected = await host.connect();
  assert.ok(connected.type === 'connect-reply' && connected.ok);

  // 297 datagrams in six seconds, all inside one minute, with the collector's expiry check at most once a second.
  let now = BASE + 2000;
  let lastCheck = 0;
  let expiries = 0;
  for (let sent = 0; sent < 297;) {
    const batch: EvidenceInput[] = [];
    for (let i = 0; i < 4 && sent < 297; i++) batch.push(v9Datagram(now, sent++));
    const before = rig.through;
    assert.equal(rig.journal.append(batch).state, 'open', 'the journal never stopped: expiring made room');
    host.wall = now;
    rig.runtime.publishLive(readFrom(rig, before));
    now += 80;
    if (now - lastCheck >= 1000) { lastCheck = now; while (expireStep(rig, now)) expiries++; }
    host.tick();
    await settle();
  }
  // Then the quiet 30 s check (EXPIRY_CHECK_MS): the journal is still within two segments of its limit.
  now += 30_000;
  host.wall = now;
  while (expireStep(rig, now)) expiries++;
  host.tick();
  await settle();

  const firstRetained = rig.journal.snapshot().firstEntryId;
  assert.ok(expiries >= 2 && firstRetained > 1, `segments expired (${expiries}), the journal starts at entry ${firstRetained}`);
  assert.equal(rig.store.size(), HEADER_ONLY, 'the sidecar is the header alone while the run is live: the minute is still open, so nothing was posted');
  assert.equal(posts.length, 0, 'and no post was even attempted');

  // Stop seals the minute: the first post. It continues from the Worker's old base and the sidecar's was reset.
  rig.runtime.publishLive(rig.add(stop(now + 1000, S1, 'user')));
  await settle();
  assert.equal(posts.length, 1);
  const refused = posts[0];
  const reason = refused.refusal ?? '';
  assert.match(reason, /^a batch after entry 0 does not continue the sidecar, which continues from entry \d+$/, reason);
  assert.equal(Number(/continues from entry (\d+)/.exec(reason)?.[1]), firstRetained - 1, 'the sidecar continues from where the journal now begins');
  assert.ok(refused.room > 2 * MiB, `not the storage limit: the limit leaves ${refused.room} bytes, the batch is a few hundred`);
  assert.equal(rig.store.size(), HEADER_ONLY, 'the refusal wrote nothing; this is what a drive that quits now finds');
  assert.equal(host.phases().at(-1), 'rebuilding', 'the Worker announces rebuilding, with the retry on a timer');
  const message = host.posts.filter((p) => p.type === 'rebuild' && (p as { message?: string }).message !== undefined).map((p) => (p as { message: string }).message).at(-1);
  assert.match(message ?? '', /^The rollups are paused: the sidecar refused to grow \(a batch after entry 0 does not continue the sidecar/);

  // The retry fires: the sidecar is reset to the journal's start, the retained journal is replayed and the minute posted.
  host.tick();
  await host.host.settled();
  await settle();
  assert.equal(host.phases().at(-1), 'live');
  assert.equal(rig.store.watermark()?.throughEntryId, rig.through, 'the sidecar is caught up to the journal');
  const minutes = rig.store.readMinutes(V9, 0, Number.MAX_SAFE_INTEGER, 1 << 30).map((m) => decodeMinuteRollup(m.bytes, inflate));
  const retainedDatagrams = readFrom(rig, firstRetained - 1).filter((e) => e.kind === 'datagram').length;
  assert.equal(minutes.reduce((n, m) => n + m.records, 0), retainedDatagrams * RECORDS, 'it holds exactly the retained journal; what expired is the archive\'s');
});

const failures = await runAll();
process.exit(failures === 0 ? 0 : 1);
