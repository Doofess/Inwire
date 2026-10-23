/**
 * Assertion tests for the Worker's half of policy 2 (ADRs 0064-0066): the decode state a host carries,
 * the template checkpoints it writes, and what it says about a v9 or IPFIX source.
 *
 *   npx tsx scripts/monitoring/host-checkpoints.ts
 *
 * `planCheckpoints` is the spacing rule, tested with small numbers because nobody fills 256 MiB in a
 * test. The rest is a `MonitoringWorkerHost` over the in-memory rig: a tail catch-up that starts at the
 * sidecar's checkpoint and not at entry 1, a cache from the 1.5 build continued and not rebuilt, the
 * checkpoint the live feed writes at a stop, the health of a template source, and a detail that
 * decodes a v9 record by the templates before it.
 */
import assert from 'node:assert/strict';
import { planCheckpoints, type CheckpointCandidate, type CheckpointSpacing } from '../../src/services/monitoring/checkpointPlan';
import { DecodeState } from '../../src/services/monitoring/decodeState';
import { ROLLUP_FRAMING, decodeFileHeader, encodeFileHeader } from '../../src/services/monitoring/journalCodec';
import type { EvidenceInput } from '../../src/services/monitoring/journal';
import { decodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { MemorySegmentDirectory, decodeSegmentHeader, encodeSegmentHeader } from '../../src/services/monitoring/segments';
import { sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import { LIMITS, type Evidence, type SegmentGeometry } from '../../src/services/monitoring/types';
import { COLLECTOR, EXPORTER, be, dataSet, templateRecord, templateSet, v9Message, type WireField } from './fixtures';
import { BASE, HostRig, MIN, Rig, S2, deflate, inflate, rollUp, runAll, start, stop, test } from './queryRig';

const m = (n: number, ms = 0): number => BASE + n * MIN + ms;
const V9 = sourceKeyFor('v9', EXPORTER, 1);

// --- v9 datagrams ------------------------------------------------------------------------------------------

const F = (type: number, length: number): WireField => ({ type, length });
const BASIC: WireField[] = [F(8, 4), F(12, 4), F(7, 2), F(11, 2), F(4, 1), F(1, 4), F(2, 4)];
const TEMPLATE_ID = 300;
const record = (src: string, dst: string, octets: number, packets: number): number[] =>
  be.concat(be.ipv4(src), be.ipv4(dst), be.u16(1000), be.u16(80), be.u8(6), be.u32(octets), be.u32(packets));

let v9Sequence = 0;
/** A v9 export received at `receivedMs`, its header's clock agreeing with the receipt time and its uptime always rising. */
function v9(receivedMs: number, sets: number[][]): EvidenceInput {
  const bytes = v9Message({ uptime: receivedMs - BASE + 1_000_000, secs: Math.floor(receivedMs / 1000), sequence: v9Sequence++, sourceId: 1 }, sets);
  return { kind: 'datagram', receivedMs, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}
const template = (receivedMs: number): EvidenceInput => v9(receivedMs, [templateSet(9, [templateRecord(9, TEMPLATE_ID, BASIC)])]);
const data = (receivedMs: number, records: number[][]): EvidenceInput => v9(receivedMs, [dataSet(TEMPLATE_ID, records)]);
const TWO = [record('10.0.0.1', '10.0.0.2', 100, 2), record('10.0.0.3', '10.0.0.4', 50, 1)];

/** The minutes of one source the sidecar holds, decoded. */
function minutesOf(rig: Rig, key: string) {
  return rig.store.readMinutes(key, 0, Number.MAX_SAFE_INTEGER, 1 << 30).map((x) => decodeMinuteRollup(x.bytes, inflate));
}

/** Counts every `readPage` a runtime is asked for, by where it starts. */
function spyReads(rig: Rig): number[] {
  const starts: number[] = [];
  const inner = rig.runtime.readPage.bind(rig.runtime);
  rig.runtime.readPage = async (snapshot, afterId, maxEntries, maxBytes) => {
    starts.push(afterId);
    return inner(snapshot, afterId, maxEntries, maxBytes);
  };
  return starts;
}

/** The journal's segments rewritten as the 1.5 build wrote them: decoder policy 1 in every header. */
function asPolicyOne(dir: MemorySegmentDirectory): MemorySegmentDirectory {
  const files: Record<string, Uint8Array> = {};
  for (const name of dir.list()) {
    const file = dir.open(name);
    const bytes = new Uint8Array(file.size());
    file.read(0, bytes);
    const header = decodeSegmentHeader(bytes);
    if (!header.ok) throw new Error(`${name}: ${header.reason}`);
    bytes.set(encodeSegmentHeader({ ...header.value, policyVersion: 1 }), 0);
    files[name] = bytes;
  }
  return new MemorySegmentDirectory(files);
}

// --- planCheckpoints: the spacing ---------------------------------------------------------------------------

const OPTIONS = { spacingBytes: 1000, stopMs: 60 * MIN, maxBodyBytes: ROLLUP_FRAMING.maxBodyBytes, maxPerBatch: 4 };
const raw = (n: number): Uint8Array => Uint8Array.from({ length: 8 }, (_, i) => (n + i) & 0xff);
const seg = (firstEntryId: number, lastEntryId: number, bytes: number, policy = 2): SegmentGeometry => ({ firstEntryId, lastEntryId, bytes, policy });
const role1 = (segmentFirstId: number, ms: number): CheckpointCandidate => ({ role: 1, throughEntryId: segmentFirstId - 1, throughMs: ms, raw: raw(segmentFirstId) });
const role2 = (stopId: number, ms: number): CheckpointCandidate => ({ role: 2, throughEntryId: stopId, throughMs: ms, raw: raw(stopId) });
const base: CheckpointSpacing = { role1Through: 0, latestMs: m(0), storedThrough: 0 };

test('plan: role 1 is written at the first segment start at least the spacing past the last one, and moves the anchor', () => {
  const geometry = [seg(1, 10, 600), seg(11, 20, 600), seg(21, 30, 600), seg(31, 40, 100)];
  const r = planCheckpoints([role1(11, m(1)), role1(21, m(2)), role1(31, m(3))], 40, geometry, base, deflate, OPTIONS);
  // Segment 1 alone is 600 bytes: under the spacing. Segments 1 and 2 are 1200: over, so a role-1 at 21.
  // From there segment 3 alone is 600: under.
  assert.deepEqual(r.write.map((c) => [c.role, c.throughEntryId]), [[1, 20]]);
  assert.equal(r.spacing.role1Through, 20);
  assert.equal(r.spacing.latestMs, m(2));
  assert.equal(r.spacing.storedThrough, 20);
  assert.deepEqual(r.pending, [], 'decided candidates are not kept');
  assert.deepEqual(r.write[0].bytes, deflate(raw(21)), 'the bytes are the deflated checkpoint');
});

test('plan: role 2 is written at a stop only an hour of receipt time after the latest kind-3 entry, of either role', () => {
  const r = planCheckpoints([role2(5, m(30)), role2(9, m(61)), role2(12, m(100))], 20, null, base, deflate, OPTIONS);
  assert.deepEqual(r.write.map((c) => [c.role, c.throughEntryId]), [[2, 9]], 'm(30) is too soon after the base; m(100) too soon after m(61)');
  const after1 = planCheckpoints([role1(11, m(70)), role2(15, m(100))], 20, [seg(1, 10, 5000), seg(11, 20, 10)], base, deflate, OPTIONS);
  assert.deepEqual(after1.write.map((c) => [c.role, c.throughEntryId]), [[1, 10]], 'a role-1 entry resets the hour too');
});

test('plan: a candidate past the batch\'s watermark waits; one at or below what the sidecar holds is dropped', () => {
  const r = planCheckpoints([role2(5, m(61)), role2(9, m(200))], 8, null, { ...base, storedThrough: 5 }, deflate, OPTIONS);
  assert.deepEqual(r.write, []);
  assert.deepEqual(r.pending.map((c) => c.throughEntryId), [9]);
  // The same through twice (a stop that ends a segment, then the next segment's start): written once.
  const twice = planCheckpoints([role2(10, m(61)), role1(11, m(61))], 20, [seg(1, 10, 5000), seg(11, 20, 10)], base, deflate, OPTIONS);
  assert.deepEqual(twice.write.map((c) => [c.role, c.throughEntryId]), [[2, 10]]);
});

test('plan: a checkpoint over the sidecar\'s entry body is skipped, and does not move the spacing', () => {
  const big: CheckpointCandidate = { role: 2, throughEntryId: 9, throughMs: m(61), raw: Uint8Array.from({ length: 64 }, (_, i) => (i * 97) & 0xff) };
  const r = planCheckpoints([big], 20, null, base, deflate, { ...OPTIONS, maxBodyBytes: 24 + 10 });
  assert.deepEqual(r.write, []);
  assert.deepEqual(r.pending, []);
  assert.deepEqual(r.spacing, base);
});

test('plan: at most maxPerBatch are written, the rest wait for the next batch', () => {
  const stops = [1, 2, 3, 4, 5, 6].map((i) => role2(i * 10, m(i * 61)));
  const r = planCheckpoints(stops, 100, null, base, deflate, OPTIONS);
  assert.deepEqual(r.write.map((c) => c.throughEntryId), [10, 20, 30, 40]);
  assert.deepEqual(r.pending.map((c) => c.throughEntryId), [50, 60]);
});

// --- the host -----------------------------------------------------------------------------------------------

test('tail catch-up: starts at the sidecar\'s checkpoint, and data after the watermark decodes by a template before it', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), template(m(1)), data(m(2), TWO), template(m(65)), stop(m(70))]);
  const stopId = rig.through;
  await rollUp(rig);
  assert.deepEqual(rig.store.checkpoints().map((c) => [c.role, c.throughEntryId]), [[2, stopId]], 'a role-2 checkpoint at a stop an hour after the base');
  assert.equal(rig.store.watermark()?.throughEntryId, stopId);

  rig.append([start(m(71), S2), data(m(72), TWO), stop(m(73), S2)]);
  rig.reopen();
  const reads = spyReads(rig);
  await rollUp(rig);
  assert.ok(reads.length > 0 && reads.every((after) => after >= stopId), `nothing before the checkpoint is read again: ${reads.join(',')}`);
  const minute = minutesOf(rig, V9).find((r) => r.minuteMs === m(72));
  assert.ok(minute !== undefined, 'the minute after the watermark is rolled up under its v9 source');
  assert.equal(minute.records, 2);
  assert.equal(minute.reportedOctets, 150n);
  assert.equal(minute.awaitingSets, 0, 'the template from before the watermark is known');
});

test('policy-1-cache-under-policy-2: the 1.5 cache opens ok and is continued; its minutes keep policy 1, new ones are policy 2', async () => {
  const old = new Rig();
  old.append([start(m(0)), template(m(1)), data(m(1, 10), TWO), stop(m(2))]);
  const rig = new Rig(0xa0, 1 << 30, asPolicyOne(old.jdir));
  await rollUp(rig);
  const oldMark = rig.store.watermark();
  assert.ok(oldMark !== null);
  assert.equal(oldMark.policyVersion, 1, 'a cache of policy-1 minutes says policy 1');
  // The 1.5 build wrote the sidecar's header under policy 1 too.
  const header = new Uint8Array(64);
  rig.sfile.read(0, header);
  const parsed = decodeFileHeader(ROLLUP_FRAMING, header);
  assert.ok(parsed.ok);
  rig.sfile.write(0, encodeFileHeader(ROLLUP_FRAMING, { generation: parsed.generation, createdMs: parsed.createdMs, policyVersion: 1 }));

  rig.reopen();
  rig.append([start(m(10), S2), template(m(11)), data(m(11, 10), TWO), stop(m(12), S2)]);
  rig.reopen();
  assert.equal(rig.sidecarStatus, 'ok', 'not rebuild-required');
  const reads = spyReads(rig);
  await rollUp(rig);
  assert.ok(reads.every((after) => after >= oldMark.throughEntryId), `no full rebuild: ${reads.join(',')}`);
  const exporterMinute = minutesOf(rig, EXPORTER).find((r) => r.minuteMs === m(1));
  assert.ok(exporterMinute !== undefined && exporterMinute.policy === 1 && exporterMinute.unsupported === 2, 'v9 under policy 1 stays unsupported');
  const v9Minute = minutesOf(rig, V9).find((r) => r.minuteMs === m(11));
  assert.ok(v9Minute !== undefined, 'v9 decodes past the watermark');
  assert.equal(v9Minute.policy, 2);
  assert.equal(v9Minute.records, 2);
  assert.equal(rig.store.watermark()?.policyVersion, 2);
});

test('live checkpoint: the stop an hour after the base writes one, and it equals a state replayed from empty', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), template(m(1)), data(m(2), TWO)]);
  const h = await rollUp(rig);
  const added = rig.add(template(m(65)), stop(m(70)));
  rig.runtime.publishLive(added);
  await h.host.settled();
  const stopId = rig.through;
  assert.deepEqual(rig.store.checkpoints().map((c) => [c.role, c.throughEntryId]), [[2, stopId]]);
  const stored = rig.store.readCheckpoint(stopId);
  assert.ok(stored !== null);
  const replayed = DecodeState.empty();
  for (const e of readAll(rig)) replayed.step(e);
  assert.deepEqual(inflate(stored, LIMITS.checkpointBytes), replayed.checkpoint());
});

test('reopen at the end: nothing after the watermark, and a live v9 datagram still decodes by the template before it', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), template(m(1)), data(m(2), TWO), template(m(65)), stop(m(70))]);
  await rollUp(rig);
  rig.reopen();
  const h = await rollUp(rig);
  rig.runtime.publishLive(rig.add(start(m(71), S2), data(m(72), TWO), stop(m(73), S2)));
  await h.host.settled();
  const minute = minutesOf(rig, V9).find((r) => r.minuteMs === m(72));
  assert.ok(minute !== undefined, 'the live minute is rolled up under its v9 source');
  assert.equal(minute.records, 2);
  assert.equal(minute.awaitingSets, 0, 'the state was prepared though there was nothing to catch up');
});

function readAll(rig: Rig): Evidence[] {
  const snap = rig.journal.snapshot();
  const out: Evidence[] = [];
  let after = 0;
  for (;;) {
    const page = rig.journal.readPage(snap, after, 256, 1 << 20);
    out.push(...page.entries);
    after = page.nextAfterId;
    if (page.done) return out;
  }
}

test('health: a v9 source gets its own row, its awaiting sets counted, and the exporter snapshot lists its template', async () => {
  const rig = new Rig();
  rig.append([start(m(0))]);
  const h = new HostRig(rig.runtime);
  h.wall = BASE;
  await h.connect();
  for (const input of [data(m(1), TWO), template(m(1, 5)), data(m(1, 10), TWO)]) {
    rig.runtime.publishLive(rig.add(input));
    await h.host.settled();
  }
  h.tick();
  const last = h.healthPosts().at(-1);
  assert.ok(last !== undefined && last.health !== null);
  const row = last.health.templateSources.find((s) => s.sourceKey === V9);
  assert.ok(row !== undefined, 'a v9 row');
  assert.equal(row.accepted, 3);
  assert.equal(row.flows, 2);
  assert.equal(row.awaitingSets, 1, 'the data before its template');
  assert.equal(last.health.unsupported, 0, 'v9 is not unsupported');
  assert.ok(last.sources.includes(V9));
  const exporter = last.exporters.find((x) => x.sourceKey === V9);
  assert.ok(exporter !== undefined);
  assert.deepEqual(exporter.templates.map((t) => t.id), [TEMPLATE_ID]);
  assert.equal(exporter.protocol, 'v9');
});

test('detail: a v9 record is decoded by the template an earlier entry defined', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), template(m(1)), data(m(2), TWO)]);
  const h = await rollUp(rig);
  const snapshot = rig.journal.snapshot();
  const id = h.send({ type: 'detail', snapshot, ref: { generation: rig.generation, entryId: rig.through }, recordIndex: 1 });
  const reply = await h.waitFor(() => h.repliesTo(id)[0], 'the detail reply');
  assert.ok(reply.type === 'detail-reply' && reply.ok, JSON.stringify(reply, (_, v) => (typeof v === 'bigint' ? String(v) : v)));
  assert.equal(reply.record.srcAddr, '10.0.0.3');
  assert.equal(reply.record.reportedOctets, 50n);
});

process.exit((await runAll()) === 0 ? 0 : 1);
