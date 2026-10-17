/**
 * Assertion tests for what the monitoring Worker pushes about the source (ADRs 0059, 0060):
 * the `health` message and the `sources` list it carries.
 *
 *   npx tsx scripts/monitoring/health-push.ts
 *
 * A `MonitoringWorkerHost` over an in-memory runtime, with the monotonic clock and the tick
 * timer in the test's hands (`HostRig.tick`). The reducer's own rules are `health-budget.ts`;
 * what is here is the wiring: which entries feed the health, when it is posted, and what
 * stops it.
 */
import assert from 'node:assert/strict';
import { initialSourceHealth } from '../../src/services/monitoring/sourceHealth';
import { LIMITS, type Evidence } from '../../src/services/monitoring/types';
import { sourceKey } from '../../src/services/monitoring/v5';
import { EXPORTER } from './fixtures';
import {
  BASE, HostRig, MIN, Rig, SRC, SRC1, dgram, junk, rollUp, runAll, start, stop, test, v9,
} from './queryRig';

const m = (n: number, ms = 0): number => BASE + n * MIN + ms;
const OTHER = '192.0.2.99';

/** A rig with an open session, a host connected and caught up, and the connect's own post already counted. */
async function live(prefill: (rig: Rig) => void = () => undefined): Promise<{ rig: Rig; h: HostRig }> {
  const rig = new Rig();
  rig.append([start(m(0))]);
  prefill(rig);
  const h = new HostRig(rig.runtime);
  // The wall clock sits at the start of the journal's own hour, so an entry is never aged by the
  // distance between the rig's fixed `NOW` and its receipt times; the M2 tests move it on purpose.
  h.wall = BASE;
  const reply = await h.connect();
  assert.ok(reply.type === 'connect-reply' && reply.ok);
  assert.equal(h.host.rebuildPhase, 'live');
  return { rig, h };
}

/** Appends to the journal and announces it, as the utility does, then waits for the host to have consumed it. */
async function push(rig: Rig, h: HostRig, ...inputs: Parameters<Rig['add']>): Promise<Evidence[]> {
  const added = rig.add(...inputs);
  rig.runtime.publishLive(added);
  await h.host.settled();
  return added;
}

test('health: one post right after connect, with no health to report yet and the connect\'s sources', async () => {
  const { h } = await live();
  const posts = h.healthPosts();
  assert.equal(posts.length, 1);
  assert.equal(posts[0].health, null);
  assert.deepEqual(posts[0].sources, []);
  // And it came after the connect reply, not before.
  const types = h.posts.map((p) => p.type);
  assert.ok(types.indexOf('health') > types.indexOf('connect-reply'));
});

test('health: N datagrams inside one flush window make one post, at the next tick', async () => {
  const { rig, h } = await live();
  for (let i = 0; i < 5; i++) await push(rig, h, dgram(m(1, i), [{}], { sequence: i }));
  assert.equal(h.healthPosts().length, 1, 'nothing is posted per datagram');
  h.tick();
  const posts = h.healthPosts();
  assert.equal(posts.length, 2);
  const health = posts[1].health;
  assert.ok(health !== null);
  assert.equal(health.accepted, 5);
  assert.equal(health.engines[0].expectedSequence, 5);
  assert.equal(health.exporterIPv4, EXPORTER);
  // A tick in which only the clock moved posts nothing.
  h.tick();
  h.tick();
  assert.equal(h.healthPosts().length, 2);
  assert.equal(h.timers.count, 1, 'the next tick is scheduled');
  assert.deepEqual(h.timers.delays, [LIMITS.flushMs]);
});

test('health: entries already in the journal at connect are replay and update nothing (R7.2)', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{}]), dgram(m(1, 5), [{}], { sequence: 1 }), junk(m(1, 9))]);
  const h = await rollUp(rig);
  h.wall = BASE;
  h.tick();
  h.tick();
  for (const p of h.healthPosts()) assert.equal(p.health, null, 'replay never makes a health');
  // The sources the replay admitted are still reported: that is the Worker's own fact.
  assert.deepEqual(h.healthPosts().at(-1)?.sources, [SRC]);
  // And the first live entry counts as one, not as four.
  rig.runtime.publishLive(rig.add(dgram(m(2), [{}], { sequence: 2 })));
  await h.host.settled();
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.accepted, 1);
  assert.equal(health.malformed, 0);
});

test('health: a hole read through to fill a missed push counts, because those entries arrived after connect', async () => {
  const { rig, h } = await live();
  rig.add(dgram(m(1), [{}], { sequence: 0 })); // appended, never announced
  const later = rig.add(dgram(m(1, 5), [{}], { sequence: 1 }));
  rig.runtime.publishLive(later);
  await h.host.settled();
  h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.accepted, 2);
});

test('health: malformed and unsupported datagrams are counted and do not make the source fresh', async () => {
  const { rig, h } = await live();
  await push(rig, h, junk(m(1)), v9(m(1, 1)));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.malformed, 1);
  assert.equal(health.unsupported, 1);
  assert.equal(health.freshness, 'never');
  assert.equal(health.accepted, 0);
});

test('health: a valid datagram carries its own sequence, record count, entry id and receipt time', async () => {
  const { rig, h } = await live();
  const [a] = await push(rig, h, dgram(m(1, 500), [{}, {}], { sequence: 100, engineType: 0, engineId: 0 }));
  await push(rig, h, dgram(m(1, 600), [{}], { sequence: 105 }));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  const engine = health.engines[0];
  assert.equal(engine.sourceKey, SRC);
  assert.equal(engine.flows, 3);
  assert.equal(engine.gaps, 1, '102 was expected and 105 arrived');
  assert.equal(engine.jumpedFlows, 3);
  assert.equal(engine.lastSequence, 105);
  assert.equal(engine.expectedSequence, 106);
  assert.equal(health.lastValidWallMs, m(1, 600));
  assert.equal(health.lastValidEntryId, a.ref.entryId + 1);
  assert.equal(health.freshness, 'fresh');
});

test('health: fresh turns stale after staleMs of ticks with no datagram, and that flip is posted', async () => {
  const { rig, h } = await live();
  h.clock = 1000;
  await push(rig, h, dgram(m(1), [{}]));
  h.tick(); // clock 2000: the datagram is seen
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'fresh');
  const after = h.healthPosts().length;
  // Up to just short of staleMs after the datagram, ticks change only the clock.
  while (h.clock + LIMITS.flushMs - 1000 < LIMITS.staleMs) h.tick();
  assert.equal(h.clock - 1000, LIMITS.staleMs - LIMITS.flushMs);
  assert.equal(h.healthPosts().length, after, 'no post while nothing but the clock changed');
  h.tick();
  assert.equal(h.clock - 1000, LIMITS.staleMs);
  assert.equal(h.healthPosts().length, after + 1);
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'stale');
  h.tick();
  assert.equal(h.healthPosts().length, after + 1, 'and stale is not posted again');
});

test('health: a datagram from another exporter address starts a fresh health for it', async () => {
  const { rig, h } = await live();
  await push(rig, h, dgram(m(1), [{}], { sequence: 7 }));
  await push(rig, h, dgram(m(1, 5), [{}], { sequence: 1 }, OTHER));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.exporterIPv4, OTHER);
  assert.equal(health.accepted, 1, 'the earlier exporter\'s counts are not carried over');
  assert.equal(health.engines.length, 1);
  assert.equal(health.engines[0].sourceKey, sourceKey(OTHER, 0, 0));
  assert.equal(health.engines[0].expectedSequence, 2);
});

test('sources: the connect\'s sources plus every engine admitted since, sorted and without duplicates', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{}], { engineId: 1 }), dgram(m(1, 1), [{}], { engineId: 0 }), stop(m(2))]);
  await rollUp(rig);
  const h = new HostRig(rig.runtime);
  h.wall = BASE;
  await h.connect();
  assert.deepEqual(h.healthPosts()[0].sources, [SRC, SRC1], 'what the sidecar knew, sorted');
  rig.runtime.publishLive(rig.add(start(m(3, 0), 's2')));
  await h.host.settled();
  await push(rig, h, dgram(m(3, 5), [{}], { engineId: 9 }), dgram(m(3, 6), [{}], { engineId: 1 }), dgram(m(3, 7), [{}], { engineId: 9 }));
  h.tick();
  assert.deepEqual(h.healthPosts().at(-1)?.sources, [SRC, SRC1, sourceKey(EXPORTER, 0, 9)]);
});

test('sources: a change in the list alone is posted, and an unchanged one is not', async () => {
  const { rig, h } = await live();
  h.tick();
  assert.equal(h.healthPosts().length, 1);
  await push(rig, h, dgram(m(1), [{}]));
  h.tick();
  assert.equal(h.healthPosts().length, 2);
  await push(rig, h, dgram(m(1, 5), [{}], { sequence: 1 }));
  h.tick();
  assert.equal(h.healthPosts().length, 3, 'the counts changed');
});

test('health: a datagram from an engine the Worker did not admit is counted against the limit and given no row', async () => {
  const rig = new Rig();
  const sixteen = Array.from({ length: LIMITS.enginesPerExporter }, (_, i) => dgram(m(1, i), [{}], { engineId: i }));
  rig.append([start(m(0)), ...sixteen, stop(m(2))]);
  await rollUp(rig);
  rig.append([start(m(3), 's2')]);
  const h = new HostRig(rig.runtime);
  h.wall = BASE;
  await h.connect();
  await push(rig, h, dgram(m(3, 5), [{}], { engineId: LIMITS.enginesPerExporter }));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.engineLimitRejected, 1);
  assert.equal(health.engines.length, 0);
  assert.equal(health.freshness, 'never');
  assert.ok(!h.healthPosts().at(-1)?.sources.includes(sourceKey(EXPORTER, 0, LIMITS.enginesPerExporter)));
});

test('health: the analyzed and rolled-up watermarks follow the entries and the acknowledged posts', async () => {
  const { rig, h } = await live();
  await push(rig, h, dgram(m(1), [{}]));
  await push(rig, h, dgram(m(2), [{}], { sequence: 1 })); // a later minute seals the first
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.analyzedThroughEntryId, rig.through);
  assert.ok(health.rolledUpThroughEntryId !== null && health.rolledUpThroughEntryId >= 1);
  assert.ok(health.rolledUpThroughEntryId <= health.analyzedThroughEntryId);
});

/** Fails a live host the way a generation change does: a push naming another generation. */
async function failRebuild(rig: Rig, h: HostRig): Promise<void> {
  const [entry] = rig.add(dgram(m(9), [{}], { sequence: 900 }));
  rig.runtime.publishLive([{ ...entry, ref: { ...entry.ref, generation: 'ff'.repeat(16) } }]);
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'failed');
}

test('health: ticks stop on shutdown and nothing is posted after', async () => {
  const a = await live();
  assert.equal(a.h.timers.count, 1);
  const id = a.h.send({ type: 'shutdown' });
  await a.h.waitFor(() => a.h.repliesTo(id)[0], 'the shutdown reply');
  assert.equal(a.h.timers.count, 0);
  const posted = a.h.posts.length;
  a.h.tick();
  assert.equal(a.h.posts.length, posted);

  // A failed host is shut down like any other.
  const b = await live();
  await failRebuild(b.rig, b.h);
  const idB = b.h.send({ type: 'shutdown' });
  await b.h.waitFor(() => b.h.repliesTo(idB)[0], 'the shutdown reply');
  assert.equal(b.h.timers.count, 0);
});

test('health: a failed rebuild does not stop the clock, so a silent source still goes stale (I1)', async () => {
  const { rig, h } = await live();
  h.clock = 1000;
  await push(rig, h, dgram(m(1), [{}]));
  h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'fresh');
  await failRebuild(rig, h);
  assert.equal(h.timers.count, 1, 'the tick is still armed');
  // No datagram for staleMs: nothing is being analyzed, but the exporter has gone quiet all the same.
  for (let waited = 0; waited < LIMITS.staleMs; waited += LIMITS.flushMs) h.tick();
  const last = h.healthPosts().at(-1)?.health;
  assert.ok(last);
  assert.equal(last.freshness, 'stale');
  assert.equal(last.accepted, 1);
});

test('health: a datagram that arrives after the rebuild failed still counts (I1)', async () => {
  const { rig, h } = await live();
  await failRebuild(rig, h);
  await push(rig, h, dgram(m(10), [{}, {}], { sequence: 901 }));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.accepted, 1);
  assert.equal(health.freshness, 'fresh');
  assert.equal(health.engines[0].flows, 2);
});

test('health: with the sidecar failing at connect, live datagrams still make a health and a source list (I1)', async () => {
  const rig = new Rig();
  rig.append([start(m(0))]);
  rig.runtime.watermark = async () => { throw new Error('the sidecar cannot be read'); };
  const h = new HostRig(rig.runtime);
  h.wall = BASE;
  const reply = await h.connect();
  assert.ok(reply.type === 'connect-reply' && reply.ok && reply.phase === 'failed');
  assert.equal(h.timers.count, 1, 'a failed connect still ticks');
  await push(rig, h, dgram(m(1), [{}], { sequence: 0 }), dgram(m(1, 5), [{}, {}], { sequence: 1 }), junk(m(1, 9)));
  h.tick();
  const post = h.healthPosts().at(-1);
  assert.ok(post?.health);
  assert.equal(post.health.accepted, 2);
  assert.equal(post.health.malformed, 1);
  assert.equal(post.health.freshness, 'fresh');
  assert.deepEqual(post.sources, [SRC]);
  // The same silence turns it stale.
  for (let waited = 0; waited < LIMITS.staleMs; waited += LIMITS.flushMs) h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'stale');
});

test('health: an entry fed late carries its real age, so a source that went quiet during a long rebuild is stale (M2)', async () => {
  const { rig, h } = await live();
  h.clock = 500_000;
  // Received 100 s before the host feeds it.
  h.wall = m(1) + 100_000;
  await push(rig, h, dgram(m(1), [{}]));
  h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'stale', '100 s old on arrival is past staleMs');
});

test('health: an entry fed late stays fresh until its real age reaches staleMs (M2)', async () => {
  const { rig, h } = await live();
  h.clock = 500_000;
  const age = 10_000;
  h.wall = m(1) + age;
  await push(rig, h, dgram(m(1), [{}]));
  h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'fresh');
  while (h.clock - 500_000 + age + LIMITS.flushMs < LIMITS.staleMs) h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'fresh', 'just short of staleMs of real age');
  h.tick();
  assert.equal(h.healthPosts().at(-1)?.health?.freshness, 'stale');
});

test('health: an entry stamped in the future of this clock is not aged (M2)', async () => {
  const { rig, h } = await live();
  h.clock = 500_000;
  h.wall = m(1) - 5_000; // the wall clock stepped back
  await push(rig, h, dgram(m(1), [{}]));
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.freshness, 'fresh');
  assert.equal(health.lastValidElapsedMs, 500_000);
});

test('health: replay moves neither watermark, including the rolled-up one (M1, R7.2)', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{}]), dgram(m(1, 5), [{}], { sequence: 1 }), stop(m(2))]);
  const h = await rollUp(rig);
  h.wall = BASE;
  const floor = rig.through;
  // The rebuild posted the replayed minute to the sidecar, so its watermark is the replay's.
  assert.equal(rig.store.watermark()?.throughEntryId, floor);
  // A live datagram in a later minute seals nothing that was open, so nothing new is rolled up.
  rig.runtime.publishLive(rig.add(start(m(4), 's2'), dgram(m(5), [{}], { sequence: 2 })));
  await h.host.settled();
  h.tick();
  const health = h.healthPosts().at(-1)?.health;
  assert.ok(health);
  assert.equal(health.analyzedThroughEntryId, floor + 2);
  assert.equal(health.rolledUpThroughEntryId, null, 'the sidecar watermark the replay left is not a live fact');
});

test('health: a host given no timer posts the connect\'s health and nothing else', async () => {
  const rig = new Rig();
  rig.append([start(m(0))]);
  const h = new HostRig(rig.runtime, { setTimer: undefined });
  await h.connect();
  rig.runtime.publishLive(rig.add(dgram(m(1), [{}])));
  await h.host.settled();
  assert.equal(h.healthPosts().length, 1);
});

test('health: a fresh health for an unseen exporter is what initialSourceHealth makes (the reducer\'s start)', () => {
  assert.equal(initialSourceHealth(OTHER).exporterIPv4, OTHER);
});

process.exit((await runAll()) === 0 ? 0 : 1);
