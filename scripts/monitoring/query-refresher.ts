/**
 * The History's refresh loop (`queryRefresher.ts`), for the final review's CR1.
 *
 * The client keeps one query per view id and a new one supersedes the old, so a
 * 5 s tick that always asked again cancelled a query slower than 5 s on every
 * tick, and the chart never answered. The first test is that exact case: a
 * query that takes 12 s against ticks every 5 s, on a clock the test turns.
 */
import assert from 'node:assert/strict';
import { createQueryRefresher } from '../../src/services/monitoring/queryRefresher';
import { test, runAll } from './queryRig';

interface Ask { n: number; resolve(v: string): void; reject(e: unknown): void }

/** An `ask` the test answers by hand, with the number of times it was called. */
function rig() {
  const asks: Ask[] = [];
  const applied: string[] = [];
  const busy: boolean[] = [];
  const refresher = createQueryRefresher<string>({
    ask: () => new Promise<string>((resolve, reject) => { asks.push({ n: asks.length + 1, resolve, reject }); }),
    apply: (r) => applied.push(r),
    busy: (b) => busy.push(b),
  });
  return { asks, applied, busy, refresher };
}

const settle = async (): Promise<void> => { for (let i = 0; i < 5; i++) await Promise.resolve(); };

test('refresh: a query slower than the interval is never cancelled by the ticks', async () => {
  const r = rig();
  r.refresher.restart(); // t = 0: the view opens and asks
  assert.equal(r.asks.length, 1);
  // t = 5 s and t = 10 s: the query is still being read
  r.refresher.tick();
  r.refresher.tick();
  assert.equal(r.asks.length, 1, 'ticks while the query is pending ask nothing, so nothing is superseded');
  // t = 12 s: the reply arrives, and is the one shown
  r.asks[0]!.resolve('first');
  await settle();
  assert.deepEqual(r.applied, ['first'], 'the slow query was answered');
  // t = 15 s: the next tick asks again
  r.refresher.tick();
  assert.equal(r.asks.length, 2);
  r.asks[1]!.resolve('second');
  await settle();
  assert.deepEqual(r.applied, ['first', 'second']);
});

test('refresh: a change the user made supersedes what is pending, and the old reply is dropped', async () => {
  const r = rig();
  r.refresher.restart();
  r.refresher.restart();
  assert.equal(r.asks.length, 2, 'a restart always asks');
  r.asks[0]!.resolve('stale');
  await settle();
  assert.deepEqual(r.applied, [], 'the superseded reply is not shown');
  assert.equal(r.busy.at(-1), true, 'and does not clear the spinner of the query that replaced it');
  r.asks[1]!.resolve('current');
  await settle();
  assert.deepEqual(r.applied, ['current']);
  assert.equal(r.busy.at(-1), false);
});

test('refresh: a tick after a restart whose reply has not come asks nothing', async () => {
  const r = rig();
  r.refresher.restart();
  r.refresher.tick();
  assert.equal(r.asks.length, 1);
});

test('refresh: stop drops a reply still to come, and a tick afterwards asks again', async () => {
  const r = rig();
  r.refresher.restart();
  r.refresher.stop();
  r.asks[0]!.resolve('late');
  await settle();
  assert.deepEqual(r.applied, [], 'nothing is shown after stop');
  r.refresher.tick();
  assert.equal(r.asks.length, 2, 'a stopped refresher is not left believing a query is pending');
});

test('refresh: a rejected ask clears the pending state so the next tick can ask', async () => {
  const r = rig();
  r.refresher.restart();
  r.asks[0]!.reject(new Error('worker gone'));
  await settle();
  assert.deepEqual(r.applied, []);
  assert.equal(r.busy.at(-1), false, 'the spinner is cleared');
  r.refresher.tick();
  assert.equal(r.asks.length, 2);
});

test('refresh: ticks over many intervals ask once per answered query, not once per tick', async () => {
  const r = rig();
  r.refresher.restart();
  // 60 s of 5 s ticks against a 12 s query
  let answered = 0;
  for (let t = 5; t <= 60; t += 5) {
    r.refresher.tick();
    const open = r.asks.find((_a, i) => i === answered && t >= (answered + 1) * 12);
    if (open) { open.resolve(`r${answered}`); answered++; await settle(); }
  }
  assert.ok(r.applied.length >= 3, `answers came through: ${r.applied.length}`);
  assert.ok(r.asks.length <= answered + 1, `${r.asks.length} asks for ${answered} answers`);
});

process.exit((await runAll()) === 0 ? 0 : 1);
