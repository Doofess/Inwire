/**
 * `runQuitDrain`: the will-quit drain always ends in `settled`, which is what marks the drain done
 * and quits again (ADR 0058). A drain that rejects, or throws before it returns a promise, must not
 * leave the quit held behind `wait` for ever.
 *
 *   npx tsx scripts/monitoring/quit-drain.ts
 */
import assert from 'node:assert/strict';
import { planQuitDrain, runQuitDrain } from '../../electron/monitoring/quitDrain';

let passes = 0;
let failures = 0;

async function test(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`);
  }
}

/** What a caller sees of one run, in order. */
async function run(drain: () => Promise<string>): Promise<string[]> {
  const calls: string[] = [];
  await runQuitDrain(
    drain,
    (result) => { calls.push(`report:${result}`); },
    (error) => { calls.push(`fail:${(error as Error).message}`); },
    () => { calls.push('settled'); },
  );
  return calls;
}

async function main(): Promise<void> {
  await test('a drain that answers reports its result and then settles', async () => {
    assert.deepEqual(await run(async () => 'clean'), ['report:clean', 'settled']);
  });

  await test('a drain that rejects is reported as a failure and still settles', async () => {
    assert.deepEqual(await run(() => Promise.reject(new Error('utility gone'))), ['fail:utility gone', 'settled']);
  });

  await test('a drain that throws before it returns a promise is the same', async () => {
    assert.deepEqual(await run(() => { throw new Error('no host'); }), ['fail:no host', 'settled']);
  });

  await test('a report that throws is a failure too, and settled is still called once', async () => {
    const calls: string[] = [];
    await runQuitDrain(
      async () => 'x',
      () => { throw new Error('log failed'); },
      (error) => { calls.push(`fail:${(error as Error).message}`); },
      () => { calls.push('settled'); },
    );
    assert.deepEqual(calls, ['fail:log failed', 'settled']);
  });

  await test('settled still runs when the failure handler itself throws', async () => {
    let settled = 0;
    const p = runQuitDrain(
      () => Promise.reject(new Error('a')),
      () => undefined,
      () => { throw new Error('b'); },
      () => { settled++; },
    );
    await p.then(() => assert.fail('the failure handler threw, so the chain rejects with it'), (e) => assert.equal((e as Error).message, 'b'));
    assert.equal(settled, 1, 'settled still ran, which is the part a quit depends on');
  });

  await test('settled does not run before the drain has', async () => {
    let finish!: (v: string) => void;
    const order: string[] = [];
    const p = runQuitDrain(
      () => new Promise<string>((r) => { finish = r; }),
      () => { order.push('report'); },
      () => { order.push('fail'); },
      () => { order.push('settled'); },
    );
    await new Promise<void>((r) => setImmediate(r));
    assert.deepEqual(order, [], 'a drain in flight settles nothing');
    finish('done');
    await p;
    assert.deepEqual(order, ['report', 'settled']);
  });

  await test('planQuitDrain: a settled drain lets the app go, one in flight holds it, a running listener starts one', async () => {
    assert.equal(planQuitDrain({ running: true, draining: false, drained: true }), 'quit');
    assert.equal(planQuitDrain({ running: false, draining: true, drained: false }), 'wait');
    assert.equal(planQuitDrain({ running: true, draining: false, drained: false }), 'drain');
    assert.equal(planQuitDrain({ running: false, draining: false, drained: false }), 'quit');
  });

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
