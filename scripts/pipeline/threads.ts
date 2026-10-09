/**
 * Multi Threaded Capture: what each setting runs on a given machine.
 *
 *   npx tsx scripts/pipeline/threads.ts
 */
import { autoShards, readThreads, shardsFor, threadChoices, THREAD_CHOICES } from '../../src/services/pipeline/threads';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}

check('1 is the single Worker on any machine', [2, 8, 24].map((c) => shardsFor(1, c)), [0, 0, 0]);
check('Auto leaves two cores and stops at six', [2, 4, 8, 24, 64].map((c) => autoShards(c)), [0, 2, 6, 6, 6]);
check('Auto is the single Worker when only one shard would fit', autoShards(3), 0);
check('a count is that many shards where the cores allow', [2, 4, 8, 16].map((n) => shardsFor(n as 2, 24)), [2, 4, 8, 16]);
check('...held one below the cores on a smaller machine', shardsFor(16, 8), 7);
check('...and never fewer than two', shardsFor(4, 2), 2);
check('a 24-core machine is offered every count', threadChoices(24), [...THREAD_CHOICES]);
check('an 8-core machine is offered what leaves the coordinator a core', threadChoices(8), [1, 2, 4, 6]);
check('a 2-core machine is offered 1 alone', threadChoices(2), [1]);
check('every offered count reads back', THREAD_CHOICES.map((n) => readThreads(n)), [...THREAD_CHOICES]);
check('Auto reads back', readThreads('auto'), 'auto');
check('anything else does not', [5, '4', null, 0, 1.5].map((v) => readThreads(v)), [null, null, null, null, null]);

console.log(failures === 0 ? '\nAll thread-setting checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
