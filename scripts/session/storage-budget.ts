/**
 * Assertion tests for the storage budget's eviction.
 *
 *   npx tsx scripts/session/storage-budget.ts
 *
 * Since `docs/decisions/0012` a stored capture is discarded only when the user
 * asks - with exactly one exception, which is this. When a session outgrows
 * `STORAGE_BUDGET_BYTES` the oldest frames stop being stored, so a long capture
 * quietly loses its beginning.
 *
 * That is the right end to drop, since the recent frames are the ones on
 * screen, and the wrong end to drop silently, since the beginning is the half a
 * user is least likely to notice missing. So the two properties held here are:
 * it drops the least it can, and it reports exactly how much it dropped, so the
 * app can say so.
 */
import { planBudgetEviction } from '../../src/services/sessionStore';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** A ledger of `n` frames of `bytes` each, ids from `firstId`. */
const ledger = (n: number, bytes: number, firstId = 1) =>
  Array.from({ length: n }, (_, i) => ({ id: firstId + i, bytes }));

// --- Under budget: nothing is touched ---------------------------------------------
{
  const l = ledger(10, 100);
  const plan = planBudgetEviction(l, 1000, 5000);
  check('a session inside its budget evicts nothing', plan.evictCount, 0);
  check('...and keeps every byte', plan.remainingBytes, 1000);
  check('...and moves no floor', plan.dropUpTo, 0);

  // Exactly at the budget is not over it. An off-by-one here would throw away
  // history the moment a session reached its limit rather than passed it.
  check('exactly at the budget evicts nothing', planBudgetEviction(l, 5000, 5000).evictCount, 0);
}

// --- Over budget: the least that gets back under -----------------------------------
{
  const l = ledger(10, 100);          // 1000 bytes, ids 1..10
  const plan = planBudgetEviction(l, 1000, 950);
  check('one frame over evicts one frame', plan.evictCount, 1);
  check('...leaving it under budget', plan.remainingBytes, 900);
  checkTrue('...which is actually under', plan.remainingBytes <= 950);
  // Exclusive: the floor names the first id still kept, not the last dropped.
  check('...and the floor is the first id still kept', plan.dropUpTo, 2);

  const half = planBudgetEviction(l, 1000, 500);
  check('half over evicts half', half.evictCount, 5);
  check('...and reports what is left', half.remainingBytes, 500);
  check('...with the floor past the fifth frame', half.dropUpTo, 6);
}

// --- The floor is an id, not a count ----------------------------------------------
//
// A trimmed session does not start at frame 1, and using the index as the floor
// would delete the wrong frames entirely.
{
  const l = ledger(5, 100, 40_001);
  const plan = planBudgetEviction(l, 500, 250);
  check('a session that starts at 40,001 evicts from there', plan.evictCount, 3);
  check('...and the floor is a real frame id', plan.dropUpTo, 40_004);
}

// --- Frames are not all the same size ----------------------------------------------
//
// 50,000 small ACKs and 50,000 offload frames differ by orders of magnitude,
// which is the whole reason the budget is in bytes and not in frames.
{
  const mixed = [
    { id: 1, bytes: 9000 },
    { id: 2, bytes: 60 },
    { id: 3, bytes: 60 },
    { id: 4, bytes: 60 },
  ];
  const plan = planBudgetEviction(mixed, 9180, 1000);
  check('one large frame can be enough on its own', plan.evictCount, 1);
  check('...and the small ones behind it are kept', plan.remainingBytes, 180);
}

// --- It cannot loop past the end ---------------------------------------------------
//
// A budget smaller than a single frame must stop when the ledger runs out
// rather than spinning or reporting more evictions than there were frames.
{
  const l = ledger(3, 100);
  const plan = planBudgetEviction(l, 300, 0);
  check('an impossible budget evicts everything and stops', plan.evictCount, 3);
  check('...reporting nothing left', plan.remainingBytes, 0);
  check('an empty ledger evicts nothing', planBudgetEviction([], 500, 0).evictCount, 0);
}

// --- The count is what the UI reports ----------------------------------------------
//
// The number the panel shows is this one, so it must be the number of frames
// that stopped being restorable - not bytes, not a floor, not an index.
{
  const l = ledger(100, 10);
  const plan = planBudgetEviction(l, 1000, 550);
  check('the count is frames, and is exact', plan.evictCount, 45);
  checkTrue('...and matches the bytes actually freed',
    1000 - plan.remainingBytes === plan.evictCount * 10);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All storage-budget checks passed.');
process.exit(0);
