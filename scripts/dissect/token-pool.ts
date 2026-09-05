/**
 * Assertion tests for the shared per-frame lists.
 *
 *   npx tsx scripts/dissect/token-pool.ts
 *
 * `frameProtocols`, `analysisFlags` and `expert` are short lists with very few
 * distinct values across a capture - 21, 13 and 209 over both fixtures - so one
 * array per distinct list replaces one per frame, worth 204 B a frame
 * (`scripts/perf/record-cost.ts`, `docs/decisions/0016`).
 *
 * Pooling turns a per-frame value into **shared mutable state**, and that is
 * the whole risk. A list handed to ten thousand frames is one object; anything
 * that writes to it rewrites what all ten thousand report, and the symptom
 * would be a capture that disagrees with itself rather than an error. So what
 * is held here is not that pooling saves memory - the measurement says that -
 * but that it cannot corrupt anything:
 *
 *   - equal lists come back identical, or there is no saving;
 *   - **unequal lists never do**, including the orderings and the delimiter
 *     collisions that a naive key would confuse;
 *   - order is preserved exactly, because the protocol hierarchy reads it;
 *   - the pooled array is frozen, so a writer fails loudly instead of quietly;
 *   - the pool is bounded, and degrades to unpooled rather than to wrong.
 */
import {
  clearTokenPool, poolExpert, poolTokens, pooledListCounts,
} from '../../src/services/dissect/tokenPool';
import type { ExpertInfo } from '../../src/types/packet';

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

// --- Equal lists share; unequal ones never do ---------------------------------
{
  clearTokenPool();
  const a = poolTokens(['frame', 'eth', 'ip', 'tcp']);
  const b = poolTokens(['frame', 'eth', 'ip', 'tcp']);
  checkTrue('two equal chains are the same array', a === b);
  check('...with the contents unchanged', [...a], ['frame', 'eth', 'ip', 'tcp']);

  const c = poolTokens(['frame', 'eth', 'ip', 'udp']);
  checkTrue('a different chain is a different array', a !== c);

  // Order is the meaning here: the protocol hierarchy reads `frameProtocols`
  // in nesting order, so a token's position is what makes it a child of the
  // layer before it. Two chains with the same tokens in different orders are
  // two different chains and must not be conflated.
  const forward = poolTokens(['ip', 'tcp', 'tls']);
  const reversed = poolTokens(['tls', 'tcp', 'ip']);
  checkTrue('a reordered chain is not the same chain', forward !== reversed);
  check('...and keeps its own order', [...reversed], ['tls', 'tcp', 'ip']);

  // The key is built by joining, so the separator has to be something a token
  // cannot contain. `join(':')` would make these two collide - and
  // `frameProtocols` really is joined with `:` elsewhere in the app, which is
  // exactly where that idea would have come from.
  const split = poolTokens(['a', 'b']);
  const joined = poolTokens(['a:b']);
  checkTrue('["a","b"] and ["a:b"] are different lists', split !== joined);
  check('...and the second keeps its single token', [...joined], ['a:b']);

  const empty1 = poolTokens([]);
  const empty2 = poolTokens([]);
  checkTrue('empty lists share too', empty1 === empty2);
  check('...and stay empty', [...empty1], []);
}

// --- A shared array must not be writable --------------------------------------
//
// The failure this prevents: one frame sorting or pushing to its
// `frameProtocols` would change what every other frame carrying that chain
// reports. Nothing does today; freezing is what keeps that true, by turning the
// mistake into a throw rather than a capture that quietly disagrees with itself.
{
  clearTokenPool();
  const chain = poolTokens(['frame', 'eth', 'arp']);
  checkTrue('a pooled chain is frozen', Object.isFrozen(chain));
  let threw = false;
  try { (chain as string[]).push('nonsense'); } catch { threw = true; }
  checkTrue('...so pushing to it throws', threw);
  check('...and it is unchanged', [...chain], ['frame', 'eth', 'arp']);
}

// --- Expert findings, one level deeper -----------------------------------------
{
  clearTokenPool();
  const retransmit = (): ExpertInfo[] => [
    { severity: 'warn', message: 'This frame is a (suspected) retransmission' },
  ];
  const a = poolExpert(retransmit());
  const b = poolExpert(retransmit());
  checkTrue('two equal finding sets are the same array', a === b);
  checkTrue('...so the findings inside are shared too', a[0] === b[0]);
  check('...with the finding intact', a[0].message,
    'This frame is a (suspected) retransmission');

  // Severity is part of what a finding IS, so the same sentence at two
  // severities is two different findings - and the colour rules and the expert
  // tab both branch on it.
  const warn = poolExpert([{ severity: 'warn', message: 'same words' }]);
  const error = poolExpert([{ severity: 'error', message: 'same words' }]);
  checkTrue('the same message at a different severity is not shared', warn !== error);
  check('...and keeps its own severity', error[0].severity, 'error');

  // Two findings in one set, against the same two in the other order.
  const ab = poolExpert([
    { severity: 'note', message: 'a' }, { severity: 'note', message: 'b' },
  ]);
  const ba = poolExpert([
    { severity: 'note', message: 'b' }, { severity: 'note', message: 'a' },
  ]);
  checkTrue('finding order distinguishes two sets', ab !== ba);

  // A set of one finding whose message is the concatenation of two, against
  // the set of those two. Different lists; a careless key would agree.
  const one = poolExpert([{ severity: 'note', message: 'ab' }]);
  checkTrue('one joined message is not two findings', one !== ab);

  checkTrue('the expert pool is counted separately',
    pooledListCounts().expert > 0 && pooledListCounts().tokens === 0);
}

// --- Bounded, and degrading to unpooled rather than to wrong ---------------------
{
  clearTokenPool();
  // Past the cap the caller gets its own array back: still correct, merely not
  // shared. A capture with custom dissectors can legitimately produce a great
  // many chains, and an unbounded pool would be the leak this exists to avoid.
  const kept: string[][] = [];
  for (let i = 0; i < 5000; i++) kept.push(poolTokens(['proto' + i]));
  const count = pooledListCounts().tokens;
  checkTrue('the pool is bounded', count > 0 && count < 5000);

  const overflow = ['well', 'past', 'the', 'cap'];
  const returned = poolTokens(overflow);
  checkTrue('past the cap the caller gets its own array', returned === overflow);
  checkTrue('...unfrozen, since nothing else holds it', !Object.isFrozen(returned));
  check('...and correct', [...returned], ['well', 'past', 'the', 'cap']);

  // Everything admitted before the cap still answers.
  checkTrue('an early chain is still shared', poolTokens(['proto0']) === kept[0]);
}

// --- Clearing --------------------------------------------------------------------
{
  clearTokenPool();
  const before = poolTokens(['frame', 'eth']);
  clearTokenPool();
  const after = poolTokens(['frame', 'eth']);
  checkTrue('a cleared pool hands back a fresh array', before !== after);
  check('...equal to the old one', [...after], [...before]);
  check('...and the counts reset', pooledListCounts(), { tokens: 1, expert: 0 });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All token-pool checks passed.');
process.exit(0);
