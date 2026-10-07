/**
 * The public-identity lookup's retry rule (`src/services/lookupRetry.ts`).
 *
 *   npx tsx scripts/geoip/lookup-retry.ts
 *
 * The lookup now retries by itself instead of failing until the panel is
 * reopened. What has to hold is the bound: every attempt is a request to a
 * third party that shows in the user's own capture, so the budget must end,
 * a refusal must never be retried, and waiting for the connection must not
 * spend requests. And the component must actually go through this module,
 * or none of it is true of the app.
 */
import { readFileSync } from 'node:fs';
import { failureForStatus, nextRetry, RETRY_DELAYS_MS, type LookupFailure } from '../../src/services/lookupRetry';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}

/** How many requests a lookup failing the same way every time makes, the first included. */
function requestsUntilStop(failure: LookupFailure): number {
  let requests = 1;
  for (let retries = 0; retries < 100; ) {
    const step = nextRetry(failure, retries);
    if (step.kind === 'stop') return requests;
    if (step.kind === 'after') { retries++; requests++; }
    else return Infinity;   // waits for the connection: no request until then
  }
  return Infinity;
}

check('a network failure is retried after a delay', nextRetry('network', 0), { kind: 'after', ms: RETRY_DELAYS_MS[0] });
check('...a growing one', RETRY_DELAYS_MS.every((ms, i) => i === 0 || ms > RETRY_DELAYS_MS[i - 1]), true);
check('...and the budget ends', requestsUntilStop('network'), RETRY_DELAYS_MS.length + 1);
check('a server error is retried within the same budget', requestsUntilStop('server'), RETRY_DELAYS_MS.length + 1);
check('a refusal is never retried', [nextRetry('refused', 0), requestsUntilStop('refused')], [{ kind: 'stop' }, 1]);
check('offline waits for the connection instead of a timer', nextRetry('offline', 0), { kind: 'when-online' });
check('...even with the budget spent, since waiting sends nothing', nextRetry('offline', RETRY_DELAYS_MS.length), { kind: 'when-online' });
check('the whole budget is under three minutes', RETRY_DELAYS_MS.reduce((a, b) => a + b, 0) <= 180_000, true);

check('2xx is success', [failureForStatus(200), failureForStatus(204)], [null, null]);
check('a rate limit and other 4xx are refusals', [failureForStatus(429), failureForStatus(403), failureForStatus(404)], ['refused', 'refused', 'refused']);
check('5xx is the server\'s trouble', [failureForStatus(500), failureForStatus(503)], ['server', 'server']);

const component = readFileSync('src/components/network/PublicIdentity.tsx', 'utf8');
check('the panel decides through nextRetry', /\bnextRetry\(/.test(component), true);
check('...and sorts statuses through failureForStatus', /\bfailureForStatus\(/.test(component), true);
check('...and keeps no delay of its own', /setTimeout\([^)]*\d{3,}/.test(component), false);
check('...and clears its timer and listener when it goes away',
  /clearTimeout\(timer\)/.test(component) && /removeEventListener\('online'/.test(component), true);

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll lookup retry checks passed.');
process.exit(0);
