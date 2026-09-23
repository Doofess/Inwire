/**
 * Assertion tests for what reverse DNS does to the network.
 *
 *   npx tsx scripts/geoip/reverse-dns-queue.ts
 *
 * `scripts/geoip/gating.ts` next door proves nothing is sent before consent.
 * This proves what is sent *after* it is something a person would recognise as
 * the thing they agreed to.
 *
 * `resolveHostname` fired one `fetch` per address from inside a loop over
 * newly-arrived packets, so a capture with 300 distinct remote hosts opened 300
 * simultaneous DNS-over-HTTPS streams. The geo endpoint one screen above it in
 * the same file already carries the comment about having been fixed for exactly
 * that - "a burst of simultaneous requests - which is what earned the 429s that
 * then poisoned the cache permanently" - and the DoH path never got the same
 * treatment.
 *
 * DoH cannot be batched the way geojs can: RFC 8484 carries one question per
 * query. So the bound is on concurrency, and concurrency is a property only a
 * test that counts *overlapping* requests can see - a count of total requests
 * looks identical either way, which is why this file exists rather than one
 * more assertion in `gating.ts`.
 *
 * Every `fetch` below is a stub. Nothing here touches a network.
 */
import {
  resetGeoCacheForTests,
  resetNameResolutionForTests,
  resolveHostname,
  setNameResolutionOptions,
} from '../../src/services/geoIpService';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The stub's bookkeeping: how many requests, and how many at once. */
interface Wire {
  total: number;
  concurrentPeak: number;
  names: string[];
}

/**
 * A `fetch` that answers PTR queries after a delay, and records the overlap.
 *
 * The delay is what makes the concurrency measurable at all: an instantly
 * resolving stub never has two requests in flight together, so a completely
 * unbounded implementation would measure a peak of 1 and pass.
 */
function stubFetch(wire: Wire, delayMs: number, answer: (name: string) => string | null): void {
  let live = 0;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    wire.total++;
    wire.names.push(url);
    live++;
    if (live > wire.concurrentPeak) wire.concurrentPeak = live;
    await sleep(delayMs);
    live--;
    const name = answer(url);
    return {
      ok: true,
      json: async () => (name === null ? {} : { Answer: [{ data: `${name}.` }] }),
    } as unknown as Response;
  }) as typeof fetch;
}

/**
 * A public IPv4 per index.
 *
 * **Not `203.0.113.x`.** TEST-NET-3 is the obvious choice for a test and
 * `classifyIP` calls it `reserved` on purpose - "TEST-NET shows up in tutorials
 * and synthetic traffic" - so `isLocatable` is false and `resolveHostname`
 * returns before it reaches the network. Every assertion below passed vacuously
 * on zero requests the first time this was written, which is the same shape of
 * silent pass the module it tests exists to prevent.
 */
const address = (i: number) => `51.75.${1 + Math.floor(i / 250)}.${i % 250}`;

async function main() {
  // --- The bound itself -----------------------------------------------------

  {
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: false, reverseDns: true });

    const wire: Wire = { total: 0, concurrentPeak: 0, names: [] };
    stubFetch(wire, 20, () => 'host.example');

    // 40 distinct addresses, asked for the way the map asks: a loop, no await
    // between them. This is the shape that produced 300 open streams.
    const asked = Array.from({ length: 40 }, (_, i) => resolveHostname(address(i)));
    const names = await Promise.all(asked);

    check('every address still gets its answer', names.filter((n) => n === 'host.example').length, 40);
    check('...and each was asked exactly once', wire.total, 40);
    // The number is `MAX_DOH_CONCURRENT`. Asserted as an upper bound rather
    // than an equality so tuning it down never fails this.
    checkTrue(`at most 4 requests were ever in flight at once (peak ${wire.concurrentPeak})`,
      wire.concurrentPeak <= 4);
    // And the lower half: a bound of 1 would pass the line above while making
    // 40 lookups take 40 round trips.
    checkTrue('...and more than one, so the queue is not serial',
      wire.concurrentPeak > 1);
  }

  // --- One request per address, however many callers ask --------------------

  {
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: false, reverseDns: true });

    const wire: Wire = { total: 0, concurrentPeak: 0, names: [] };
    stubFetch(wire, 10, () => 'shared.example');

    // The map asks once per address per tick, and ticks are 500 ms apart -
    // but a re-render inside one tick asks again while the first is in flight.
    const first = resolveHostname(address(9));
    const second = resolveHostname(address(9));
    const third = resolveHostname(address(9));
    const all = await Promise.all([first, second, third]);

    check('one address is one request', wire.total, 1);
    // The bug this replaces: callers 2 and 3 got `null` immediately, cached
    // nothing, and the real answer reached only whoever asked first.
    check('...and every caller gets the same answer, not null',
      all, ['shared.example', 'shared.example', 'shared.example']);
  }

  // --- A network failure is not a permanent "no hostname" -------------------

  {
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: false, reverseDns: true });

    const wire: Wire = { total: 0, concurrentPeak: 0, names: [] };
    globalThis.fetch = (async () => {
      wire.total++;
      throw new Error('offline');
    }) as typeof fetch;

    check('a failed lookup answers null', await resolveHostname(address(7)), null);
    // `remember` makes this distinction for geo results and this path did not:
    // it cached the null, so one blip left a host unnamed for the session.
    stubFetch(wire, 1, () => 'recovered.example');
    check('...and asking again actually asks again',
      await resolveHostname(address(7)), 'recovered.example');
    check('...which took two requests, not one', wire.total, 2);
  }

  // --- An address with no PTR record IS cached ------------------------------

  {
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: false, reverseDns: true });

    const wire: Wire = { total: 0, concurrentPeak: 0, names: [] };
    stubFetch(wire, 1, () => null);

    check('an address with no PTR record answers null', await resolveHostname(address(8)), null);
    await resolveHostname(address(8));
    await resolveHostname(address(8));
    // The other half of the same coin. Most addresses have no PTR record, so
    // not caching this would be one request per address per session for ever -
    // which is the failure mode that looks like "reverse DNS never works".
    check('...and is not asked about again', wire.total, 1);
  }

  // --- Turning the switch off stops what was already queued -----------------

  {
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: false, reverseDns: true });

    const wire: Wire = { total: 0, concurrentPeak: 0, names: [] };
    stubFetch(wire, 30, () => 'late.example');

    const asked = Array.from({ length: 40 }, (_, i) => resolveHostname(address(300 + i)));
    // Off one tick later, with most of the queue still waiting behind the
    // concurrency bound. Consent withdrawn has to reach the queue, not only
    // the front door - otherwise the bound turns "one burst" into "a trickle
    // that outlives the switch", which is worse rather than better.
    setNameResolutionOptions({ geoIp: false, reverseDns: false });
    const names = await Promise.all(asked);

    checkTrue(`the queue stopped well short of 40 (asked ${wire.total})`, wire.total < 40);
    check('...and no caller is left hanging', names.length, 40);
  }

  resetNameResolutionForTests();
  resetGeoCacheForTests();

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All reverse-DNS queue checks passed.');
  process.exit(0);
}

void main();
