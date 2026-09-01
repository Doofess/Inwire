/**
 * Assertion tests for the name-resolution gate.
 *
 *   npx tsx scripts/geoip/gating.ts
 *
 * This is the one part of the feature carrying a promise to the user - the
 * settings copy names two third-party endpoints and says nothing is sent until
 * you turn them on. Without coverage that promise rests on a boolean nobody
 * checks.
 *
 * The subtle assertion here is the SECOND one in each pair: a disabled resolver
 * must not write to the cache. Caching "no result" while the lookup is off
 * would make re-enabling it resolve nothing, permanently - the exact
 * permanent-negative-cache failure the module header says it was rewritten to
 * eliminate.
 */
import {
  getNameResolutionOptions,
  onNameResolutionEnabled,
  resetGeoCacheForTests,
  resetNameResolutionForTests,
  resolveHostname,
  resolveIP,
  resolveSelfLocation,
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

/**
 * Fails the run if anything reaches the network.
 *
 * Stronger than inspecting return values: a resolver could return null having
 * already fired the request, which is precisely the failure this exists to
 * prevent, and only intercepting fetch can see that.
 */
const attempted: string[] = [];
globalThis.fetch = (async (input: RequestInfo | URL) => {
  attempted.push(String(input));
  throw new Error('network access attempted while name resolution was disabled');
}) as typeof fetch;

async function main() {
  // --- Off by default -------------------------------------------------------

  resetNameResolutionForTests();
  resetGeoCacheForTests();
  check('both lookups start disabled', getNameResolutionOptions(), {
    geoIp: false,
    reverseDns: false,
  });

  // --- Nothing leaves while they are off ------------------------------------

  {
    const geo = await resolveIP('8.8.8.8');
    check('a disabled geo lookup returns a RETRYABLE failure', geo, {
      kind: 'failed',
      retryable: true,
    });
    // Retryable is the load-bearing word: `remember` deliberately does not
    // cache those, so nothing about the disabled state is persisted.
    check('...and nothing reached the network', attempted.length, 0);
  }

  {
    const host = await resolveHostname('8.8.8.8');
    check('a disabled reverse DNS lookup returns null', host, null);
    check('...and nothing reached the network', attempted.length, 0);
  }

  {
    const self = await resolveSelfLocation();
    check('the self-location request is gated too', self, null);
    // This is the request that asks a third party where the USER is, and it
    // used to be a bare fetch in a component that no gate could have reached.
    check('...and nothing reached the network', attempted.length, 0);
  }

  // --- Re-enabling is not poisoned by the disabled period -------------------

  {
    // With geo on, the same address must be asked about rather than answered
    // from a cached "no". The fetch stub throws, so the request failing is
    // expected - what matters is that it was ATTEMPTED.
    let notified = 0;
    const off = onNameResolutionEnabled(() => { notified++; });
    setNameResolutionOptions({ geoIp: true, reverseDns: false });
    check('enabling a lookup notifies callers so they can re-ask', notified, 1);

    const pending = resolveIP('8.8.8.8');
    // Give the batch window time to flush.
    await new Promise((r) => setTimeout(r, 400));
    check('an enabled lookup actually attempts the request',
      attempted.some((u) => u.includes('get.geojs.io')), true);
    await pending.catch(() => undefined);
    off();
  }

  {
    // Switching a lookup off must not leave its answers on screen.
    attempted.length = 0;
    setNameResolutionOptions({ geoIp: false, reverseDns: false });
    const geo = await resolveIP('8.8.8.8');
    check('turning it back off clears the cache rather than serving stale answers',
      geo, { kind: 'failed', retryable: true });
    check('...and still nothing reaches the network', attempted.length, 0);
  }

  // --- The two switches are independent -------------------------------------

  {
    attempted.length = 0;
    resetNameResolutionForTests();
    resetGeoCacheForTests();
    setNameResolutionOptions({ geoIp: true, reverseDns: false });
    const host = await resolveHostname('8.8.8.8');
    // Different providers, seeing different data. Turning on location lookup
    // must not quietly turn on DNS as well.
    check('enabling geo does not enable reverse DNS', host, null);
    check('...and no DNS request was made',
      attempted.some((u) => u.includes('cloudflare-dns.com')), false);
  }

  resetNameResolutionForTests();
  resetGeoCacheForTests();

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All checks passed.');
  process.exit(0);
}

main();
