/**
 * Assertion tests for the link-context reader.
 *
 *   npx tsx scripts/flow/link-context.ts
 *
 * The API is Chromium-only and everything it returns is optional, so the whole
 * risk here is a browser that reports *some* of it, or none. The failure mode
 * is a "0 ms RTT" or an "unknown" chip appearing on a browser that simply never
 * had the API - a claim about the network made out of the absence of one.
 */
import {
  describeLink,
  linkChanged,
  linkContextAvailable,
  readLinkContext,
  watchLinkChanges,
  type LinkChange,
} from '../../src/services/linkContext';

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

/** A stand-in for `navigator.connection`, with a real EventTarget. */
class FakeConnection extends EventTarget {
  type?: string;
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
  constructor(init: Partial<FakeConnection> = {}) {
    super();
    Object.assign(this, init);
  }
  fire() { this.dispatchEvent(new Event('change')); }
}

// Node defines `navigator` as a getter-only property, so it is redefined
// rather than assigned - and restored afterwards, because every later check in
// this file runs in the same process.
const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');

function withConnection(conn: FakeConnection | null, body: () => void) {
  Object.defineProperty(globalThis, 'navigator', {
    value: conn === null ? {} : { connection: conn },
    configurable: true,
    writable: true,
  });
  try {
    body();
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, 'navigator', originalDescriptor);
    else delete (globalThis as { navigator?: unknown }).navigator;
  }
}

// --- 1. A browser that does not have the API -----------------------------------
//
// The case that must produce nothing at all rather than zeroes.
withConnection(null, () => {
  check('a browser without the API reports it is unavailable', linkContextAvailable(), false);
  check('...and reads as null, not as an empty link', readLinkContext(), null);
  check('...and describes as an empty string', describeLink(readLinkContext()), '');
  let called = false;
  const stop = watchLinkChanges(() => { called = true; });
  check('...and watching it is a no-op that still unsubscribes cleanly',
    typeof stop, 'function');
  stop();
  check('...and never calls back', called, false);
});

// --- 2. A browser that reports everything ---------------------------------------
withConnection(new FakeConnection({
  type: 'wifi', effectiveType: '4g', downlink: 10, rtt: 50, saveData: false,
}), () => {
  check('the API is found', linkContextAvailable(), true);
  check('every field is read', readLinkContext(),
    { type: 'wifi', effectiveType: '4g', downlinkMbps: 10, rttMs: 50, saveData: false });
  // "-class" and not "4g": the API's effectiveType is a performance bucket,
  // so a wired gigabit link reports "4g" and saying that plainly on a desktop
  // would be the API's wording repeated as a finding about the network.
  check('...and described in one line, with the bucket named as a bucket',
    describeLink(readLinkContext()), 'wifi, 4g-class, ~10 Mbit/s, ~50 ms');
});

// --- 3. A browser that reports only part of it ----------------------------------
//
// Chrome on desktop reports no `type`. An absent field must stay absent - a
// zero would be a statement about the network.
withConnection(new FakeConnection({ effectiveType: '4g', downlink: 0, rtt: 0 }), () => {
  check('absent fields are absent, not zero', readLinkContext(),
    { effectiveType: '4g', downlinkMbps: 0, rttMs: 0 });
  checkTrue('...and a real zero is kept, because it was reported',
    readLinkContext()?.downlinkMbps === 0);
  check('a partial link still describes', describeLink(readLinkContext()),
    '4g-class, ~0 Mbit/s, ~0 ms');
});

// --- 4. Change detection ---------------------------------------------------------
{
  check('two identical readings are not a change',
    linkChanged({ effectiveType: '4g' }, { effectiveType: '4g' }), false);
  check('a different bucket is', linkChanged({ effectiveType: '4g' }, { effectiveType: '3g' }), true);
  check('so is losing a field entirely', linkChanged({ type: 'wifi' }, {}), true);
  check('so is data saver going on',
    linkChanged({ saveData: false }, { saveData: true }), true);
}

// --- 5. Watching -----------------------------------------------------------------
{
  const conn = new FakeConnection({ effectiveType: '4g', rtt: 50 });
  withConnection(conn, () => {
    const seen: LinkChange[] = [];
    const stop = watchLinkChanges((c) => seen.push(c));

    // The reading at subscription is not a change: a capture starting on Wi-Fi
    // has not just moved to Wi-Fi, and a marker at t=0 on every capture would
    // teach people to ignore the ones that mean something.
    check('subscribing does not itself report a change', seen.length, 0);

    // An event that carries no actual difference - the API fires these.
    conn.fire();
    check('an event with nothing behind it reports nothing', seen.length, 0);

    conn.effectiveType = '3g';
    conn.rtt = 300;
    conn.fire();
    check('a real transition is reported once', seen.length, 1);
    check('...with what it was', seen[0].before, { effectiveType: '4g', rttMs: 50 });
    check('...and what it became', seen[0].after, { effectiveType: '3g', rttMs: 300 });
    checkTrue('...stamped on the packet clock', seen[0].atUs > 1_600_000_000_000_000);

    conn.effectiveType = '4g';
    conn.fire();
    check('a change back is a change too', seen.length, 2);
    check('...measured from the last state, not the first',
      seen[1].before.effectiveType, '3g');

    stop();
    conn.effectiveType = 'slow-2g';
    conn.fire();
    check('unsubscribing stops it', seen.length, 2);
  });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All link context checks passed.');
process.exit(0);
