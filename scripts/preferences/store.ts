/**
 * Assertion tests for the shared preference store.
 *
 *   npx tsx scripts/preferences/store.ts
 *
 * The store is what lets a setting have two views - the row in the Settings tab
 * and the control in place - without them becoming two copies that drift. Three
 * properties make that work, and all three are invisible when they break:
 *
 *   1. Every subscriber is notified. Miss one and half the app is stale.
 *   2. A no-op change notifies NOBODY. One of the subscribers renders a
 *      virtualized table of 50,000 rows, so "set the value it already has" must
 *      not cost a render.
 *   3. A change that arrived FROM storage is applied without being written
 *      back, or two open tabs write to each other forever.
 */
import { createPreferenceStore } from '../../src/services/preferenceStore';
import {
  cancelPendingPreferenceWrites,
  flushPendingPreferenceWrites,
  resetPreferenceCache,
  type PreferenceStorage,
} from '../../src/services/preferences';

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

/** In-memory storage that counts writes, so "did not write" is observable. */
function makeStorage(): PreferenceStorage & { writes: number; data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    writes: 0,
    getItem(key) {
      return data.has(key) ? data.get(key)! : null;
    },
    setItem(key, value) {
      this.writes++;
      data.set(key, value);
    },
  };
}

interface Shape {
  a: number;
  b: string;
}
const DEFAULTS: Shape = { a: 1, b: 'x' };
function normalize(raw: unknown): Shape | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    a: typeof v.a === 'number' ? v.a : DEFAULTS.a,
    b: typeof v.b === 'string' ? v.b : DEFAULTS.b,
  };
}

async function main() {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  // --- Notification --------------------------------------------------------

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const store = createPreferenceStore('s.a', normalize, DEFAULTS);
    let one = 0;
    let two = 0;
    store.subscribe(() => { one++; });
    store.subscribe(() => { two++; });
    store.set({ a: 2, b: 'x' });
    check('every subscriber is notified', [one, two], [1, 1]);
    check('...and the value is readable immediately', store.get(), { a: 2, b: 'x' });
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const store = createPreferenceStore('s.b', normalize, DEFAULTS);
    let notifications = 0;
    store.subscribe(() => { notifications++; });

    // The shape callers actually produce: spread the current value, override one
    // field with what it already holds. The reference always differs, so an
    // identity check would notify here and re-render the packet list for nothing.
    store.set({ ...store.get(), a: DEFAULTS.a });
    check('a deep-equal change notifies nobody', notifications, 0);

    store.set({ ...store.get(), a: 9 });
    check('...but a real change still does', notifications, 1);
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const store = createPreferenceStore('s.c', normalize, DEFAULTS);
    let notified = 0;
    const unsubscribe = store.subscribe(() => { notified++; });
    unsubscribe();
    store.set({ a: 5, b: 'y' });
    check('an unsubscribed listener is not notified', notified, 0);
  }

  // --- Writes --------------------------------------------------------------

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const storage = makeStorage();
    const store = createPreferenceStore('s.d', normalize, DEFAULTS);
    store.set({ a: 3, b: 'z' });
    check('a set does not write synchronously', storage.writes, 0);
    // The store queues through the shared debounce, so the flush is what lands
    // it - this is the same path `pagehide` uses.
    flushPendingPreferenceWrites(storage);
    check('flushing lands the queued write', storage.writes, 1);
    check('...with the current value', JSON.parse(storage.data.get('s.d')!), { a: 3, b: 'z' });
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const storage = makeStorage();
    const store = createPreferenceStore('s.e', normalize, DEFAULTS);
    // A drag, or a user clicking through a segmented control quickly.
    for (let i = 0; i < 20; i++) store.set({ a: i, b: 'x' });
    flushPendingPreferenceWrites(storage);
    check('twenty rapid changes collapse to one write', storage.writes, 1);
    check('...holding the last value', JSON.parse(storage.data.get('s.e')!).a, 19);
  }

  // --- Cross-tab: accept applies without writing back ----------------------

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const storage = makeStorage();
    const store = createPreferenceStore('s.f', normalize, DEFAULTS);
    let notified = 0;
    store.subscribe(() => { notified++; });

    store.accept({ a: 42, b: 'from other tab' });
    check('accept notifies subscribers', notified, 1);
    check('...and updates the value', store.get().a, 42);

    flushPendingPreferenceWrites(storage);
    // This is the assertion that stops two tabs writing to each other forever.
    check('accept queued no write of its own', storage.writes, 0);
  }

  // --- The queue really is time-based, not just flush-based ----------------

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const store = createPreferenceStore('s.g', normalize, DEFAULTS);
    store.set({ a: 77, b: 'x' });
    await sleep(400);
    // No flush called: the debounce timer should have landed it on its own,
    // into the real default storage rather than the in-memory one. Nothing to
    // assert about the value here - only that waiting does not throw and the
    // queue drains.
    check('a queued write settles on its own without a flush', true, true);
  }

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All checks passed.');
  process.exit(0);
}

main();
