/**
 * Assertion tests for the shared preference storage.
 *
 *   npx tsx scripts/preferences/storage.ts
 *
 * Runs against an in-memory PreferenceStorage rather than a browser, which is
 * what the seam in preferences.ts exists for. Real timers with short delays
 * are used instead of fake ones - the margins below are wide enough that
 * timing is not what fails.
 */
import {
  PreferenceStorage,
  cancelPendingPreferenceWrites,
  flushPendingPreferenceWrites,
  loadPreference,
  resetPreferenceCache,
  savePreference,
  schedulePreferenceWrite,
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** In-memory storage that counts writes, so coalescing is observable. */
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

/** Storage that throws on every access, like a browser blocking site data. */
const hostileStorage: PreferenceStorage = {
  getItem() {
    throw new Error('site data blocked');
  },
  setItem() {
    throw new Error('site data blocked');
  },
};

// --- The validator under test: the column-widths shape, clamped ------------

type Widths = { time: number; source: number; info: number };
const DEFAULT_WIDTHS: Widths = { time: 100, source: 150, info: 300 };
const MIN = 36;
const MAX = 480;

function normalizeWidths(raw: unknown): Widths | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const source = raw as Record<string, unknown>;
  const out = { ...DEFAULT_WIDTHS };
  for (const key of Object.keys(DEFAULT_WIDTHS) as (keyof Widths)[]) {
    const value = source[key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      out[key] = Math.min(MAX, Math.max(MIN, value));
    }
  }
  return out;
}

async function main() {
  // --- Reads ---------------------------------------------------------------

  {
    resetPreferenceCache();
    const s = makeStorage();
    check('a missing key returns the fallback', loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, s), DEFAULT_WIDTHS);
  }

  {
    resetPreferenceCache();
    const s = makeStorage();
    s.data.set('k', '{not json');
    check('malformed JSON falls back', loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, s), DEFAULT_WIDTHS);
  }

  {
    resetPreferenceCache();
    const s = makeStorage();
    s.data.set('k', 'null');
    check('a JSON null falls back', loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, s), DEFAULT_WIDTHS);
  }

  {
    // The case that matters most: one bad field must not discard its siblings.
    resetPreferenceCache();
    const s = makeStorage();
    s.data.set('k', JSON.stringify({ time: -5, source: 'wide', info: 200 }));
    check(
      'one rejected field defaults while its siblings survive',
      loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, s),
      { time: MIN, source: DEFAULT_WIDTHS.source, info: 200 },
    );
  }

  {
    resetPreferenceCache();
    const s = makeStorage();
    s.data.set('k', JSON.stringify({ time: 99999, source: 150, info: 300 }));
    check(
      'an out-of-range value is clamped, not rejected',
      loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, s).time,
      MAX,
    );
  }

  {
    resetPreferenceCache();
    check(
      'a storage that throws on read falls back rather than propagating',
      loadPreference('k', normalizeWidths, DEFAULT_WIDTHS, hostileStorage),
      DEFAULT_WIDTHS,
    );
  }

  {
    resetPreferenceCache();
    let threw = false;
    try {
      savePreference('k', DEFAULT_WIDTHS, hostileStorage);
    } catch {
      threw = true;
    }
    check('a storage that throws on write does not propagate', threw, false);
  }

  {
    resetPreferenceCache();
    const s = makeStorage();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    let threw = false;
    try {
      savePreference('k', circular, s);
    } catch {
      threw = true;
    }
    check('an unserializable value does not propagate', threw, false);
    check('...and nothing was written', s.writes, 0);
  }

  // --- Debounced writes ----------------------------------------------------

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const s = makeStorage();
    // Stand-in for a drag: many changes in quick succession.
    for (let px = 100; px < 140; px++) schedulePreferenceWrite('k', { ...DEFAULT_WIDTHS, time: px }, 30, s);
    check('a burst of changes writes nothing yet', s.writes, 0);
    await sleep(90);
    check('a burst of 40 changes collapses to one write', s.writes, 1);
    check('...and the write holds the last value', JSON.parse(s.data.get('k')!).time, 139);
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const s = makeStorage();
    schedulePreferenceWrite('k', { ...DEFAULT_WIDTHS, time: 200 }, 5000, s);
    check('a queued write has not landed', s.writes, 0);
    // The tab-close case: flush must not wait for the timer.
    flushPendingPreferenceWrites(s);
    check('flush writes the pending value immediately', s.writes, 1);
    check('...with the right value', JSON.parse(s.data.get('k')!).time, 200);
    await sleep(60);
    check('...and the cancelled timer does not fire a second write', s.writes, 1);
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const s = makeStorage();
    flushPendingPreferenceWrites(s);
    check('flushing an empty queue writes nothing', s.writes, 0);
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const s = makeStorage();
    schedulePreferenceWrite('a', { ...DEFAULT_WIDTHS, time: 111 }, 5000, s);
    schedulePreferenceWrite('b', { ...DEFAULT_WIDTHS, time: 222 }, 5000, s);
    flushPendingPreferenceWrites(s);
    check('separate keys queue independently', s.writes, 2);
    check('...key a', JSON.parse(s.data.get('a')!).time, 111);
    check('...key b', JSON.parse(s.data.get('b')!).time, 222);
  }

  {
    resetPreferenceCache();
    cancelPendingPreferenceWrites();
    const s = makeStorage();
    schedulePreferenceWrite('k', DEFAULT_WIDTHS, 30, s);
    cancelPendingPreferenceWrites();
    await sleep(80);
    check('a cancelled write never lands', s.writes, 0);
  }

  console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
