/**
 * The order an import does its things in, and what a failed one leaves behind.
 *
 *   npx tsx scripts/capture/import-lifecycle.ts
 *
 * `App.tsx` binds the effects and is unreachable from here, so the ordering
 * lives in `importLifecycle.ts`, which takes them as functions. These checks
 * run it against fakes that record the calls.
 *
 * What each one defends:
 *   - a live capture is stopped AND sealed before the import's store opens,
 *     because the agent's stop notice arrives between the file's windows and
 *     would otherwise seal the import part-way;
 *   - the view is emptied before the first read, with the previous capture's
 *     offer kept aside, because rows older than the resident tail read their
 *     bytes from whatever the store holds;
 *   - a failed import discards its own directory, clears its id (the next
 *     import must open a store, not write over the dead one) and gives the
 *     previous capture back.
 */
import { createImportLifecycle, type ImportEffects } from '../../src/services/importLifecycle';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

interface Rig {
  events: string[];
  lifecycle: ReturnType<typeof createImportLifecycle<string>>;
  /** Settles the pending seal, when the rig was told to hold it. */
  releaseSeal: () => void;
}

function rig(options: { capturing: boolean; offer: string | null; holdSeal?: boolean }): Rig {
  const events: string[] = [];
  let release: () => void = () => {};
  let ids = 0;
  const effects: ImportEffects<string> = {
    capturing: () => options.capturing,
    stopAndSeal: () => {
      events.push('stopAndSeal');
      return options.holdSeal === true
        ? new Promise<void>((resolve) => { release = () => { events.push('sealed'); resolve(); }; })
        : Promise.resolve();
    },
    currentOffer: () => { events.push('currentOffer'); return options.offer; },
    clearView: () => { events.push('clearView'); },
    newCaptureId: () => `import-${++ids}`,
    openStore: (id) => { events.push(`openStore ${id}`); },
    discardStore: (id) => { events.push(`discardStore ${id}`); },
    sealStore: (id) => { events.push(`sealStore ${id}`); },
    pruneOthers: (id) => { events.push(`pruneOthers ${id}`); },
    offer: (kept) => { events.push(`offer ${kept}`); },
  };
  return { events, lifecycle: createImportLifecycle(() => effects), releaseSeal: () => release() };
}

async function main(): Promise<void> {
  // --- a live capture is sealed first --------------------------------------
  {
    const r = rig({ capturing: true, offer: 'live', holdSeal: true });
    const began = r.lifecycle.begin();
    await Promise.resolve();
    check('capturing: the seal is asked for, and nothing else runs while it is pending',
      r.events, ['stopAndSeal']);
    r.releaseSeal();
    check('capturing: begin resolves true once the seal has', await began, true);
    check('capturing: the offer is read and the view cleared only after the seal',
      r.events, ['stopAndSeal', 'sealed', 'currentOffer', 'clearView']);
    r.lifecycle.onBatch();
    check('capturing: the import store opens last', r.events.at(-1), 'openStore import-1');
  }

  // --- not capturing: no stop, no seal --------------------------------------
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    check('not capturing: nothing is stopped or sealed', r.events, ['currentOffer', 'clearView']);
  }

  // --- before the first read ------------------------------------------------
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    check('begin empties the view with the previous offer kept: it is not offered, nor is a store opened',
      r.events.some((e) => e.startsWith('offer') || e.startsWith('openStore')), false);
    check('begin opens no store: a file that is not a capture leaves no directory', r.lifecycle.storeId(), null);
  }

  // --- the store opens once, on the first batch -------------------------------
  {
    const r = rig({ capturing: false, offer: null });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    r.lifecycle.onBatch();
    r.lifecycle.onBatch();
    check('three batches open one store', r.events.filter((e) => e.startsWith('openStore')), ['openStore import-1']);
    check('the lifecycle remembers the id', r.lifecycle.storeId(), 'import-1');
  }

  // --- a failure after the first batch ------------------------------------------
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    r.events.length = 0;
    r.lifecycle.fail();
    check('a failure after a batch discards the import and re-offers the kept capture',
      r.events, ['discardStore import-1', 'offer previous']);
    check('...and clears the id', r.lifecycle.storeId(), null);
    check('...and nothing is pruned or sealed', r.events.some((e) => e.startsWith('prune') || e.startsWith('seal')), false);
    r.events.length = 0;
    r.lifecycle.fail();
    check('a second fail is a no-op', r.events, []);

    // The bug the id guards: the next import skipped the open and wrote 1..N over the dead directory.
    check('a new import may begin after the failure', await r.lifecycle.begin(), true);
    r.lifecycle.onBatch();
    check('...and opens a store of its own, not the dead one',
      r.events.filter((e) => e.startsWith('openStore')), ['openStore import-2']);
  }

  // --- a failure before any batch ------------------------------------------------
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    r.events.length = 0;
    r.lifecycle.fail();
    check('a failure before any batch discards nothing and still re-offers', r.events, ['offer previous']);
  }

  // --- nothing was offered to begin with --------------------------------------------
  {
    const r = rig({ capturing: false, offer: null });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    r.events.length = 0;
    r.lifecycle.fail();
    check('with no previous capture a failure discards and offers nothing', r.events, ['discardStore import-1']);
  }

  // --- success -------------------------------------------------------------------------
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    r.events.length = 0;
    check('success answers the import\'s capture id', r.lifecycle.succeed(), 'import-1');
    check('success seals the import, prunes the rest and offers nothing',
      r.events, ['sealStore import-1', 'pruneOthers import-1']);
    check('...and clears the id', r.lifecycle.storeId(), null);
    r.events.length = 0;
    r.lifecycle.fail();
    check('a fail after the success is a no-op', r.events, []);
  }
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    r.events.length = 0;
    check('success with no batch has no capture id', r.lifecycle.succeed(), null);
    check('...and touches no store', r.events, []);
  }

  // --- one at a time --------------------------------------------------------------------
  {
    const r = rig({ capturing: true, offer: 'live', holdSeal: true });
    const first = r.lifecycle.begin();
    const second = await r.lifecycle.begin();
    check('a second begin is refused while the first awaits its seal', second, false);
    check('...and did not ask for a second seal', r.events, ['stopAndSeal']);
    r.releaseSeal();
    await first;
    check('still refused while the import runs', await r.lifecycle.begin(), false);
    r.lifecycle.fail();
    check('accepted again once it has ended', await rig({ capturing: false, offer: null }).lifecycle.begin(), true);
  }
  {
    const r = rig({ capturing: false, offer: null });
    await r.lifecycle.begin();
    r.lifecycle.succeed();
    check('begin is accepted after a success', await r.lifecycle.begin(), true);
  }

  // --- a seal that throws ---------------------------------------------------------------------
  {
    const events: string[] = [];
    const lifecycle = createImportLifecycle<string>(() => ({
      capturing: () => true,
      stopAndSeal: () => Promise.reject(new Error('seal failed')),
      currentOffer: () => 'live',
      clearView: () => { events.push('clearView'); },
      newCaptureId: () => 'x',
      openStore: () => {}, discardStore: () => {}, sealStore: () => {}, pruneOthers: () => {},
      offer: (kept) => { events.push(`offer ${kept}`); },
    }));
    let thrown = false;
    try { await lifecycle.begin(); } catch { thrown = true; }
    check('a seal that fails rejects begin and leaves the view alone', [thrown, events], [true, []]);
    check('...and releases the lifecycle', lifecycle.running(), false);
  }

  if (failures > 0) {
    console.log(`\n${failures} check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll import lifecycle checks passed.');
}

void main();
