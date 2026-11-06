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
import { runImportFlow } from '../../src/services/importFlow';
import { awaitImportOpen } from '../../src/services/importOpen';
import {
  beginImportJob, cancelImportJob, endImportJob, getImportJob, importCancelRequested, lockImportCancel,
  setImportJobCancel,
} from '../../src/services/importJob';

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

/** A condition, with what to show when it fails. */
function ok(name: string, condition: boolean, detail?: unknown): void {
  if (condition) check(name, true, true);
  else check(name, detail ?? false, true);
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

  // --- Cancel -------------------------------------------------------------------------------
  //
  // The phase ordering is `importFlow.ts`'s (the panel calls it), driven here with the
  // real lifecycle and the real job store; the fakes record what the effects saw. The job
  // stays `running` until `fail()` has returned - a `cancelling` state would open every
  // `status === 'running'` gate (Start, Reopen, export) while the discard was still going.
  {
    // Cancel pressed while a live capture is being sealed: no store is open yet.
    const r = rig({ capturing: true, offer: 'live', holdSeal: true });
    beginImportJob('a.pcap', 10);
    let read = 0;
    const flowing = runImportFlow({
      begin: async () => { if (!(await r.lifecycle.begin())) throw new Error('refused'); },
      failed: () => r.lifecycle.fail(),
      cancelRequested: importCancelRequested,
      lockCancel: lockImportCancel,
      read: async () => { read++; return { ok: false, failure: { kind: 'unreadable', message: 'unreachable' } }; },
      adopt: async () => {},
    });
    await Promise.resolve();
    cancelImportJob();
    r.releaseSeal();
    const flow = await flowing;
    ok('cancel before opening discards nothing and offers the previous capture',
      flow.status === 'cancelled' && read === 0
      && JSON.stringify(r.events) === JSON.stringify(['stopAndSeal', 'sealed', 'currentOffer', 'clearView', 'offer live']),
      { flow, read, events: r.events });
    ok('...and the file was never read, no store opened', r.lifecycle.storeId() === null && !r.events.some((e) => e.startsWith('openStore')));
    endImportJob();
  }
  {
    // Cancel pressed while the page awaits the capture's open: the Worker is
    // waiting on `storeOpen`, the lifecycle's store is already open.
    const r = rig({ capturing: false, offer: 'previous' });
    beginImportJob('b.pcap', 10);
    const statusDuring: string[] = [];
    const seen = (what: string) => { statusDuring.push(`${what}:${getImportJob().status}`); };
    const lifecycle = r.lifecycle;
    const flow = await runImportFlow({
      begin: async () => { if (!(await lifecycle.begin())) throw new Error('refused'); },
      failed: () => { seen('failed'); lifecycle.fail(); seen('after'); },
      cancelRequested: importCancelRequested,
      lockCancel: lockImportCancel,
      read: () => new Promise((resolve) => {
        // What `importCapture` does: register the run's cancel, then the Worker asks to open.
        setImportJobCancel(() => resolve({ ok: false, failure: { kind: 'cancelled', message: 'The import was cancelled.' } }));
        lifecycle.onBatch();
        // ...the open is awaited, and Cancel arrives.
        cancelImportJob();
      }),
      adopt: async () => { throw new Error('nothing may be adopted'); },
    });
    ok('cancel during the awaited open discards the opened capture',
      flow.status === 'cancelled'
      && JSON.stringify(r.events.slice(-2)) === JSON.stringify(['discardStore import-1', 'offer previous'])
      && lifecycle.storeId() === null && !r.events.some((e) => e.startsWith('sealStore') || e.startsWith('pruneOthers')),
      { flow, events: r.events });
    ok('gates stay closed until fail() returns, then open',
      JSON.stringify(statusDuring) === JSON.stringify(['failed:running', 'after:running'])
      && getImportJob().status === 'running' && !lifecycle.running()
      && (endImportJob(), getImportJob().status === 'idle'),
      { statusDuring });
  }
  {
    // An in-process format has no handle: the request is seen when it returns.
    const r = rig({ capturing: false, offer: 'previous' });
    beginImportJob('c.csv', 10);
    let adopted = 0;
    const flow = await runImportFlow({
      begin: async () => { await r.lifecycle.begin(); },
      failed: () => r.lifecycle.fail(),
      cancelRequested: importCancelRequested,
      lockCancel: lockImportCancel,
      read: async () => {
        cancelImportJob();
        return { ok: true, packets: [], notes: [] };
      },
      adopt: async () => { adopted++; },
    });
    ok('a cancel during an in-process import is honoured when it returns: nothing adopted, previous capture offered',
      flow.status === 'cancelled' && adopted === 0 && r.events.at(-1) === 'offer previous', { flow, adopted, events: r.events });
    endImportJob();
  }
  {
    // Past the lock the import is sealed and the old capture pruned: Cancel cannot undo it.
    const r = rig({ capturing: false, offer: 'previous' });
    beginImportJob('d.pcap', 10);
    let cancellableInAdopt: boolean | null = null;
    const flow = await runImportFlow({
      begin: async () => { await r.lifecycle.begin(); },
      failed: () => r.lifecycle.fail(),
      cancelRequested: importCancelRequested,
      lockCancel: lockImportCancel,
      read: async () => { r.lifecycle.onBatch(); return { ok: true, packets: [], notes: [] }; },
      adopt: async () => {
        r.lifecycle.succeed();
        cancelImportJob();
        cancellableInAdopt = (getImportJob() as { cancellable?: boolean }).cancellable ?? null;
      },
    });
    ok('a cancel during adoption is a no-op: the import is kept, not discarded',
      flow.status === 'done' && cancellableInAdopt === false
      && !r.events.some((e) => e.startsWith('discardStore') || e === 'offer previous'),
      { flow, cancellableInAdopt, events: r.events });
    endImportJob();
  }

  // --- Cancel that lands while the store's open is still pending ------------------------------
  //
  // The lifecycle has opened the store (`onBatch`) and the page awaits the store's answer
  // (`awaitImportOpen`). Cancel runs `fail()`, which discards the id - but a store whose
  // `ready` was already on its way can answer after that, and the open then settles
  // successfully for a capture nobody owns. It must be discarded, not left open under the
  // import's id with the session still naming the previous capture.
  {
    const r = rig({ capturing: false, offer: 'previous' });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    const id = r.lifecycle.storeId();
    let answer: () => void = () => {};
    const opened = new Promise<void>((resolve) => { answer = resolve; });
    const waiting = awaitImportOpen({
      captureId: id, opened,
      owns: (captured) => r.lifecycle.storeId() === captured,
      discard: (captured) => { r.events.push(`discardOpened ${captured}`); },
    }).then((value) => `resolved ${value}`, (error: Error) => `rejected ${error.message}`);
    r.lifecycle.fail();
    answer();
    const settled = await waiting;
    ok('a cancel during the awaited open discards the capture the store then opens, and the wait fails',
      settled.startsWith('rejected') && r.events.includes('discardOpened import-1')
      && !r.events.some((e) => e.startsWith('sealStore') || e.startsWith('pruneOthers')),
      { settled, events: r.events });
  }
  {
    const r = rig({ capturing: false, offer: null });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    const settled = await awaitImportOpen({
      captureId: r.lifecycle.storeId(), opened: Promise.resolve(),
      owns: (captured) => r.lifecycle.storeId() === captured,
      discard: (captured) => { r.events.push(`discardOpened ${captured}`); },
    });
    ok('an open nobody cancelled answers its id and discards nothing',
      settled === 'import-1' && !r.events.some((e) => e.startsWith('discard')), { settled, events: r.events });
  }
  {
    const r = rig({ capturing: false, offer: null });
    await r.lifecycle.begin();
    r.lifecycle.onBatch();
    const failure = await awaitImportOpen({
      captureId: r.lifecycle.storeId(), opened: Promise.reject(new Error('the store would not open')),
      owns: (captured) => r.lifecycle.storeId() === captured,
      discard: (captured) => { r.events.push(`discardOpened ${captured}`); },
    }).then(() => 'resolved', (error: Error) => error.message);
    ok('an open the store refuses fails with the store\'s own reason, and the lifecycle\'s fail owns the discard',
      failure === 'the store would not open' && !r.events.some((e) => e.startsWith('discard')), { failure, events: r.events });
  }
  {
    const failure = await awaitImportOpen({
      captureId: null, opened: null, owns: () => false, discard: () => {},
    }).then(() => 'resolved', (error: Error) => error.message);
    ok('no store opened is the old message', failure === 'The import could not open its capture.', failure);
  }

  if (failures > 0) {
    console.log(`\n${failures} check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll import lifecycle checks passed.');
}

void main();
