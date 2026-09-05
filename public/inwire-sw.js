/**
 * Inwire's session-cleanup worker.
 *
 * Captured frames are written to IndexedDB so a refresh does not throw the
 * session away. That convenience leaves raw packet bytes sitting on the disk,
 * which is not something a packet analyzer should do once the user is done
 * with it - so this worker deletes them the moment the app is actually closed.
 *
 * A page cannot do that job itself. `pagehide` fires identically for a refresh
 * and for a close, so at that instant nothing in the page can tell which one is
 * happening, and asynchronous IndexedDB work started during unload is routinely
 * killed before it commits. A service worker outlives the page it came from, so
 * it can wait a few seconds, see whether a window came back, and only then act.
 *
 * Deliberately NO `fetch` handler. This worker never intercepts a request, so
 * it cannot serve a stale asset - which is the usual reason a service worker is
 * painful to have around during development. It handles two messages and
 * nothing else.
 *
 * It does not cover quitting the browser outright: the worker is torn down with
 * everything else, mid-wait, and the deletion never runs. That case is caught
 * on the next launch by the startup guard in `src/services/sessionLifecycle.ts`
 * - the two mechanisms are meant to be read together.
 */

const DB_NAME = 'inwire';

/**
 * How long to wait after the last window disappears before deleting.
 *
 * Long enough that a slow reload reclaims the session rather than losing it,
 * short enough that a closed app does not leave packet bytes on disk for any
 * meaningful length of time. The reload path does not actually depend on this
 * being generous - a returning page cancels explicitly - so it is a safety
 * margin rather than a race to win.
 */
const GRACE_MS = 5000;

/**
 * Bumped by every message. A pending deletion captures the value it was
 * scheduled with and stands down if it no longer matches, which is how a page
 * that comes back cancels the delete that its own departure scheduled.
 */
let generation = 0;

function deleteSessionDatabase() {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    let request;
    try {
      request = indexedDB.deleteDatabase(DB_NAME);
    } catch {
      finish();
      return;
    }

    request.onsuccess = finish;
    request.onerror = finish;
    // `blocked` means a connection is still open somewhere. Every window is
    // gone by this point so it should not happen, but if it does the deletion
    // stays queued and completes when that connection closes - so resolve and
    // let the worker idle out rather than holding it alive waiting.
    request.onblocked = finish;
  });
}

self.addEventListener('install', () => {
  // Take over immediately; waiting for a reload would leave the first session
  // after an update unprotected.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const type = event.data && event.data.type;

  // A window checked in: either a fresh load or the far side of a reload.
  // Either way the session is in use again, so any pending deletion is void.
  if (type === 'inwire:hello') {
    generation += 1;
    return;
  }

  if (type !== 'inwire:goodbye') return;

  const scheduled = (generation += 1);

  // `waitUntil` is what keeps the worker alive across the wait. A bare
  // setTimeout would be killed with the worker as soon as it went idle, which
  // is exactly the window this needs to survive.
  event.waitUntil(
    new Promise((resolve) => setTimeout(resolve, GRACE_MS)).then(async () => {
      // A newer message arrived - a page came back and owns the session now.
      if (generation !== scheduled) return;

      // `includeUncontrolled` matters: a page that loaded before this worker
      // took control is still the app being open, and deleting the session out
      // from under it would be the worst possible outcome.
      const windows = await self.clients.matchAll({
        type: 'window',
        includeUncontrolled: true,
      });
      if (windows.length > 0) return;

      await deleteSessionDatabase();
    }),
  );
});
