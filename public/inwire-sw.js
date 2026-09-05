/**
 * Inwire's session worker.
 *
 * **This worker used to delete the stored capture, and deliberately no longer
 * does.** It is kept, and kept registered, because that is the only way to stop
 * the version that did: a service worker already installed in someone's browser
 * goes on running until a new one replaces it, so removing this file would
 * leave the deleting worker in place and still deleting. `skipWaiting` plus
 * `clients.claim` below is what displaces it on the next load.
 *
 * The policy it enforced was that captured bytes "live exactly as long as the
 * app is open, and no longer" - the database was deleted a few seconds after
 * the last window went away. That was right while the store was only a
 * convenience so a refresh did not lose the last few thousand frames. It stops
 * being right once the disk is where a long capture actually lives: closing a
 * tab after three hours of capture would throw the whole thing away, and a tab
 * is closed by accident all the time.
 *
 * So a stored capture is now discarded only when the user asks for it
 * (`docs/decisions/0012`). The trade is real and is not hidden: raw frames,
 * including payloads this app can decrypt, stay on disk until then. The app
 * shows what is stored and how large it is, and offers one action that removes
 * it - which is a better bargain than deleting a user's capture without asking.
 *
 * Deliberately NO `fetch` handler, as before. This worker never intercepts a
 * request, so it cannot serve a stale asset.
 */

self.addEventListener('install', () => {
  // Take over immediately. This is the whole point of the file now: an old
  // worker that still deletes must be replaced at the first opportunity, not
  // at the next natural reload.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

/**
 * The page still sends `inwire:hello` and `inwire:goodbye`.
 *
 * They are accepted and ignored. The messages are left in place on the page
 * side because a browser that has not yet picked up this version is still
 * running the old worker, and the old worker cancels its pending deletion when
 * it hears `hello` - so a page that stopped sending them would make the last
 * session before an update *more* likely to be deleted, not less.
 */
self.addEventListener('message', () => {
  // Nothing. Retention is the user's decision now, taken in the app.
});
