/**
 * Claiming the stored session for this tab.
 *
 * This module used to decide whether a stored session was leftovers and delete
 * it if so. It no longer deletes anything, and the reversal is the point of the
 * file: a stored capture is now discarded **only when the user asks**
 * (`docs/decisions/0012-stored-captures-persist.md`).
 *
 * The old rule was that captured bytes "live exactly as long as the app is
 * open, and no longer" - enforced here for the browser-quit case and by
 * `public/inwire-sw.js` for the last-window-closed case. That was a good rule
 * while the store was only a convenience so a refresh did not lose the last few
 * thousand frames. It is the wrong rule once the disk is where a long capture
 * actually lives: an accidental tab close should not destroy three hours of
 * capture, and every mechanism that deleted "orphans" could not tell an orphan
 * from a capture someone still wanted.
 *
 * What remains is the tab marker, which is still worth keeping: it is how a
 * reload is told apart from a fresh tab, which the restore path uses to decide
 * whether it is continuing a capture or opening a stored one.
 *
 * The discriminator is `sessionStorage`, which is per-tab: it survives a reload
 * and is discarded when the tab closes.
 */

const TAB_MARKER_KEY = 'inwire.tabAlive';
const CHANNEL_NAME = 'inwire.session';
const SW_URL = '/inwire-sw.js';

/** How long to wait for another window to answer a liveness ping. */
const LIVENESS_TIMEOUT_MS = 250;

/**
 * What to do with a stored session at startup.
 *
 * `wipe` is retained in the type because the explicit-discard path still needs
 * a name for the act, but nothing decides it automatically any more.
 */
export type StartupAction = 'wipe' | 'restore';

/**
 * The whole startup decision, as a pure function so it can be tested.
 *
 * `tabMarker` is the sessionStorage value (null when absent) and
 * `otherWindowLive` is whether a second Inwire window answered a ping.
 */
export function decideStartupAction(
  tabMarker: string | null,
  otherWindowLive: boolean,
): StartupAction {
  // Always. A stored capture belongs to whoever stored it until they say
  // otherwise, and neither of these signals distinguishes "nobody wants this"
  // from "the tab was closed". Both arguments are kept because they still
  // describe the situation truthfully and the callers already compute them -
  // and because a future policy that does discriminate should be written here,
  // where it can be tested, rather than inline at the call site.
  void tabMarker;
  void otherWindowLive;
  return 'restore';
}

// --- Storage access ----------------------------------------------------------

/**
 * sessionStorage throws outright in some privacy configurations rather than
 * returning null, so every access is guarded. A browser that refuses it reads
 * as "no marker", which errs toward wiping - the safe direction for data the
 * user asked not to keep.
 */
function readTabMarker(): string | null {
  try {
    return sessionStorage.getItem(TAB_MARKER_KEY);
  } catch {
    return null;
  }
}

function markTabAlive(): void {
  try {
    sessionStorage.setItem(TAB_MARKER_KEY, String(Date.now()));
  } catch {
    // Nothing to do: the session simply gets wiped on the next load instead.
  }
}

// --- Cross-window liveness ---------------------------------------------------

function openChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === 'undefined') return null;
  try {
    return new BroadcastChannel(CHANNEL_NAME);
  } catch {
    return null;
  }
}

/**
 * Asks whether another Inwire window is open, resolving false if none answers.
 *
 * BroadcastChannel does not deliver a message back to the sender, so a lone
 * window cannot mistake its own ping for company.
 */
export function anotherWindowIsLive(timeoutMs = LIVENESS_TIMEOUT_MS): Promise<boolean> {
  const channel = openChannel();
  if (!channel) return Promise.resolve(false);

  return new Promise((resolve) => {
    let settled = false;
    const finish = (answer: boolean) => {
      if (settled) return;
      settled = true;
      try {
        channel.close();
      } catch {
        // Already closed; the answer still stands.
      }
      resolve(answer);
    };

    channel.onmessage = (event) => {
      if (event.data?.type === 'inwire:here') finish(true);
    };
    channel.postMessage({ type: 'inwire:who-is-there' });
    setTimeout(() => finish(false), timeoutMs);
  });
}

/**
 * Answers liveness pings from other windows for as long as this one is open.
 *
 * Without this every window would believe it was alone, and the second tab a
 * user opened would wipe the first tab's capture.
 */
export function answerLivenessPings(): () => void {
  const channel = openChannel();
  if (!channel) return () => {};

  channel.onmessage = (event) => {
    if (event.data?.type !== 'inwire:who-is-there') return;
    try {
      channel.postMessage({ type: 'inwire:here' });
    } catch {
      // The asker has gone away; it will time out and decide on its own.
    }
  };

  return () => {
    try {
      channel.close();
    } catch {
      // Already closed.
    }
  };
}

// --- Service worker ----------------------------------------------------------

/**
 * The worker this page registered, held because `controller` is null on the
 * very first load - before the worker has claimed the page - and that first
 * load is precisely when a session most needs the goodbye to land.
 */
let registeredWorker: ServiceWorker | null = null;

function postToWorker(type: string): void {
  const target = navigator.serviceWorker?.controller ?? registeredWorker;
  try {
    target?.postMessage({ type });
  } catch {
    // A worker that cannot be reached simply means the startup guard handles
    // this session instead.
  }
}

/**
 * Registers the cleanup worker and tells it when this window comes and goes.
 *
 * Returns a teardown for the React effect. The `pagehide` listener is the point
 * of the whole thing, so it is registered even if the worker never resolves -
 * an unregistered worker just ignores the message.
 */
export function registerSessionWorker(): () => void {
  const container = navigator.serviceWorker;
  if (!container) return () => {};

  let disposed = false;

  // The script this points at was renamed when the app was. That needs no
  // cleanup of its own: a registration is keyed by SCOPE, not by script URL, so
  // registering a different script at the same '/' scope replaces the previous
  // registration rather than adding a second one beside it. The old worker is
  // discarded once this one activates.
  void container
    .register(SW_URL, { scope: '/' })
    .then((registration) => {
      if (disposed) return;
      registeredWorker =
        registration.active ?? registration.waiting ?? registration.installing;
      // Checking in cancels any deletion the previous page scheduled on its way
      // out, which is what makes a reload keep its session.
      postToWorker('inwire:hello');
    })
    .catch(() => {
      // Service workers need a secure context. Served over plain http on a LAN
      // address registration fails, and the startup guard covers the session on
      // its own - so this is a degradation, not a failure.
    });

  const sayGoodbye = () => postToWorker('inwire:goodbye');
  // `pagehide` rather than `beforeunload`: it fires in cases beforeunload does
  // not, including a mobile tab being discarded.
  window.addEventListener('pagehide', sayGoodbye);

  return () => {
    disposed = true;
    window.removeEventListener('pagehide', sayGoodbye);
  };
}

// --- The guard ---------------------------------------------------------------

/**
 * Claims the stored session for this tab.
 *
 * Nothing is deleted here any more; see the note at the top of this file. It is
 * still awaited before the store is read, because claiming the tab first is
 * what makes a reload distinguishable from a fresh open.
 */
export async function prepareStoredSession(): Promise<StartupAction> {
  const marker = readTabMarker();
  // Claimed immediately: from here on this tab owns whatever is in the store,
  // so a reload restores instead of wiping.
  markTabAlive();

  // Only worth asking when the marker is missing - a reload already has its
  // answer, and skipping the ping keeps the common path off a 250ms wait.
  const action = decideStartupAction(marker, marker === null ? await anotherWindowIsLive() : false);

  // No automatic deletion. `clearSession` is still exported and is still what
  // an explicit discard calls - it is just not called from here.
  return action;
}
