/**
 * Deciding whether a stored session is still the user's, or leftovers.
 *
 * The session store keeps raw packet bytes on disk so a refresh does not lose a
 * capture. The rule this module enforces is the other half of that bargain:
 * those bytes live exactly as long as the app is open, and no longer.
 *
 * Two mechanisms share the job, because neither covers the whole of it:
 *
 *   - `public/inwire-sw.js` deletes the database a few seconds after the last
 *     window goes away. That handles closing the app while the browser keeps
 *     running, which is the common case, and it deletes at close rather than
 *     merely before the next use.
 *
 *   - The startup guard here catches what the worker cannot: quitting the
 *     browser outright kills the worker mid-wait, so the deletion never runs.
 *     On the next launch this notices the session is orphaned and wipes it
 *     before the restore effect can put any of it on screen.
 *
 * The discriminator is `sessionStorage`, which is per-tab: it survives a reload
 * and is discarded when the tab closes. A marker that is still there means this
 * page is the same tab reloading and the session is its own. A missing marker
 * means a brand new tab, so anything on disk belongs to a session that is gone.
 */
import { clearSession } from './sessionStore';

const TAB_MARKER_KEY = 'inwire.tabAlive';
const CHANNEL_NAME = 'inwire.session';
const SW_URL = '/inwire-sw.js';

/** How long to wait for another window to answer a liveness ping. */
const LIVENESS_TIMEOUT_MS = 250;

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
  // Same tab, reloaded: sessionStorage survived, so this session is ours.
  if (tabMarker !== null) return 'restore';
  // A fresh tab, but another window is already using this database. Wiping
  // would destroy a capture that is live on screen somewhere else.
  if (otherWindowLive) return 'restore';
  return 'wipe';
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
 * Wipes an orphaned session, and claims this tab either way.
 *
 * Must be awaited before anything reads the store, so a session that belongs to
 * a closed run of the app is deleted rather than restored onto the screen.
 */
export async function prepareStoredSession(): Promise<StartupAction> {
  const marker = readTabMarker();
  // Claimed immediately: from here on this tab owns whatever is in the store,
  // so a reload restores instead of wiping.
  markTabAlive();

  // Only worth asking when the marker is missing - a reload already has its
  // answer, and skipping the ping keeps the common path off a 250ms wait.
  const action = decideStartupAction(marker, marker === null ? await anotherWindowIsLive() : false);

  if (action === 'wipe') await clearSession();
  return action;
}
