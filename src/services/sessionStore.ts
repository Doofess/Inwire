
/**
 * What is left of the stored session: everything about it except the frames.
 *
 * This module used to be where a capture lived. It held every frame's raw
 * bytes in IndexedDB, bounded by a 512 MB budget, drained by a single-flight
 * write queue, and a refresh restored the capture by re-dissecting all of it.
 * The frames are now in the capture store (`services/capture/`), and what
 * remains here is the session's **metadata** - which adapter, which
 * interfaces, the relative-time origin, whose machine it was, and which
 * capture directory on disk belongs to this session.
 *
 * Three things went with the frames, and each is worth naming because each was
 * load-bearing:
 *
 *  - **`toStoredFrame` and the re-dissecting restore.** A frame's row is not a
 *    function of its own bytes - the TCP sequence base, the TLS record cursor,
 *    the DNS pairing are state the frames before it built - so re-dissecting
 *    one from the middle of a capture could produce a *different* Info line,
 *    not merely a slower one. The capture store writes the row itself, so a
 *    restore reads what the reader actually saw. It is also five seconds
 *    faster on a full buffer, which was never the reason.
 *  - **`STORAGE_BUDGET_BYTES` and `planBudgetEviction`.** These deleted the
 *    oldest frames to stay under 512 MB, and were the last automatic deletion
 *    in the app (`docs/decisions/0012`). Their floor also rose faster than the
 *    RAM window's, which pinned raw bytes in memory - see
 *    `services/capture/captureReader.ts`.
 *  - **The drain loop.** A single-flight queue existed because IndexedDB
 *    transactions queued faster than they retired and the clones piled up
 *    behind them. A synchronous access handle in a Worker has no such
 *    failure mode.
 *
 * The metadata is a few hundred bytes written every couple of seconds, so
 * IndexedDB is still exactly right for it - and keeping it here means a
 * session's non-frame half is unchanged by all of the above.
 */

const DB_NAME = 'inwire';

/**
 * The database name this app used before it was renamed.
 *
 * Read once, on the first open after an update, and deleted afterwards. See
 * `migrateLegacyDatabase`.
 */
const LEGACY_DB_NAME = 'netview';

/** Frames copied per transaction during that migration. */
/**
 * Bumped when the frames left.
 *
 * Version 2 **deletes** the `frames` object store, which is the only way to
 * reclaim what a previous build wrote: up to 512 MB of raw capture that
 * nothing reads any more, and which would otherwise sit against the origin's
 * quota - the same quota the capture store now needs. An object store cannot
 * be dropped outside an upgrade, so the version had to move.
 */
const DB_VERSION = 2;
const LEGACY_FRAME_STORE = 'frames';
const META_STORE = 'meta';
const SESSION_KEY = 'session';

/** The bits of a session that are not frames. */
export interface SessionMeta {
  /** Which adapter the capture was running on, so it can be re-selected. */
  selectedInterfaces: string[];
  /**
   * The adapters known at save time, as id/label pairs.
   *
   * Stored once per session rather than per frame. A StoredFrame keeps only
   * `interfaceName`, which is the human label - but the Frame layer also shows
   * the adapter's id, and rebuilding it needs the pair. Holding the table here
   * costs a few hundred bytes for the whole session instead of ~90 bytes on
   * every one of up to 50,000 frames, and still restores a buffer that spans
   * more than one adapter correctly, since the lookup is per frame.
   */
  interfaces: { name: string; label: string }[];
  /** The relative-time origin, so restored packets keep their timeline. */
  captureStartMs: number | null;
  /** The last packet's epoch time, so the first new delta is honest. */
  lastPacketMs: number | null;
  /** When this session was last written, for the "restored" notice. */
  updatedAt: number;
  /**
   * Which capture directory on disk this session's frames are in.
   *
   * The one link between the two halves, and it has to exist: the metadata
   * says what the relative-time origin is and which adapter labels map to
   * which ids, and pairing that with a *different* capture's frames would
   * shift every timestamp in the list. A session written before this was
   * saved, or one whose directory has since been removed, restores nothing -
   * which is what a session with no frames has always done.
   */
  captureId?: string | null;
  /**
   * Whose machine took this capture.
   *
   * Saved rather than re-derived, and it is not an optimisation. A restore
   * re-dissects every frame from its bytes, and the dissector needs the
   * direction *while* it works: the checksum verdict depends on it (a frame
   * this machine sent was handed to the sniffer before the NIC filled the
   * checksum in, so the honest verdict is `Unverified`), and that verdict is a
   * tree row, an expert finding and a dense column - none of which can be
   * corrected afterwards. The direction pass that runs after a restore is
   * therefore too late for it.
   *
   * An import solves the same problem by scoring a prefix before it dissects
   * (`PcapService.inferHostFromFrames`). A session does not have to: it knew
   * the answer when it captured - usually from the agent's own adapter list,
   * which is better than any inference - so it writes it down. That also
   * carries a user's manual override across a reload, which re-inferring
   * would silently discard.
   *
   * A `Set` does not survive the trip into IndexedDB as itself, so the two
   * sets travel as arrays and are rebuilt on load, exactly as they are on the
   * way to the Worker.
   */
  host?: StoredHost;
}

/** `HostIdentity` in a shape IndexedDB can hold. See `SessionMeta.host`. */
export interface StoredHost {
  macs: string[];
  addresses: string[];
  inferred: boolean;
  confidence: number;
  basis?: string;
}

// --- Opening -----------------------------------------------------------------

let dbPromise: Promise<IDBDatabase | null> | null = null;

/**
 * Opens the database, or resolves null if IndexedDB is unavailable.
 *
 * Null rather than throwing: persistence is a convenience, and a browser with
 * site data blocked, a private window that refuses IndexedDB, or a failed
 * upgrade must all leave the app fully working with an in-memory-only session.
 * Every function below no-ops on null.
 */
function openDb(): Promise<IDBDatabase | null> {
  if (dbPromise) return dbPromise;
  // The migration is folded into the open rather than run beside it, so that
  // every caller - restore, trim, append - is holding a database that has
  // already absorbed the old one. A migration running in parallel with the
  // first append would be racing it for the same object store.
  dbPromise = openCurrentDb().then(async (db) => {
    if (db) await migrateLegacyDatabase(db);
    return db;
  });
  return dbPromise;
}

function openCurrentDb(): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    request.onupgradeneeded = () => {
      const db = request.result;
      // The frames are in the capture store now. Dropping the store here is
      // what actually frees the bytes a previous build left behind; clearing
      // it would leave an empty store to explain for ever.
      if (db.objectStoreNames.contains(LEGACY_FRAME_STORE)) {
        db.deleteObjectStore(LEGACY_FRAME_STORE);
      }
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE);
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      // Another tab opening a newer version would otherwise block it forever.
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });
}

/**
 * Carry a stored session across the app's rename, once.
 *
 * The captured session is a crash-recovery cache rather than authored data,
 * but it is the difference between reopening the tab onto the adapter and
 * timeline you were working with and reopening it onto nothing - which after
 * an update reads as "the update lost my capture".
 *
 * **The metadata only.** The old database's frames are in a store this build
 * has just deleted from its own database, and copying them into a store that
 * no longer exists to feed a restore that no longer reads it would be work
 * with no reader. A session carried across the rename comes back naming a
 * capture directory that the old build never wrote, so it restores no frames -
 * which is the same answer as before for anyone whose frames the old build's
 * 512 MB budget had already evicted.
 *
 * Only runs when the current database is empty. A session already stored under
 * the new name is the newer one by construction, and must not be overwritten
 * by whatever the old build left behind.
 *
 * Opening the old database WITHOUT a version is what makes this safe to call
 * forever: that form opens an existing database at whatever version it is on,
 * and only fires `onupgradeneeded` when it had to create one. So an
 * `onupgradeneeded` here means there was nothing to migrate, and the empty
 * database this call just brought into being is deleted again on the way out -
 * otherwise every load would recreate the very thing it is trying to remove.
 */
async function migrateLegacyDatabase(db: IDBDatabase): Promise<void> {
  try {
    const existing = await runTx<unknown>(db, META_STORE, 'readonly', (store) =>
      store.get(SESSION_KEY));
    if (existing) return;

    const legacy = await new Promise<IDBDatabase | null>((resolve) => {
      let created = false;
      let request: IDBOpenDBRequest;
      try {
        request = indexedDB.open(LEGACY_DB_NAME);
      } catch {
        resolve(null);
        return;
      }
      request.onupgradeneeded = () => {
        created = true;
      };
      request.onsuccess = () => {
        const opened = request.result;
        if (created) {
          opened.close();
          try {
            indexedDB.deleteDatabase(LEGACY_DB_NAME);
          } catch {
            // Nothing to clean up that we can reach. Harmless either way.
          }
          resolve(null);
          return;
        }
        resolve(opened);
      };
      request.onerror = () => resolve(null);
      request.onblocked = () => resolve(null);
    });
    if (!legacy) return;

    try {
      const meta = legacy.objectStoreNames.contains(META_STORE)
        ? await runTx<unknown>(legacy, META_STORE, 'readonly', (store) => store.get(SESSION_KEY))
        : null;
      if (meta) {
        await runTx(db, META_STORE, 'readwrite', (store) => store.put(meta, SESSION_KEY));
      }
    } finally {
      legacy.close();
    }

    try {
      indexedDB.deleteDatabase(LEGACY_DB_NAME);
    } catch {
      // The copy is what mattered; a database left behind costs nothing but
      // space, and the emptiness check above stops it being read twice.
    }
  } catch {
    // A blocked, full or unavailable IndexedDB. The session is a cache - the
    // app starts without it exactly as it would on a fresh machine.
  }
}

function runTx<T>(
  db: IDBDatabase,
  store: string,
  mode: IDBTransactionMode,
  body: (store: IDBObjectStore) => IDBRequest<T> | null,
): Promise<T | null> {
  return new Promise((resolve) => {
    let request: IDBRequest<T> | null = null;
    try {
      const tx = db.transaction(store, mode);
      request = body(tx.objectStore(store));
      tx.oncomplete = () => resolve(request ? request.result : null);
      tx.onerror = () => resolve(null);
      tx.onabort = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function saveSessionMeta(meta: SessionMeta): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await runTx(db, META_STORE, 'readwrite', (store) => {
    store.put(meta, SESSION_KEY);
    return null;
  });
}

/**
 * Forgets the stored session.
 *
 * The metadata only. The frames are in the capture store, and removing them is
 * `captureStore.discard` - one act, in one place, because "the only thing that
 * deletes a user's capture" (`docs/decisions/0012`) is a promise that needs a
 * single door rather than two that have to be kept in step.
 */
export async function clearSession(): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await runTx(db, META_STORE, 'readwrite', (store) => {
    store.delete(SESSION_KEY);
    return null;
  });
}

// --- Reading -----------------------------------------------------------------

function isSessionMeta(value: unknown): value is SessionMeta {
  if (typeof value !== 'object' || value === null) return false;
  const meta = value as Record<string, unknown>;
  return Array.isArray(meta.selectedInterfaces);
}

export async function loadSessionMeta(): Promise<SessionMeta | null> {
  const db = await openDb();
  if (!db) return null;
  const raw = await runTx<unknown>(db, META_STORE, 'readonly', (store) => store.get(SESSION_KEY));
  if (!isSessionMeta(raw)) return null;
  return {
    selectedInterfaces: raw.selectedInterfaces.filter((i): i is string => typeof i === 'string'),
    interfaces: Array.isArray(raw.interfaces)
      ? raw.interfaces.filter(
          (i): i is { name: string; label: string } =>
            typeof i === 'object' && i !== null &&
            typeof (i as { name?: unknown }).name === 'string' &&
            typeof (i as { label?: unknown }).label === 'string',
        )
      : [],
    captureStartMs: typeof raw.captureStartMs === 'number' ? raw.captureStartMs : null,
    lastPacketMs: typeof raw.lastPacketMs === 'number' ? raw.lastPacketMs : null,
    updatedAt: typeof raw.updatedAt === 'number' ? raw.updatedAt : 0,
    captureId: typeof raw.captureId === 'string' ? raw.captureId : null,
    host: readStoredHost((raw as { host?: unknown }).host),
  };
}

/**
 * Reads back a stored host, field by field like every other preference here.
 *
 * `undefined` for a session written before this was saved, which is the same
 * answer as "this capture never had a host" and gets the same treatment: the
 * frames restore with no direction, exactly as they did before, rather than
 * with one invented out of a half-read record.
 */
function readStoredHost(raw: unknown): StoredHost | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const h = raw as Partial<StoredHost>;
  const strings = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  const macs = strings(h.macs);
  const addresses = strings(h.addresses);
  // A host that names nothing cannot decide any frame's direction, so it is
  // not a host: `NO_HOST` and a missing record are the same state and are
  // deliberately not distinguished.
  if (macs.length === 0 && addresses.length === 0) return undefined;
  return {
    macs,
    addresses,
    inferred: h.inferred === true,
    confidence: typeof h.confidence === 'number' ? h.confidence : 0,
    ...(typeof h.basis === 'string' ? { basis: h.basis } : {}),
  };
}
