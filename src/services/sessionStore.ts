import { Packet, PacketStatus } from '../types/packet';

/**
 * Persists the live capture session so a browser refresh does not throw it
 * away.
 *
 * What is stored is what a pcap file stores: the raw frame bytes plus the
 * timestamps around them. Everything else a Packet carries - the dissected
 * layers, the protocol label, the info column, the stream ids - is derived
 * from those bytes by `decodeRawEthernetPacket`, so re-deriving on load is
 * both smaller and guaranteed to agree with a fresh dissection rather than
 * being a second copy that can drift.
 *
 * Measured on a real capture, at the 50,000-packet buffer cap:
 *
 *                        raw frames (this)   whole dissected packets
 *   storage                      46 MB              212 MB
 *   write cost per packet        36 us               93 us
 *   read back                   0.3 s               3.1 s
 *   rebuild after read          5.8 s                 -
 *
 * So storing dissected packets would restore about twice as fast but costs
 * 4.6x the disk and 2.6x the per-packet write during capture - and the write
 * happens continuously while the restore happens once. The restore is chunked
 * (see `readFrames`) so those seconds are spent with a responsive UI and a
 * filling list rather than a frozen tab.
 *
 * That 46 MB is for a 962-byte average frame, and is NOT an upper bound. A
 * link doing TCP segmentation offload hands up frames of tens of kilobytes:
 * the same 50,000-packet buffer measured 162 MB on a busy link, and the
 * theoretical worst case is far higher. Hence STORAGE_BUDGET_BYTES below - the
 * frame count mirrors the live buffer, but bytes need their own ceiling.
 *
 * IndexedDB rather than localStorage: even the small figure is ten times
 * localStorage's ~5 MB cap, and localStorage is synchronous - writing it
 * during capture would block the main thread this app has just been optimized
 * to keep free.
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
const MIGRATION_BATCH = 2000;
const DB_VERSION = 1;
const FRAME_STORE = 'frames';
const META_STORE = 'meta';
const SESSION_KEY = 'session';

/**
 * One captured frame, in the smallest form that can rebuild a Packet.
 *
 * `raw` is absent when the agent sent metadata only (no bytes to dissect). In
 * that case `fallback` carries the handful of display fields that packet ever
 * had, so it comes back exactly as unhelpful as it originally was rather than
 * being silently dropped or, worse, reconstructed with invented payload.
 */
export interface StoredFrame {
  id: number;
  /** Epoch milliseconds. Kept for frames stored before `tsUs` existed. */
  timestamp: number;
  /** Epoch microseconds; absent on frames stored by an older build. */
  tsUs?: number;
  relativeTime: number;
  timeDelta: number;
  length: number;
  interfaceName?: string;
  raw?: Uint8Array;
  fallback?: {
    source: string;
    destination: string;
    sourcePort?: number;
    destPort?: number;
    protocol: string;
    /**
     * The free-form protocol name, when it differs from the coarse `protocol`.
     *
     * A live agent frame never sets this - it has no dissector to name a layer.
     * A frame reconstructed from a spreadsheet row does: the Protocol column
     * holds what the packet list displayed ("TLSv1.2"), which is not a member
     * of `ProtocolType`, so the two halves have to travel separately.
     */
    protocolLabel?: string;
    info: string;
    /** Absent means 'ok', which is what a frame with no bytes to judge gets. */
    status?: PacketStatus;
  };
}

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
      if (!db.objectStoreNames.contains(FRAME_STORE)) {
        // Keyed by packet id, which is monotonic. That is what lets a buffer
        // trim delete a contiguous range rather than hunting for rows.
        db.createObjectStore(FRAME_STORE, { keyPath: 'id' });
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
 * The captured session is a crash-recovery cache rather than authored data, but
 * it is the difference between reopening the tab onto the packets you were
 * looking at and reopening it onto nothing - which after an update reads as
 * "the update lost my capture".
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
      const hasStores = legacy.objectStoreNames.contains(FRAME_STORE)
        && legacy.objectStoreNames.contains(META_STORE);
      const meta = hasStores
        ? await runTx<unknown>(legacy, META_STORE, 'readonly', (store) =>
            store.get(SESSION_KEY))
        : null;

      if (meta) {
        // Batched rather than one `getAll`, for the same reason the restore
        // path is: a full buffer is 50,000 frames and was measured at 162 MB,
        // and pulling that into a single array before writing any of it doubles
        // the peak for no benefit.
        let after = -Infinity;
        for (;;) {
          const range = Number.isFinite(after)
            ? IDBKeyRange.lowerBound(after, true)
            : undefined;
          const batch = await runTx<StoredFrame[]>(legacy, FRAME_STORE, 'readonly', (store) =>
            store.getAll(range, MIGRATION_BATCH));
          if (!batch?.length) break;
          await runTx(db, FRAME_STORE, 'readwrite', (store) => {
            for (const frame of batch) store.put(frame);
            return null;
          });
          after = batch[batch.length - 1].id;
          if (batch.length < MIGRATION_BATCH) break;
        }

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

// --- Writing -----------------------------------------------------------------

/**
 * Reduces a live Packet to the bytes worth keeping.
 *
 * Deliberately drops `layers`, `fields`, `frameProtocols`, `expert`,
 * `streamId` and the rest: all of them come back out of `raw` on restore, and
 * keeping them is what made the "store the whole packet" option 4.6x larger.
 */
export function toStoredFrame(packet: Packet): StoredFrame {
  const frame: StoredFrame = {
    id: packet.id,
    timestamp: packet.tsUs / 1000,
    tsUs: packet.tsUs,
    relativeTime: packet.relativeTime,
    timeDelta: packet.timeDelta,
    length: packet.length,
    interfaceName: packet.interfaceName,
  };
  if (packet.rawBytes && packet.rawBytes.length > 0) {
    // Copied, not referenced: the live packet's Uint8Array may be a view onto
    // a larger buffer, and structured-cloning a view would persist the whole
    // backing store behind it.
    frame.raw = new Uint8Array(packet.rawBytes);
  } else {
    frame.fallback = {
      source: packet.source,
      destination: packet.destination,
      sourcePort: packet.sourcePort,
      destPort: packet.destPort,
      protocol: packet.protocol,
      protocolLabel: packet.protocolLabel,
      info: packet.info,
      status: packet.status,
    };
  }
  return frame;
}

/**
 * The write path, which is single-flight and coalescing.
 *
 * This shape is not decoration - the naive version cost a locked-up tab. The
 * first cut called `put` straight from the 100ms packet flush and issued a
 * range delete on every flush once the buffer was full. That is fine at the
 * 20-100 packets/second a quiet link produces, and fatal at the ~1,000/second
 * a busy one does: ten transactions a second, each cloning about 100KB of
 * frames, with a range delete over a 50,000-row store behind every one of
 * them. The transactions queued faster than IndexedDB retired them, the cloned
 * frames piled up behind them, and the tab stopped responding entirely.
 *
 * So: at most one transaction in flight, everything that arrives while it runs
 * is merged into the next one, and the trim is amortized. Throughput is then
 * bounded by what IndexedDB can actually retire rather than by how fast
 * packets arrive.
 */

/** Frames waiting to be written. Drained whole, not one batch at a time. */
let pendingFrames: StoredFrame[] = [];
/** The lowest id worth keeping, applied by the drain loop when it has moved far enough. */
let pendingTrimFloor = 0;
let appliedTrimFloor = 0;
let drainPromise: Promise<void> | null = null;

/**
 * How far the live buffer's floor must rise before a delete is worth issuing.
 *
 * A range delete costs roughly the same whether it removes one row or ten
 * thousand, and once the buffer is capped the floor rises on every single
 * flush - so deleting per flush is the most expensive possible schedule for
 * the least possible benefit. Batching means the store runs at most this many
 * frames above the live buffer, which against a 50,000-packet cap is noise.
 */
const TRIM_BATCH = 5000;

/**
 * The most frames allowed to wait for the writer.
 *
 * Backpressure has to end somewhere. If IndexedDB cannot keep up with the
 * capture - a slow disk, a sustained flood - the choice is between dropping
 * some persistence and growing a queue until the tab dies. Persistence is a
 * convenience and the tab is not, so the oldest waiting frames are dropped.
 * The buffer in memory is unaffected; only what a refresh could restore is.
 */
const MAX_PENDING_FRAMES = 20000;

/**
 * The most disk a stored session may occupy.
 *
 * The live buffer is capped by packet count, which says nothing about bytes:
 * 50,000 small ACKs are about 46 MB, and 50,000 segmentation-offload frames
 * would be measured in gigabytes. Chrome's quota is a share of free disk, so
 * on a full drive the large case would start failing writes - silently, since
 * every write here is best-effort. A ceiling turns that into a predictable
 * "the oldest frames are not restorable" instead.
 *
 * When it is exceeded the oldest frames are dropped from disk only. The live
 * buffer is untouched, so this can cost a refresh some history but can never
 * cost the running session anything.
 */
const STORAGE_BUDGET_BYTES = 512 * 1024 * 1024;

/**
 * How much of the oldest history to drop to get back under the budget.
 *
 * Pure, and exported, because it is the only thing left in the app that deletes
 * a user's frames without being asked (`docs/decisions/0012`) - which makes it
 * worth being able to test directly rather than only through IndexedDB.
 *
 * It evicts from the front, so what a long capture loses is its **beginning**.
 * That is the right end to lose (the recent frames are the ones on screen) and
 * the wrong end to lose silently, which is why the count comes back out.
 */
export function planBudgetEviction(
  ledger: readonly { id: number; bytes: number }[],
  writtenBytes: number,
  budgetBytes: number,
): { evictCount: number; remainingBytes: number; dropUpTo: number } {
  let remainingBytes = writtenBytes;
  let evictCount = 0;
  let dropUpTo = 0;
  while (evictCount < ledger.length && remainingBytes > budgetBytes) {
    remainingBytes -= ledger[evictCount].bytes;
    // Exclusive: the floor is "the first id still kept", so it is one past the
    // frame just dropped.
    dropUpTo = ledger[evictCount].id + 1;
    evictCount++;
  }
  return { evictCount, remainingBytes, dropUpTo };
}

/**
 * Sizes of what has been written, oldest first, so the budget above can be
 * enforced without asking IndexedDB how big it is (which it cannot answer per
 * record). Two numbers per frame - at the 50,000 cap this ledger is a few
 * hundred KB, against the hundreds of MB it is there to bound.
 */
let writtenLedger: { id: number; bytes: number }[] = [];
let writtenBytes = 0;

/** Roughly what one frame occupies: its payload plus fixed-field overhead. */
function frameBytes(frame: StoredFrame): number {
  return (frame.raw?.byteLength ?? 0) + 64;
}

/** True when frames had to be dropped, so the caller can say so honestly. */
let droppedFromQueue = 0;

/**
 * Frames the storage budget evicted from disk.
 *
 * Counted apart from ordinary trimming, which is not a loss - a frame the live
 * buffer has already forgotten was never going to be restored. This one is:
 * these frames were captured, shown, and are still in the buffer, and the
 * beginning of the capture simply stops being restorable.
 *
 * It is counted because since `docs/decisions/0012` this is the **only**
 * automatic deletion left in the app, and an app that promises to keep a
 * capture until asked must say when it could not.
 */
let evictedForBudget = 0;

export function pendingWriteBacklog(): {
  queued: number;
  dropped: number;
  storedBytes: number;
  storageBudgetBytes: number;
  evictedForBudget: number;
} {
  return {
    queued: pendingFrames.length,
    dropped: droppedFromQueue,
    storedBytes: writtenBytes,
    storageBudgetBytes: STORAGE_BUDGET_BYTES,
    evictedForBudget,
  };
}

/**
 * Queues a batch of frames for persistence and returns immediately.
 *
 * Deliberately not async from the caller's point of view: the packet flush
 * must never wait on a disk write.
 */
export function appendFrames(packets: Packet[]): void {
  if (packets.length === 0) return;
  for (const packet of packets) pendingFrames.push(toStoredFrame(packet));
  if (pendingFrames.length > MAX_PENDING_FRAMES) {
    const overflow = pendingFrames.length - MAX_PENDING_FRAMES;
    pendingFrames.splice(0, overflow);
    droppedFromQueue += overflow;
  }
  void startDrain();
}

/**
 * Records that everything below `firstKeptId` has fallen out of the live
 * buffer. The delete itself happens in the drain loop, batched.
 */
export function trimFramesBelow(firstKeptId: number): void {
  if (firstKeptId > pendingTrimFloor) pendingTrimFloor = firstKeptId;
  void startDrain();
}

function startDrain(): Promise<void> {
  // Single flight: a drain already running will pick up whatever has been
  // queued behind it, so there is never a second concurrent writer.
  if (drainPromise) return drainPromise;
  drainPromise = drain().finally(() => {
    drainPromise = null;
    // Anything that arrived during the final transaction still needs a writer.
    if (pendingFrames.length > 0 || pendingTrimFloor - appliedTrimFloor >= TRIM_BATCH) {
      void startDrain();
    }
  });
  return drainPromise;
}

async function drain(): Promise<void> {
  const db = await openDb();
  if (!db) {
    // No database: stop accumulating frames nothing will ever write.
    pendingFrames = [];
    return;
  }

  while (pendingFrames.length > 0) {
    const batch = pendingFrames;
    pendingFrames = [];
    await runTx(db, FRAME_STORE, 'readwrite', (store) => {
      for (const frame of batch) store.put(frame);
      return null;
    });
    for (const frame of batch) {
      const bytes = frameBytes(frame);
      writtenLedger.push({ id: frame.id, bytes });
      writtenBytes += bytes;
    }
  }

  // Over budget: raise the trim floor past enough of the oldest frames to get
  // back under it. This only ever moves the floor forward, so it composes with
  // the buffer's own trimming rather than fighting it.
  if (writtenBytes > STORAGE_BUDGET_BYTES) {
    const plan = planBudgetEviction(writtenLedger, writtenBytes, STORAGE_BUDGET_BYTES);
    writtenBytes = plan.remainingBytes;
    writtenLedger = writtenLedger.slice(plan.evictCount);
    // Only here, not in the appliedTrimFloor pass below: that one drops frames
    // the live buffer has already forgotten, which costs the user nothing.
    evictedForBudget += plan.evictCount;
    if (plan.dropUpTo > pendingTrimFloor) pendingTrimFloor = plan.dropUpTo;
  }

  // Frames already dropped by the buffer's own trim are no longer ours to
  // count; without this the ledger would grow for the life of the session.
  if (appliedTrimFloor > 0) {
    let index = 0;
    while (index < writtenLedger.length && writtenLedger[index].id < appliedTrimFloor) {
      writtenBytes -= writtenLedger[index].bytes;
      index++;
    }
    if (index > 0) writtenLedger = writtenLedger.slice(index);
  }

  if (pendingTrimFloor - appliedTrimFloor >= TRIM_BATCH) {
    const floor = pendingTrimFloor;
    await runTx(db, FRAME_STORE, 'readwrite', (store) => {
      store.delete(IDBKeyRange.upperBound(floor, true));
      return null;
    });
    appliedTrimFloor = floor;
  }
}

/** Test seam, and what a buffer clear needs so no stale write lands after it. */
export function resetWriteQueue(): void {
  pendingFrames = [];
  pendingTrimFloor = 0;
  appliedTrimFloor = 0;
  droppedFromQueue = 0;
  writtenLedger = [];
  writtenBytes = 0;
  evictedForBudget = 0;
}

export async function saveSessionMeta(meta: SessionMeta): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await runTx(db, META_STORE, 'readwrite', (store) => {
    store.put(meta, SESSION_KEY);
    return null;
  });
}

/** Wipes the stored session. What "Clear Packet Buffer" means on disk. */
export async function clearSession(): Promise<void> {
  // Dropped first, so frames queued before the clear cannot land after it and
  // resurrect part of the capture the user just discarded.
  resetWriteQueue();
  const db = await openDb();
  if (!db) return;
  await runTx(db, FRAME_STORE, 'readwrite', (store) => {
    store.clear();
    return null;
  });
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

export async function countFrames(): Promise<number> {
  const db = await openDb();
  if (!db) return 0;
  const n = await runTx<number>(db, FRAME_STORE, 'readonly', (store) => store.count());
  return n ?? 0;
}

/**
 * Streams stored frames to `onBatch` in id order, a chunk at a time.
 *
 * Chunked rather than one `getAll`, because the caller has to dissect each
 * frame and dissection is the expensive half of a restore (115us per packet
 * measured, so 5.8s for a full 50,000-packet buffer). Handing them over in
 * batches lets the caller decode a batch, yield to the browser, and decode the
 * next - the list fills in visibly instead of the tab locking up.
 *
 * `onBatch` may return false to stop early.
 */
/**
 * The span of frame ids whose bytes are actually on disk right now.
 *
 * Pure, so the rule can be tested without a database. The write ledger holds
 * one entry per frame the store has confirmed written, oldest first, and both
 * the buffer's trimming and the storage budget slice from its front - so the
 * ledger *is* the answer to "what could be read back", and its ends are the
 * range. Null when nothing is stored.
 *
 * This is what makes it safe to stop holding a frame's bytes in memory: they
 * can be dropped once they are inside this range, and must not be dropped
 * before, because `toStoredFrame` writes a byte-less frame as a `fallback`
 * block and the bytes would be gone from both places at once.
 */
export function ledgerRange(
  ledger: readonly { id: number; bytes: number }[],
): { first: number; last: number } | null {
  if (ledger.length === 0) return null;
  return { first: ledger[0].id, last: ledger[ledger.length - 1].id };
}

/** The span of frame ids currently readable from disk, or null. */
export function storedIdRange(): { first: number; last: number } | null {
  return ledgerRange(writtenLedger);
}

/**
 * The raw bytes of specific frames, read back from disk.
 *
 * The counterpart to not keeping every frame's bytes in memory. Every frame's
 * bytes are already written (`toStoredFrame`), and the store is keyed by frame
 * id, so this needs no new persistence - only a way to ask for one frame rather
 * than walking the whole session with `readFrames`.
 *
 * One transaction for the whole request: a stream of a few thousand frames is a
 * few thousand `get`s, and a transaction each would be a few thousand round
 * trips. Ids absent from the result are frames the store does not have - budget
 * evicted, trimmed, or never written - which is a fact for the caller to render
 * honestly rather than an error.
 */
export async function readFrameBytes(
  ids: readonly number[],
): Promise<Map<number, Uint8Array>> {
  const out = new Map<number, Uint8Array>();
  if (ids.length === 0) return out;
  const db = await openDb();
  if (!db) return out;

  const wanted = [...new Set(ids)];
  await runTx<StoredFrame | undefined>(db, FRAME_STORE, 'readonly', (store) => {
    let last: IDBRequest<StoredFrame | undefined> | null = null;
    for (const id of wanted) {
      const request = store.get(id) as IDBRequest<StoredFrame | undefined>;
      // Collected per request rather than from the transaction, which reports
      // only the last one. `oncomplete` still gates the promise, so every
      // handler below has run by the time this resolves.
      request.onsuccess = () => {
        const raw = request.result?.raw;
        if (raw && raw.byteLength > 0) out.set(id, raw);
      };
      last = request;
    }
    return last;
  });
  return out;
}

export async function readFrames(
  batchSize: number,
  onBatch: (frames: StoredFrame[]) => boolean | void | Promise<boolean | void>,
): Promise<void> {
  const db = await openDb();
  if (!db) return;

  let lastKey: number | null = null;
  for (;;) {
    const range = lastKey === null ? null : IDBKeyRange.lowerBound(lastKey, true);
    const batch = await runTx<StoredFrame[]>(db, FRAME_STORE, 'readonly', (store) =>
      store.getAll(range, batchSize),
    );
    if (!batch || batch.length === 0) return;
    lastKey = batch[batch.length - 1].id;
    // Seed the size ledger from what is already on disk. Without this the byte
    // budget would only ever account for frames written since the last page
    // load, so a store could grow past the ceiling one refresh at a time.
    for (const frame of batch) {
      const bytes = frameBytes(frame);
      writtenLedger.push({ id: frame.id, bytes });
      writtenBytes += bytes;
    }
    const keepGoing = await onBatch(batch);
    if (keepGoing === false) return;
    if (batch.length < batchSize) return;
  }
}
