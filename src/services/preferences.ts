import { useEffect, useRef } from 'react';

/**
 * One mechanism for every UI preference NetView persists in localStorage.
 *
 * Each preference keeps its own key and its own shape - there is no combined
 * envelope. Separate keys mean a corrupt value in one cannot take the others
 * down with it, and the `storage` event names the key that changed, so a
 * listener can react to exactly one preference instead of re-reading all of
 * them.
 *
 * Three things this exists to get right, which every hand-rolled copy of this
 * logic in the app got wrong in the same way:
 *
 *   1. Writes are debounced. A column or minimap drag changes its value on
 *      every mousemove, and each write is a synchronous serialize.
 *   2. Pending writes are flushed on `pagehide`, so a drag followed straight
 *      away by closing the tab is not lost.
 *   3. Reads validate. A value from localStorage is untrusted input - it can
 *      be hand-edited, or left behind by an older build - and a bad one must
 *      produce defaults, never a crash.
 */

/**
 * The storage seam. Only here so the logic can be exercised against an
 * in-memory implementation in `scripts/preferences/storage.ts`, where there is
 * no browser - it is not an abstraction over "maybe we switch to cookies",
 * which we are not doing.
 */
export interface PreferenceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * Reading `globalThis.localStorage` at all throws in a browser configured to
 * block site data - it is not merely absent - so even the lookup is guarded.
 */
function defaultStorage(): PreferenceStorage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * The last value each key is known to hold, as serialized JSON.
 *
 * This is what stops two open tabs from writing to each other forever: a tab
 * that receives a `storage` event applies the new value to its own state,
 * whose change would otherwise schedule a write of that same value straight
 * back, waking the other tab again. Recording what we just read or wrote lets
 * the writer recognise "this value is already stored" and stay quiet.
 *
 * It also means mounting the app writes nothing, since loading a preference
 * records it.
 */
const lastSerialized = new Map<string, string>();

/** Debounced writes that have not landed yet, keyed by preference. */
const pendingWrites = new Map<
  string,
  { value: unknown; timer: ReturnType<typeof setTimeout> }
>();

/**
 * Reads a preference, validating it through `normalize`.
 *
 * `normalize` returns null for anything it will not vouch for, and the caller's
 * `fallback` is used instead. Validating field by field rather than trusting
 * that `JSON.parse` succeeded is the whole point - see `normalizeLibrary` in
 * filterPresets.ts for the pattern at its fullest.
 */
export function loadPreference<T>(
  key: string,
  normalize: (raw: unknown) => T | null,
  fallback: T,
  storage: PreferenceStorage | null = defaultStorage(),
): T {
  let value = fallback;
  try {
    const raw = storage?.getItem(key);
    if (raw) value = normalize(JSON.parse(raw)) ?? fallback;
  } catch {
    // Unreadable storage, malformed JSON, or a normalize that threw. All three
    // mean the same thing to the caller: use the default.
  }
  // Record the *normalized* value rather than the raw string. Recording the raw
  // string would make the first change look like a no-op whenever normalize
  // clamped something, and the clamped value would never reach storage.
  try {
    lastSerialized.set(key, JSON.stringify(value));
  } catch {
    // A value that cannot be serialized simply is not tracked; the writer will
    // treat the next change as new, which is the safe direction.
  }
  return value;
}

/** Writes a preference immediately. Failures are silent by design. */
export function savePreference(
  key: string,
  value: unknown,
  storage: PreferenceStorage | null = defaultStorage(),
): void {
  try {
    const serialized = JSON.stringify(value);
    storage?.setItem(key, serialized);
    lastSerialized.set(key, serialized);
  } catch {
    // Quota exhausted, site data blocked, or an unserializable value. The
    // preference still works for this session; only persistence is lost, and
    // there is nothing useful to recover.
  }
}

/**
 * True when `value` already matches what storage is known to hold, so writing
 * it again would be pure noise.
 */
function alreadyStored(key: string, value: unknown): boolean {
  try {
    return lastSerialized.get(key) === JSON.stringify(value);
  } catch {
    return false;
  }
}

/**
 * Queues a write, replacing any write already queued for the same key.
 *
 * Exported for the tests; components use `useDebouncedPreference`.
 */
export function schedulePreferenceWrite(
  key: string,
  value: unknown,
  delayMs: number,
  storage: PreferenceStorage | null = defaultStorage(),
): void {
  const existing = pendingWrites.get(key);
  if (existing) clearTimeout(existing.timer);
  const timer = setTimeout(() => {
    pendingWrites.delete(key);
    savePreference(key, value, storage);
  }, delayMs);
  pendingWrites.set(key, { value, timer });
}

/**
 * Writes every queued preference right now.
 *
 * Called from `pagehide`, and available to tests. localStorage writes are
 * synchronous, so they complete even as the page goes away.
 */
export function flushPendingPreferenceWrites(
  storage: PreferenceStorage | null = defaultStorage(),
): void {
  for (const [key, entry] of pendingWrites) {
    clearTimeout(entry.timer);
    savePreference(key, entry.value, storage);
  }
  pendingWrites.clear();
}

/** Test seam: drop queued writes without performing them. */
export function cancelPendingPreferenceWrites(): void {
  for (const entry of pendingWrites.values()) clearTimeout(entry.timer);
  pendingWrites.clear();
}

/** Test seam: forget what storage is believed to hold. */
export function resetPreferenceCache(): void {
  lastSerialized.clear();
}

/**
 * Keys this build no longer reads.
 *
 * Retiring a preference is not the same as ignoring it. A key nothing honours
 * still sits in storage looking like live configuration to anyone who opens
 * devtools and reads it - which is the reasoning that was already written out
 * for `netview.packetTheme`, as a one-off `removeItem` at the top of App. This
 * is that, with somewhere for the next one to go.
 */
export const RETIRED_PREFERENCE_KEYS: readonly string[] = [
  // The packet list used to carry its own theme, chosen separately from the
  // app theme. The two are one choice now.
  'netview.packetTheme',
];

export function clearRetiredPreferences(
  storage: PreferenceStorage | null = defaultStorage(),
): void {
  for (const key of RETIRED_PREFERENCE_KEYS) {
    try {
      // Not every PreferenceStorage has removeItem - the in-memory one used by
      // the assertion scripts is the read/write pair and nothing more - so this
      // asks rather than assumes.
      (storage as { removeItem?: (k: string) => void } | null)?.removeItem?.(key);
    } catch {
      // Storage unavailable or blocked. Nothing to clean up, nothing to report.
    }
  }
}

/**
 * One set of flush listeners for the whole app rather than a pair per hook -
 * they all flush the same queue, so more than one is redundant.
 *
 * `pagehide` rather than `beforeunload`: `beforeunload` disqualifies the page
 * from the back/forward cache, and `pagehide` fires in every case that one
 * does. `visibilitychange` covers being backgrounded on mobile, where a tab
 * can be discarded without ever firing `pagehide`.
 */
let flushListenersAttached = false;
/**
 * Exported because a module-level preference store has no unmount hook.
 *
 * `useDebouncedPreference` attaches these on mount, so anything using the hook
 * gets flush-on-hide for free. A store created at module scope never mounts,
 * and until this was exported it inherited the listeners only by accident -
 * whenever some *other* component happened to use the hook. Its queued writes
 * were one "nobody used the hook this session" away from being dropped at
 * page hide.
 */
export function ensureFlushListeners(): void {
  attachFlushListeners();
}

function attachFlushListeners(): void {
  if (flushListenersAttached || typeof window === 'undefined') return;
  flushListenersAttached = true;
  const flush = () => flushPendingPreferenceWrites();
  window.addEventListener('pagehide', flush);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flush();
  });
}

/**
 * Persists `value` under `key`, debounced, flushing on page hide.
 *
 * Deliberately writes nothing when the value already matches storage, which
 * covers both the initial mount and a value that arrived from another tab.
 */
export function useDebouncedPreference(key: string, value: unknown, delayMs = 250): void {
  useEffect(() => {
    attachFlushListeners();
  }, []);

  useEffect(() => {
    if (alreadyStored(key, value)) return;
    schedulePreferenceWrite(key, value, delayMs);
  }, [key, value, delayMs]);

  // A component that unmounts mid-drag - switching views, closing a modal -
  // must not take its pending write with it.
  useEffect(() => {
    return () => {
      const pending = pendingWrites.get(key);
      if (pending) {
        clearTimeout(pending.timer);
        pendingWrites.delete(key);
        savePreference(key, pending.value);
      }
    };
  }, [key]);
}

/**
 * Calls `onExternalChange` when another tab changes this preference.
 *
 * The `storage` event fires only in tabs that did *not* perform the write, so
 * a handler here can set state without echoing back to itself. The handler
 * receives the already-validated value.
 */
export function usePreferenceSync<T>(
  key: string,
  normalize: (raw: unknown) => T | null,
  onExternalChange: (value: T) => void,
): void {
  // Held in a ref so a caller passing an inline arrow does not re-subscribe on
  // every render.
  const handlerRef = useRef(onExternalChange);
  useEffect(() => {
    handlerRef.current = onExternalChange;
  }, [onExternalChange]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onStorage = (event: StorageEvent) => {
      if (event.key !== key) return;
      // newValue is null when the key was removed - treat that as "nothing to
      // apply" rather than clobbering state with defaults.
      if (event.newValue === null) return;
      let next: T | null = null;
      try {
        next = normalize(JSON.parse(event.newValue));
      } catch {
        return; // Another tab wrote something unreadable; keep what we have.
      }
      if (next === null) return;
      lastSerialized.set(key, event.newValue);
      handlerRef.current(next);
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [key, normalize]);
}
