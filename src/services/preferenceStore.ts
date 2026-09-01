import { useCallback, useSyncExternalStore } from 'react';
import {
  ensureFlushListeners,
  loadPreference,
  schedulePreferenceWrite,
} from './preferences';

/**
 * A preference that more than one component reads and writes.
 *
 * `preferences.ts` gives each component a way to own a preference outright, and
 * for most of them that is right: the minimap owns its width, the packet list
 * owns its column widths, and nothing else asks.
 *
 * The interface settings are not like that. Each one has at least two views -
 * the Settings tab where it is listed, and the thing it actually controls - and
 * several have a third, because the control is also offered in place (a column
 * menu, a rail button, a divider). Those views are in different subtrees, and
 * some of them WRITE.
 *
 * The obvious answer, a hook that each component calls, does not work here, and
 * the reason is worth writing down because the failure is quiet. Cross-tab sync
 * arrives through the `storage` event, which by specification fires only in the
 * tabs that did NOT perform the write. Two components each holding their own
 * copy would therefore never learn about each other's changes WITHIN one tab -
 * the settings toggle would move and the thing it controls would not.
 *
 * So the value lives once, in a module, and components subscribe. The
 * alternative - lifting all of it into App - would put a dozen values and their
 * setters through a component that re-renders about ten times a second during
 * capture, and would drill callbacks down to leaves that only want to write.
 *
 * Deliberately not a state library: this is the store interface
 * `useSyncExternalStore` already expects, and it reuses the validation,
 * debouncing and flush-on-hide that `preferences.ts` has.
 */
export interface PreferenceStore<T> {
  readonly key: string;
  readonly defaults: T;
  readonly normalize: (raw: unknown) => T | null;
  get(): T;
  /** Applies a change and queues a write. */
  set(next: T): void;
  /**
   * Applies a change that came FROM storage - another tab's write.
   *
   * Notifies subscribers without queueing a write of its own, which is what
   * stops two open tabs from writing the same value back and forth forever.
   */
  accept(next: T): void;
  subscribe(listener: () => void): () => void;
}

/** How long a change waits before it is written. Matches useDebouncedPreference. */
const WRITE_DELAY_MS = 250;

export function createPreferenceStore<T>(
  key: string,
  normalize: (raw: unknown) => T | null,
  defaults: T,
): PreferenceStore<T> {
  // Read once, at module scope, so the first render already has the stored
  // value rather than a default that gets corrected a frame later.
  let value = loadPreference(key, normalize, defaults);
  const listeners = new Set<() => void>();
  const emit = () => {
    for (const listener of listeners) listener();
  };

  return {
    key,
    defaults,
    normalize,
    get: () => value,

    set(next: T) {
      // A deep comparison, not Object.is. Callers build the next value by
      // spreading - `{ ...get(), panes: false }` - so the reference always
      // differs even when every field is unchanged. Without this, re-selecting
      // the option that is already active would notify every subscriber, and
      // one of those subscribers renders a virtualized table of 50,000 rows.
      if (JSON.stringify(next) === JSON.stringify(value)) return;
      value = next;
      // The queue is flushed on pagehide by listeners that `preferences.ts`
      // attaches lazily. A module store has no unmount hook to flush from, so
      // this is its only chance to be flushed at all.
      ensureFlushListeners();
      schedulePreferenceWrite(key, value, WRITE_DELAY_MS);
      emit();
    },

    accept(next: T) {
      value = next;
      emit();
    },

    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

/**
 * Reads a preference store, and returns a patcher for it.
 *
 * The patcher takes a partial so callers change one field without restating the
 * rest - `patch({ panes: false })` rather than spreading by hand at every call
 * site and risking one that drops a sibling.
 */
export function usePreferenceStore<T extends object>(
  store: PreferenceStore<T>,
): [T, (patch: Partial<T>) => void] {
  const value = useSyncExternalStore(store.subscribe, store.get, store.get);
  const patch = useCallback(
    (next: Partial<T>) => store.set({ ...store.get(), ...next }),
    [store],
  );
  return [value, patch];
}

/**
 * Reads a store whose value is a bare string, number or boolean.
 *
 * Kept separate from the patching version because a partial of a primitive is
 * meaningless - these are set outright.
 */
export function usePreferenceValue<T>(store: PreferenceStore<T>): [T, (next: T) => void] {
  const value = useSyncExternalStore(store.subscribe, store.get, store.get);
  const set = useCallback((next: T) => store.set(next), [store]);
  return [value, set];
}
