import { useEffect } from 'react';
import { motionStore } from '../services/interfacePrefs';
import { usePreferenceValue } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';

/**
 * Applies the motion setting to the document.
 *
 * Three states - follow the system, always animate, never animate - collapsed
 * here into the two the rest of the app cares about, written to `<html>` as
 * `data-motion="reduce" | "full"`.
 *
 * The resolution has to happen in JS. The obvious implementation is a CSS media
 * query, and that is what the app had: `@media (prefers-reduced-motion: reduce)`
 * killing the menu animations. A media query cannot be overridden by an
 * attribute, so an in-app setting layered on top would have been broken in both
 * directions - "Always" could not re-enable motion for someone whose OS asks
 * for less of it, and "Never" would not have stopped it for someone whose OS
 * does not. Reading the query here and writing a resolved value gives CSS one
 * thing to look at, and the setting actually works.
 *
 * `matchMedia` is subscribed to, not merely read, so changing the OS setting
 * takes effect immediately while on "Follow system" rather than at next reload.
 */
export function useMotionPreference(): void {
  const [motion] = usePreferenceValue(motionStore);
  usePreferenceSync(motionStore.key, motionStore.normalize, motionStore.accept);

  useEffect(() => {
    const root = document.documentElement;
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');

    const apply = () => {
      const reduce = motion === 'never' || (motion === 'system' && query.matches);
      root.setAttribute('data-motion', reduce ? 'reduce' : 'full');
    };

    apply();
    // Only worth listening while the setting defers to the system; an explicit
    // choice does not change because the OS did.
    if (motion !== 'system') return;
    query.addEventListener('change', apply);
    return () => query.removeEventListener('change', apply);
  }, [motion]);
}

/**
 * Whether motion should be suppressed, for code CSS cannot reach.
 *
 * The blanket CSS rule covers animations and transitions, which is most of the
 * app. It does not cover a MapLibre camera flight or a D3 transition, because
 * neither is a CSS animation - they are JavaScript writing new values every
 * frame. Those have to ask.
 */
export function prefersReducedMotion(): boolean {
  if (typeof document === 'undefined') return false;
  return document.documentElement.getAttribute('data-motion') === 'reduce';
}
