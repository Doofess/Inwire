import { useEffect } from 'react';
import { nameResolutionStore, type NameResolutionPrefs } from '../services/interfacePrefs';
import { usePreferenceStore } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';
import { setNameResolutionOptions } from '../services/geoIpService';

/**
 * The name-resolution settings, and the side effect of applying them.
 *
 * Two of the four are passive and read by the views directly; the other two
 * gate an outbound lookup, and those have to reach the service that performs
 * it. The preference and the gate are deliberately in different places: the
 * preference is a UI concern - React store, cross-tab sync, a settings row -
 * while the gate is a service concern that has to cover every caller,
 * including ones that do not exist yet, which a component cannot promise.
 *
 * The outbound half is applied in an effect rather than during render because
 * it mutates module state, and React may render a component more than once for
 * a single commit.
 *
 * Returns the settings and a patcher so the app subscribes once. Two
 * components reading the same store is harmless; the app reading it twice in
 * the same render is a second subscription for a value it already has.
 */
export function useNameResolutionPreference(): ReturnType<typeof usePreferenceStore<NameResolutionPrefs>> {
  const [options, patch] = usePreferenceStore(nameResolutionStore);
  usePreferenceSync(
    nameResolutionStore.key,
    nameResolutionStore.normalize,
    nameResolutionStore.accept,
  );

  useEffect(() => {
    setNameResolutionOptions(options);
  }, [options]);

  return [options, patch];
}
