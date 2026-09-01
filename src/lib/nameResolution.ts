import { useEffect } from 'react';
import { nameResolutionStore } from '../services/interfacePrefs';
import { usePreferenceStore } from '../services/preferenceStore';
import { usePreferenceSync } from '../services/preferences';
import { setNameResolutionOptions } from '../services/geoIpService';

/**
 * Pushes the outbound-lookup settings into the service that performs them.
 *
 * The preference and the gate are deliberately in different places. The
 * preference is a UI concern - it needs a React store, cross-tab sync and a
 * settings row. The gate is a service concern: it has to cover every caller,
 * including ones that do not exist yet, and a component cannot promise that.
 *
 * Applied in an effect rather than during render because it mutates module
 * state, and React may render a component more than once for a single commit.
 */
export function useNameResolutionPreference(): void {
  const [options] = usePreferenceStore(nameResolutionStore);
  usePreferenceSync(
    nameResolutionStore.key,
    nameResolutionStore.normalize,
    nameResolutionStore.accept,
  );

  useEffect(() => {
    setNameResolutionOptions(options);
  }, [options]);
}
