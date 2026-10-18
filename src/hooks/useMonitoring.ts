import { useSyncExternalStore } from 'react';
import { getMonitoringClient } from '../services/monitoring/appClient';
import type { MonitoringState } from '../services/monitoring/state';

// Module-level, so React sees the same functions on every render and does not
// resubscribe. The client replaces its state object only when something changed,
// which is what makes the snapshot stable between renders.
const subscribe = (onChange: () => void): (() => void) => getMonitoringClient().subscribe(onChange);
const getSnapshot = (): MonitoringState => getMonitoringClient().state;

/**
 * What the UI knows about monitoring. Reading it does not connect; the component that
 * opens the sheet calls `getMonitoringClient().ensureConnected()`. Only components that
 * call this re-render, and at most as often as the state changes - a health push per
 * flush window at most, never a datagram.
 */
export function useMonitoring(): MonitoringState {
  return useSyncExternalStore(subscribe, getSnapshot);
}
