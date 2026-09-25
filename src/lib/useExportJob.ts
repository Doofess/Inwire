import { useSyncExternalStore } from 'react';
import { getExportJob, subscribeExportJob, type ExportJobState } from '../services/export/exportJob';

/**
 * The running or last export, for a view that may mount and unmount while it
 * runs. See `services/export/exportJob.ts` for why it is not React state.
 */
export function useExportJob(): ExportJobState {
  return useSyncExternalStore(subscribeExportJob, getExportJob, getExportJob);
}
