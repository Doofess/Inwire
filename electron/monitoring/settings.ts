/**
 * The saved settings: `settings.json` in the monitoring directory (ADRs 0058, 0061).
 *
 * Main's, not the renderer's: the file holds the address the app will bind a
 * socket on and the folder the dataset lives in, so the page may ask for them
 * and propose a replacement and nothing more. It holds
 * `{ version: 2, source, location, retention }` and nothing else. It stays in
 * `<userData>/monitoring/` wherever the dataset is: it is the app's, not the
 * dataset's. A version-1 file (`{ version: 1, source }`) reads as the default
 * location and the default retention, and is rewritten as version 2 on the
 * next save.
 *
 * **Every failure is a stated one.** A missing file is the first run and reads
 * as no source; a file that cannot be read, is not JSON, or fails validation
 * reads as a failure with the reason, because a silently defaulted address is a
 * socket on the wrong interface and a silently defaulted location is a dataset
 * that seems to be gone. A save that does not validate is refused, and one that
 * fails to write says so - the page must never believe it saved what it did not.
 *
 * No Electron: the directory is handed in, so a script drives it under `tsx`.
 */
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { readSourceConfig } from '../../src/services/monitoring/config';
import { DEFAULT_RETENTION, validateRetentionPolicy, type RetentionPolicy } from '../../src/services/monitoring/retention';
import type { SourceConfig } from '../../src/services/monitoring/types';
import { writeFileAtomic } from '../atomicWrite';

export const SETTINGS_FILE = 'settings.json';
const SETTINGS_VERSION = 2;

export interface MonitoringSettings {
  config: SourceConfig | null;
  /** The dataset folder's absolute path, or null for the default (`<userData>/monitoring/`). */
  location: string | null;
  retention: RetentionPolicy;
}

export type SettingsReadResult =
  | ({ ok: true } & MonitoringSettings)
  | { ok: false; message: string };

export type SettingsSaveResult =
  | ({ ok: true } & MonitoringSettings)
  | { ok: false; message: string };

/** What a save may change besides the source. A key left out keeps what the file holds. */
export interface SettingsPatch {
  location?: string | null;
  retention?: unknown;
}

const describe = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const defaults = (): MonitoringSettings => ({ config: null, location: null, retention: { ...DEFAULT_RETENTION } });

/** The saved settings, defaults where nothing was ever saved, or why the file cannot be trusted. */
export function readMonitoringSettings(directory: string): SettingsReadResult {
  const file = path.join(directory, SETTINGS_FILE);
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { ok: true, ...defaults() };
    return { ok: false, message: `The monitoring settings could not be read (${describe(e)}).` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, message: `The monitoring settings are not valid JSON (${describe(e)}).` };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, message: 'The monitoring settings are not a JSON object.' };
  }
  const { version, source, location, retention } = parsed as Record<string, unknown>;
  if (version !== 1 && version !== SETTINGS_VERSION) {
    return { ok: false, message: `The monitoring settings are version ${String(version)}; this build reads version ${SETTINGS_VERSION}.` };
  }
  // A version-2 file may have a folder and a policy before it has a source.
  let config: SourceConfig | null = null;
  if (!(version === SETTINGS_VERSION && source === null)) {
    config = readSourceConfig(source);
    if (config === null) return { ok: false, message: 'The saved monitoring source is not a valid configuration.' };
  }
  if (version === 1) return { ok: true, config, location: null, retention: { ...DEFAULT_RETENTION } };
  if (location !== null && (typeof location !== 'string' || location.length === 0)) {
    return { ok: false, message: 'The saved monitoring location is not a folder path.' };
  }
  const policy = validateRetentionPolicy(retention);
  if (policy === null) return { ok: false, message: 'The saved retention policy is not valid.' };
  return { ok: true, config, location: location as string | null, retention: policy };
}

/**
 * Validates and writes. `value` replaces the source when it is not `undefined`; `patch` replaces the
 * location and the retention policy where it names them. Everything else the file holds is kept, so a
 * save of one thing never resets another. A file that cannot be read is replaced only by a save of the
 * source (the way out of it, as before); a patch alone is refused rather than written over it. `write`
 * is the file write, a parameter so a script can make it fail; the default is `writeFileAtomic`.
 */
export function saveMonitoringSettings(
  directory: string, value: unknown, patch: SettingsPatch = {},
  write: (file: string, data: string) => void = writeFileAtomic,
): SettingsSaveResult {
  const read = readMonitoringSettings(directory);
  if (!read.ok && value === undefined) return { ok: false, message: `${read.message} Nothing was saved over it.` };
  const current: MonitoringSettings = read.ok ? read : defaults();
  let config = current.config;
  if (value !== undefined) {
    config = readSourceConfig(value);
    if (config === null) {
      return { ok: false, message: 'That is not a valid source: it needs the exporter\'s address, a specific local address, a port and a storage limit.' };
    }
  }
  let location = current.location;
  if (patch.location !== undefined) {
    if (patch.location !== null && (typeof patch.location !== 'string' || patch.location.length === 0)) {
      return { ok: false, message: 'That is not a folder path.' };
    }
    location = patch.location;
  }
  let retention = current.retention;
  if (patch.retention !== undefined) {
    const policy = validateRetentionPolicy(patch.retention);
    if (policy === null) return { ok: false, message: 'That is not a valid retention policy: keep raw evidence for a whole number of days from 1, or leave it off, and choose what happens at the limit.' };
    retention = policy;
  }
  try {
    mkdirSync(directory, { recursive: true });
    write(path.join(directory, SETTINGS_FILE), JSON.stringify({ version: SETTINGS_VERSION, source: config, location, retention }, null, 2));
  } catch (e) {
    return { ok: false, message: `The monitoring settings could not be saved (${describe(e)}).` };
  }
  return { ok: true, config, location, retention };
}
