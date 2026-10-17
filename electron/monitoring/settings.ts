/**
 * The saved source: `settings.json` in the monitoring directory (ADR 0058).
 *
 * Main's, not the renderer's: the file holds the address the app will bind a
 * socket on, so the page may ask for it and propose a replacement and nothing
 * more. It holds `{ version: 1, source }` and nothing else.
 *
 * **Every failure is a stated one.** A missing file is the first run and reads
 * as no source; a file that cannot be read, is not JSON, or fails
 * `readSourceConfig` reads as a failure with the reason, because a silently
 * defaulted address is a socket on the wrong interface. A save that does not
 * validate is refused, and one that fails to write says so - the page must
 * never believe it saved what it did not.
 *
 * No Electron: the directory is handed in, so a script drives it under `tsx`.
 */
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { readSourceConfig } from '../../src/services/monitoring/config';
import type { SourceConfig } from '../../src/services/monitoring/types';
import { writeFileAtomic } from '../atomicWrite';

export const SETTINGS_FILE = 'settings.json';
const SETTINGS_VERSION = 1;

export type SettingsReadResult =
  | { ok: true; config: SourceConfig | null }
  | { ok: false; message: string };

export type SettingsSaveResult =
  | { ok: true; config: SourceConfig }
  | { ok: false; message: string };

const describe = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** The saved source, `null` when nothing was ever saved, or why the file cannot be trusted. */
export function readMonitoringSettings(directory: string): SettingsReadResult {
  const file = path.join(directory, SETTINGS_FILE);
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { ok: true, config: null };
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
  const { version, source } = parsed as Record<string, unknown>;
  if (version !== SETTINGS_VERSION) {
    return { ok: false, message: `The monitoring settings are version ${String(version)}; this build reads version ${SETTINGS_VERSION}.` };
  }
  const config = readSourceConfig(source);
  if (config === null) return { ok: false, message: 'The saved monitoring source is not a valid configuration.' };
  return { ok: true, config };
}

/**
 * Validates `value` and writes it. `write` is the file write, a parameter so
 * a script can make it fail; the default is `writeFileAtomic`.
 */
export function saveMonitoringSettings(
  directory: string, value: unknown,
  write: (file: string, data: string) => void = writeFileAtomic,
): SettingsSaveResult {
  const config = readSourceConfig(value);
  if (config === null) {
    return { ok: false, message: 'That is not a valid source: it needs the exporter\'s address, a specific local address, a port and a storage limit.' };
  }
  try {
    mkdirSync(directory, { recursive: true });
    write(path.join(directory, SETTINGS_FILE), JSON.stringify({ version: SETTINGS_VERSION, source: config }, null, 2));
  } catch (e) {
    return { ok: false, message: `The monitoring settings could not be saved (${describe(e)}).` };
  }
  return { ok: true, config };
}
