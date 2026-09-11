/**
 * What the save dialog is asked for: a name and a type list.
 *
 * Split from `saveFile.ts` for the reason every decision in `electron/` is
 * split out - that file imports `electron`, so nothing in it can be driven
 * under plain `tsx`. What is left there is the dialog call and the write; what
 * is here is everything with a rule in it.
 */
import path from 'node:path';

export interface SaveTargetRequest {
  suggestedName: string;
  extensions?: string[];
  description?: string;
}

/** Used when the renderer suggests nothing usable. Never an empty name. */
export const FALLBACK_NAME = 'inwire-export';

/**
 * The name the dialog opens with.
 *
 * `basename`, because the renderer supplies this and a suggestion containing
 * `..\..\` would otherwise choose the dialog's starting directory for the
 * person. It is not a security boundary on its own - the person picks the real
 * path in a dialog they can see, and that is the authorisation - but a dialog
 * that opens somewhere the page chose is a dialog that can be aimed.
 *
 * A name that reduces to nothing, or to a bare `.` or `..`, becomes the
 * fallback rather than an empty `defaultPath`, which some platforms read as
 * "no suggestion" and others as a directory.
 */
export function safeName(suggested: unknown): string {
  if (typeof suggested !== 'string') return FALLBACK_NAME;
  // Backslashes too, and on every platform: this runs on Windows, where
  // `path.basename` handles both, but a build running elsewhere must not start
  // treating `a\b.pcap` as a filename containing a separator.
  const flattened = suggested.replace(/\\/g, '/');
  const base = path.posix.basename(flattened).trim();
  if (!base || base === '.' || base === '..') return FALLBACK_NAME;
  return base;
}

/**
 * The dialog's type dropdown.
 *
 * "All files" is always present and always **last**: the first entry is the
 * default, and a default of "anything" produces files with no extension. It is
 * present at all so somebody who wants a different extension is not trapped by
 * a list this app wrote.
 */
export function filtersFor(request: SaveTargetRequest): { name: string; extensions: string[] }[] {
  const filters: { name: string; extensions: string[] }[] = [];
  // Leading dots are stripped: Electron wants `pcapng`, and `.pcapng` produces
  // a filter that matches nothing at all rather than an error.
  const extensions = (request.extensions ?? [])
    .map((extension) => extension.replace(/^\.+/, '').toLowerCase())
    .filter(Boolean);
  if (extensions.length > 0) {
    filters.push({ name: request.description ?? 'File', extensions });
  }
  filters.push({ name: 'All files', extensions: ['*'] });
  return filters;
}
