/**
 * Handing a generated file to the person who asked for it.
 *
 * ## What this replaces, and why it is not the same thing tidied up
 *
 * `downloadBlob` created an object URL, synthesised an anchor, attached it,
 * clicked it and revoked the URL on a later macrotask. Two of those five lines
 * existed to work around browser behaviour - Firefox ignores a click on a
 * detached anchor, and a URL revoked in the same task can be dead before the
 * fetch behind the download starts. All of it existed because a web page has
 * no way to write a file.
 *
 * This app is not a web page any more, and the difference that matters is not
 * that the code is shorter. **A download cannot tell the app where the file
 * went.** A save dialog can, so an export can name the path it wrote, and a
 * cancel is a cancel rather than indistinguishable from success.
 *
 * ## The three outcomes are three, not two
 *
 * Saved, cancelled, failed. Collapsing cancelled into failed puts an error in
 * front of somebody who pressed Cancel on purpose, which is the most common
 * way this function ends and not a problem at all.
 */

export type SaveOutcome =
  | { saved: true; path: string }
  | { saved: false; canceled: true }
  | { saved: false; canceled: false; error: string };

/** The dialog's type dropdown, derived from the extension the caller wants. */
const DESCRIPTIONS: Record<string, string> = {
  pcap: 'Capture file',
  pcapng: 'Capture file',
  zip: 'Zip archive',
  json: 'JSON',
  csv: 'CSV',
  txt: 'Text file',
  md: 'Markdown',
  html: 'HTML',
};

/**
 * Writes `bytes` wherever the person chooses.
 *
 * `suggestedName` carries the extension - `inwire_capture_1725300000000.pcapng` -
 * and the dropdown is derived from it, so no call site has to state the same
 * thing twice.
 */
export async function saveGeneratedFile(
  bytes: Uint8Array,
  suggestedName: string,
): Promise<SaveOutcome> {
  const save = window.inwire?.saveFile;
  if (!save) {
    // Reachable only from the assertion scripts, which import this module's
    // neighbours and must not be made to stand up a preload bridge. An honest
    // failure rather than a silent no-op: a script that saved nothing and said
    // nothing would report a passing export.
    return { saved: false, canceled: false, error: 'no desktop bridge to save through' };
  }

  const dot = suggestedName.lastIndexOf('.');
  const extension = dot > 0 ? suggestedName.slice(dot + 1).toLowerCase() : '';

  const result = await save({
    suggestedName,
    extensions: extension ? [extension] : undefined,
    description: DESCRIPTIONS[extension],
    bytes,
  });
  return narrowSaveResult(result);
}

/** Convenience for the callers that still hold a `Blob`. */
export async function saveGeneratedBlob(blob: Blob, suggestedName: string): Promise<SaveOutcome> {
  return saveGeneratedFile(new Uint8Array(await blob.arrayBuffer()), suggestedName);
}

/**
 * The bridge is typed `Promise<unknown>` on purpose.
 *
 * `src/types/desktop.d.ts` describes what the preload exposes and cannot
 * import a type from `electron/`, because the two TypeScript programs are
 * deliberately separate - the main process one has no DOM lib, which is what
 * makes a reference to `window` there a build failure. So the shape is checked
 * here, once, rather than asserted with a cast at the call site.
 */
export function narrowSaveResult(value: unknown): SaveOutcome {
  // `typeof === 'object'` before anything else, and not for tidiness: `'error'
  // in value` throws a TypeError on a primitive, so a bridge that ever answered
  // with a bare string would take the renderer down rather than fall through to
  // the failure branch written for exactly that case.
  // A loose record rather than `Partial<SaveOutcome>`: the union's members do
  // not all carry `error`, so narrowing to it makes reading that field a type
  // error at the exact point this function exists to handle - a value that is
  // NOT one of the three shapes.
  const result = (value !== null && typeof value === 'object')
    ? value as Record<string, unknown>
    : null;
  if (result && result.saved === true && typeof result.path === 'string') {
    return { saved: true, path: result.path };
  }
  if (result && result.saved === false && result.canceled === true) {
    return { saved: false, canceled: true };
  }
  const error = result && typeof result.error === 'string'
    ? result.error
    : 'the file could not be written';
  return { saved: false, canceled: false, error };
}

/**
 * The timestamped stem every export shares: `inwire_capture_1725300000000`.
 *
 * Callers append their own extension. Kept here so the zip wrapper and the file
 * it wraps cannot end up with two different timestamps, which is what happens
 * when each call site writes `Date.now()` for itself.
 */
export function exportStem(prefix = 'inwire_capture'): string {
  return `${prefix}_${Date.now()}`;
}
