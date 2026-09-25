/**
 * Writing a generated file where the person asked for it.
 *
 * ## What this replaces
 *
 * `lib/download.ts` built an object URL, synthesised an anchor, clicked it and
 * revoked the URL on a later macrotask - five lines with two browser bugs
 * documented in them, one about revocation timing and one about Firefox
 * ignoring a detached anchor. None of that was ever what the app wanted. It
 * wanted to write a file, and it went through a download because a web page
 * has no other way.
 *
 * A desktop app does. The gain is not tidiness: the app now knows **where the
 * file went**, which is the one thing a download cannot tell it, so an export
 * can say "saved to ..." instead of "the browser has it somewhere".
 *
 * ## The suggested name is the renderer's, the path is not
 *
 * `basename` is applied to whatever the renderer suggests, because a suggested
 * name containing `..\..\` would otherwise open the dialog somewhere the
 * caller chose. The person then picks the real path in a dialog they can see,
 * which is the actual authorisation for the write - not anything this file
 * checks.
 *
 * ## Bytes, not a Blob, and one copy
 *
 * The payload crosses IPC as a `Uint8Array`, which is a structured-clone copy
 * of the whole file. That is fine for a report and not for a capture larger
 * than the renderer's heap, which is what `saveStream.ts` is for: the same
 * dialog, then the bytes in pieces.
 */
import { BrowserWindow, dialog, type IpcMainInvokeEvent, type WebContents } from 'electron';
import { writeFile } from 'node:fs/promises';
import { filtersFor, safeName, type SaveTargetRequest } from './saveTarget';

export interface SaveFileRequest extends SaveTargetRequest {
  bytes: Uint8Array;
}

export type SaveFileResult =
  | { saved: true; path: string }
  /** The person pressed Cancel. Not an error and must not be shown as one. */
  | { saved: false; canceled: true }
  | { saved: false; canceled: false; error: string };

/**
 * Shows the save dialog and answers with the chosen path, or null on Cancel.
 *
 * Shared with `saveStream.ts`, so the two ways of saving cannot drift into two
 * dialogs with different rules about overwriting.
 */
export async function chooseSavePath(
  sender: WebContents,
  request: SaveTargetRequest,
): Promise<string | null> {
  // Parented to the window that asked, so the dialog is modal to it rather
  // than a floating window the person can lose behind the app.
  const owner = BrowserWindow.fromWebContents(sender);

  const options: Electron.SaveDialogOptions = {
    defaultPath: safeName(request.suggestedName),
    filters: filtersFor(request),
    // Without this, a person who types a name that exists gets no warning and
    // the file is replaced. Electron's default already asks; naming it here
    // stops a future options rewrite from dropping it silently.
    properties: ['showOverwriteConfirmation', 'createDirectory'],
  };

  const chosen = owner
    ? await dialog.showSaveDialog(owner, options)
    : await dialog.showSaveDialog(options);
  return chosen.canceled || !chosen.filePath ? null : chosen.filePath;
}

export async function saveGeneratedFile(
  event: IpcMainInvokeEvent,
  request: SaveFileRequest,
): Promise<SaveFileResult> {
  const chosen = await chooseSavePath(event.sender, request);
  if (chosen === null) return { saved: false, canceled: true };

  try {
    await writeFile(chosen, request.bytes);
    return { saved: true, path: chosen };
  } catch (error) {
    // A full disk, a read-only volume, a path a policy forbids. The message is
    // shown to a person, so it is the OS's own rather than a paraphrase.
    return {
      saved: false,
      canceled: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
