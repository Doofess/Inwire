/**
 * "Save as captured"'s IPC handler: the dialog, then `capturedFiles.ts`.
 *
 * A thin adapter, like `saveStream.ts`. Every rule - which files, which
 * names, whole or not at all - is in `capturedFiles.ts`, where a script can
 * reach it; what only this file can do is show a dialog.
 */
import { BrowserWindow, dialog, type IpcMain, type IpcMainInvokeEvent } from 'electron';
import { SAVE_CAPTURED_CHANNEL } from './channels';
import { chooseSavePath } from './saveFile';
import { capturedFilePath, capturedFiles, copyRing, copyWhole } from './capturedFiles';
import { isCaptureId } from '../src/services/capture/captureDirectory';

export type SaveCapturedResult =
  | { saved: true; path: string; files: number }
  | { saved: false; canceled: true }
  | { saved: false; canceled: false; error: string };

export function registerSaveCaptured(ipc: IpcMain, captureRoot: string): void {
  ipc.handle(SAVE_CAPTURED_CHANNEL, async (event: IpcMainInvokeEvent, raw: unknown): Promise<SaveCapturedResult> => {
    if (typeof raw !== 'string' || !isCaptureId(raw)) {
      return { saved: false, canceled: false, error: 'that is not a capture this app made' };
    }
    const names = capturedFiles(captureRoot, raw);
    if (names.length === 0) {
      return {
        saved: false, canceled: false,
        error: 'the agent wrote no file for this capture - it writes one for every capture it starts, '
          + 'from version 0.5.0 on',
      };
    }
    try {
      if (names.length === 1) {
        const target = await chooseSavePath(event.sender, {
          suggestedName: `${raw}.pcapng`, extensions: ['pcapng'], description: 'Capture file',
        });
        if (target === null) return { saved: false, canceled: true };
        copyWhole([capturedFilePath(captureRoot, raw, names[0])], [target]);
        return { saved: true, path: target, files: 1 };
      }
      // A ring: its files go into a folder of their own, inside one the
      // person picks.
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: `Choose where to put the ${names.length} files of this capture`,
        buttonLabel: 'Save here',
        properties: ['openDirectory', 'createDirectory'],
      };
      const chosen = owner ? await dialog.showOpenDialog(owner, options) : await dialog.showOpenDialog(options);
      if (chosen.canceled || chosen.filePaths.length === 0) return { saved: false, canceled: true };
      const folder = copyRing(captureRoot, raw, names, chosen.filePaths[0]);
      return { saved: true, path: folder, files: names.length };
    } catch (error) {
      return { saved: false, canceled: false, error: error instanceof Error ? error.message : String(error) };
    }
  });
}
