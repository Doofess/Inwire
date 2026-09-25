/**
 * The streaming save's three IPC handlers.
 *
 * A thin adapter: the dialog is `saveFile.ts`'s, and every rule about tokens,
 * partial files and cleanup is `saveSession.ts`'s, where a script can reach
 * it. What only this file can do is know which webContents asked and notice
 * when it goes away.
 */
import { app, type IpcMain, type IpcMainInvokeEvent, type WebContents } from 'electron';
import {
  SAVE_STREAM_CLOSE_CHANNEL, SAVE_STREAM_OPEN_CHANNEL, SAVE_STREAM_WRITE_CHANNEL,
} from './channels';
import { chooseSavePath } from './saveFile';
import { SaveSessions } from './saveSession';
import type { SaveTargetRequest } from './saveTarget';

/**
 * The request as the renderer sent it, reduced to the shape `saveTarget.ts`
 * expects. It arrives as `unknown`: `filtersFor` calls `.replace` on each
 * extension, and a number in that list would throw inside main.
 */
function targetRequest(raw: unknown): SaveTargetRequest {
  const value = raw !== null && typeof raw === 'object' ? raw as Record<string, unknown> : {};
  const extensions = Array.isArray(value.extensions)
    ? value.extensions.filter((extension): extension is string => typeof extension === 'string')
    : undefined;
  return {
    suggestedName: typeof value.suggestedName === 'string' ? value.suggestedName : '',
    extensions,
    description: typeof value.description === 'string' ? value.description : undefined,
  };
}

export function registerSaveStream(ipc: IpcMain): SaveSessions {
  const sessions = new SaveSessions();
  const watched = new Set<number>();

  // A window that closes, or a renderer that dies, mid-export leaves nobody to
  // commit or abort - so its partials are deleted here rather than left
  // beside the file the person chose. A reload is covered too: the page that
  // held the token is gone even though the webContents is not.
  function watch(sender: WebContents): void {
    const id = sender.id;
    if (watched.has(id)) return;
    watched.add(id);
    const drop = (): void => { void sessions.dropSender(id); };
    sender.on('render-process-gone', drop);
    sender.on('did-start-navigation', (details) => {
      if (details.isMainFrame && !details.isSameDocument) drop();
    });
    sender.once('destroyed', () => {
      watched.delete(id);
      drop();
    });
  }

  // Quitting mid-export: the window's `destroyed` above starts an abort, but
  // an abort is asynchronous and the process may be gone before it runs. This
  // one is synchronous, so no partial outlives the app.
  app.on('will-quit', () => sessions.abandonAllSync());

  ipc.handle(SAVE_STREAM_OPEN_CHANNEL, async (event: IpcMainInvokeEvent, raw: unknown) => {
    const target = await chooseSavePath(event.sender, targetRequest(raw));
    if (target === null) return { canceled: true };
    watch(event.sender);
    return sessions.open(event.sender.id, target);
  });
  ipc.handle(SAVE_STREAM_WRITE_CHANNEL, (event: IpcMainInvokeEvent, token: unknown, bytes: unknown) =>
    sessions.write(event.sender.id, token, bytes));
  ipc.handle(SAVE_STREAM_CLOSE_CHANNEL, (event: IpcMainInvokeEvent, token: unknown, commit: unknown) =>
    sessions.close(event.sender.id, token, commit === true));

  return sessions;
}
