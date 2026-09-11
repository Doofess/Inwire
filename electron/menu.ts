/**
 * The application menu, built explicitly.
 *
 * Neither of the two obvious choices is safe here.
 *
 * **`Menu.setApplicationMenu(null)`** looks like the right answer for an app
 * with its own chrome, and it silently kills **Ctrl+C, Ctrl+V, Ctrl+A and
 * Ctrl+Z in every text input on Windows** - those accelerators come from the
 * default menu's edit roles, not from Chromium. This app has a filter bar, a
 * search box, a display-filter editor and a colour-rule editor.
 *
 * **The default menu** brings Ctrl+R, Ctrl+Shift+R and Ctrl+W. A renderer
 * reload tears down the pipeline worker, the WebSocket and the RAM buffer
 * exactly as a browser refresh did - and the elaborate reload-intent heuristic
 * in `App.tsx` existed only to tell that refresh apart from a close. In a
 * desktop app there is no reason to offer a reload at all, so in a packaged
 * build there is not one.
 *
 * So: the edit roles, kept for the shortcuts; a view menu without reload; and
 * developer tools, which stay in production deliberately - this app's users are
 * the population most likely to want them, and diagnosing a packaged-only
 * failure without them is miserable.
 */
// `import type` only. A runtime `import { Menu } from 'electron'` would make
// this module unloadable outside Electron, and `scripts/electron/menu.ts`
// drives `menuTemplate` under plain Node - the reload accelerator's absence in
// a packaged build is a decision, so it is asserted rather than trusted.
import type { Menu, MenuItemConstructorOptions } from 'electron';

export interface MenuOptions {
  /** In a packaged build the reload accelerators are not offered. */
  packaged: boolean;
}

export function menuTemplate({ packaged }: MenuOptions): MenuItemConstructorOptions[] {
  const view: MenuItemConstructorOptions[] = [
    { role: 'resetZoom' },
    { role: 'zoomIn' },
    { role: 'zoomOut' },
    { type: 'separator' },
    { role: 'togglefullscreen' },
    { type: 'separator' },
    { role: 'toggleDevTools' },
  ];

  // Only outside a packaged build, and even then behind the View menu rather
  // than as a bare accelerator.
  if (!packaged) {
    view.unshift({ role: 'reload' }, { role: 'forceReload' }, { type: 'separator' });
  }

  return [
    {
      label: '&File',
      submenu: [{ role: 'quit', label: 'Exit' }],
    },
    {
      label: '&Edit',
      // The whole reason this menu exists. `role: 'editMenu'` is the set of
      // clipboard and undo accelerators Windows expects to come from here.
      role: 'editMenu',
    },
    { label: '&View', submenu: view },
  ];
}

export function buildMenu(options: MenuOptions): Menu {
  // Required here rather than imported above, so the module stays loadable in
  // Node. This function is only ever called from the main process.
  const { Menu: runtimeMenu } = require('electron') as typeof import('electron');
  return runtimeMenu.buildFromTemplate(menuTemplate(options));
}
