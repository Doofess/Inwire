import React from 'react';
import { OctagonAlert } from 'lucide-react';

import { CRASH_SCREEN_TEXT, crashReasonSentence, readCrashReason } from '../../lib/crashScreen';
import { useWindowChrome, windowControl } from '../../lib/windowChrome';
import { AlertButton, AlertCard } from './AlertCard';
import { BrandMark } from './BrandMark';
import { WindowControls } from './WindowControls';

/**
 * What the window shows after its renderer died.
 *
 * The renderer that normally draws dialogs is the thing that crashed, so main
 * loads this page (`crash.html`, its own entry in the build) into the same
 * window instead of the OS's Win32 box, which Windows paints light whatever the
 * theme. It wears the owner's theme, accent and motion setting through the same
 * `RootProviders` the app does, and its card is the quit confirm's (`AlertCard`).
 *
 * **It keeps a title row**, because the window is frameless and these are the
 * only way to move, minimise or close it. The row is `.app-drag` with the three
 * buttons carrying their own `.app-no-drag`; without them a crashed window
 * would be one Alt+F4 from stuck.
 *
 * **Quit is the window's close**, never a destroy, and it does not ask: main
 * clears its unsaved-capture flag when the page dies, because the frames it
 * stood for died with it and what reached the store is kept either way.
 * **Reload navigates to the app shell** with
 * `location.replace`, so the crash screen is not a history entry to go back to
 * and no new IPC exists for it. The exit code is deliberately absent; it is in
 * main's log line.
 */
export function CrashScreen(): React.ReactElement {
  const { focused, maximized } = useWindowChrome();
  const reloadRef = React.useRef<HTMLButtonElement>(null);
  const sentence = crashReasonSentence(readCrashReason(window.location.search));

  // `focusVisible`, as the quit confirm does: the page arrives without a key
  // press, and Chromium rings a scripted focus only after one. The reader has
  // to see which answer Enter gives. Not in TypeScript's DOM lib yet.
  React.useEffect(() => {
    reloadRef.current?.focus({ focusVisible: true } as FocusOptions);
  }, []);

  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <header
        className={`h-8 shrink-0 flex items-center app-drag transition-opacity ${focused ? '' : 'opacity-60'}`}
      >
        <div className="ml-1 w-11 shrink-0 flex items-center justify-center">
          <BrandMark className="w-6 h-6 shrink-0" size={24} />
        </div>
        <span className="flex-1 truncate text-xs font-medium text-foreground/80">Inwire</span>
        <WindowControls maximized={maximized} />
      </header>
      <main className="flex min-h-0 flex-1 items-center justify-center p-4">
        <div
          role="alertdialog"
          aria-labelledby="crash-screen-title"
          aria-describedby="crash-screen-message"
          className="w-full max-w-md"
        >
          <AlertCard
            // An error, not a warning: the quit confirm's `text-warning` asks
            // before something is lost, and this is what already broke.
            icon={<OctagonAlert aria-hidden className="size-6 shrink-0 text-destructive" />}
            title={CRASH_SCREEN_TEXT.title}
            titleId="crash-screen-title"
            message={sentence}
            messageId="crash-screen-message"
            detail={CRASH_SCREEN_TEXT.followUp}
          >
            <AlertButton variant="secondary" onClick={() => windowControl('close')}>
              {CRASH_SCREEN_TEXT.buttons.quit}
            </AlertButton>
            <AlertButton
              ref={reloadRef}
              variant="primary"
              autoFocus
              onClick={() => window.location.replace('/')}
            >
              {CRASH_SCREEN_TEXT.buttons.reload}
            </AlertButton>
          </AlertCard>
        </div>
      </main>
    </div>
  );
}
