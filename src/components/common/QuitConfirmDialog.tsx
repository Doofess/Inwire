import React from 'react';
import { motion } from 'motion/react';
import { TriangleAlert } from 'lucide-react';

import { modalPanelMotion } from '../../lib/modalMotion';
import { QUIT_CONFIRM_TEXT, readQuitConfirmRequest } from '../../lib/quitConfirm';

/**
 * "Quit Inwire?", drawn by the app rather than by the OS.
 *
 * Main asks for it on `close` with a capture in the buffer
 * (`electron/quitConfirm.ts`). It used to be `showMessageBox`, which on Windows
 * is a task dialog the OS paints light whatever the app's theme - a white box
 * over a window in Night. Drawn here it takes the theme's tokens like every
 * other surface. Main still owns the decision: it shows the OS's box instead
 * if this does not say `shown` within a second, so a hung page can never leave
 * the window unclosable.
 *
 * **A native `<dialog>` opened with `showModal()`**, where the import error
 * dialog is a hand-rolled `motion` div. The difference is the job: this one has
 * to be keyboard-complete over a window that is still capturing, and the top
 * layer gives that for free - everything behind is inert, so Tab moves between
 * the two buttons and nowhere else, and a click on the scrim cannot reach the
 * packet list. The card inside still enters with `modalPanelMotion`, so it
 * moves like its sibling.
 *
 * Mounted beside `App` in `main.tsx` rather than inside it, so App's ten
 * renders a second during a capture never reach it.
 */
export function QuitConfirmDialog(): React.ReactElement {
  /**
   * The confirm on screen, or null. `asked` counts main's requests for it,
   * because a second close re-asks the SAME id - and has to be answered
   * `shown` again, which an unchanged state would never re-run the effect for.
   */
  const [open, setOpen] = React.useState<{ id: number; asked: number } | null>(null);
  const dialogRef = React.useRef<HTMLDialogElement>(null);
  const keepRef = React.useRef<HTMLButtonElement>(null);

  React.useEffect(() => window.inwire?.onQuitConfirm?.((value) => {
    const request = readQuitConfirmRequest(value);
    if (request === null) return;
    setOpen((current) => {
      if (!request.open) return current?.id === request.id ? null : current;
      return { id: request.id, asked: (current?.id === request.id ? current.asked : 0) + 1 };
    });
  }), []);

  // Up, focused on Keep capturing, and only then `shown` - the acknowledgement
  // is main's evidence the question is on screen, so it is sent after the
  // dialog is, never before.
  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) return;
    if (open === null) {
      if (dialog.open) dialog.close();
      return;
    }
    if (!dialog.open) dialog.showModal();
    // `focusVisible`, or the default would carry no ring on the usual route:
    // the close is a CLICK on the window's own X, and Chromium rings a
    // scripted focus only when the last input was a key. The reader has to
    // see which answer Enter gives. Not in TypeScript's DOM lib yet.
    keepRef.current?.focus({ focusVisible: true } as FocusOptions);
    window.inwire?.answerQuitConfirm?.(open.id, 'shown');
  }, [open]);

  // Every key stops here while the confirm is up. `showModal` makes the page
  // inert to the pointer and to focus, but a `keydown` still reaches the
  // listeners on `window`, where App's Escape would navigate the view
  // underneath and the shortcuts (Ctrl+1..5, Ctrl+B) would act on a capture
  // the reader is being asked about. Stopping it cancels no default action, so
  // Enter and Space still press the focused button, Tab still moves, and
  // Escape still raises the dialog's own `cancel`.
  //
  // **Registered once, at mount, and never re-registered** - which is why this
  // reads a ref rather than depending on `open`. The other capture-phase
  // listeners on `window` (FilterBar, the rail, the import error dialog) sit
  // on the same node, where `stopImmediatePropagation` only silences the ones
  // added AFTER it. Mounted before `App` in `main.tsx` and added once, this is
  // the first.
  const openRef = React.useRef(false);
  openRef.current = open !== null;
  React.useEffect(() => {
    const swallow = (e: KeyboardEvent): void => {
      if (openRef.current) e.stopImmediatePropagation();
    };
    window.addEventListener('keydown', swallow, true);
    return () => window.removeEventListener('keydown', swallow, true);
  }, []);

  const answer = (quit: boolean): void => {
    if (open === null) return;
    window.inwire?.answerQuitConfirm?.(open.id, quit ? 'quit' : 'keep');
    setOpen(null);
  };

  return (
    <dialog
      ref={dialogRef}
      role="alertdialog"
      aria-labelledby="quit-confirm-title"
      aria-describedby="quit-confirm-message"
      // Escape is a Keep. Prevented so the dialog does not close itself behind
      // React's back; `answer` closes it through state like every other way out.
      onCancel={(e) => { e.preventDefault(); answer(false); }}
      // A click on the scrim lands on the dialog element itself - the card
      // stops nothing, it simply is not the target. Keep, the safe answer.
      onClick={(e) => { if (e.target === e.currentTarget) answer(false); }}
      className="m-auto w-[calc(100%-2rem)] max-w-md overflow-visible border-0 bg-transparent p-0 text-card-foreground backdrop:bg-black/70"
    >
      {open !== null && (
        <motion.div
          {...modalPanelMotion}
          className="rounded-xl border border-border bg-card shadow-2xl"
        >
          <div className="flex items-start gap-3 px-5 pt-4 pb-3">
            <TriangleAlert aria-hidden className="size-6 shrink-0 text-warning" />
            <div className="min-w-0 space-y-1.5">
              <h2 id="quit-confirm-title" className="text-base font-bold text-balance">
                {QUIT_CONFIRM_TEXT.title}
              </h2>
              <p id="quit-confirm-message" className="text-sm text-foreground/90 text-pretty">
                {QUIT_CONFIRM_TEXT.message}
              </p>
              <p className="text-xs leading-relaxed text-muted-foreground text-pretty">
                {QUIT_CONFIRM_TEXT.detail}
              </p>
            </div>
          </div>
          <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
            <button
              type="button"
              onClick={() => answer(true)}
              className="rounded-md bg-secondary px-4 py-1.5 text-xs font-medium text-foreground transition-[background-color,scale] hover:bg-accent active:scale-95"
            >
              {QUIT_CONFIRM_TEXT.quit}
            </button>
            <button
              ref={keepRef}
              type="button"
              // Focused on open by the effect above; `autoFocus` says so to
              // anything reading the markup, and Enter keeps.
              autoFocus
              onClick={() => answer(false)}
              className="rounded-md bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground transition-[background-color,scale] hover:bg-primary/90 active:scale-95"
            >
              {QUIT_CONFIRM_TEXT.keep}
            </button>
          </div>
        </motion.div>
      )}
    </dialog>
  );
}
