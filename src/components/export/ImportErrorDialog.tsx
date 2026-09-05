import React from 'react';
import { motion } from 'motion/react';
import { TbAlertTriangle, TbFileX, TbRefresh, TbX } from 'react-icons/tb';

import { ImportFailure } from '../../services/exportSchema';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';

/**
 * What the user sees when a file is refused.
 *
 * A dialog rather than the inline red line the import panel used to show,
 * because a rejection needs to say more than one sentence: which file, why,
 * and - for the common case of a spreadsheet with the wrong headings - what it
 * found against what it needed. That last part is the difference between "the
 * import failed" and "your sheet says Src/Dst where Source/Destination were
 * expected", and only one of those tells the user what to do next.
 *
 * Hand-rolled `motion` rather than `ui/dialog.tsx`: every modal in this app is
 * built that way (see `modalMotion.ts`), and the Radix dialog is currently
 * imported by nothing, so using it here would make this the one screen that
 * animates and traps focus differently from its five siblings.
 */

interface ImportErrorDialogProps {
  filename: string;
  failure: ImportFailure;
  onRetry: () => void;
  onClose: () => void;
}

/** A short heading per failure kind - the one-line version of what went wrong. */
function headlineFor(failure: ImportFailure): string {
  switch (failure.kind) {
    case 'unreadable':
      return 'This file could not be read';
    case 'no-table':
      return 'No packet table in this file';
    case 'missing-columns':
      return 'This does not look like packet data';
    case 'no-rows':
      return 'No packets in this file';
    case 'too-large':
      return 'This file is too large';
    default:
      return 'This file could not be imported';
  }
}

export const ImportErrorDialog: React.FC<ImportErrorDialogProps> = ({
  filename,
  failure,
  onRetry,
  onClose,
}) => {
  // Escape closes this and nothing behind it. Capture phase with
  // stopPropagation, the same shape FilterBar uses, so one Escape dismisses one
  // thing rather than taking the export modal down with it.
  React.useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [onClose]);

  return (
    <motion.div
      {...modalBackdropMotion}
      // z-60 rather than z-50: this opens on top of the export modal, which is
      // still on screen behind it.
      className="fixed inset-0 z-60 bg-black/70 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <motion.div
        {...modalPanelMotion}
        onClick={e => e.stopPropagation()}
        className="w-full max-w-lg rounded-xl border bg-card border-border text-card-foreground flex flex-col shadow-2xl"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="import-error-title"
      >
        <div className="px-5 py-3.5 border-b border-border flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <TbAlertTriangle className="w-6 h-6 shrink-0 text-amber-500" />
            <div className="min-w-0">
              <div id="import-error-title" className="font-bold text-base">
                {headlineFor(failure)}
              </div>
              <p className="text-xs text-muted-foreground font-mono truncate" title={filename}>
                {filename}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground shrink-0"
            aria-label="Close"
          >
            <TbX className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <p className="text-sm leading-relaxed text-foreground/90">{failure.message}</p>

          {failure.kind === 'missing-columns' && (
            <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-3">
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground font-mono mb-1.5">
                  Columns required
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {['source', 'destination', 'protocol', 'length'].map(name => (
                    <span
                      key={name}
                      className={`px-1.5 py-0.5 rounded font-mono text-[11px] border ${
                        failure.missing.includes(name as never)
                          ? 'border-rose-500/50 bg-rose-500/10 text-rose-600 dark:text-rose-300'
                          : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      }`}
                    >
                      {name}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground font-mono mb-1.5">
                  Columns found in your file
                </div>
                {failure.found.length === 0 ? (
                  <span className="italic text-muted-foreground">None - the first row was empty.</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto custom-scrollbar">
                    {failure.found.map((name, i) => (
                      <span
                        key={`${name}-${i}`}
                        className="px-1.5 py-0.5 rounded font-mono text-[11px] border border-border bg-background text-foreground/80"
                      >
                        {name}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Common spellings are recognised automatically - <span className="font-mono">Src</span>,{' '}
                <span className="font-mono">Dst</span>, <span className="font-mono">Proto</span> and{' '}
                <span className="font-mono">Len</span> all work. Rename the columns above to match and try again.
              </p>
            </div>
          )}

          {failure.kind === 'no-table' && (
            <div className="rounded-lg border border-border bg-muted/40 p-3 text-[11px] text-muted-foreground leading-relaxed flex gap-2">
              <TbFileX className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                PDF import reads only the reports Inwire itself generates. Any other PDF has no reliable
                table structure to read, and guessing at one would produce packets that were never on a wire.
              </span>
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-border flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground font-medium transition-colors text-xs"
          >
            Cancel
          </button>
          <button
            onClick={onRetry}
            className="px-4 py-1.5 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 font-medium transition-colors text-xs flex items-center gap-1.5"
          >
            <TbRefresh className="w-3.5 h-3.5" />
            Choose another file
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
