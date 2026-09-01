import React, { useEffect, useRef } from 'react';
import { TbX } from 'react-icons/tb';
import { motion } from 'motion/react';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';

/**
 * The window a dashboard widget opens into, wherever it was opened from.
 *
 * There are two doors to it - the expand button on a card in the full column,
 * and an icon in the collapsed rail - and they used to lead to two different
 * rooms. The card's button put GeoMap into a panel it drew itself; the rail put
 * the same widget inside a shell the dashboard drew, with its own title bar
 * above the widget's, at a different size, with a different close control. Same
 * widget, same intent, two answers.
 *
 * Both call this now, so "the same window" is true by construction rather than
 * by two files agreeing on a set of class names.
 *
 * It also owns the things a hand-rolled panel keeps forgetting: Escape, and
 * putting focus back where it came from. The card path had neither.
 */
interface WidgetOverlayProps {
  /** Accessible name for the panel - the widget's own name. */
  label: string;
  onClose: () => void;
  /**
   * Leave the icon rail uncovered.
   *
   * Only true when the rail is what opened this. The rail sits above the scrim
   * precisely so a second icon SWAPS the widget instead of forcing
   * close-then-reopen, and a panel drawn over it would take that back. It is
   * the one thing the two doors cannot share, because in the full column there
   * is no rail to leave room for.
   */
  gutter?: boolean;
  /**
   * `tabpanel` when the rail opened it - the rail is a tablist and this is what
   * the selected tab controls. `dialog` from a card, where there is no tablist
   * for it to belong to. Not `aria-modal` either way: the rail stays reachable
   * on purpose, and a monitoring dashboard is the worst thing to make modal.
   */
  panelRole?: 'dialog' | 'tabpanel';
  children: React.ReactNode;
}

export const WidgetOverlay: React.FC<WidgetOverlayProps> = ({
  label,
  onClose,
  gutter,
  panelRole = 'dialog',
  children,
}) => {
  // Captured on mount rather than passed in, so both doors get focus restored
  // without either having to hold a ref to the control that opened it.
  const openerRef = useRef<HTMLElement | null>(
    typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null),
  );

  useEffect(() => {
    const opener = openerRef.current;
    return () => {
      // Dropping focus to <body> strands a keyboard user at the top of the
      // document, which is a long way from the icon they just closed.
      if (opener?.isConnected) requestAnimationFrame(() => opener.focus());
    };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // Capture phase and stopped, matching the modals: while this is up it is
      // the topmost thing on screen, and Escape belongs to it.
      e.stopPropagation();
      onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  return (
    <>
      <motion.div
        {...modalBackdropMotion}
        onClick={onClose}
        className="fixed inset-0 z-30 bg-black/70 backdrop-blur-xs"
      />
      <motion.div
        {...modalPanelMotion}
        role={panelRole}
        aria-label={label}
        tabIndex={0}
        className={`fixed inset-4 md:inset-10 ${
          gutter ? 'mr-16' : ''
        } z-40 rounded-xl border bg-card border-border text-card-foreground shadow-2xl flex flex-col overflow-hidden`}
      >
        {/* The single close control, in the same place for every widget.
            Floating rather than sitting in a title bar of its own: four of the
            five widgets already draw their own heading, and a shell heading
            above them was the most visible way the two doors differed. */}
        <button
          type="button"
          onClick={onClose}
          aria-label={`Close ${label}`}
          title="Close"
          className="absolute top-2 right-2 z-10 p-1.5 rounded-md bg-card/80 backdrop-blur-xs text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer"
        >
          <TbX className="w-4 h-4" />
        </button>
        <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar">{children}</div>
      </motion.div>
    </>
  );
};
