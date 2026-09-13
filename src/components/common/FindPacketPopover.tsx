import React, { useEffect, useRef } from 'react';
import { TbSearch, TbX } from 'react-icons/tb';

/**
 * Find packet, as a rail control.
 *
 * It was an expanding field in the filter bar - a magnifier that grew a 224px
 * input when clicked. The gesture survives; what changed is where it lives,
 * which is the rail's bottom group beside Export/Import and Settings.
 *
 * ## Why the bottom group and not the views
 *
 * The rail's groups are kinds of thing rather than degrees of importance:
 * capture is what the agent is doing, views are places, widgets are panels, and
 * the bottom group is **actions** - things you do rather than places you are.
 * Find is an action. It also fits the one hard constraint the rail has: at
 * 539px there was room for two more icons, and the counts widget takes the
 * other (`scripts/session/view.ts`).
 *
 * ## The search is not a filter, and the distinction is load-bearing
 *
 * A display filter is compiled and answered over the **whole capture**, on
 * disk, by the store (ADR 0031). This is a substring match applied on top of
 * that, over the rows already in hand - which is why the two are separate
 * controls and why this one never moved into the filter expression. Putting it
 * in the rail makes that separation visible rather than implying a relationship
 * by adjacency.
 *
 * ## Escape
 *
 * Escape here clears the text before it closes the popover, and stops
 * propagating either way. That is the app's documented innermost-first rule: a
 * focused input blurs or clears before anything above it acts, and without
 * `stopPropagation` the same key would also run `App`'s view chain and send
 * somebody back to Packets from a search box.
 */
export interface FindPacketPopoverProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  text: string;
  onTextChange: (text: string) => void;
  /** The rail button this hangs off. Rendered by the caller, styled by it. */
  children: React.ReactNode;
}

export const FindPacketPopover: React.FC<FindPacketPopoverProps> = ({
  open, onOpenChange, text, onTextChange, children,
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Focus on open. The whole point of a shortcut-reachable find box is that it
  // is typeable the instant it appears.
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  // Click-outside closes, but **only when the box is empty**. A search with text
  // in it is narrowing the list behind the popover, so closing on the first
  // click into that list would undo the thing the user is looking at.
  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e: PointerEvent): void => {
      if (wrapRef.current?.contains(e.target as Node) === true) return;
      if (text.trim() !== '') return;
      onOpenChange(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open, text, onOpenChange]);

  return (
    <div className="relative" ref={wrapRef}>
      {children}

      {open && (
        <div
          role="dialog"
          aria-label="Find packet"
          // To the right, like every other popover the rail opens: a 56px strip
          // has no room under a control, and this one is 288px wide.
          className="absolute left-full bottom-0 ml-2 z-50 w-72 rounded-lg border p-2
            shadow-2xl bg-popover border-border text-popover-foreground"
        >
          <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-md border
            bg-background border-border"
          >
            <TbSearch className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
            <input
              ref={inputRef}
              type="text"
              placeholder="Find packet (IP, protocol, info)..."
              value={text}
              onChange={(e) => onTextChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== 'Escape') return;
                // Innermost first: clear, then close on a second press.
                e.stopPropagation();
                if (text !== '') onTextChange('');
                else onOpenChange(false);
              }}
              className="flex-1 min-w-0 bg-transparent outline-none text-xs font-mono
                text-foreground placeholder-muted-foreground"
            />
            {text !== '' && (
              <button
                onClick={() => { onTextChange(''); inputRef.current?.focus(); }}
                aria-label="Clear search"
                className="p-0.5 shrink-0 rounded-full hover:bg-accent text-muted-foreground
                  cursor-pointer"
              >
                <TbX className="w-3 h-3" />
              </button>
            )}
          </div>
          {/* Says what this is NOT, because the control above it looks exactly
              like the display filter two rows up and answers a different
              question over a different set of frames. */}
          <p className="text-[10px] leading-snug text-muted-foreground px-1 pt-1.5">
            Substring match over the rows the display filter already selected. The filter
            itself is answered over the whole capture, on disk; this is not.
          </p>
        </div>
      )}
    </div>
  );
};
