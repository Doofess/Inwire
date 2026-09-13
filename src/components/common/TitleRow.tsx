import React from 'react';

/**
 * The 40px strip the window is dragged by.
 *
 * Almost all of it is drag region, which is the point: the capture controls went
 * into the rail precisely so this row could be mostly empty. What is left is the
 * command palette's trigger on the left, the window's own name in the middle,
 * and the area Windows draws its buttons into on the right.
 *
 * ## What makes this read as native rather than as a web page in a frame
 *
 *  - **The colour.** `bg-card`, the same ground the rail uses, never the
 *    saturated `--chrome` accent. Every app this one is measured against - VS
 *    Code, Windows Terminal, Figma - keeps its title bar within a few percent of
 *    the window background. `electron/titleBarColors.ts` sends main the matching
 *    pair so the native glyphs sit on the same colour as this row.
 *  - **No self-drawn corners.** Windows 11 rounds the frame itself, and the
 *    frame is still there - `titleBarStyle: 'hidden'` only removes the caption.
 *    A radius drawn here would be a second, wrong curve inside the real one.
 *  - **The dim is the foreground's.** An unfocused window fades its text and
 *    glyphs, not its ground, which is what Windows does to a caption.
 *  - **`titlebar-reserve`, not a constant.** The button area is ~138px at 100%
 *    scaling and ~207px at 150%, so it is read from `env()`. A hardcoded width
 *    puts the palette trigger under the close button on any machine that is not
 *    at 100%.
 *
 * The height is `h-10`, matching `TITLE_BAR_HEIGHT` in `electron/window.ts`,
 * which is what `titleBarOverlay` reserves. `scripts/electron/shell.ts` pins
 * that number; if it moves, both have to.
 */
export interface TitleRowProps {
  /** The command palette's trigger. The only control in the row. */
  children: React.ReactNode;
  /** What the window is called, shown centred. */
  title: string;
  /** From `useWindowChrome`. Dims the row's contents when false. */
  focused: boolean;
}

export const TitleRow: React.FC<TitleRowProps> = ({ children, title, focused }) => (
  <header
    className={`h-10 shrink-0 flex items-center gap-2 pl-1 border-b border-border
      bg-card text-card-foreground app-drag titlebar-reserve transition-opacity
      ${focused ? '' : 'opacity-60'}`}
  >
    {/* Every interactive thing in here has to opt out of the drag region, or it
        moves the window instead of being pressed - and the only symptom is a
        click that does nothing. The class is on the wrapper so the trigger's own
        markup does not have to know it is in a title bar. */}
    <div className="app-no-drag shrink-0">{children}</div>

    {/* Centred in what is left after the reserved area, not in the window: the
        row is already padded clear of the buttons, so centring inside it is
        centring between the palette trigger and the first button. */}
    <span
      className="flex-1 min-w-0 text-center text-[11px] font-medium tracking-wide
        text-muted-foreground truncate"
    >
      {title}
    </span>

    {/* Balances the trigger's width so the title is centred rather than merely
        between them. `aria-hidden` because it is spacing, not content. */}
    <div aria-hidden className="w-8 shrink-0" />
  </header>
);
