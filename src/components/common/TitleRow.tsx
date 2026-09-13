import React from 'react';
import { WindowControls } from './WindowControls';

/**
 * The 40px strip the window is dragged by.
 *
 * The capture controls went into the rail precisely so this row could be
 * empty, and the menu that used to trigger from its left edge is gone. What is
 * left is the window's own name in the middle and **the app's own three window
 * buttons** on the right - the window is frameless, so those are ours to draw.
 *
 * **It holds no control at all, and that is the finished state rather than a
 * gap.** Every app this one is measured against does the same: VS Code's title
 * bar carries a command centre and nothing else, Windows Terminal's carries
 * tabs, Figma's carries its menu - none carries a second navigation surface
 * beside one that already exists. Adding a button back here means taking it from
 * the rail, where it is one of thirteen in a strip built to hold exactly that.
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
 *  - **The reserve is a constant again, and that is what frameless bought.**
 *    Under `titleBarOverlay` the button area was ~138px at 100% scaling and
 *    ~207px at 150%, so it had to be read from `env(titlebar-area-width)` - a
 *    hardcoded width ran the app's content under the close button on any
 *    machine that was not at 100%. The buttons are elements now, so they are
 *    138 CSS pixels at every scale factor and the spacer below simply matches
 *    them.
 *
 * The height is `h-10`, matching `TITLE_BAR_HEIGHT` in `electron/window.ts`,
 * which is what `titleBarOverlay` reserves. `scripts/electron/shell.ts` pins
 * that number; if it moves, both have to.
 */
export interface TitleRowProps {
  /** What the window is called, shown centred. */
  title: string;
  /** From `useWindowChrome`. Dims the row's contents when false. */
  focused: boolean;
  /** From `useWindowChrome`. Decides the maximize button's glyph and label. */
  maximized: boolean;
}

/**
 * Anything interactive added in here needs `app-no-drag` on it or on a wrapper,
 * or it moves the window instead of being pressed - and the only symptom is a
 * click that does nothing at all. `WindowControls` carries it; a second control
 * would have to carry its own.
 */
export const TitleRow: React.FC<TitleRowProps> = ({ title, focused, maximized }) => (
  <header
    className={`h-10 shrink-0 flex items-center border-b border-border
      bg-card text-card-foreground app-drag transition-opacity
      ${focused ? '' : 'opacity-60'}`}
  >
    {/* Balances the controls so the title is centred in the WINDOW rather than
        in the space left over beside them. `aria-hidden` because it is spacing,
        not content, and 138px because that is what three 46px buttons come to -
        the one number in this file that has to track `WindowControls`. */}
    <div aria-hidden className="w-[138px] shrink-0" />

    <span
      className="flex-1 min-w-0 text-center text-[11px] font-medium tracking-wide
        text-muted-foreground truncate"
    >
      {title}
    </span>

    <WindowControls maximized={maximized} />
  </header>
);
