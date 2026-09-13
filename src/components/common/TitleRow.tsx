import React from 'react';

/**
 * The 40px strip the window is dragged by.
 *
 * All of it is drag region now, which is the point: the capture controls went
 * into the rail precisely so this row could be empty, and the menu that used to
 * trigger from its left edge is gone - three of its seven entries duplicated
 * rail buttons, two became rail buttons, and the last two went to Settings. So
 * what is left is the window's own name in the middle and the area Windows draws
 * its buttons into on the right.
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
 *  - **`titlebar-reserve`, not a constant.** The button area is ~138px at 100%
 *    scaling and ~207px at 150%, so it is read from `env()`. A hardcoded width
 *    would run the title under the close button on any machine that is not at
 *    100% - and it is what keeps the centring below honest, since the row is
 *    padded clear of the buttons before anything is centred in it.
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
}

/**
 * If a control ever comes back in here it needs `app-no-drag` on it or on a
 * wrapper, or it moves the window instead of being pressed - and the only
 * symptom is a click that does nothing at all. There is nothing to carry that
 * class today, so the rule lives in this comment rather than on an empty div.
 */
export const TitleRow: React.FC<TitleRowProps> = ({ title, focused }) => (
  <header
    className={`h-10 shrink-0 flex items-center px-2 border-b border-border
      bg-card text-card-foreground app-drag titlebar-reserve transition-opacity
      ${focused ? '' : 'opacity-60'}`}
  >
    {/* Centred in what is left after the reserved area, not in the window.
        `titlebar-reserve` has already padded the row clear of the native
        buttons, so centring inside it puts the title in the middle of the space
        a person actually sees rather than under the close button. */}
    <span
      className="flex-1 min-w-0 text-center text-[11px] font-medium tracking-wide
        text-muted-foreground truncate"
    >
      {title}
    </span>
  </header>
);
