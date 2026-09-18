import React from 'react';
import { ChevronLeft, PanelBottom } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { WindowControls } from './WindowControls';

/**
 * The 32px strip the window is dragged by, across the whole window width.
 *
 * The capture controls went into the rail precisely so this row could be
 * empty, and the menu that used to trigger from its left edge is gone. What is
 * left is **the app's mark at the top-left corner**, the packet counter
 * centred, and the app's own three window buttons on the right - the window is
 * frameless, so those are ours to draw.
 *
 * ## The centre holds the counter, not the window's name
 *
 * It held `windowTitleFor(...)`, which read `Inwire` when idle and
 * `Ethernet - capturing - Inwire` during a capture. That string has not been
 * deleted and still names the window: `useWindowTitle` sends it to main, so the
 * taskbar, Alt-Tab and the window list are exactly as they were. What it stopped
 * doing is spending the centre of the one strip nobody can look away from on the
 * app's own name, which the mark two hundred pixels to its left already gives.
 *
 * The counter earned the slot by being the thing that was hardest to reach:
 * it was a dock widget, so the answer to "how many rows did this filter select"
 * was only on screen if you had chosen to keep a panel open. See
 * `PacketCountsReadout` for why it subscribes rather than taking props, and for
 * the one argument in this repository that says not to do this.
 *
 * ## Why this row spans the window and the rail sits under it
 *
 * The rail used to run the full height with this row beside it, which put the
 * window's top-left corner inside the rail and the mark in the middle of this
 * row - the one place in the window that is neither the corner nor the caption.
 * Now the row is the full width, the rail starts below it, and the mark is at
 * the corner where an application's identity belongs and where every app this
 * one is measured against puts it.
 *
 * **The two read as one surface, and that is the point.** This row and the rail
 * are both `bg-secondary`, and this row draws no bottom border - so there is no
 * line across the top-left corner, and the ground runs unbroken from the mark
 * down into the rail. The border that remains is `<main>`'s `border-l` and
 * `border-t`, which separates the content pane from this surface rather than
 * cutting across it. The rail carried a `border-r` once and does not any more:
 * the two would have drawn the same line twice in the same place, and the one
 * on the pane is the one that follows the rounded corner round.
 *
 * **They were `bg-card` and are one step brighter.** That is a lighter grey in
 * Night (#232323 against #1a1a1a) and a grey rather than white in Day, and it
 * does something the old pair could not: `--card` against `--background` is a
 * 4/255 delta in Night, so the seam where this surface meets `<main>` was
 * invisible and the 1px border was the only thing the eye could follow along
 * it. At `--secondary` the delta is 13/255 and the edge reads on its own. The
 * border stays anyway - it is what carries the edge in Day, where the two are
 * much closer. That argument was first made about a rounded notch `<main>` cut
 * out of this surface; the corner is square now and the deltas are unchanged,
 * because they were always about two grounds meeting rather than about a curve.
 *
 * It costs `TITLE_BAR_HEIGHT` of window rather than of rail: `MIN_WINDOW_HEIGHT`
 * is 680, so the row comes off the top without the rail paying for it. Taking it
 * from the rail instead would have eaten into a budget that had nothing spare at
 * the time, and an overflow there does not scroll - the bottom group is pinned
 * with `mt-auto`, so Settings goes off the bottom edge.
 *
 * **The status bar at the other end was funded the opposite way**, and the
 * contrast is the point: by the time it arrived the rail had 154px of slack, so
 * its 24px came out of that and the window minimum stayed 680. Rail budget is
 * 680 - 32 - 24 = 624 against the 494 its icons come to.
 * `scripts/session/view.ts` does the sum; the numbers were quoted here as
 * 40 / 640 / 630 long after all three had moved.
 *
 * **There is no lockup any more, only the mark.** The wordmark is deleted, so
 * the question the previous three paragraphs here answered at length - whether
 * a lockup's two halves may carry different colours - has no subject. The mark
 * is a shaded form carrying its own two colours from `lib/brandMark.ts`, which
 * is the one place that decides them, and there is no second half to drift
 * from.
 *
 * One consequence for `scripts/themes/registry.ts`: its contrast check tested
 * `--card-foreground` against `--card` and was described as covering "the brand
 * mark in the title row". It was covering the WORDMARK, which no longer exists,
 * and against a ground this row no longer uses. That file's own comment warns
 * that a guard aimed at the wrong ground passes for exactly as long as it is
 * wrong; the check is retargeted rather than left pointing here.
 *
 * **It holds no NAVIGATION, and that is the finished state rather than a gap.**
 * Every app this one is measured against does the same: VS Code's title bar
 * carries a command centre and nothing else, Windows Terminal's carries tabs,
 * Figma's carries its menu - none carries a second navigation surface beside one
 * that already exists. Adding a button back here means taking it from the rail,
 * where it is one of fourteen in a strip built to hold exactly that.
 *
 * It does hold exactly one control, and only because deleting the counts widget
 * would otherwise have deleted it: the `+N UNSEARCHED` rescan button inside the
 * readout, which is the only way to re-run a whole-capture filter scan. It
 * carries `app-no-drag` itself.
 *
 * ## What makes this read as native rather than as a web page in a frame
 *
 *  - **The colour.** `bg-secondary`, the same ground the rail uses, never the
 *    saturated `--chrome` accent. Every app this one is measured against - VS
 *    Code, Windows Terminal, Figma - keeps its title bar within a few percent of
 *    the window background. There are no native glyphs to match any more:
 *    `lib/windowChrome.ts` sends main the theme's NAME, and `windowColors.ts`
 *    turns it into the ground the next window opens on.
 *  - **No self-drawn corners.** `roundedCorners` defaults true and is never
 *    set, so Windows 11 rounds this window even though it is frameless - the
 *    rounded top-left the continuous surface above is drawn into is the OS's.
 *    A radius drawn here would be a second, wrong curve inside the real one.
 *  - **The dim is the foreground's.** An unfocused window fades its text and
 *    glyphs, not its ground, which is what Windows does to a caption.
 *  - **The reserve is a constant again, and that is what frameless bought.**
 *    Under `titleBarOverlay` the button area was ~138px at 100% scaling and
 *    ~207px at 150%, so it had to be read from `env(titlebar-area-width)` - a
 *    hardcoded width ran the app's content under the close button on any
 *    machine that was not at 100%. The buttons are elements now, so they are
 *    138 CSS pixels at every scale factor and the corner block below simply matches
 *    them.
 *
 * The height is `h-8` - 32px - matching `TITLE_BAR_HEIGHT` in
 * `electron/window.ts`. `scripts/electron/shell.ts` pins that number; if it
 * moves, both have to. It was `h-10`, then `h-9`, and **this is the floor**: the
 * window buttons are 46x32 because 32 is Windows' own caption metric, so at
 * `h-8` they fill the row exactly and anything shorter means redrawing them.
 */
export interface TitleRowProps {
  /** From `useWindowChrome`. Dims the row's contents when false. */
  focused: boolean;
  /** From `useWindowChrome`. Decides the maximize button's glyph and label. */
  maximized: boolean;
  /** Whether the packet detail panes are shown below the list. */
  panesVisible: boolean;
  onTogglePanes: () => void;
  /**
   * The name of the view a back step lands on, or null at a root.
   *
   * The LABEL rather than the view id, because this row has no business
   * knowing what the views are - it renders a control and says where it goes.
   * `viewPrefs.ts` owns the hierarchy and `App` resolves it.
   */
  backLabel: string | null;
  onBack: () => void;
  /**
   * What sits in the middle of the row. The display filter, today.
   *
   * A slot rather than the filter's own props, because this row has no
   * business knowing what a display filter is - it decides where the centre is
   * and how wide it may get, and `App` decides what goes in it.
   */
  center?: React.ReactNode;
}

/**
 * Anything interactive added in here needs `app-no-drag` on it or on a wrapper,
 * or it moves the window instead of being pressed - and the only symptom is a
 * click that does nothing at all. `WindowControls` carries it; a second control
 * would have to carry its own.
 */
export const TitleRow: React.FC<TitleRowProps> = ({
  focused, maximized, panesVisible, onTogglePanes, backLabel, onBack, center,
}) => (
  <header
    className={`h-8 shrink-0 flex items-center
      bg-secondary text-secondary-foreground app-drag transition-opacity
      ${focused ? '' : 'opacity-60'}`}
  >
    {/* The corner. 138px wide so it balances the controls and the counter stays
        centred in the WINDOW rather than in the space left over beside them -
        that is what three 46px buttons come to, and it is the one number in
        this file that has to track `WindowControls`.

        **The `INWIRE` wordmark was here and is deleted.** It had come back from
        the web build, where the lockup was a `w-9 h-9` mark plus the word at
        `text-lg` on a 64px accent header; here it was scaled to `text-xs`,
        led the mark, and named the app in the caption. What it was doing is
        what the window already does twice - the OS caption and the taskbar both
        carry `windowTitleFor(...)`, which `useWindowTitle` still sends to main
        and which this row never showed.

        **The mark is back on the rail's axis**, which is what the wordmark cost
        and what deleting it returns. It sits directly above the column of icons
        below it rather than 8px to their left, and that alignment is the reason
        the mark used to be in a rail cell at all.

        **Its block has to track the rail's GEOMETRY, not just its width.** The
        rail is a card now, inset from the window by the cluster band's 4px
        gutter, so its centre is at 4 + 44/2 = 26 rather than at half its own
        width. `ml-1 w-11` puts this block over exactly that span. Matching only
        the width - which is what was here when the card landed, and was wrong
        for a commit - leaves the mark 4px left of the icons it is meant to
        crown. `scripts/session/view.ts` holds both halves now, because the two
        numbers live in three different files.

        The mark carries no `title` and is decorative, which is `BrandMark`'s
        own default and its own stated reason. With the word gone that stops
        being "the wordmark beside it names the app" and becomes "the window's
        caption does" - an icon that announced itself as "Inwire" to a screen
        reader on every focus would be the third telling. */}
    <div className="w-[138px] shrink-0 flex items-center">
      {/* **24 CSS pixels in a 32px row**, and the two numbers have to be read
          together. The mark carries about 10% optical margin of its own - the
          art spans 12..88 of a 100 box - so a 24px box draws roughly 19px of
          ink, which leaves the row 6 or 7px of air rather than the 4 the
          numbers suggest. It was 16, where the ink was 12px and the mark read
          as a detail rather than as the app's corner.

          `size` is what picks the DRAWING and the class is what picks the BOX,
          so the two must agree or a mark is rendered at one size and drawn for
          another. `scripts/brand/icon.ts` asserts they do. 24 is still below
          the 32px tier boundary, so this is the three-plate small tier - five
          at 24 would put the gap at 2.2px and merge them. */}
      <div className="ml-1 w-11 shrink-0 flex items-center justify-center">
        <BrandMark className="w-6 h-6 shrink-0" size={24} />
      </div>

    </div>

    {/* Empty, and that is the finished state.

        **The packet counter was here and is in the status bar now.**
        `lib/windowChrome.ts` argued against it being here for as long as it was:
        a number that changes is the most distracting thing that can go in a
        title bar, and it sat here only because nothing better existed. A status
        bar is what "something better" turned out to be, and it took the
        `+N UNSEARCHED` rescan button with it.

        The 138px corner above still balances the three 46px buttons opposite,
        and this spacer is what holds them apart - without it `WindowControls`
        slides left and the mark loses the corner it exists to occupy.
        `scripts/electron/window-chrome.ts` asserts that 138.

        The row now holds no control at all, which makes the drag-region rule
        below vacuous here rather than delicate: there is nothing inside it that
        needs `app-no-drag`. */}
    {/* **The centre, and the display filter is in it.**

        It was empty, and before that it held the packet counter - which
        `windowChrome.ts` argued against for as long as it was there, on the
        grounds that a number changing ten times a second is the most
        distracting thing that can go in a title bar. A search field is not a
        changing number, and it is the one control this app is used through
        most, so this is the slot finally doing something worth its position.

        **It had its own 44px row and does not need one.** A filter expression
        is at most a line of text; a strip spanning the window to hold one was
        44px of height spent on air either side of it. `max-w-[26rem]` is about
        what a two-clause expression needs, and the flex spacers either side
        keep it centred in the WINDOW rather than in the space left over
        between the corner and the controls - which are 138px and ~210px, so
        centring on the leftover would be visibly off.

        **One `app-no-drag` wrapper covers everything inside.** The filter
        carries a text field, a clear button, a save button and a preset list,
        and every one of them would otherwise drag the window instead of
        working. Opting the slot out once is what makes that unconditional:
        whatever goes in here is safe by construction rather than by each
        control remembering. */}
    {/* **The back step sits immediately left of the filter, and a spacer of the
        same width sits right of it.**

        It was in the 138px corner beside the mark, which is where an
        application usually puts one - and that is the argument it lost. The
        corner is the app's identity; a control that comes and going there
        reads as part of the mark's block, and it was as far as it could be
        from the only other navigation in the row. Next to the filter it is in
        the centre group with the one control the app is used through most.

        The mirrored `w-9` spacer is what keeps the field where it was: without
        it the centred group would be the button plus the field, so the filter
        would shift 18px on every view change that gained or lost a back step.
        With it the geometry is constant and only the glyph appears. */}
    <div className="flex-1 min-w-0 flex items-center justify-center px-2">
      <div className="w-9 shrink-0 flex items-center justify-center">
        {/* **One step back up the view hierarchy**, rendered only when there is
            somewhere to go: `Packets`, `Statistics` and the `Routing Map` are
            roots, so nothing appears there. It replaces the "Back to frame N"
            button that lived in Follow Stream's own footer - a way out that
            existed in one view and nowhere else - and it is also the way out of
            Settings, which reads "Back to <the view underneath>".

            `app-no-drag`, like every control in this row. It carries its own
            rather than leaning on the centre slot's wrapper, because it is
            outside it: that wrapper covers whatever `App` puts in the slot. */}
        {backLabel !== null && (
          <button
            type="button"
            onClick={onBack}
            title={`Back to ${backLabel}`}
            aria-label={`Back to ${backLabel}`}
            className="w-9 h-8 shrink-0 inline-flex items-center justify-center rounded
              app-no-drag cursor-pointer transition-colors text-foreground/70
              hover:bg-accent hover:text-foreground focus-visible:outline-none
              focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {center !== undefined && (
        <div className="app-no-drag w-full max-w-[26rem] min-w-0">{center}</div>
      )}

      {/* The counterweight. Never anything but air - see above. */}
      <div className="w-9 shrink-0" aria-hidden />
    </div>

    {/* **The detail panes, on and off.** It was a switch in
        `Settings -> Interface`, and this is where every editor puts its layout
        toggles for a reason that applies here: it is reached for while reading
        a capture, not while configuring the app. `Settings` keeps the pane
        ARRANGEMENT, which is chosen once.

        **Not 46px wide.** That is Windows' caption metric and it belongs to the
        three buttons beside this one; a control of ours that borrowed it would
        claim to be part of that set. It is `w-9` with a rounded hover, which is
        what the rail's buttons look like and what VS Code's layout controls
        look like.

        The two halves of the row are no longer equal - 138px of corner against
        this plus 138 of controls - and that is fine now in a way it was not
        before: the centre held the packet counter, which had to be centred in
        the WINDOW, and it is empty since that moved to the status bar.

        `app-no-drag`, without which this moves the window instead of being
        pressed - a click that silently does nothing, which is the one failure
        mode this row has. */}
    <button
      type="button"
      onClick={onTogglePanes}
      aria-pressed={panesVisible}
      title={panesVisible ? 'Hide packet detail panes' : 'Show packet detail panes'}
      aria-label="Toggle packet detail panes"
      className={`w-9 h-8 mr-1 shrink-0 inline-flex items-center justify-center rounded
        app-no-drag cursor-pointer transition-colors hover:bg-accent
        focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring
        focus-visible:ring-inset ${panesVisible ? 'text-foreground' : 'text-foreground/60'}`}
    >
      <PanelBottom className="w-4 h-4" />
    </button>

    <WindowControls maximized={maximized} />
  </header>
);
