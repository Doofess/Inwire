import React from 'react';
import {
  Play,
  Square,
  EthernetPort,
  TriangleAlert,
  Clock,
  List,
  ChartNoAxesCombined,
  Map as MapIcon,
  ArrowLeftRight,
  Settings,
  FileOutput,
  ListTree,
  Network,
} from 'lucide-react';
import type { AgentHealth } from '../../services/agentHealth';
import { agentNeedsAttention, agentStatusLabel } from '../../services/agentHealth';
import { isScheduleEmpty, type CaptureSchedule } from '../../services/captureSchedule';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import type { Capabilities } from '../../types/packet';
import { APP_VIEWS, type AppView } from '../../services/viewPrefs';
import type { SideBarPanel } from '../../services/sideBarPrefs';
import { useRovingFocus } from './useRovingFocus';

/**
 * The one strip of chrome that is always there.
 *
 * Three groups, and the grouping is the only thing saying that two of them
 * behave differently: the views are a radio - one active at a time, switching
 * what fills the window - while the adapter, the schedule and Start/Stop are
 * controls that are simply on or off. A divider alone does not convey that, so
 * the active states are deliberately different shapes:
 *
 *  - a view carries a **translucent fill in the theme's own accent** -
 *    `--primary` at 20%, with `--foreground` on the glyph;
 *  - a control that is on carries an **outline only**, and a dot where it has
 *    something to report.
 *
 * **The view marker used to be two things: a 2px left accent edge over an
 * `--accent` fill.** That was VS Code's "you are here" pair, and the fill was
 * the weaker half - `--accent` is one step off the rail's own ground, so the
 * edge was doing the work and the fill was barely a tint. Tinting with the
 * accent HUE inverts that: the fill carries the state on its own, and an edge in
 * the same colour drawn against a button already filled with it is a second mark
 * for one fact.
 *
 * **20%, and the glyph is `--foreground` rather than `--primary`.** Both of
 * those are Day's doing. A solid `--primary` fill was tried first and reads as
 * a button rather than a selection; translucent is the right weight. But
 * `--primary` on a tint of ITSELF cannot reach 4.5:1 in Day at any alpha - it
 * peaks at 3.97 and falls from there, because `#0b6bcb` is a mid-blue and the
 * tint lightens toward it. So the accent-on-accent-tint pattern is out, and the
 * glyph takes `--foreground`: 11.1:1 in Day, 8.4:1 in Night. The progression
 * from inactive is then two things at once, `--muted-foreground` to
 * `--foreground` and no fill to a blue one.
 *
 * At 20% the fill sits 15.4 (Day) / 17.7 (Night) deltaE from the rail's ground
 * and 12.4 / 15.1 from the HOVER state, which is the pair that actually matters:
 * an active marker a hover can be mistaken for is not a marker.
 * `scripts/themes/registry.ts` holds all four of those numbers, and reads the
 * alpha out of this file so the two cannot drift.
 *
 * Neither appears on hover. The active marker is the strongest indicator in the
 * UI, and firing it on hover flashes it five times as a pointer crosses the
 * rail, with a moment where two items read as active.
 *
 * ## Why 44px, and what the air is for
 *
 * `w-11`. The interior is what this number is really about: two 1px borders
 * leave 42px for a 36px target, so each icon has **3px of air** either side.
 * That is the figure to reason from if it moves again - the outer width on its
 * own says nothing once the card has borders, and 3px is the constant every
 * width this rail has had came out at.
 *
 * It was 56, then 52, and the first of those two steps was free: the icons did
 * not move, so what was spent was air. This one was not free and was taken
 * knowingly - 52 was still too wide, and the only thing left to give at 3px of
 * air is the button. The target went back to 36 and the glyph to 20, which is
 * what this rail was before six deleted icons left the room to enlarge them.
 *
 * `FrameMetaRail` is 48, and index.css's own comment says two icon strips that
 * disagree by a few pixels is "something you only notice when they are on
 * screen together". This rail was 8px WIDER than that one and is now 4px
 * narrower, so the disagreement has changed sign rather than gone away. Still
 * accepted, and for the reason it always was: that rail is one group of icons
 * inside a pane, this one is three groups in the window's chrome.
 *
 * ## The card it sits in
 *
 * The rail is a **card**, which is VS Code's Modern UI arrangement rather than
 * an invention here: `floatingPanels.css`, `.part.activitybar.left`. Read that
 * file before changing any of the four facts below, because each of them is
 * load-bearing there for a reason it took them a comment to explain.
 *
 * **A border on all four sides, always; a radius on the corners nothing
 * covers.** Both of VS Code's arrangements are live here and which one is in
 * force is a single boolean, `sideBarOpen`:
 *
 *  - **Closed.** Nothing to connect to, so the card "closes up as a standalone
 *    panel with every corner rounded" - `.nosidebar` in `floatingPanels.css` -
 *    and `<main>` supplies the 4px gap as its own `ml-1`.
 *  - **Open.** The side bar butts against this edge and the two read as ONE
 *    surface: the right corners square, the side bar gives up its left border,
 *    and this card draws the only seam between them.
 *
 * **The border never becomes conditional, and that is arithmetic rather than
 * taste.** At `w-11` under `border-box` the interior is exact - 44 less two 1px
 * borders is 42, an even interior for a 36px target. Hand the facing border to
 * the neighbour, which is the obvious way to make one seam out of two edges,
 * and the interior is 43 and the icon column lands on a half pixel.
 * `floatingPanels.css` records the identical finding in its own words, which is
 * why the rail draws the seam in both codebases.
 *
 * The left corners are stated unconditionally for the same reason the border
 * is: they face the band's gutter and can never square, so the only corner an
 * edit can get wrong is the one that actually varies.
 *
 * **The gap is `ml-1` on the element to the RIGHT, never `mr-1` here** - on
 * `<main>` when this card's neighbour is `<main>`, and on the sash when the
 * side bar is between them. VS Code's convention, and worth keeping rather than
 * splitting: one margin is one number to change, where a margin on each side is
 * two that have to agree.
 *
 * **The radius is legal because the card does not touch the window.** The
 * shell's rule is that nothing drawing against the window's own edge may carry
 * a corner - Windows draws the only curve out there. `App.tsx`'s cluster band
 * insets this card by a 4px gutter on the left and the bottom, so the rule is
 * not bent, it is not engaged. Remove the gutter and the radius has to go with
 * it, in that order.
 *
 * **Flush to the title row at the top, 4px clear of the status bar.** Also VS
 * Code's: cards meet the title bar and take the gutter at the window edge.
 *
 * ## Height
 *
 * 11 icons at 36px, two dividers and the bottom group's padding come to
 * **452px** against the 618px the rail gets - a 680px minimum window, less the
 * 32px title row above it, the 24px status bar below, the cluster's 4px bottom
 * gutter, and this card's own two 1px borders. It fits, with 166px of slack -
 * room for four more.
 *
 * **The two strips are funded differently, and that is the thing to carry
 * forward.** The window minimum carries the title row, so this number did not
 * have to move when the row arrived: taking those 32px out of the rail instead
 * would have pushed Settings off the bottom edge, back when there was no slack
 * to take them from. The status bar came later, by which time six deleted icons
 * had left 154px spare, so it comes out of that slack and the minimum stays
 * 680 - which is 24px of window every small laptop keeps.
 *
 * ## How it got from 630 to 494 while the icons got BIGGER
 *
 * That is the part worth writing down, because the two halves pull opposite
 * ways and a future session reading only one of them will draw the wrong
 * conclusion.
 *
 * **Six icons were deleted.** Packet counts stopped being a widget - the counter
 * is a fixture of the title row now - then Protocol breakdown and Top talkers
 * went outright, and finally the dock itself took the last three widget icons
 * and its own 20px collapse header with it. The map came back as a fourth
 * **view**, so the views group grew by one.
 *
 * **Then every target grew from 36px to 44px**, and the glyph from 20 to 24.
 * That costs 8px an icon and it is what the deletions paid for: the strip was
 * full at 630 against 640, which is why nothing in it could be made larger
 * before.
 *
 * Moving an icon between groups is **free**, which is the one piece of this
 * arithmetic that surprises people. Both groups gap the same, so when Find
 * packet moved from the bottom group into the capture group, `group(4) -
 * group(3)` and `group(3) - group(2)` were both 38 and they cancelled exactly.
 * Only adding or deleting changes the total.
 *
 * **494 has since survived a swap, for the same reason.** Find packet was
 * deleted from the capture group and Frame Detail added to the views group -
 * `group(4) - group(3)` against `group(5) - group(4)`, both 46 - so the strip is
 * the same height with a different set of icons in it. That is a coincidence of
 * this particular change rather than a rule, and the number is checked rather
 * than assumed: `scripts/session/view.ts` adds up the groups as they actually
 * are.
 *
 * **414 -> 452 is the free move and the paid-for icon in one change.**
 * Export/Import went from the bottom group up under the schedule, which cost
 * nothing by the rule above; Network came BACK from Settings into the slot it
 * left, and that is a genuine eleventh icon at 36 + 2 = 38. Read the pair
 * together and the rule is unmissable: rearranging this strip is free and
 * growing it is not.
 *
 * **452 -> 452 is that rule said a second time**, which is why the sequence ends
 * on a repeat. Network moved again, up into the capture group under
 * Export/Import, leaving Settings alone at the bottom: `group(5) - group(4)` is
 * 38 and `group(2) - group(1)` is 38, so the deltas cancel exactly as they did
 * when Export/Import made the same trip the other way. A rule derived once is a
 * coincidence; the same arithmetic twice, in opposite directions, is a rule.
 *
 * That number is added up from these classes by `scripts/session/view.ts`, which
 * also holds each class to what the sum assumes. This comment said 549 until that
 * script was written: the figure was for `my-1` dividers, it counted three rather
 * than the four actually rendered, and it ignored the capture group's `pt-1` and
 * the bottom group's `pb-2`. A height budget nothing checks is a height budget
 * that has already drifted.
 *
 * **If the slack is ever spent, the views group is the one that scrolls.** It
 * used to be the widgets group and there is no widgets group; capture has to
 * stay reachable because it is how a capture starts, and the bottom group is
 * pinned with `mt-auto`, so an overflow there does not scroll anything - it
 * pushes Settings off the bottom edge.
 *
 * The slack came back, and it is worth knowing where from. Deleting the
 * hamburger menu pushed this to 617px - Export/Import and Custom Dissectors took
 * the bottom group to three icons, which was the last one that fit. Then Custom
 * Dissectors went to Settings beside Decryption, and **Network stopped being a
 * view at all**: it described the machine rather than the capture, which is why
 * the filter row had to be hidden above it and nowhere else, so it became a
 * Settings tab next to Driver Info. That is two icons back - and Network has
 * since spent one of them again, as a SHEET rather than a view: not in
 * `APP_VIEWS`, no `Ctrl+n`, no place in the numbering, but a button of its own
 * at the end of the capture group, under Export/Import. The half of that
 * decision that stood was "it is not a way of looking at the capture"; the half
 * that did not was "therefore it belongs inside the configuration panel".
 * **The bottom group is Settings alone now**, which is VS Code's own
 * arrangement and makes the divider above it mean something rather than merely
 * separating: everything above opens a surface beside the workspace, the one
 * below takes the workspace itself. Every digit below it
 * has shifted twice since - Network leaving, then Frame Detail arriving second -
 * and the current assignment is Packets `Ctrl+1`, Frame Detail `Ctrl+2`,
 * Statistics `Ctrl+3`, Routing Map `Ctrl+4`, Follow Stream `Ctrl+5`. None of
 * that is written down twice: `APP_VIEWS` order IS the numbering, which is the
 * whole reason a view can be inserted without a second table to update.
 *
 * Find packet took the other, and has since been **deleted** rather than moved
 * again: it was a substring match over the rows already in hand, which is the
 * weaker of two overlapping answers - the display filter is compiled and
 * answered over the whole capture on disk. What replaced it is not a smaller
 * search but a different control, the Frame Detail view's go-to box, which takes
 * a frame number and nothing else.
 *
 * The capture group took one of those back: the schedule picker was a labelled
 * button in the filter row, and it is a capture control - it decides when a
 * capture starts and stops - so it sits with Start/Stop and the adapter. The
 * group reads top to bottom in the order it is used - **start, what to listen
 * on, and when.**
 *
 * A further 40px came from **deleting the top cell**. It held the brand mark,
 * aligned to the title row; the mark is in the title row itself now - beside
 * the wordmark, which leads it - and an empty cell would have been 40px spent
 * on nothing.
 */

/**
 * The button's hit target, and the glyph inside it.
 *
 * **36 in a 44px rail**, with a 20px glyph. The ratio is the thing to hold:
 * the glyph is 56% of the target and the target leaves 3px of air either side
 * inside the card's borders, which is what every previous size of this rail has
 * also done. 32-in-48, 36-in-56, 44-in-56 and now 36-in-44 are four points on
 * one line.
 *
 * It went 36 -> 44 once, when six deleted icons left the height to spend, and
 * came back when the rail was narrowed on request: a 44px target cannot fit a
 * rail this narrow without the button's edges becoming the rail's own, which is
 * the state that reads as a column of boxes rather than of icons.
 *
 * **44 is the touch-target floor every platform guideline names, and giving it
 * up is deliberate.** There is no touch here - this is a desktop window with a
 * pointer - and 36 is what Windows' own command bars use. It is also 4 more
 * than the 32 the caption buttons beside it are, so nothing in the chrome is
 * harder to hit than the close button.
 */
const TARGET = 'w-9 h-9';
const GLYPH = 'w-5 h-5';

const GROUP = 'flex flex-col items-center gap-0.5 shrink-0';

/**
 * The divider between groups.
 *
 * Decorative, so it is hidden from assistive tech: the grouping is carried
 * properly by the `role="group"` + `aria-label` on each cluster, and a
 * separator announced between them would be noise on top of that.
 */
const RailDivider: React.FC = () => (
  // `border` on `card` is a small delta on a dark theme - on Night it is
  // #3c3c3c on #222222 - and at 1px by 24px the line was very nearly
  // invisible, which left the grouping carried by the active states alone.
  // Wider, and `muted-foreground` at low opacity so it reads on both grounds
  // rather than on the light one.
  <div aria-hidden className="my-1.5 h-px w-7 shrink-0 bg-muted-foreground/30" />
);

/** The shared button shape. `active` styling is supplied per group. */
function railButton(active: boolean, kind: 'view' | 'toggle'): string {
  const base = `relative ${TARGET} flex items-center justify-center rounded-md `
    + 'transition-colors cursor-pointer shrink-0 app-no-drag '
    + 'focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring';
  if (!active) return `${base} text-muted-foreground hover:bg-accent hover:text-foreground`;
  return kind === 'view'
    // The theme's own accent, at a fifth. See the note above the group for what
    // this replaced, why the edge went with it, and why the glyph is
    // `--foreground` rather than the accent itself.
    ? `${base} bg-primary/20 text-foreground`
    // Outline only: a control that is ON, not "where you are".
    : `${base} text-foreground ring-1 ring-inset ring-border`;
}

const VIEW_ICONS: Record<AppView, React.ComponentType<{ className?: string }>> = {
  packets: List,
  // The same glyph the pane's own header wears, which is the whole of why it is
  // this one: the rail icon and the thing it opens should be recognisably one
  // surface, and a tree is what the view actually shows.
  detail: ListTree,
  statistics: ChartNoAxesCombined,
  geo: MapIcon,
  stream: ArrowLeftRight,
};

export interface ActivityRailProps {
  /* --- capture ---------------------------------------------------------- */
  isCapturing: boolean;
  onStartCapture: () => void;
  onStopCapture: () => void;
  /** Emptied before a restart, so every buffer is one continuous recording. */
  onClearPackets: () => void;
  bufferedPackets: number;
  permissions: Capabilities;
  /**
   * Still here, and only for the BUTTON - the list itself is the panel's.
   *
   * The rail draws a health badge on this glyph and names the chosen adapter
   * in its tooltip, both of which need the list. What it no longer does is
   * carry the list itself, the selection callback, the traffic samples or the
   * open/close hook that gated them: those went to
   * `sidebar/CaptureInterfacePanel.tsx` with the menu they belonged to.
   */
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  captureOwnedElsewhere?: boolean;
  agentHealth: AgentHealth;
  /**
   * The capture schedule, which moved here from the filter row.
   *
   * It is a capture control - it decides when one starts and when it stops - so
   * it sits with Start/Stop and the adapter rather than above the packet list.
   */
  /**
   * Still here, and only for the BUTTON.
   *
   * The dot needs to know whether anything is scheduled and the tooltip needs
   * the summary; neither needs the schedule's editing surface. The four props
   * that existed purely to be forwarded into the dropdown - the change
   * callback, the presets, their callback, and the clock - went to
   * `sidebar/CaptureSchedulePanel.tsx` with the menu.
   */
  schedule: CaptureSchedule;
  /** "Stops in 14:58" - the panel header's detail, and this button's tooltip. */
  scheduleSummary: string;

  /* --- views ------------------------------------------------------------ */
  view: AppView;
  onViewChange: (view: AppView) => void;
  /**
   * Whether Follow Stream has anything to follow: the selected frame sits on a
   * stream, or one is already open.
   *
   * It used to be the second half alone, which disabled the button in exactly
   * the state a user reaches it from - a frame selected, nothing followed yet.
   */
  streamAvailable: boolean;

  // **There was a widgets group here and it is gone with the dock.** Five
  // props - the item list, a toggle, the minimized flag, its toggle, and the
  // stored titles for the tooltips - driving six icons that switched panels in a
  // column. The three surviving widgets are surfaces of their own now: the map
  // is a VIEW in the group above, and the two charts are a tab of the Statistics
  // pane.

  /* --- bottom ----------------------------------------------------------- */
  /**
   * Whether the Settings pane is up.
   *
   * It takes the workspace card but is not a view, so it is not in `view` and
   * has to arrive on its own. The button carries the same active marker every
   * view button does, because from the rail's side it is the same fact: this is
   * what is on screen.
   */
  settingsOpen: boolean;
  onOpenSettings: () => void;
  /**
   * Whether the Network sheet is up.
   *
   * The same shape as `settingsOpen` and for the same reason: Network takes the
   * workspace card without being a view, because nothing in it changes when a
   * packet arrives - it describes the MACHINE. Two booleans here rather than one
   * "which sheet" enum, because this strip has no concept of a sheet: it draws a
   * button and says whether that button's surface is on screen. `App` owns the
   * rule that only one can be.
   */
  networkOpen: boolean;
  onOpenNetwork: () => void;
  /**
   * Which side bar panel is open, or null.
   *
   * The panel rather than a boolean per button, because four buttons in this
   * strip mark one column: what each needs to know is whether the surface on
   * screen is ITS surface, which is one comparison against one value. Four
   * booleans would make "two lit at once" representable in a strip that has
   * exactly one column to point at.
   */
  sideBarPanel: SideBarPanel | null;
  onOpenSideBar: (panel: SideBarPanel) => void;
  /**
   * Whether the side bar is open against this card's right edge.
   *
   * **The rail's own geometry is the only thing this changes**, which is why it
   * arrives as a boolean rather than as the panel: which panel is open is the
   * side bar's business, and this strip only needs to know whether there is a
   * card to connect to. VS Code's two arrangements are the same one boolean -
   * `.nosidebar` versus a side bar against the rail.
   */
  sideBarOpen: boolean;
  /**
   * Export / Import PCAP.
   *
   * It took the Update Center's slot, and that cost nothing: `onOpenUpdates`
   * and `onOpenSettings` were the same handler - both opened the Settings modal,
   * which is where the Update Center lives as a section - and `updateAvailable`
   * was passed `false` at the only call site, so the badge could never light. It
   * was a second Settings button with a dot that never appeared. Settings ->
   * Updates is still the one place this app updates anything (ADR 0032).
   */
  onOpenExport: () => void;

}

export const ActivityRail: React.FC<ActivityRailProps> = ({
  isCapturing, onStartCapture, onStopCapture, onClearPackets,
  bufferedPackets, permissions, agentInterfaces, selectedInterfaces,
  captureOwnedElsewhere, agentHealth,
  view, onViewChange, streamAvailable,
  settingsOpen, onOpenSettings, networkOpen, onOpenNetwork, onOpenExport, sideBarOpen,
  sideBarPanel, onOpenSideBar,
  schedule, scheduleSummary,
}) => {
  const selected = agentInterfaces.find((i) => i.name === selectedInterfaces[0]) ?? null;
  const attention = agentNeedsAttention(agentHealth);

  /**
   * The adapter control's accessible name, and the reason it has a stable half.
   *
   * `scripts/electron/smoke.ts` finds this button by
   * `getByRole('button', { name: 'Interfaces' })`, and the health state is part
   * of what the control says - so the name cannot be only the health text, or
   * the one end-to-end check that drives the real app would break on a machine
   * with no agent. The word the locator matches therefore leads, always, and
   * the state follows it.
   */
  const adapterDetail = attention
    ? agentStatusLabel(agentHealth)
    : selected === null
      ? 'none selected'
      : shortInterfaceLabel(selected.label);
  const adapterName = `Interfaces - ${adapterDetail}`;

  // A clock glyph looks the same whether or not anything is scheduled, which is
  // the failure the adapter's warning badge exists to avoid - so the dot is the
  // signal and the tooltip carries the detail.
  const scheduleSet = !isScheduleEmpty(schedule);

  const adapterTitle = attention && 'summary' in agentHealth
    ? `${agentHealth.summary}. Settings > Driver Info has the detail.`
    : selected === null
      ? 'Choose which adapter to capture from'
      : selected.label;

  /**
   * A stopped capture cannot be resumed, so starting again means discarding.
   *
   * Unchanged from the header this replaces, and unchanged for the same reason:
   * a buffer appended to across two runs has a gap in the middle that nothing
   * in the file records.
   */
  const restartDiscards = !isCapturing && bufferedPackets > 0;
  const startBlocked = !permissions.canCapture || selected === null || captureOwnedElsewhere;
  const captureBlocked = captureOwnedElsewhere
    || (!isCapturing && (startBlocked || (restartDiscards && !permissions.canClearBuffer)));

  /**
   * Whether the "this discards what you captured" prompt is showing.
   *
   * Local, as it was in the header this replaces: nothing else needs to know a
   * question is being asked, and it is a question about one control.
   */
  const [confirmRestart, setConfirmRestart] = React.useState(false);
  const confirmRef = React.useRef<HTMLDivElement | null>(null);

  // A capture that STARTS while the prompt is up, or a buffer that empties from
  // somewhere else, has answered the question by other means.
  React.useEffect(() => {
    if (isCapturing || bufferedPackets === 0) setConfirmRestart(false);
  }, [isCapturing, bufferedPackets]);

  React.useEffect(() => {
    if (!confirmRestart) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== 'Escape') return;
      // Claimed before the view-level handler can read it: Escape in a
      // non-Packets view switches to Packets, and dismissing a prompt must not
      // also navigate. This is the innermost link in that chain.
      e.stopPropagation();
      setConfirmRestart(false);
    };
    const onDown = (e: PointerEvent): void => {
      if (!confirmRef.current?.contains(e.target as Node)) setConfirmRestart(false);
    };
    // Capture phase, so a click on some other control cancels the prompt rather
    // than being swallowed by it.
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('pointerdown', onDown, true);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('pointerdown', onDown, true);
    };
  }, [confirmRestart]);

  const startFresh = (): void => {
    setConfirmRestart(false);
    // Clear first. Both are synchronous, so by the time the agent is told to
    // start there is no buffer left for its packets to be appended to.
    onClearPackets();
    onStartCapture();
  };

  /**
   * Arrow keys move focus within the rail, and must not leave it.
   *
   * The implementation was here and is `useRovingFocus` now, because the side
   * bar's panels are the same shape - a column of plain buttons - and needed
   * the same thing. What moved with it is the reason it is not twenty lines
   * anybody can rewrite: `stopPropagation`. `useKeyboardNavigation` listens on
   * `window` for the arrow keys and moves the packet selection, so a container
   * that forgets it does not fail visibly, it quietly steps the capture
   * underneath while the pointer is nowhere near the list.
   */
  const onRailKeyDown = useRovingFocus('vertical');

  return (
    <div
      role="toolbar"
      aria-orientation="vertical"
      aria-label="Activity"
      onKeyDown={onRailKeyDown}
      className={`w-11 shrink-0 flex flex-col items-center bg-secondary
        text-secondary-foreground select-none
        border border-border rounded-l-lg ${sideBarOpen ? '' : 'rounded-r-lg'}`}
    >
      {/* No top cell, and the mark is not in one. The rail starts below the
          title row rather than beside it, so the window's top-left corner is
          the ROW's - which is where the mark sits. A cell here would put it
          40px below the corner it is meant to occupy and cost 40px this rail
          does not have.

          This card's top border is the line under the title row, and the
          title row does not draw it. `border-box` takes a border out of the
          element's own height, so a `border-b` on the `h-8` row would leave
          31px for caption buttons that are 46x32 because Windows' are - and
          the same argument keeps `border-t` off the `h-6` status bar.

          The card's ground is the band's ground, `bg-secondary` either side of
          its border, so the outline is the whole separation. Anything that
          paints its own patch of ground on this rail - the adapter badge's
          `fill-secondary` is the only one - has to name that token too, or it
          reads as a darker square in Night.

          The cell also carried `.app-drag`, so the window could be grabbed by
          the top-left corner. That is gone with it: the title row is drag
          region across its whole width bar the controls, which is where a
          window is grabbed. The rail is now entirely no-drag. */}
      <div className={`${GROUP} pt-1`} role="group" aria-label="Capture">
        {/* The capture button and its discard prompt. `relative` so the prompt
            anchors here; it opens to the right, because there is no room below
            a control in a 56px strip. */}
        <div className="relative" ref={confirmRef}>
          <button
            data-tour="start"
            onClick={isCapturing
              ? onStopCapture
              : restartDiscards
                ? () => setConfirmRestart((open) => !open)
                : onStartCapture}
            disabled={captureBlocked}
            aria-label={
              isCapturing
                ? 'Stop capture'
                : restartDiscards
                  ? 'Start a new capture, discarding the current one'
                  : 'Start capture'
            }
            aria-haspopup={restartDiscards ? 'dialog' : undefined}
            aria-expanded={restartDiscards ? confirmRestart : undefined}
            title={
              captureOwnedElsewhere
                ? 'Another Inwire window is capturing. Stop it there, or close that window.'
                : isCapturing
                  ? 'Stop capture. A stopped capture cannot be resumed.'
                  : startBlocked
                    ? 'Choose an interface first'
                    : restartDiscards
                      ? `Start a new capture - discards the ${bufferedPackets.toLocaleString()} packets in the buffer`
                      : 'Start capture'
            }
            className={`${railButton(false, 'toggle')} ${
              captureBlocked ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            {/* Outlined record when idle, filled red stop while capturing, and
                no cross-fade. The header's two glyphs used to dissolve into each
                other over 180ms; in a tool whose whole job is watching a live
                list, the one control that says whether it is recording should
                change on the frame it is clicked. */}
            {isCapturing
              ? <Square className={`${GLYPH} fill-current text-danger`} />
              : <Play className={GLYPH} />}
          </button>

          {/* Opens to the RIGHT, not below: a 56px strip has no room under a
              control, and the prompt is 288px wide. Card colours, because it
              hangs over the app's own ground rather than over the rail. */}
          {confirmRestart && (
            <div
              role="dialog"
              aria-label="Discard the current capture?"
              className="absolute left-full top-0 ml-2 z-50 w-72 rounded-lg border p-3
                shadow-2xl bg-popover border-border text-popover-foreground"
            >
              <div className="flex items-start gap-2">
                <TriangleAlert className="w-4 h-4 mt-0.5 shrink-0 text-warning" />
                <div className="text-[11px] leading-relaxed text-muted-foreground">
                  <span className="font-bold text-foreground">
                    Discard {bufferedPackets.toLocaleString()} captured packets?
                  </span>
                  <br />
                  A stopped capture cannot be resumed, so starting again clears the buffer
                  first. Export the capture from the menu if you want to keep it.
                </div>
              </div>
              <div className="flex justify-end gap-1.5 mt-3">
                <button
                  type="button"
                  onClick={() => setConfirmRestart(false)}
                  className="px-2.5 py-1 rounded bg-secondary hover:bg-accent text-foreground
                    text-[11px] font-medium transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  autoFocus
                  onClick={startFresh}
                  className="px-2.5 py-1 rounded bg-danger hover:bg-danger/90
                    text-danger-foreground text-[11px] font-bold transition-colors cursor-pointer"
                >
                  Discard and start
                </button>
              </div>
            </div>
          )}
        </div>

        {/* **The adapter button opens a panel, and it is no longer ever
            disabled.**

            It forked on an empty list once and rendered a DEAD button, on the
            sound argument that "a button that opens an empty menu reads as
            broken rather than as blocked". That argument was about a MENU. A
            panel exists when its content does not, so the empty case finally
            has somewhere to say which of three reasons applies - and until now
            the state a fresh install lands in, an agent connected and healthy
            with no driver to listen on, had a hover tooltip and nothing else.

            **The marker changed with it.** It carried the outline, meaning "an
            adapter is chosen"; it carries the FILL now, meaning "this is what
            is on screen", which is the rail's own rule for a surface. The fact
            it used to carry moved to the dot beside it, where the schedule's
            equivalent already lived - so the strip's vocabulary got smaller
            rather than larger: fill is a surface, dot is something to report. */}
        <button
          data-tour="interfaces"
          onClick={() => onOpenSideBar('interfaces')}
          aria-label={adapterName}
          aria-pressed={sideBarPanel === 'interfaces'}
          title={adapterTitle}
          className={railButton(sideBarPanel === 'interfaces', 'view')}
        >
          {selected !== null && (
            <span
              aria-hidden
              className="absolute right-1 top-1 w-1.5 h-1.5 rounded-full bg-primary"
            />
          )}
          <AdapterGlyph attention={attention} />
        </button>

        {/* The schedule picker, which was a labelled button in the filter row.

            It is a capture control - it decides when a capture starts and when
            it stops - so it belongs with Start/Stop and the adapter rather than
            above the packet list. What it loses in the move is its summary
            text: the row had 12rem for "Stops in 14:58", and a 56px strip has
            none. The summary is the tooltip and the popover's own heading now,
            and the glyph carries a dot when a schedule is set, because a clock
            that looks identical whether or not anything is scheduled is the
            same failure the adapter's health badge exists to avoid. */}
        {/* **The schedule button opens a panel, and the summary it computes
            is no longer only a tooltip.**

            It was a dropdown hanging off this button, and the summary -
            "Stops in 14:58", recomputed every second - was shown to whoever
            happened to hover a 36px icon and to nobody else. It is the panel
            header's `detail` now. The tooltip keeps it too, because the button
            is still reachable with the panel closed.

            The dot stays: a clock glyph looks identical whether or not anything
            is scheduled, which is the failure the adapter's warning badge
            exists to avoid. The FILL is what changed - the marker now means
            "this panel is on screen", and "a schedule is set" is what the dot
            has always said. */}
        <button
          data-tour="schedule"
          onClick={() => onOpenSideBar('schedule')}
          aria-label={scheduleSet ? `Capture schedule - ${scheduleSummary}` : 'Capture schedule'}
          aria-pressed={sideBarPanel === 'schedule'}
          title={scheduleSet ? scheduleSummary : 'Schedule when this capture starts and stops'}
          className={railButton(sideBarPanel === 'schedule', 'view')}
        >
          {scheduleSet && (
            <span
              aria-hidden
              className="absolute right-1 top-1 w-1.5 h-1.5 rounded-full bg-primary"
            />
          )}
          <Clock className={GLYPH} />
        </button>

        {/* **Export / Import, under the schedule.**

            It was pinned at the bottom with Settings, in the group for "the
            application" - and it is not about the application, it is about THIS
            capture: it writes the frames in hand out to a file, or reads a file
            in as the frames in hand. That is the same subject as the three
            controls above it, which decide what is captured and when, so it
            belongs at the end of that run rather than beside the app's
            configuration. Moving an icon between two groups costs nothing:
            both gap the same, so the two deltas cancel.

            `FileOutput` rather than the menu's `Download`, and deliberately
            not `ArrowRightLeft`: an exchange glyph would sit four icons above
            Follow Stream's `ArrowLeftRight` and read as the same control
            twice. That mistake has been made in this strip once already - the
            brand mark opened as an `EthernetPort`, identical to the adapter
            button 42px under it, and only a screenshot found it. */}
        <button
          onClick={onOpenExport}
          aria-label="Export or import a capture"
          title="Export / Import PCAP"
          className={railButton(false, 'toggle')}
        >
          <FileOutput className={GLYPH} />
        </button>

        {/* **Network, under Export/Import.**

            It was a VIEW once, on `Ctrl+3`, and it failed the view list's own
            test - it describes the MACHINE rather than the capture, and nothing
            in it changes when a packet arrives. It became a Settings tab on
            that argument, and the tab was the wrong conclusion from a right
            premise: Settings is where the app is CONFIGURED, and Network
            configures nothing. It is a report, and a report about what this
            computer is connected to should not be three clicks inside a
            preferences panel.

            **It sits here rather than at the bottom because of what the run
            above it is.** Start/Stop, the adapter, the schedule and
            Export/Import are the capture and the machine it runs on, in the
            order they are used; Network is the same subject read the other way
            - what this computer is connected to, which is what those frames
            are coming off. The bottom group is left holding Settings alone,
            which is VS Code's own arrangement and makes the divider mean
            something: everything above it opens a surface beside the
            workspace, the one below takes the workspace itself.

            Moving it here cost nothing. Both groups gap the same, so
            `group(5) - group(4)` and `group(2) - group(1)` are both 38 and
            they cancel - the strip is still 452px. `scripts/session/view.ts`
            adds it up rather than trusting this sentence.

            `Network` rather than `EthernetPort` - that glyph is the adapter
            button three icons above, and this strip has shipped two identical
            icons once already. */}
        <button
          onClick={onOpenNetwork}
          aria-label="Network"
          title="Network - adapters, DNS and this machine's public identity"
          aria-pressed={networkOpen}
          className={railButton(networkOpen, 'view')}
        >
          <Network className={GLYPH} />
        </button>

        {/* **Find packet was here and is deleted.**

            A substring match over the rows already in hand, with a popover, a
            stored query and a dot on this button to say the list was quietly
            short of rows. What replaced it is not a smaller version of it: the
            Frame Detail view's go-to box takes a frame NUMBER and nothing else.

            Those are different features and the swap is a real reduction, said
            plainly rather than sold as an upgrade. What is gone is searching by
            protocol, address or info text over the buffer. What is left is the
            display filter, which answers the same questions in a language that
            says what it means (`ip.addr == 10.0.0.1`, `http.host contains
            "cdn"`) and - unlike the search - is compiled and answered over the
            WHOLE capture on disk rather than the rows the window happens to
            hold. The search was the weaker of the two overlapping answers, and
            two search boxes in one window is the thing the rail was built to
            stop. */}
      </div>

      <RailDivider />

      {/* The tour's "everything else lives here" step used to point at the
          hamburger. It points here now - the rail IS the answer to that
          sentence. `scripts/accessibility/tour.ts` asserts both directions, so
          deleting the old anchor without moving the step fails the suite rather
          than leaving a step pointing at nothing. */}
      <div className={GROUP} role="group" aria-label="Views" data-tour="rail">
        {APP_VIEWS.map(({ id, label, shortcut }) => {
          const Icon = VIEW_ICONS[id];
          const active = view === id;
          // Follow Stream needs something to follow. Disabled rather than
          // hidden: a group that changes length moves the divider and the
          // group below it every time a stream is opened or cleared.
          //
          // `streamAvailable` is now about the SELECTION - does the selected
          // frame sit on a stream - rather than about a stream already being
          // open, which is what it used to mean and what made this button read
          // as a place rather than a verb. `App` holds the rule; see
          // `handleViewChange` there for the three symptoms that came of the
          // old one.
          const unavailable = id === 'stream' && !streamAvailable;
          return (
            <button
              key={id}
              onClick={() => onViewChange(id)}
              disabled={unavailable}
              aria-pressed={active}
              aria-label={label}
              title={unavailable
                ? `${label} - select a frame on a TCP or UDP stream first`
                : `${label} (${shortcut})`}
              className={`${railButton(active, 'view')} ${
                unavailable ? 'opacity-40 cursor-not-allowed' : ''
              }`}
            >
              {/* **The 2px accent edge was here and is deleted.** It was a
                  child rather than a border so it did not change the button's
                  box, and it was the stronger half of a two-part marker - VS
                  Code's "you are here" rule, an edge plus a `--accent` fill.
                  The fill is the theme's own accent now and carries the state on
                  its own; an edge in the same colour, against a button already
                  filled with it, is a second mark for one fact. */}
              <Icon className={GLYPH} />
            </button>
          );
        })}
      </div>
      {/* **The widgets group was here, and so was the dock's collapse control.**
          Six icons switching panels in a column, plus a 20px group header in
          this divider's slot that hid and showed the column - the only way back
          from a hidden dock, since every widget icon opened an overlay there.

          All of it went with the dock. What the three surviving widgets became:
          the map is a view in the group above, and the traffic timeline and the
          packet-size chart are a tab of the Statistics pane. None of them needed
          an open flag, a pin, a drag-reorder or an overlay.

          The 20px header is worth one line of its own, because it was an
          arithmetic workaround that outlived the arithmetic: at 630px against
          640 there was no room for a thirteenth 36px icon, so the control went
          into a divider slot for 15px instead. The rail has room now, and there
          is nothing left for it to collapse. */}


      {/* Pinned to the bottom, where every app in the reference class keeps its
          settings. `mt-auto` rather than absolute positioning so the groups
          above can grow without overlapping it. */}
      <div className={`${GROUP} mt-auto pb-2`} role="group" aria-label="Application">
        <RailDivider />
        {/* **A toggle now, and marked like a view.** Settings was a modal
            with an X and a Close button; it is a pane taking the workspace
            card, so the rail has to say it is on screen and pressing this again
            has to put it away. `'view'` rather than `'toggle'` for the marker:
            the fill means "this is what you are looking at", which is exactly
            what it means here, and the outline means "this control is on",
            which Settings is not. */}
        <button
          onClick={onOpenSettings}
          aria-label="Settings"
          title="Settings"
          aria-pressed={settingsOpen}
          className={railButton(settingsOpen, 'view')}
        >
          <Settings className={GLYPH} />
        </button>
      </div>
    </div>
  );
};

/**
 * The adapter icon, with its warning badge.
 *
 * Tint **and** shape. The label this control used to carry is gone - it is a
 * 32px icon now - and a tint on its own is the one signal a colour-blind user
 * cannot read, so the badge is the signal and the colour reinforces it. The full
 * sentence is in the accessible name, the tooltip and the popover this opens.
 */
const AdapterGlyph: React.FC<{ attention: boolean }> = ({ attention }) => (
  <>
    <EthernetPort className={`${GLYPH} ${attention ? 'text-warning' : ''}`} />
    {attention && (
      <TriangleAlert
        aria-hidden
        className="absolute -right-0.5 -bottom-0.5 w-3 h-3 text-warning fill-secondary"
      />
    )}
  </>
);
