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
} from 'lucide-react';
import type { AgentHealth } from '../../services/agentHealth';
import { agentNeedsAttention, agentSilentLabel } from '../../services/agentHealth';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';
import { CaptureSchedulePicker } from './CaptureSchedulePicker';
import { isScheduleEmpty, type CaptureSchedule, type SchedulePreset } from '../../services/captureSchedule';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import type { Capabilities } from '../../types/packet';
import { APP_VIEWS, type AppView } from '../../services/viewPrefs';

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
 * **A border on all four sides, and the facing one is the seam.** `<main>` sits
 * flush against this card's right edge and gives up its own `border-l`, so the
 * single hairline between them is drawn HERE. VS Code's reason is the one that
 * applies: the rail has to draw it, or its visible interior runs past its own
 * edge to the neighbour's border and the icon column ends up on a half pixel.
 * At `w-11` with `border-box` that is exact - 44 less two 1px borders is 42, an
 * even interior for a 36px target. Give the border away and it is 43.
 *
 * **Rounded on the window side, square on the neighbour's**: `rounded-l-lg`,
 * 8px, which is `--vscode-cornerRadius-large`. The right corners stay square so
 * the rail and the workspace read as one connected surface rather than two
 * cards with a gap painted between them.
 *
 * **The radius is legal because the card no longer touches the window.** The
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
 * 10 icons at 36px, two dividers and the bottom group's padding come to
 * **414px** against the 618px the rail gets - a 680px minimum window, less the
 * 32px title row above it, the 24px status bar below, the cluster's 4px bottom
 * gutter, and this card's own two 1px borders. It fits, with 204px of slack -
 * room for five more.
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
 * Settings tab next to Driver Info. That is two icons back. Every digit below it
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
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  onSelectInterface: (name: string) => void;
  interfaceRates?: Record<string, number[]>;
  onInterfacePickerOpenChange?: (open: boolean) => void;
  captureOwnedElsewhere?: boolean;
  agentHealth: AgentHealth;
  /**
   * The capture schedule, which moved here from the filter row.
   *
   * It is a capture control - it decides when one starts and when it stops - so
   * it sits with Start/Stop and the adapter rather than above the packet list.
   */
  schedule: CaptureSchedule;
  onScheduleChange: (next: CaptureSchedule) => void;
  schedulePresets: SchedulePreset[];
  onSchedulePresetsChange: (next: SchedulePreset[]) => void;
  /** "Stops in 14:58". The tooltip, now that there is no room for a label. */
  scheduleSummary: string;
  /** The schedule hook's clock, so "already passed" updates without a timer. */
  scheduleNow: number;

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
  onOpenSettings: () => void;
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
  bufferedPackets, permissions, agentInterfaces, selectedInterfaces, onSelectInterface,
  interfaceRates, onInterfacePickerOpenChange, captureOwnedElsewhere, agentHealth,
  view, onViewChange, streamAvailable,
  onOpenSettings, onOpenExport,
  schedule, onScheduleChange, schedulePresets, onSchedulePresetsChange,
  scheduleSummary, scheduleNow,
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
    ? agentSilentLabel(agentHealth)
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
   * `stopPropagation` is the load-bearing half. `useKeyboardNavigation` listens
   * on `window` for ArrowUp/ArrowDown and moves the packet selection, guarded
   * only against `[role="grid"]` - so without this an arrow press in the rail
   * would move focus here AND step the selected packet. The old dashboard rail
   * called `preventDefault` alone and has had that bug the whole time.
   */
  const onRailKeyDown = (e: React.KeyboardEvent<HTMLDivElement>): void => {
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown' && e.key !== 'Home' && e.key !== 'End') {
      return;
    }
    const buttons = [...e.currentTarget.querySelectorAll<HTMLButtonElement>(
      'button:not([disabled])',
    )];
    if (buttons.length === 0) return;
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    e.preventDefault();
    e.stopPropagation();
    const next = e.key === 'Home'
      ? 0
      : e.key === 'End'
        ? buttons.length - 1
        : at < 0
          ? 0
          : (at + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next]?.focus();
  };

  return (
    <div
      role="toolbar"
      aria-orientation="vertical"
      aria-label="Activity"
      onKeyDown={onRailKeyDown}
      className="w-11 shrink-0 flex flex-col items-center bg-secondary
        text-secondary-foreground select-none
        border border-border rounded-l-lg"
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

        {agentInterfaces.length === 0 ? (
          // A dead end by design: there is no adapter list to open, and a button
          // that opens an empty menu reads as broken rather than as blocked.
          <button
            disabled
            data-tour="interfaces"
            aria-label={adapterName}
            title={adapterTitle}
            className={`${railButton(false, 'toggle')} cursor-not-allowed opacity-60`}
          >
            <AdapterGlyph attention={attention} />
          </button>
        ) : (
          <CaptureInterfacePicker
            interfaces={agentInterfaces}
            selectedInterface={selectedInterfaces[0] ?? null}
            onSelect={onSelectInterface}
            interfaceRates={interfaceRates}
            onOpenChange={onInterfacePickerOpenChange}
            align="start"
            side="right"
          >
            <button
              data-tour="interfaces"
              aria-label={adapterName}
              title={adapterTitle}
              className={railButton(selected !== null, 'toggle')}
            >
              <AdapterGlyph attention={attention} />
            </button>
          </CaptureInterfacePicker>
        )}

        {/* The schedule picker, which was a labelled button in the filter row.

            It is a capture control - it decides when a capture starts and when
            it stops - so it belongs with Start/Stop and the adapter rather than
            above the packet list. What it loses in the move is its summary
            text: the row had 12rem for "Stops in 14:58", and a 56px strip has
            none. The summary is the tooltip and the popover's own heading now,
            and the glyph carries a dot when a schedule is set, because a clock
            that looks identical whether or not anything is scheduled is the
            same failure the adapter's health badge exists to avoid. */}
        <CaptureSchedulePicker
          schedule={schedule}
          onScheduleChange={onScheduleChange}
          presets={schedulePresets}
          onPresetsChange={onSchedulePresetsChange}
          bufferedPackets={bufferedPackets}
          now={scheduleNow}
          align="start"
          side="right"
        >
          <button
            data-tour="schedule"
            aria-label={scheduleSet ? `Capture schedule - ${scheduleSummary}` : 'Capture schedule'}
            title={scheduleSet ? scheduleSummary : 'Schedule when this capture starts and stops'}
            className={railButton(false, 'toggle')}
          >
            {scheduleSet && (
              <span
                aria-hidden
                className="absolute right-1 top-1 w-1.5 h-1.5 rounded-full bg-primary"
              />
            )}
            <Clock className={GLYPH} />
          </button>
        </CaptureSchedulePicker>

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
        {/* `FileOutput` rather than the menu's `Download`, and deliberately
            not `ArrowRightLeft`: an exchange glyph would sit five icons below
            Follow Stream's `ArrowLeftRight` and read as the same control
            twice. That mistake has been made in this strip once already - the
            brand mark opened as an `EthernetPort`, identical to the adapter button
            42px under it, and only a screenshot found it. */}
        <button
          onClick={onOpenExport}
          aria-label="Export or import a capture"
          title="Export / Import PCAP"
          className={railButton(false, 'toggle')}
        >
          <FileOutput className={GLYPH} />
        </button>
        <button
          onClick={onOpenSettings}
          aria-label="Settings"
          title="Settings"
          className={railButton(false, 'toggle')}
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
