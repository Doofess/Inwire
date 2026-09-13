import React from 'react';
import {
  TbPlayerPlay,
  TbPlayerStop,
  TbNetwork,
  TbAlertTriangle,
  TbListDetails,
  TbChartHistogram,
  TbSitemap,
  TbArrowsLeftRight,
  TbSettings,
  TbFileExport,
  TbCode,
} from 'react-icons/tb';
import type { AgentHealth } from '../../services/agentHealth';
import { agentNeedsAttention, agentSilentLabel } from '../../services/agentHealth';
import { BrandMark } from './BrandMark';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import { WIDGET_RENDERERS } from '../analytics/dashboardWidgets';
import { WIDGET_TYPE_IDS, widgetTitle, type WidgetInstance, type WidgetTypeId } from '../../services/dashboardPrefs';
import type { Capabilities } from '../../types/packet';
import { APP_VIEWS, type AppView } from '../../services/viewPrefs';

/**
 * The one strip of chrome that is always there.
 *
 * Four groups, and the grouping is the only thing saying that two of them
 * behave differently: the views are a radio - one active at a time, switching
 * what fills the window - and the widgets are checkboxes, each contributing a
 * panel to the dock. A divider alone does not convey that, and no app in the
 * reference class mixes the two in one rail (VS Code's activity bar is purely
 * view-switching; its panel toggles are elsewhere). So the active states are
 * deliberately different shapes:
 *
 *  - a view carries a **2px left accent edge and a filled background** - VS
 *    Code's "you are here" marker, which people already read;
 *  - a widget carries a **dot and an outline only**.
 *
 * Neither appears on hover. The edge is the strongest indicator in the UI, and
 * firing it on hover flashes it four times as a pointer crosses the rail, with a
 * moment where two items read as active.
 *
 * ## Why 56px when everything else is 48
 *
 * `DASHBOARD_RAIL_WIDTH` and `FrameMetaRail` are both 48, and index.css's own
 * comment says two icon strips that disagree by a few pixels is "something you
 * only notice when they are on screen together". This one is 56 anyway, as a
 * deliberate and accepted choice: it carries four groups rather than one, and at
 * 48 a 20px glyph has 14px of air around it. A future session should not "fix"
 * the disagreement by narrowing it.
 *
 * ## Height
 *
 * 14 icons, 36px targets, four dividers and a 40px top cell come to **617px**
 * against a 640px minimum window height. It fits, with 23px of slack - which is
 * **not** another icon. The rail is full.
 *
 * That number is added up from these classes by `scripts/session/view.ts`, which
 * also holds each class to what the sum assumes. This comment said 549 until that
 * script was written: the figure was for `my-1` dividers, it counted three rather
 * than the four actually rendered, and it ignored the capture group's `pt-1` and
 * the bottom group's `pb-2`. A height budget nothing checks is a height budget
 * that has already drifted.
 *
 * So if a sixth widget ever arrives, **the widgets group is the one that
 * scrolls** - capture, the views and the bottom group have to stay reachable
 * without one, and the bottom group is pinned with `mt-auto`, so an overflow
 * does not scroll anything: it pushes Settings off the bottom edge.
 *
 * The last slot went to Custom Dissectors when the hamburger menu was deleted.
 * Of that menu's seven entries, three already had a rail button - Capture
 * Statistics, Network and Settings - Export/Import and Custom Dissectors became
 * the two here, and the two name-resolution switches went to
 * Settings -> Interface, beside the two outbound lookups that were already
 * there. That last pair came here first and did not fit: four icons in this
 * group is 693px, 53px past the smallest window this app opens at.
 */

/** 32px was the old rail's target in a 48px strip; 36 is this one's in 56. */
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
  // `border` on `card` is a small delta on the dark themes - measured on
  // Graphite it is #292524 on #1c1917 - and at 1px by 24px the line was very
  // nearly invisible, which left the grouping carried by the active states
  // alone. Wider, and `muted-foreground` at low opacity so it reads on all four
  // grounds rather than on the two light ones.
  <div aria-hidden className="my-1.5 h-px w-7 shrink-0 bg-muted-foreground/30" />
);

/** The shared button shape. `active` styling is supplied per group. */
function railButton(active: boolean, kind: 'view' | 'toggle'): string {
  const base = `relative ${TARGET} flex items-center justify-center rounded-md `
    + 'transition-colors cursor-pointer shrink-0 app-no-drag '
    + 'focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring';
  if (!active) return `${base} text-muted-foreground hover:bg-accent hover:text-foreground`;
  return kind === 'view'
    // The filled state plus the accent edge, drawn by the caller's ::before.
    ? `${base} bg-accent text-foreground`
    // Outline only: a widget is on, not "where you are".
    : `${base} text-foreground ring-1 ring-inset ring-border`;
}

const VIEW_ICONS: Record<AppView, React.ComponentType<{ className?: string }>> = {
  packets: TbListDetails,
  statistics: TbChartHistogram,
  network: TbSitemap,
  stream: TbArrowsLeftRight,
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

  /* --- views ------------------------------------------------------------ */
  view: AppView;
  onViewChange: (view: AppView) => void;
  /** Follow Stream is disabled until something is being followed. */
  streamAvailable: boolean;

  /* --- widgets ---------------------------------------------------------- */
  /** The dock's list: every type, each with whether it is open. */
  dockItems: { type: WidgetTypeId; open: boolean }[];
  onToggleWidget: (type: WidgetTypeId) => void;
  /** `inwire.dashboard`, for the custom titles the tooltips show. */
  widgets: WidgetInstance[];

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
  /**
   * Custom Dissectors, which took the rail's last free slot.
   *
   * With this the rail is 617px against a 640px minimum window - 23px of slack,
   * which is not another icon. Anything else that needs a permanent home has to
   * go to Settings or make the widgets group scroll; `scripts/session/view.ts`
   * is where that stops being a matter of opinion.
   */
  onOpenDissectors: () => void;
}

export const ActivityRail: React.FC<ActivityRailProps> = ({
  isCapturing, onStartCapture, onStopCapture, onClearPackets,
  bufferedPackets, permissions, agentInterfaces, selectedInterfaces, onSelectInterface,
  interfaceRates, onInterfacePickerOpenChange, captureOwnedElsewhere, agentHealth,
  view, onViewChange, streamAvailable,
  dockItems, widgets, onToggleWidget,
  onOpenSettings, onOpenExport, onOpenDissectors,
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

  const enabled = new Set(dockItems.filter((i) => i.open).map((i) => i.type));
  const byType = new Map(widgets.map((w) => [w.type, w] as const));

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
      className="w-14 shrink-0 flex flex-col items-center border-r border-border bg-card
        text-card-foreground select-none"
    >
      {/* Aligned to the title row so the mark sits level with the window title,
          and part of the drag region: the rail is otherwise entirely no-drag,
          but a window needs somewhere to be grabbed on the left. */}
      <div className="h-10 w-full shrink-0 flex items-center justify-center app-drag">
        {/* The real mark, not a `TbNetwork`. The first version of this used that
            glyph and put it 42px above the adapter button, which uses the SAME
            glyph - two near-identical icons at the top of the strip, one of
            which is a logo and one a control. Caught by looking at it; no
            assertion would have. The wordmark it used to sit beside needed
            1280px of window to appear at all, and there is no room for it here.

            `text-chrome-brand` follows the Colourful setting, which is what the
            old lockup did and the one place in the new chrome that still reads
            that token. */}
        <BrandMark className="w-6 h-6 text-chrome-brand" title="Inwire" />
      </div>

      <div className={`${GROUP} pt-1`} role="group" aria-label="Capture">
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
              ? <TbPlayerStop className={`${GLYPH} fill-current text-danger`} />
              : <TbPlayerPlay className={GLYPH} />}
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
                <TbAlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-warning" />
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
          // widgets below it every time a stream is opened or cleared.
          const unavailable = id === 'stream' && !streamAvailable;
          return (
            <button
              key={id}
              onClick={() => onViewChange(id)}
              disabled={unavailable}
              aria-pressed={active}
              aria-label={label}
              title={unavailable
                ? `${label} - follow a stream from a packet's context menu first`
                : `${label} (${shortcut})`}
              className={`${railButton(active, 'view')} ${
                unavailable ? 'opacity-40 cursor-not-allowed' : ''
              }`}
            >
              {/* The 2px edge. A child rather than a border so it does not
                  change the button's box, and only on the active one. */}
              {active && (
                <span
                  aria-hidden
                  className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full bg-primary"
                />
              )}
              <Icon className={GLYPH} />
            </button>
          );
        })}
      </div>

      <RailDivider />

      <div className={GROUP} role="group" aria-label="Widgets">
        {WIDGET_TYPE_IDS.map((type) => {
          const Icon = WIDGET_RENDERERS[type].icon;
          const on = enabled.has(type);
          const instance = byType.get(type);
          const label = instance ? widgetTitle(instance) : type;
          return (
            <button
              key={type}
              onClick={() => onToggleWidget(type)}
              aria-pressed={on}
              aria-label={label}
              title={on ? `Hide ${label}` : `Show ${label}`}
              className={railButton(on, 'toggle')}
            >
              {/* The dot, not an edge: many can be on at once, so this says
                  "showing" rather than "you are here". */}
              {on && (
                <span
                  aria-hidden
                  className="absolute right-1 top-1 w-1.5 h-1.5 rounded-full bg-primary"
                />
              )}
              <Icon className={GLYPH} />
            </button>
          );
        })}
      </div>

      {/* Pinned to the bottom, where every app in the reference class keeps its
          settings. `mt-auto` rather than absolute positioning so the groups
          above can grow without overlapping it. */}
      <div className={`${GROUP} mt-auto pb-2`} role="group" aria-label="Application">
        <RailDivider />
        {/* `TbFileExport` rather than the menu's `TbDownload`, and deliberately
            not `TbArrowsExchange`: an exchange glyph would sit five icons below
            Follow Stream's `TbArrowsLeftRight` and read as the same control
            twice. That mistake has been made in this strip once already - the
            brand mark opened as a `TbNetwork`, identical to the adapter button
            42px under it, and only a screenshot found it. */}
        <button
          onClick={onOpenExport}
          aria-label="Export or import a capture"
          title="Export / Import PCAP"
          className={railButton(false, 'toggle')}
        >
          <TbFileExport className={GLYPH} />
        </button>
        {/* `TbCode` - the angle brackets - rather than another file glyph: it
            sits directly under `TbFileExport` and two file icons in a row read
            as one control with a modifier. */}
        <button
          onClick={onOpenDissectors}
          aria-label="Custom dissectors"
          title="Custom Dissectors"
          className={railButton(false, 'toggle')}
        >
          <TbCode className={GLYPH} />
        </button>
        <button
          onClick={onOpenSettings}
          aria-label="Settings"
          title="Settings"
          className={railButton(false, 'toggle')}
        >
          <TbSettings className={GLYPH} />
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
    <TbNetwork className={`${GLYPH} ${attention ? 'text-warning' : ''}`} />
    {attention && (
      <TbAlertTriangle
        aria-hidden
        className="absolute -right-0.5 -bottom-0.5 w-3 h-3 text-warning fill-card"
      />
    )}
  </>
);
