import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  TbPlayerPlay,
  TbPlayerStop,
  TbAlertTriangle,
  TbNetwork,
} from 'react-icons/tb';
import { Capabilities } from '../../types/packet';
import { AppMenu } from './AppMenu';
import { BrandMark } from './BrandMark';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';
import { headerButtonClass } from './headerButton';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import type { NameResolutionPrefs } from '../../services/interfacePrefs';

interface HeaderProps {
  isCapturing: boolean;
  /** Starts capturing on whatever adapter is currently selected. The Start
   *  button is disabled until one is, so this never begins a capture with
   *  no adapter named. */
  onStartCapture: () => void;
  /** Stops the capture and tells the agent to stop sniffing. */
  onPauseCapture: () => void;
  onClearPackets: () => void;
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  onSelectInterface: (interfaceName: string) => void;
  /** Recent packets/sec per interface name, for the picker's sparklines. */
  interfaceRates?: Record<string, number[]>;
  /**
   * True when the agent is capturing for a different Inwire window.
   *
   * The capture belongs to whoever started it, so this window can neither stop
   * it nor move it to another adapter - and the controls say so rather than
   * offering buttons whose only outcome would be an error. This window is not
   * receiving those packets either, which is why the row cannot simply show
   * "capturing".
   */
  captureOwnedElsewhere?: boolean;
  onInterfacePickerOpenChange?: (open: boolean) => void;
  permissions: Capabilities;
  onOpenDissectorModal: () => void;
  onOpenExportModal: () => void;
  onOpenStatisticsModal: () => void;
  onOpenNetworkModal?: () => void;
  /** The View -> Name Resolution switches, shown in the menu. */
  nameResolution: NameResolutionPrefs;
  onNameResolutionChange: (patch: Partial<NameResolutionPrefs>) => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  /** Whether the app is meant to be holding a link at all - see App.tsx. This
   *  is the difference between "the driver is not there" and "you closed the
   *  link", which agentStatus reports as the same 'disconnected'. */
  agentLinkEnabled: boolean;
  agentOutdated: boolean;
  /** The display-filter controls, rendered inline in this bar rather than in
   *  a row of their own. Passed in rather than imported so the header stays
   *  a layout component with no opinion about what the filter UI is. */
  filterSlot: React.ReactNode;
  onOpenSettingsModal: () => void;
  totalPacketsCount: number;
  /** Set while a stored session is being decoded back in; null otherwise. */
  restoreProgress?: { done: number; total: number } | null;
  filteredPacketsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  isCapturing,
  onStartCapture,
  onPauseCapture,
  onClearPackets,
  agentInterfaces,
  selectedInterfaces,
  onSelectInterface,
  interfaceRates,
  captureOwnedElsewhere = false,
  onInterfacePickerOpenChange,
  permissions,
  onOpenDissectorModal,
  onOpenExportModal,
  onOpenStatisticsModal,
  onOpenNetworkModal,
  nameResolution,
  onNameResolutionChange,
  agentStatus,
  agentLinkEnabled,
  agentOutdated,
  filterSlot,
  onOpenSettingsModal,
  totalPacketsCount,
  restoreProgress,
  filteredPacketsCount,
}) => {
  const selectedInterface = agentInterfaces.find((i) => i.name === selectedInterfaces[0]) ?? null;

  // The Interfaces button carries the whole adapter story in one control:
  // red when there is nothing to capture from, amber when adapters exist but
  // none is chosen yet, green once one is. Colour and label are derived
  // together here so a state can never show one without the other.
  //
  // Red means a settled answer, not "haven't heard yet". While the socket is
  // still opening the interface list is legitimately empty, and flashing a
  // failure during every page load would cry wolf on the one state that should
  // mean something is actually wrong.
  const adapterStateKnown = agentStatus !== 'connecting';

  // The two ways of having no interfaces are different problems with different
  // answers, and reporting both as "No interfaces detected" told the largest
  // group of people the least useful thing.
  //
  // No socket at all means the driver is not on this machine - it ships as a
  // service that is installed once and then always running, so a first-run user
  // sees exactly this, and what they need is the installer. Adapters missing
  // while the socket is up is a different failure (Npcap broken, no
  // permissions) that the installer would not fix.
  //
  // Gated on agentLinkEnabled as well, because a link the user closed
  // themselves reports the same 'disconnected' - and telling someone to install
  // software they just disconnected from would be the app calling them wrong.
  const driverMissing = agentInterfaces.length === 0
    && adapterStateKnown
    && agentLinkEnabled
    && (agentStatus === 'disconnected' || agentStatus === 'error');

  /**
   * Whether the "this will discard what you captured" prompt is showing.
   *
   * Local to the header. Nothing else needs to know a question is being asked,
   * and App already has more state than it can hold.
   */
  const [confirmRestart, setConfirmRestart] = React.useState(false);
  const confirmRef = React.useRef<HTMLDivElement | null>(null);

  // A capture that STARTS while the prompt is up, or a buffer that empties from
  // somewhere else, has answered the question by other means.
  React.useEffect(() => {
    if (isCapturing || totalPacketsCount === 0) setConfirmRestart(false);
  }, [isCapturing, totalPacketsCount]);

  React.useEffect(() => {
    if (!confirmRestart) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setConfirmRestart(false);
    };
    const onDown = (e: PointerEvent) => {
      if (!confirmRef.current?.contains(e.target as Node)) setConfirmRestart(false);
    };
    window.addEventListener('keydown', onKey);
    // Capture phase, so a click on some other control cancels the prompt
    // rather than being swallowed by it.
    window.addEventListener('pointerdown', onDown, true);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('pointerdown', onDown, true);
    };
  }, [confirmRestart]);

  /**
   * A stopped capture cannot be resumed, so starting again means discarding.
   *
   * The reference analyzer's model, and it is not arbitrary: a buffer that was appended to
   * across two separate capture runs has a gap in the middle that nothing in
   * the file records. Relative timestamps, the sequence trackers and the
   * timeline all measure from one capture's start, and none of them can express
   * "and then some unknown amount of the network went unobserved". Making the
   * discard explicit is what keeps every buffer a single continuous recording.
   */
  const restartDiscards = !isCapturing && totalPacketsCount > 0;
  const startBlocked = !permissions.canCapture || !selectedInterface || captureOwnedElsewhere;
  const captureBlocked = captureOwnedElsewhere
    || (!isCapturing && (startBlocked || (restartDiscards && !permissions.canClearBuffer)));

  const startFresh = () => {
    setConfirmRestart(false);
    // Clear first. Both are synchronous, so by the time the agent is told to
    // start there is no buffer left for its packets to be appended to.
    onClearPackets();
    onStartCapture();
  };

  const interfaceButton = agentInterfaces.length === 0
    ? adapterStateKnown
      ? driverMissing
        ? {
            label: 'Install Drivers',
            title: 'The capture driver is not running on this machine. Install it from Menu > Download Driver, then it starts on its own.',
          }
        : {
            label: 'No interfaces detected',
            title: 'The driver is running but reported no capture interfaces. Check that Npcap is installed.',
          }
      : {
          label: 'Interfaces',
          title: 'Waiting for the driver to report its capture interfaces...',
        }
    : selectedInterface === null
      ? {
          label: 'Interfaces',
          title: 'Choose which adapter to capture from',
        }
      : {
          label: shortInterfaceLabel(selectedInterface.label),
          title: selectedInterface.label,
        };

  const interfaceButtonClass = `${headerButtonClass} max-w-[14rem]`;

  // The bar is `--chrome` in every theme.
  //
  // It used to be the accent in light mode and the card colour in dark, written
  // as a `dark:` twin on a dozen classNames across three files. `--chrome` is
  // what replaced that: the accent as each ground can carry it, deepened on the
  // dark themes so a 64px bar plus a 320px drawer is not more saturated area
  // than the packet list beside it. Every twin below went with it.
  return (
    <header className="h-16 px-4 sm:px-6 border-b flex items-center gap-4 transition-colors z-40 shrink-0 bg-chrome border-chrome-foreground/15 text-chrome-foreground">
      {/* Left: App Menu, Branding & Capture Stream Controls. select-none is
          scoped to this cluster rather than the whole bar now - the filter
          controls that share the row contain an editable input. */}
      <div className="flex items-center space-x-3 sm:space-x-4 select-none shrink-0">
        {/* App Menu - Actions, Views, Filter Presets (Ctrl/Cmd+K). Leads the
            header the way GitHub's own hamburger leads its header, ahead of
            the logo rather than trailing every other control. */}
        <AppMenu
          onOpenDissectorModal={onOpenDissectorModal}
          onOpenExportModal={onOpenExportModal}
          onOpenStatisticsModal={onOpenStatisticsModal}
          onOpenNetworkModal={onOpenNetworkModal}
          nameResolution={nameResolution}
          onNameResolutionChange={onNameResolutionChange}
          onOpenSettingsModal={onOpenSettingsModal}
          agentOutdated={agentOutdated}
        />

        {/* The lockup: mark, then the wordmark, on one line.

            The colour is set once, here, and both children take it through
            `currentColor` - so the mark and the word cannot drift apart into
            two values that have to be kept in step by hand.

            `--chrome-brand`, not `--chrome-foreground` and not a `dark:`
            variant. On the two light themes it resolves to the foreground,
            white. On the two dark ones it drops to the surface tone below the
            bar, so the lockup reads as pressed into the chrome rather than
            sitting on top of it - a deliberately low-contrast treatment, about
            2:1, legitimate for a logo and not for body text.

            It has to be a token because the Colourful setting moves it: with
            the accent bar off, that same surface tone would sit on a `--card`
            ground and the lockup would all but disappear. index.css owns both
            values; this only has to name the right one.

            The face is the mono, not the rounded sans: flat terminals and
            square joins, and its true italic rather than a synthesised
            slant. */}
        <div className="hidden xl:flex items-center gap-2.5 text-chrome-brand">
          <BrandMark className="w-9 h-9 shrink-0" />
          <span className="font-mono font-extrabold italic text-lg leading-none tracking-tight">
            INWIRE
          </span>
        </div>

        {/* Capture Buttons */}
        <div className="flex items-center space-x-2">
          {/* Sits ahead of Start Capture because it gates it: with no adapter
              chosen there is nothing to start. */}
          {agentInterfaces.length === 0 ? (
            // Both red states are dead ends by design: there is no adapter
            // list to open, and a button that opens an empty menu reads as
            // broken rather than as blocked. The tooltip carries the way out.
            <button
              disabled
              data-tour="interfaces"
              className={`${interfaceButtonClass} cursor-not-allowed`}
              title={interfaceButton.title}
            >
              <TbNetwork className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">{interfaceButton.label}</span>
            </button>
          ) : (
            <CaptureInterfacePicker
              interfaces={agentInterfaces}
              selectedInterface={selectedInterfaces[0] ?? null}
              onSelect={onSelectInterface}
              interfaceRates={interfaceRates}
              onOpenChange={onInterfacePickerOpenChange}
              align="start"
            >
              {/* Both branches carry the anchor: only one is mounted at a
                  time, so the tour finds whichever state the app is in. */}
              <button
                data-tour="interfaces"
                className={`${interfaceButtonClass} active:scale-95 cursor-pointer`}
                title={interfaceButton.title}
              >
                <TbNetwork className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{interfaceButton.label}</span>
              </button>
            </CaptureInterfacePicker>
          )}

          {/* One button, two states, and only the glyph changes.
              It was two buttons whose labels each named the OTHER half of the
              pair - "Start Capture" became "Stop Capture" - so the widest thing
              in the header changed width every time capture started or stopped,
              shoving Clear Cache and the whole filter row sideways. A play/stop
              control is a shape people already read without a word beside it.

              STOP, not pause. It was a pause glyph while the button resumed
              into the same buffer; it does not do that any more, and a pause
              icon on a control that cannot be un-paused is the icon promising
              something the app will not do.

              This is also the Clear Cache button now. The two were never
              independent - a second capture run always meant discarding the
              first - so they were one decision presented as two controls, one
              of which quietly changed what the other would do.

              The two glyphs cross-fade in place rather than swapping on the
              frame: at this size a hard cut reads as a flicker, and there is
              nothing else on screen confirming that the click landed. The name
              lives in aria-label and the title, so nothing is lost for a screen
              reader or for a hover. */}
          <div className="relative" ref={confirmRef}>
            <button
              data-tour="start"
              // onPauseCapture already sends stop_capture. Sending it again here
              // is what put every stop in the agent log twice.
              onClick={
                isCapturing
                  ? onPauseCapture
                  : restartDiscards
                    ? () => setConfirmRestart((open) => !open)
                    : onStartCapture
              }
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
                      ? `Start a new capture - discards the ${totalPacketsCount.toLocaleString()} packets in the buffer`
                      : 'Start Live Packet Capture'
              }
              className={`${headerButtonClass} active:scale-95 cursor-pointer px-3 sm:px-3.5 ${
                captureBlocked ? 'opacity-50 cursor-not-allowed' : ''
              }`}
            >
              {/* 16px, not the 14px of the glyphs it holds. This is a block
                  box in a flex row, so it sets the button's content height
                  directly where the other two buttons get theirs from a 16px
                  text line box - and at 14 this button stood two pixels
                  shorter than the pair beside it. The glyphs stay 14 and
                  centre themselves in it. */}
              <span className="relative block w-4 h-4">
                {/* Both glyphs occupy the same box, absolutely, so the button's
                    width never depends on which one is showing. `initial={false}`
                    stops the icon animating itself in on first paint. */}
                <AnimatePresence initial={false}>
                  <motion.span
                    key={isCapturing ? 'stop' : 'play'}
                    initial={{ opacity: 0, scale: 0.55 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.55 }}
                    transition={{ duration: 0.18, ease: 'easeOut' }}
                    className="absolute inset-0 flex items-center justify-center"
                  >
                    {isCapturing ? (
                      <TbPlayerStop className="w-3.5 h-3.5 fill-current" />
                    ) : (
                      <TbPlayerPlay className="w-3.5 h-3.5 fill-current" />
                    )}
                  </motion.span>
                </AnimatePresence>
              </span>
            </button>

            {/* Anchored under the button rather than centred over the app.
                The prompt is about one control and names a number the user can
                see on the same screen; a modal would darken the packet list
                they are being asked to decide the fate of.

                Card colours, not the bar's: it hangs below the header, over the
                app's own ground. */}
            <AnimatePresence>
              {confirmRestart && (
                <motion.div
                  role="dialog"
                  aria-label="Discard the current capture?"
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.14, ease: 'easeOut' }}
                  className="absolute left-0 top-full mt-2 z-50 w-72 rounded-lg border p-3 shadow-2xl bg-popover border-border text-popover-foreground"
                >
                  <div className="flex items-start gap-2">
                    <TbAlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-warning" />
                    <div className="text-[11px] leading-relaxed text-muted-foreground">
                      <span className="font-bold text-foreground">
                        Discard {totalPacketsCount.toLocaleString()} captured packets?
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
                      className="px-2.5 py-1 rounded bg-secondary hover:bg-accent text-foreground text-[11px] font-medium transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      autoFocus
                      onClick={startFresh}
                      className="px-2.5 py-1 rounded bg-danger hover:bg-danger/90 text-danger-foreground text-[11px] font-bold transition-colors cursor-pointer"
                    >
                      Discard and start
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* A "Halt" button used to sit here beside Stop Capture. It was not a
              second, harder stop: App.tsx passed the same handler to both
              onPauseCapture and onStopCapture, so the two buttons ran identical
              code and differed only in styling. */}

          {/* Restoring a full 50,000-packet buffer is a few seconds of
              dissection. Saying so - with a count that visibly climbs - is the
              difference between "it is working" and a list that appears to be
              filling itself for no reason. */}
          {restoreProgress && (
            <span
              className="flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-chrome-foreground whitespace-nowrap"
              title="Restoring the capture from your previous session"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-chrome-foreground animate-pulse" />
              <span>
                Restoring {restoreProgress.done.toLocaleString()}/{restoreProgress.total.toLocaleString()}
              </span>
            </span>
          )}

          {/* Clear Cache stood here. It is the same action as starting a new
              capture, so it is now the same button - and it is still available
              on its own in Settings > Driver Info, for emptying a buffer
              without starting anything. */}

          {/* The agent's own `state` message is the only source of truth for
              whether it's actually sniffing - isCapturing is just local
              intent, which can go stale (a pre-auth click, a command sent
              while the socket was closed, another tab stopping capture).
              Matches the amber styling of the Agent Outdated pill rather
              than inventing a new visual language for "something's off". */}
          {/* An amber "Agent Idle" pill used to appear here whenever local
              intent said capturing but the agent's last `state` said idle.
              That is true for a moment after every single Start Capture -
              isCapturing flips immediately, the agent's reply arrives a beat
              later - so it fired on the normal path far more often than on the
              fault it was meant to catch. The agent's real capture state is
              still reported, unambiguously, in Settings > Driver Info. */}
        </div>
      </div>

      {/* The display-filter controls, formerly a row of their own directly
          below this one. Agent connection state used to sit here as a pill;
          it is gone because the Interfaces button already carries it - red
          and "No interfaces detected" is what an unreachable agent looks
          like - and Settings > Driver Info has the full detail. */}
      {filterSlot}
    </header>
  );
};
