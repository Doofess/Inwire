import React, { useEffect, useRef } from 'react';
import { Check } from 'lucide-react';
import { Sparkline } from '../common/Sparkline';
import { CopyButton } from '../ui/CopyButton';
import { Empty } from '../network/rows';
import { useRovingFocus } from '../common/useRovingFocus';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import { agentNeedsAttention, agentStatusLabel, type AgentHealth } from '../../services/agentHealth';
import type { AgentAdapter, AgentInterface } from '../../services/agentProtocol';
import type { CaptureOptions, FilterVerdict } from '../../services/captureOptions';
import { CaptureOptionsSection } from './CaptureOptionsSection';

/**
 * The adapters, as a live monitor you also choose from.
 *
 * This was a Radix dropdown hanging off the rail, and the inversion in that
 * first sentence is the whole of what the column buys. A menu could only ever
 * be a **pre-flight comparison**: it was modal, it closed on the click that
 * chose, and its sampling subscription died with it - so the sparklines
 * answered "which of these is busy right now" exactly once and the app forgot.
 *
 * Open beside a running capture, the same thirty samples answer a question the
 * app cannot answer at all today: **is traffic arriving on an adapter I am not
 * capturing on?** That is the mis-picked-adapter failure, it is the commonest
 * way a capture comes back empty, and the one surface that could have shown it
 * was shut by the time it mattered.
 *
 * ## What the menu forbade, and what each constraint left behind
 *
 * **A width known at authoring time.** `MAX_SPARKLINE_WIDTH = 130` was derived
 * from `w-72` *in its own comment*. In a column dragged between 170 and 600
 * that derivation is not stale, it is wrong by construction - there is no
 * authoring-time number left to derive from. Deleted rather than re-tuned, and
 * with it the sqrt easing, which was a second and dishonest encoding of volume:
 * `max={peak}` already says relative volume exactly, in the trace's HEIGHT, and
 * the easing existed precisely so that a tenth of the peak would not look like
 * a tenth. A silent adapter now draws `Sparkline`'s own flat baseline across
 * the full width, which says "nothing here" better than a 26px stub did.
 *
 * **320px of scroll anchored to a button**, so a row got ONE line - which is
 * why it held a truncated name, a chart, and nothing else, and why the driver
 * description went to a `title` attribute. A row is three lines here.
 *
 * **Dismissal on the click that chose**, so the interaction was necessarily
 * one-shot and there was no second thing you could do. The notice at the top
 * is a second thing, and it is a sentence a menu could not have held.
 *
 * ## Two things this panel deliberately does NOT do
 *
 * **It does not repeat the adapter's details.** `NetworkPane` already renders
 * name, description, MAC with vendor, status, link speed and MTU under
 * "Capture adapter", and Network is a **sibling panel in this same column, one
 * rail click away**. Reproducing that here would have the column's own two
 * panels arguing about where an adapter's facts live, which is the failure the
 * deleted hamburger menu is the monument to. The device path is the single
 * exception, and it earns it below.
 *
 * **It does not mark "capturing on this one" separately from "selected".** The
 * selection is fixed for the life of a capture (ADR 0048) - the rows are
 * disabled while one runs, and both agents refuse a `set_interfaces` that
 * arrives mid-capture - so the selection IS what is being captured on, always.
 * A second mark for that would be a second mark for one fact.
 */
export interface CaptureInterfacePanelProps {
  interfaces: AgentInterface[];
  /**
   * The `adapter_config` snapshot, joined `adapter.id === iface.name`.
   *
   * That join is exact rather than a longest-prefix guess on a display name,
   * which is what the protocol carries a device path for. It may be empty -
   * the agent sends nothing when nothing has changed - so a row degrades to
   * its name and its chart rather than dashing facts nobody established.
   */
  adapters: AgentAdapter[];
  /**
   * Every adapter being captured from - one or several. A row is a checkbox:
   * a click adds that adapter to the capture or takes it out.
   */
  selectedInterfaces: string[];
  onToggle: (name: string) => void;
  /** Packets per second, newest last, trimmed to the agent's sample window. */
  interfaceRates?: Record<string, number[]>;
  agentHealth: AgentHealth;
  /**
   * Whether THIS window is capturing, which locks the list: adapters are
   * chosen before Start and cannot change until Stop.
   */
  isCapturing: boolean;
  /** Whether another window owns the capture, which locks the list the same way. */
  captureOwnedElsewhere: boolean;
  onOpenSettings: () => void;
  /**
   * Subscribe or unsubscribe the agent's interface counters.
   *
   * Driven from this component's MOUNT rather than from a flag in `App`, and
   * that is the strongest form the answer takes: the subscription cannot
   * outlive the thing that displays it, by construction rather than by a
   * dependency array somebody can widen later. The side bar mounts exactly one
   * panel and the others do not exist, so "nothing is measured on this machine
   * while nothing is showing it" is a fact about the component tree.
   */
  onSamplingChange: (on: boolean) => void;
  /** The capture filter and snaplen the next capture asks for. */
  captureOptions: CaptureOptions;
  onCaptureOptionsChange: (patch: Partial<CaptureOptions>) => void;
  /** The agent's answer about the filter as typed (`filterVerdict`). */
  filterVerdict: FilterVerdict;
  /** Why the last capture stopped itself, as a sentence, or null. */
  stopNote?: string | null;
}

/** The chart's own row, so the trace spans the column at whatever width it is. */
const CHART = 'w-full h-4 text-muted-foreground group-data-[state=checked]:text-primary';

export const CaptureInterfacePanel: React.FC<CaptureInterfacePanelProps> = ({
  interfaces, adapters, selectedInterfaces, onToggle, interfaceRates,
  agentHealth, isCapturing, captureOwnedElsewhere, onOpenSettings, onSamplingChange,
  captureOptions, onCaptureOptionsChange, filterVerdict, stopNote = null,
}) => {
  /**
   * The ref indirection is load-bearing, not ceremony.
   *
   * `onSamplingChange` is a `useCallback` with an empty dep list in `App`
   * TODAY. The day it gains a dependency, a naked `[onSamplingChange]` dep list
   * below would tear the subscription down and rebuild it on every App render -
   * thirty times a second during a capture, each one a write down the pipe,
   * with no symptom on screen at all.
   */
  const notify = useRef(onSamplingChange);
  useEffect(() => { notify.current = onSamplingChange; });
  useEffect(() => {
    notify.current(true);
    return () => { notify.current(false); };
  }, []);

  const onKeyDown = useRovingFocus('vertical');

  /**
   * One scale for every chart, which is what makes them comparable.
   *
   * Scaling each adapter to its own maximum would make a near-idle interface
   * look as busy as a saturated one - and comparing two adapters is the only
   * reason these charts are here.
   */
  const peakRate = Math.max(
    1,
    ...Object.values(interfaceRates ?? {}).flatMap((series) => series),
  );

  const byId = new Map(adapters.map((a) => [a.id, a]));

  if (agentNeedsAttention(agentHealth)) {
    return (
      <Empty>
        <div className="space-y-2">
          <div className="text-foreground font-medium">{agentStatusLabel(agentHealth)}</div>
          {/* `detail` is on the faulted kinds and not on `connected`, which is
              the union doing its job: this branch is reached only when
              `agentNeedsAttention` is true, and every kind that satisfies it
              carries a sentence somebody can act on. */}
          {'detail' in agentHealth && <div>{agentHealth.detail}</div>}
          {/* The "Start the agent" button is deliberately NOT duplicated here.
              It raises a UAC prompt and it lives in `DriverInfoPanel`; two
              surfaces raising one elevation is how they come to disagree about
              when it is offered. */}
          <button
            type="button"
            onClick={onOpenSettings}
            className="text-primary hover:underline cursor-pointer"
          >
            Settings &gt; Capture Health
          </button>
        </div>
      </Empty>
    );
  }

  if (interfaces.length === 0) {
    return (
      <Empty>
        <div className="space-y-2">
          {/* **The state a fresh install lands in**, and until this panel
              existed its entire signal was a hover tooltip on a disabled rail
              button - because there was no menu to open, so there was nowhere
              for the reason to go. The agent is connected, healthy and
              answering; it has nothing to listen on. */}
          <div className="text-foreground font-medium">The agent has no capture devices</div>
          <div>
            It is connected and answering, so this is the driver rather than the
            link: Npcap is missing, or it was installed without the capture
            service.
          </div>
          <button
            type="button"
            onClick={onOpenSettings}
            className="text-primary hover:underline cursor-pointer"
          >
            Settings &gt; Updates
          </button>
        </div>
      </Empty>
    );
  }

  return (
    <div>
      {/* **The notice, and it says nothing in the ordinary case.**

          Every one of its states changes what a click on the list below MEANS,
          which is the test for being here rather than in the list. The fourth
          state is no element at all - a line reporting the current selection
          would be a second statement of what the list already marks. */}
      {captureOwnedElsewhere ? (
        <p className="px-3 py-2 text-[11px] leading-tight text-muted-foreground">
          Another Inwire window is capturing. Adapters can be changed once it
          stops.
        </p>
      ) : isCapturing ? (
        /* Why every row below has stopped answering. A disabled control with
           no reason beside it reads as a broken one. */
        <p className="px-3 py-2 text-[11px] leading-tight text-muted-foreground">
          Capturing. Stop the capture to change adapters, the filter or the snaplen.
        </p>
      ) : selectedInterfaces.length === 0 ? (
        <p className="px-3 py-2 text-[11px] leading-tight text-muted-foreground">
          No adapter chosen. Start stays blocked until you pick one or more.
        </p>
      ) : null}

      {/* No border and no card around the list: it IS the panel's body, and a
          box around it inside the side bar's own card is a card in a card.

          **Checkboxes, not radios.** Capture takes several adapters at once -
          the agent opens one sniffer per selected device, and the list merges
          them in timestamp order - so a row adds its adapter to the capture or
          takes it out. It was a radio group from 2026-08-26, when capture was
          narrowed to one adapter so that Start could never begin on a
          selection nobody made; that rule survives as "nothing is
          pre-selected", which checkboxes do not change. */}
      <div
        role="group"
        aria-label="Capture from"
        onKeyDown={onKeyDown}
        className="divide-y divide-border"
      >
        {interfaces.map((iface) => {
          const adapter = byId.get(iface.name) ?? null;
          const selected = selectedInterfaces.includes(iface.name);
          const series = interfaceRates?.[iface.name] ?? [];
          const latest = series.length > 0 ? series[series.length - 1] : null;
          const address = adapter?.ipv4[0]?.address ?? null;
          return (
            <button
              key={iface.name}
              type="button"
              role="checkbox"
              aria-checked={selected}
              // Set by hand, spelled out rather than helpered, so the string
              // reads as the same string the shared `ui/` primitives emit -
              // which is what lets every `data-[state=checked]:` class below
              // migrate from the deleted menu character for character. As
              // ternaries the selection language would fork, and this is one of
              // only two surfaces in the app that mark a chosen row.
              data-state={selected ? 'checked' : 'unchecked'}
              title={iface.label}
              // Locked for the whole capture, not merely ignored: a row that
              // still hovers and focuses would promise a change it cannot make.
              // The rates keep drawing, so the list is still worth watching,
              // and the chosen rows keep their colour because they are what is
              // being captured; the rest step back.
              // Another window's capture locks it too: the agent refuses a
              // selection from a window that does not own the capture, and a
              // row that changed anyway would show adapters nobody captures on.
              disabled={isCapturing || captureOwnedElsewhere}
              onClick={() => onToggle(iface.name)}
              className="group relative w-full text-left px-3 py-2 enabled:cursor-pointer
                transition-colors enabled:hover:bg-accent/60
                disabled:data-[state=unchecked]:opacity-50
                data-[state=checked]:bg-primary/15 data-[state=checked]:text-primary
                data-[state=checked]:font-semibold
                focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring
                focus-visible:ring-inset"
            >
              {/* Scales out of the left edge rather than appearing. */}
              <span
                aria-hidden
                className="absolute left-0 top-1 bottom-1 w-0.5 origin-center scale-y-0
                  rounded-full bg-primary transition-transform duration-150 ease-out
                  group-data-[state=checked]:scale-y-100"
              />

              <div className="flex items-center gap-2">
                {/* A drawn checkbox, because the fill alone does not say "you
                    can tick more than one" - and saying so is the whole change
                    from the radio this list used to be. */}
                <span
                  aria-hidden
                  className="shrink-0 grid place-items-center w-3 h-3 rounded-[3px] border
                    border-muted-foreground/60 group-data-[state=checked]:border-primary
                    group-data-[state=checked]:bg-primary text-primary-foreground"
                >
                  {selected && <Check className="w-2.5 h-2.5" />}
                </span>
                <span className="flex-1 truncate text-xs">
                  {shortInterfaceLabel(iface.label)}
                </span>
                {latest !== null && (
                  <span className="shrink-0 text-[10px] tabular-nums
                    text-muted-foreground group-data-[state=checked]:text-primary">
                    {latest.toLocaleString()} p/s
                  </span>
                )}
              </div>

              {/* The second line is what the one-line row could never hold, and
                  it is a better disambiguator than the driver description it
                  replaces - three adapters called `Ethernet`, `Ethernet 2` and
                  `Ethernet 3` differ here and not in their names. Free, too:
                  `adapter_config` is subscribed unconditionally from `hello`
                  for the packet list's direction field. */}
              {adapter !== null && (
                <div className="mt-0.5 text-[10px] font-mono text-muted-foreground truncate">
                  {[
                    address,
                    adapter.status,
                    adapter.speedMbps !== null
                      ? adapter.speedMbps >= 1000
                        ? `${adapter.speedMbps / 1000} Gb/s`
                        : `${adapter.speedMbps} Mb/s`
                      : null,
                  ].filter(Boolean).join('  ·  ')}
                </div>
              )}

              <Sparkline
                values={series}
                max={peakRate}
                // The agent's own sample window, so a full history exactly
                // fills the chart and no sample is ever squeezed.
                capacity={30}
                className={`mt-1 ${CHART}`}
              />
            </button>
          );
        })}
      </div>

      {/* Under the list they narrow, and locked by the same rule: chosen before
          Start, fixed until Stop (ADR 0050). */}
      <CaptureOptionsSection
        options={captureOptions}
        onChange={onCaptureOptionsChange}
        verdict={filterVerdict}
        locked={isCapturing || captureOwnedElsewhere}
        stopNote={isCapturing ? null : stopNote}
      />

      {/* **The one fact from the adapter that is nowhere else on screen.**

          Grep the renderer: the capture device path appears in no other
          surface. It is what `tshark -i` takes, what every agent log line
          names, and what the interface list is keyed by - so it is the string
          you need the moment you want to check this app's answer against
          another tool's, and today it is obtainable only by reading the
          agent's log.

          `Row` from `network/rows.tsx` is deliberately not reused: its label
          column is being restacked for this same column width, and a path that
          has to wrap is a path nobody can read. */}
      {selectedInterfaces.length > 0 && (
        <div className="px-3 py-2 border-t border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
            {selectedInterfaces.length === 1 ? 'Capture device' : 'Capture devices'}
          </div>
          {selectedInterfaces.map((device) => (
            <div key={device} className="flex items-center gap-1 min-w-0">
              <code className="flex-1 text-[10px] font-mono truncate">{device}</code>
              <CopyButton value={device} label="capture device path" />
            </div>
          ))}
        </div>
      )}

      {/* **There is no Refresh button, and that is a decision with a scar.**

          `refresh_adapters` re-reads adapter CONFIGURATION, never touches the
          capture-interface list, and is itself filtered by that stale list - so
          a brand-new adapter is excluded from its own snapshot. The Update
          Center found that the hard way and landed on `recycle()`: drop the
          pipe and reconnect. A button doing that beside a running capture is a
          button that ends the capture, because the agent stops when the last
          client disconnects - and "disabled while capturing" is a mitigation
          for a control that should not be here. The pair that does it
          deliberately already exists in Settings.

          It is also the only line on this surface that is NOT live. Everything
          else updates itself, so silence reads as steadiness - which is exactly
          why this one has to be written down. */}
      <p className="px-3 py-2 border-t border-border text-[11px] leading-tight
        text-muted-foreground/70">
        This list is read when the agent connects. An adapter plugged in since
        then appears after a reconnect.
      </p>
    </div>
  );
};
