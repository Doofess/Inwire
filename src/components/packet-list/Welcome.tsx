import React, { useEffect, useRef, useState } from 'react';
import { Check, History, TriangleAlert } from 'lucide-react';
import { Sparkline } from '../common/Sparkline';
import { MICRO_LABEL, TITLE } from '../common/typography';
import { useEscapeLayer } from '../../hooks/useEscapeLayer';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import type { AgentInterface } from '../../services/agentProtocol';
import type { StartGate } from '../../lib/startGate';

/**
 * What an empty Packets view shows instead of an empty table and two empty
 * panes: the adapters with their traffic, Start, and the other ways in.
 *
 * It replaces the list AND the detail panes while the buffer is empty and
 * nothing is capturing (`showWelcome` in `App.tsx`); the first packet brings
 * them back. It never writes the user's panes setting - the panes are hidden by
 * the render, not by the preference.
 *
 * **Start asks what the rail's Start asks.** A previous capture on disk is
 * deleted by a new capture and nobody can see it in the list, so pressing Start
 * with one present opens a confirm rather than starting. The decision is
 * `startGate`'s, computed in App from the same inputs the rail gets.
 */
export interface WelcomeProps {
  interfaces: AgentInterface[];
  selectedInterfaces: string[];
  onToggleInterface: (name: string) => void;
  /** Packets per second, newest last, per adapter. */
  interfaceRates: Record<string, number[]>;
  /** Subscribe or unsubscribe the agent's interface counters. */
  onSamplingChange: (on: boolean) => void;
  gate: StartGate;
  previousCapture: { label: string; onReopen: () => void } | null;
  onStart: () => void;
  onClearPackets: () => void;
  onOpenFile: () => void;
  onTakeTour: () => void;
}

const QUIET_BUTTON = 'px-2.5 py-1 rounded bg-secondary hover:bg-accent text-foreground '
  + 'text-[11px] font-medium transition-colors cursor-pointer focus-visible:outline-none '
  + 'focus-visible:ring-1 focus-visible:ring-ring';

export const Welcome: React.FC<WelcomeProps> = ({
  interfaces, selectedInterfaces, onToggleInterface, interfaceRates, onSamplingChange,
  gate, previousCapture, onStart, onClearPackets, onOpenFile, onTakeTour,
}) => {
  // Held in a ref with an empty dep list, as `CaptureInterfacePanel` does: a
  // naked `[onSamplingChange]` would rebuild the subscription on every App
  // render the day the callback gains a dependency, a write down the pipe ten
  // times a second with nothing on screen to show it. Sampling is counted
  // (`lib/samplingCount.ts`), so this and the panel can both be open.
  const notify = useRef(onSamplingChange);
  useEffect(() => { notify.current = onSamplingChange; });
  useEffect(() => {
    notify.current(true);
    return () => { notify.current(false); };
  }, []);

  const [confirming, setConfirming] = useState(false);
  const confirmRef = useRef<HTMLDivElement | null>(null);
  const asksFirst = gate.discards !== null;

  // The question answers itself if what it asked about goes away.
  useEffect(() => {
    if (!asksFirst || gate.blocked !== null) setConfirming(false);
  }, [asksFirst, gate.blocked]);

  // Claimed before the view-level Escape can read it.
  useEscapeLayer(confirming, () => setConfirming(false));

  useEffect(() => {
    if (confirming) confirmRef.current?.querySelector<HTMLElement>('[data-autofocus]')?.focus();
  }, [confirming]);

  // The gate's words are the rail's, written for a button with no list beside
  // it. Here the list is right above, so with none picked Start points at it.
  const blockedText = gate.blocked !== null && selectedInterfaces.length === 0 && interfaces.length > 0
    ? 'Pick an adapter above.'
    : gate.blocked;

  // One scale for every chart, so two adapters can be compared.
  const peakRate = Math.max(1, ...Object.values(interfaceRates).flatMap((series) => series));

  const press = (): void => {
    if (gate.blocked !== null) return;
    if (asksFirst) setConfirming(true);
    else onStart();
  };
  const startFresh = (): void => {
    setConfirming(false);
    // Clear first, so nothing is left for the new capture to be appended to.
    onClearPackets();
    onStart();
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-background">
      <div className="min-h-full flex items-center justify-center px-6 py-8">
        <div className="w-full max-w-[34rem] space-y-6">
          <h2 className={TITLE}>Start a capture</h2>

          <section aria-label="Adapters" className="space-y-2">
            <div className={MICRO_LABEL}>Adapters</div>
            {interfaces.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No adapters yet. The list arrives when the agent connects.
              </p>
            ) : (
              <div className="rounded-lg border border-border divide-y divide-border overflow-hidden">
                {interfaces.map((iface) => {
                  const selected = selectedInterfaces.includes(iface.name);
                  return (
                    <label
                      key={iface.name}
                      title={iface.label}
                      className="group flex items-center gap-3 px-3 py-2 cursor-pointer
                        transition-colors hover:bg-accent/60 has-[:checked]:bg-primary/10
                        has-[:focus-visible]:ring-1 has-[:focus-visible]:ring-ring
                        has-[:focus-visible]:ring-inset"
                    >
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={() => onToggleInterface(iface.name)}
                        className="peer sr-only"
                      />
                      <span
                        aria-hidden
                        className="shrink-0 grid place-items-center w-3.5 h-3.5 rounded-[3px] border
                          border-muted-foreground/60 text-primary-foreground
                          peer-checked:border-primary peer-checked:bg-primary"
                      >
                        {selected && <Check className="w-2.5 h-2.5" />}
                      </span>
                      <span className="flex-1 min-w-0 truncate text-xs text-foreground">
                        {shortInterfaceLabel(iface.label)}
                      </span>
                      <Sparkline
                        values={interfaceRates[iface.name] ?? []}
                        max={peakRate}
                        capacity={30}
                        className={`shrink-0 w-32 h-4 text-muted-foreground ${
                          selected ? 'text-primary' : ''}`}
                      />
                    </label>
                  );
                })}
              </div>
            )}
          </section>

          <div className="space-y-2">
            <div className="relative inline-block" ref={confirmRef}>
              <button
                type="button"
                onClick={press}
                disabled={gate.blocked !== null}
                aria-haspopup={asksFirst ? 'dialog' : undefined}
                aria-expanded={asksFirst ? confirming : undefined}
                className="h-9 px-5 rounded-lg bg-primary text-primary-foreground text-xs
                  font-semibold hover:bg-primary/90 transition-colors cursor-pointer
                  disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none
                  focus-visible:ring-2 focus-visible:ring-ring"
              >
                Start capture
              </button>
            </div>
            {blockedText !== null && (
              <p className="text-[11px] text-muted-foreground">{blockedText}</p>
            )}
            {confirming && previousCapture !== null && (
              <div
                role="dialog"
                aria-label="Delete the previous capture?"
                className="rounded-lg border border-border bg-popover p-3 text-popover-foreground"
              >
                <div className="flex items-start gap-2">
                  <TriangleAlert className="w-4 h-4 mt-0.5 shrink-0 text-warning" />
                  <div className="text-[11px] leading-relaxed text-muted-foreground">
                    <span className="font-bold text-foreground">
                      Delete the capture from {previousCapture.label}?
                    </span>
                    <br />
                    It is still on disk, and only one capture is kept. Reopen it and
                    export it first if you want to keep it.
                  </div>
                </div>
                <div className="flex justify-end gap-1.5 mt-3">
                  <button type="button" onClick={() => setConfirming(false)} className={QUIET_BUTTON}>
                    Cancel
                  </button>
                  <button
                    type="button"
                    data-autofocus
                    onClick={startFresh}
                    className="px-2.5 py-1 rounded bg-danger hover:bg-danger/90
                      text-danger-foreground text-[11px] font-bold transition-colors cursor-pointer
                      focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  >
                    Delete and start
                  </button>
                </div>
              </div>
            )}
          </div>

          {previousCapture !== null && (
            <div className="rounded-lg border border-border bg-card p-3 space-y-2">
              <p className="text-xs text-foreground">
                The capture from {previousCapture.label} is still on disk.
              </p>
              <button
                type="button"
                onClick={previousCapture.onReopen}
                className={`${QUIET_BUTTON} inline-flex items-center gap-1.5`}
              >
                <History className="w-3.5 h-3.5" aria-hidden />
                Reopen the last capture
              </button>
              <p className="text-[11px] text-muted-foreground">
                Starting a new capture replaces it.
              </p>
            </div>
          )}

          <div className="flex items-center gap-4 pt-1 border-t border-border">
            <button type="button" onClick={onOpenFile} className={`${QUIET_BUTTON} mt-3`}>
              Open a capture file…
            </button>
            <button
              type="button"
              onClick={onTakeTour}
              className="mt-3 text-[11px] text-primary hover:underline cursor-pointer
                focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded"
            >
              Take the tour
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
