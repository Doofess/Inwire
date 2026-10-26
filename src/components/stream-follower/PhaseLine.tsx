import React from 'react';
import type { Side } from '../../services/conversation/tcpStates';

export interface PhaseLineStep {
  key: string;
  text: string;
  side: Side;
  frameId: number;
  time: number;
}

/**
 * A stream's phases in the order they were first seen, each a button that
 * brings its frame into the ladder through the same request the state map's
 * states make (QUIC's phases, TCP's TLS phases). Inferred from the frames the
 * capture holds, and the tooltip says so. It wraps rather than scrolling, so
 * at the 1024 minimum window nothing leaves the pane.
 */
export const PhaseLine: React.FC<{
  label: string;
  steps: PhaseLineStep[];
  onPick(frameId: number): void;
}> = ({ label, steps, onPick }) => (
  <div
    aria-label={label}
    className="px-4 py-2 border-b border-border flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs"
  >
    <span className="text-muted-foreground mr-1">Phases</span>
    {steps.map((step, i) => (
      <React.Fragment key={step.key}>
        {i > 0 && <span className="text-muted-foreground" aria-hidden="true">→</span>}
        <button
          type="button"
          onClick={() => onPick(step.frameId)}
          title={`Frame #${step.frameId} at ${step.time.toFixed(3)} s, as read from the frames`}
          className="px-2 py-0.5 rounded border border-border bg-secondary/50 text-foreground/90
            hover:bg-accent active:opacity-70
            focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          {step.text} <span className="text-muted-foreground">{step.side}</span>
        </button>
      </React.Fragment>
    ))}
  </div>
);
