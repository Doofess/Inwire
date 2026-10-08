import React from 'react';
import { Hourglass } from 'lucide-react';
import { StatusItem } from './StatusItem';
import { liveLagLabel, useLiveLag } from '../../services/liveLag';

/**
 * How far the live view is behind the capture, and what it skipped to keep up
 * (ADR 0053).
 *
 * Its own subscriber to `services/liveLag.ts`, so a once-a-second number
 * re-renders this cell and nothing else - the same arrangement the packet
 * counter has. Absent while the view is live, by the bar's rule that an item
 * renders nothing when its subject is absent: the ordering window holds frames
 * for a fraction of a second by design, and that is not being behind.
 *
 * Worded as a fact about the VIEW, never as a loss: a frame the live view
 * skipped is in the capture's pcapng, which the agent wrote before it put the
 * frame on the pipe.
 */
export const LiveLagStatus: React.FC = () => {
  const label = liveLagLabel(useLiveLag());
  if (label === null) return null;
  return (
    <StatusItem tone="attention" title={label.title}>
      <Hourglass className="w-3 h-3 shrink-0 text-warning" aria-hidden />
      <span className="tabular-nums">{label.text}</span>
    </StatusItem>
  );
};
