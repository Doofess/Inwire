import { Check } from 'lucide-react';
import type { SpeedPhase } from '../../services/speedTest/protocol';
import { rampTickLabel } from '../../services/speedTest/stats';

const STEPS: { phase: SpeedPhase; label: string; grow: number }[] = [
  { phase: 'connecting', label: 'Connect', grow: 1 },
  { phase: 'latency', label: 'Latency', grow: 1.4 },
  { phase: 'download', label: 'Download', grow: 3 },
  { phase: 'upload', label: 'Upload', grow: 3 },
];

/**
 * Where the test is: four steps in the order they run, the current one lit,
 * the finished ones checked. The two transfers are wider because they are
 * most of the test, and carry a tick where the engine added connections. A
 * tick has no text of its own - it would crowd a 28px strip - so each says
 * what it is and when to a screen reader and on hover, and the cell's own
 * tooltip says what the ticks are.
 */
export function PhaseStrip({ phase, done, rampsAtMs, durationMs }: {
  phase: SpeedPhase | null;
  done: boolean;
  rampsAtMs: { download: number[]; upload: number[] };
  durationMs: number;
}) {
  const at = phase === null ? -1 : STEPS.findIndex((s) => s.phase === phase);
  return (
    <ol aria-label="Test progress" className="flex h-7 w-full overflow-hidden rounded-md border border-border bg-card text-[11px]">
      {STEPS.map((s, i) => {
        const current = !done && i === at;
        const finished = done || i < at;
        const ramps = s.phase === 'download' ? rampsAtMs.download : s.phase === 'upload' ? rampsAtMs.upload : [];
        return (
          <li key={s.phase} aria-current={current ? 'step' : undefined}
            title={ramps.length > 0 ? 'Ticks mark where more connections were added' : undefined} style={{ flexGrow: s.grow, flexBasis: 0 }}
            className={`relative flex min-w-0 items-center gap-1 px-2.5 ${i > 0 ? 'border-l border-border' : ''} ${
              current ? 'bg-primary/15 font-medium text-foreground'
                : finished ? 'text-muted-foreground' : 'text-muted-foreground/60'}`}>
            {finished && <Check className="h-3 w-3 shrink-0" aria-hidden />}
            <span className="truncate">{s.label}</span>
            {finished && <span className="sr-only">, finished</span>}
            {ramps.map((ms, n) => (
              // A wider, invisible target around the 1px tick so it can be hovered.
              <span key={`${n}-${ms}`} role="img" aria-label={rampTickLabel(ms)} title={rampTickLabel(ms)}
                className="absolute bottom-0 flex h-3 w-2 -translate-x-1/2 items-end justify-center"
                style={{ left: `${Math.min(100, Math.max(0, (ms / durationMs) * 100))}%` }}>
                <span aria-hidden className="h-1.5 w-px bg-muted-foreground/60" />
              </span>
            ))}
          </li>
        );
      })}
    </ol>
  );
}
