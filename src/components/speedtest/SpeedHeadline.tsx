import { ArrowDown, ArrowUp } from 'lucide-react';
import { formatMbps, rpmBand, type BloatGrade } from '../../services/speedTest/method';
import { GRADE_TONE, GRADE_WORD, Hint } from './Hint';

/**
 * The two figures and the line that says how the link behaves under load.
 *
 * The figures are the medians ADR 0054 calibrated against Ookla; what is not
 * known yet is a quiet dash at the figure's own height, never a zero. The live
 * transfer shows its running figure in its own colour, and turns to ink when
 * it is final, so colour on a figure always means "still moving".
 */
export function SpeedHeadline({ down, up, live, liveMbps, rpm, grade }: {
  down: number | null;
  up: number | null;
  live: 'download' | 'upload' | null;
  liveMbps: number;
  rpm: number | null;
  grade: BloatGrade | null;
}) {
  return (
    <div className="w-full">
      <div className="grid grid-cols-2 gap-6">
        <Figure label="Download" icon={<ArrowDown className="h-3.5 w-3.5 text-speed-download" aria-hidden />}
          value={live === 'download' ? liveMbps : down} tone={live === 'download' ? 'text-speed-download' : null} />
        <Figure label="Upload" icon={<ArrowUp className="h-3.5 w-3.5 text-speed-upload" aria-hidden />}
          value={live === 'upload' ? liveMbps : up} tone={live === 'upload' ? 'text-speed-upload' : null} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <Hint term="Responsiveness (approx.)"
          explain="Round trips a minute while the link is busy, from the loaded latency. An estimate in the spirit of the responsiveness tests, not their exact method." />
        <span className="font-mono tabular-nums text-foreground">{rpm === null ? '–' : `${rpm} RPM`}</span>
        {rpm !== null && <span>· {rpmBand(rpm)}</span>}
        {grade && (
          <span className="ml-3 inline-flex items-center gap-1.5">
            <span className={`inline-flex h-5 min-w-5 items-center justify-center rounded border px-1 font-mono text-[11px] font-bold ${GRADE_TONE[grade]}`}>
              {grade}
            </span>
            <Hint term={`Bufferbloat: ${GRADE_WORD[grade]}`}
              explain="How much the round trip rises when the link is busy. A+ means it barely moves; F means calls and games stutter while anything downloads." />
          </span>
        )}
      </div>
    </div>
  );
}

function Figure({ label, icon, value, tone }: {
  label: string; icon: React.ReactNode; value: number | null; tone: string | null;
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">{icon}{label}</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className={`font-mono text-5xl font-semibold leading-none tabular-nums ${
          value === null ? 'text-muted-foreground/50' : tone ?? 'text-foreground'}`}>
          {value === null ? '–' : formatMbps(value)}
        </span>
        {value !== null && <span className="text-sm text-muted-foreground">Mb/s</span>}
      </div>
    </div>
  );
}
