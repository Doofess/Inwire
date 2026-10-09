import React, { useEffect, useRef, useState } from 'react';
import { formatMbps, GAUGE_MARKS, gaugeFraction } from '../../services/speedTest/method';
import { prefersReducedMotion } from '../../lib/motion';

/**
 * The speed test's dial: a 270° arc on Ookla's non-linear scale, a needle, and
 * the live number under it.
 *
 * **The needle eases, the number does not jump about.** Progress arrives every
 * 100 ms and a raw value would twitch the needle on every one; the displayed
 * value follows the reported one critically damped, once a frame (~120 ms time
 * constant), so it moves the way a physical needle does. Under the app's
 * reduced-motion setting it is set straight to the value - the numbers still
 * update, nothing sweeps.
 *
 * Colours are tokens: the filled arc and the needle in `--primary`, the track
 * in `--border`, the scale in `--muted-foreground`. The scale labels are drawn
 * at a size that stays readable at the smallest workspace (a 1024 px window
 * less the side bar), since the SVG scales with its box.
 */

const START_DEG = 135;
const SWEEP_DEG = 270;
const R = 112;
const CX = 150;
const CY = 150;

function polar(deg: number, r: number): [number, number] {
  const rad = (deg * Math.PI) / 180;
  return [CX + r * Math.cos(rad), CY + r * Math.sin(rad)];
}

function arcPath(fromFrac: number, toFrac: number, r: number): string {
  const a = START_DEG + SWEEP_DEG * fromFrac;
  const b = START_DEG + SWEEP_DEG * toFrac;
  const [x1, y1] = polar(a, r);
  const [x2, y2] = polar(b, r);
  const large = b - a > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/** The reported value, eased toward once a frame; straight through under reduced motion. */
function useEased(target: number): number {
  const [shown, setShown] = useState(target);
  const shownRef = useRef(target);
  useEffect(() => {
    if (prefersReducedMotion()) {
      shownRef.current = target;
      setShown(target);
      return;
    }
    let frame = 0;
    let last = performance.now();
    const step = (t: number) => {
      const dt = Math.min(64, t - last);
      last = t;
      const k = 1 - Math.exp(-dt / 120);
      const next = shownRef.current + (target - shownRef.current) * k;
      const done = Math.abs(target - next) < 0.05;
      shownRef.current = done ? target : next;
      setShown(shownRef.current);
      if (!done) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [target]);
  return shown;
}

/** The two directions' colours, as CSS: download is the accent, upload purple (ADR 0054). */
export const SPEED_INK = {
  download: 'var(--speed-download)',
  upload: 'var(--speed-upload)',
} as const;

/**
 * The colour change between directions: short, so it reads as the dial
 * resetting into a new test rather than as decoration, and turned off with
 * every other transition under the app's reduced-motion setting.
 */
const INK_TRANSITION = { transition: 'stroke 250ms ease, fill 250ms ease, color 250ms ease' };

export function SpeedGauge({
  mbps, label, icon, active, readout, tone = 'download',
}: {
  /** Which direction is being measured: its colour on the arc, the needle and the label. */
  tone?: 'download' | 'upload';
  mbps: number;
  /** What is being measured - "Download", "Upload" - shown under the number with its icon. */
  label: string;
  icon: React.ReactNode;
  /** False between transfers: the arc rests empty and the number dims. */
  active: boolean;
  /**
   * What the centre says instead of the dial's own speed - the live ping while
   * the ping is measured, so the hero is always the thing being measured and
   * never a "0 Mb/s" that is not a measurement at all.
   */
  readout?: { value: string; unit: string } | null;
}) {
  const eased = useEased(active ? mbps : 0);
  const ink = SPEED_INK[tone];
  const frac = gaugeFraction(eased);
  const needleDeg = START_DEG + SWEEP_DEG * frac;
  const [tipX, tipY] = polar(needleDeg, R - 22);
  const [baseAX, baseAY] = polar(needleDeg + 90, 5);
  const [baseBX, baseBY] = polar(needleDeg - 90, 5);

  return (
    // Wider on a wide workspace: at 1600 px a 22rem dial sat small in a lot of
    // nothing. The SVG scales; the number steps up with it.
    <div className="relative mx-auto w-full max-w-[22rem] font-sans xl:max-w-[28rem]">
      <svg viewBox="0 0 300 268" className="block w-full" role="img"
        aria-label={`${label}: ${formatMbps(mbps)} megabits per second`}>
        {/* The track, then how far along it the speed is. */}
        <path d={arcPath(0, 1, R)} fill="none" stroke="var(--border)" strokeWidth={14} strokeLinecap="round" />
        {frac > 0.001 && (
          <path d={arcPath(0, frac, R)} fill="none" stroke={ink} style={INK_TRANSITION} strokeWidth={14} strokeLinecap="round" />
        )}
        {/* The scale: one label per mark, every mark an equal step of arc. */}
        {GAUGE_MARKS.map((mark, i) => {
          const deg = START_DEG + (SWEEP_DEG * i) / (GAUGE_MARKS.length - 1);
          const [x, y] = polar(deg, R - 30);
          return (
            <text key={mark} x={x} y={y} textAnchor="middle" dominantBaseline="central"
              fontSize={13} fill="var(--muted-foreground)" className="tabular-nums" aria-hidden>
              {mark === 1000 ? '1000+' : mark}
            </text>
          );
        })}
        {/* The needle: a slim wedge from the hub. */}
        <polygon
          points={`${tipX.toFixed(2)},${tipY.toFixed(2)} ${baseAX.toFixed(2)},${baseAY.toFixed(2)} ${baseBX.toFixed(2)},${baseBY.toFixed(2)}`}
          fill={active ? ink : 'var(--foreground)'} style={INK_TRANSITION} opacity={active ? 0.95 : 0.35} aria-hidden />
        <circle cx={CX} cy={CY} r={8} fill="var(--card)" stroke="var(--foreground)" strokeOpacity={0.5} strokeWidth={2} aria-hidden />
      </svg>
      {/* The number, in the dial's open quarter. Tabular figures in a fixed
          box, so the digits changing never shifts anything around them. */}
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center" aria-hidden>
        <div className={`flex items-baseline gap-1.5 ${active || readout ? 'text-foreground' : 'text-muted-foreground'}`}>
          <span className="inline-block min-w-[4ch] text-right text-5xl font-semibold tabular-nums leading-none xl:text-6xl">
            {readout ? readout.value : formatMbps(eased)}
          </span>
          <span className="w-10 text-sm font-medium text-muted-foreground">{readout ? readout.unit : 'Mb/s'}</span>
        </div>
        <div className="mt-1.5 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <span style={active ? { ...INK_TRANSITION, color: ink } : INK_TRANSITION} className="flex">{icon}</span>
          {label}
        </div>
      </div>
    </div>
  );
}

/** The last ten seconds of the transfer, as a line. */
export function Sparkline({ values, tone = 'download' }: { values: readonly number[]; tone?: 'download' | 'upload' }) {
  const W = 240;
  const H = 36;
  if (values.length < 2) return <div style={{ height: H }} aria-hidden />;
  const max = Math.max(...values, 1);
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * W).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="block h-9 w-60" aria-hidden preserveAspectRatio="none">
      <polyline points={pts.join(' ')} fill="none" stroke={SPEED_INK[tone]} style={INK_TRANSITION} strokeWidth={1.5}
        strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
