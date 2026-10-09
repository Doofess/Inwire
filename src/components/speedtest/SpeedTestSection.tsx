import { ArrowDown, ArrowUp, ChevronRight, Gauge } from 'lucide-react';
import { Section } from '../network/rows';
import { formatMbps, TEST_CAP_MB } from '../../services/speedTest/method';
import { startSpeedTest, useSpeedTest, speedTestAvailable } from '../../services/speedTest/state';
import { shortIsp, speedHistoryStore, whenText } from '../../services/speedTest/history';
import { usePreferenceValue } from '../../services/preferenceStore';

/**
 * The speed test's door in the Network panel (ADR 0054): the last result, a
 * button that runs a test, and a way to the full sheet.
 *
 * Here because the panel describes this machine's connection, and a speed test
 * is a measurement of exactly that - and because the rail is full. Running a
 * test opens the sheet, where the dial is; the section stays a summary.
 *
 * Sized for the panel's narrowest, 170 px (`MIN_SIDE_BAR_PX`): the numbers
 * stack rather than squeeze, and the button is full width. Its button is the
 * panel's one filled control and still smaller than the sheet's GO - it says
 * "run" without shouting over the facts around it.
 */
export function SpeedTestSection({ onOpen }: { onOpen: () => void }) {
  const state = useSpeedTest();
  const [history] = usePreferenceValue(speedHistoryStore);
  const last = history[0] ?? null;
  const running = state.status === 'running';
  if (!speedTestAvailable()) return null;

  const run = (): void => {
    startSpeedTest();
    onOpen();
  };

  return (
    <Section title="Speed test">
      <div className="space-y-2 px-3 py-2.5 font-sans">
        {running ? (
          // The phase on one line and the figure on the next: at the panel's
          // 170 px a sentence with a number in it broke between the number
          // and its unit.
          <div className="space-y-0.5">
            <div className="text-[11px] text-muted-foreground">
              Testing {state.phase === 'upload' ? 'upload' : state.phase === 'download' ? 'download' : 'ping'}…
            </div>
            {(state.phase === 'download' || state.phase === 'upload') && (
              <div className="flex items-baseline gap-1 text-sm text-foreground">
                <span className="font-semibold tabular-nums">{formatMbps(state.liveMbps)}</span>
                <span className="text-xs text-muted-foreground">Mb/s</span>
              </div>
            )}
          </div>
        ) : last ? (
          <div className="space-y-0.5">
            {/* The two figures alone on the first line and the unit with the
                rest on the second: at the panel's 170 px floor a unit after
                the figures wrapped onto a line of its own. */}
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 text-sm tabular-nums text-foreground">
              <span className="inline-flex items-center gap-1"><ArrowDown className="h-3.5 w-3.5 text-speed-download" aria-label="Download" />{formatMbps(last.downMbps)}</span>
              <span className="inline-flex items-center gap-1"><ArrowUp className="h-3.5 w-3.5 text-speed-upload" aria-label="Upload" />{formatMbps(last.upMbps)}</span>
            </div>
            <div className="text-[11px] text-muted-foreground tabular-nums">
              Mb/s · ping {Math.round(last.pingMs)} ms · {whenText(last.at, Date.now())}
            </div>
            {/* Where it ran and from which network, cut to the panel's width -
                the whole of both is the title. */}
            {last.server && (
              <div className="truncate text-[11px] text-muted-foreground"
                title={[`Cloudflare · ${last.server}`, last.isp].filter(Boolean).join(' — ')}>
                Cloudflare · {last.server}{last.isp && <> — {shortIsp(last.isp)}</>}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">How fast this connection is right now: download, upload and ping.</p>
        )}

        {running ? (
          <button type="button" onClick={onOpen}
            className="flex w-full items-center justify-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5
              text-xs font-semibold text-foreground transition-colors hover:bg-accent cursor-pointer
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            Show test <ChevronRight className="h-3.5 w-3.5" aria-hidden />
          </button>
        ) : (
          <>
            {/* A tinted outline rather than a fill: unmistakably the thing to
                press in this section, and still quieter than the facts the
                rest of the panel is for. */}
            <button type="button" onClick={run}
              className="flex w-full items-center justify-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-3 py-1.5
                text-xs font-semibold text-primary transition-colors hover:bg-primary/20 cursor-pointer
                focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <Gauge className="h-3.5 w-3.5" aria-hidden />
              {/* Short, so it fits on one line at 170 px: the section's own
                  title already says what kind of test. */}
              {last ? 'Run again' : 'Run test'}
            </button>
            {last && (
              <button type="button" onClick={onOpen}
                className="flex items-center gap-0.5 rounded-sm text-[11px] text-muted-foreground hover:text-foreground cursor-pointer
                  focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
                Results and history <ChevronRight className="h-3 w-3" aria-hidden />
              </button>
            )}
          </>
        )}

        {!running && !last && (
          <p className="text-[10px] leading-snug text-muted-foreground">
            Cloudflare sees this machine&rsquo;s address. Uses up to {TEST_CAP_MB} MB.
          </p>
        )}
      </div>
    </Section>
  );
}
