import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle, ArrowDown, ArrowUp, History, MapPin, Network, Play, RotateCcw, Server, ShieldAlert, Square,
  WifiOff, Wifi,
} from 'lucide-react';
import { requestMapFocus } from '../../services/speedTest/mapOverlay';
import { PaneHeader } from '../common/PaneHeader';
import { EmptyStateButton } from '../common/EmptyState';
import { SpeedHeadline } from './SpeedHeadline';
import { LatencyBoxes } from './LatencyBoxes';
import { ThroughputTrace } from './ThroughputTrace';
import { PhaseStrip } from './PhaseStrip';
import { fmtMsValue, Hint } from './Hint';
import { formatMbps, median, SLICE_MS, TEST_CAP_TEXT, TRANSFER_MS, WARMUP_MS } from '../../services/speedTest/method';
import { spread } from '../../services/speedTest/stats';
import {
  cancelSpeedTest, livePing, startSpeedTest, useSpeedTest, type SpeedState, type SpeedStatus,
} from '../../services/speedTest/state';
import {
  changeText, lastTraceStore, shortIsp, speedHistoryStore, whenText, type LastTrace, type SpeedHistoryEntry,
} from '../../services/speedTest/history';
import { usePreferenceValue } from '../../services/preferenceStore';
import type { SpeedPhase, SpeedServer } from '../../services/speedTest/protocol';

/**
 * The speed test's workspace sheet (ADR 0054 and its amendment): an
 * instrument for the question a network person asks - how does this link
 * behave under load? Two figures, latency per phase on one axis, and each
 * transfer's trace with the last run's behind it.
 *
 * A sheet like Settings: it takes the workspace card, the view underneath is
 * untouched, and the back step, Escape or any view on the rail leaves it. The
 * test itself lives in `services/speedTest/state.ts`, so leaving the sheet
 * does not stop a test and coming back shows it where it is.
 */

const PHASE_LABEL: Record<SpeedPhase, string> = {
  connecting: 'Connecting',
  latency: 'Ping',
  download: 'Download',
  upload: 'Upload',
};

export function SpeedTestSheet({ capturing, onShowOnMap }: {
  capturing: boolean;
  /** Opens the Routing Map; the sheet has already asked it to fly to the server. */
  onShowOnMap?: () => void;
}) {
  const state = useSpeedTest();
  const [history, setHistory] = usePreferenceValue(speedHistoryStore);
  const ghost = useGhost(state.status);

  return (
    <div className="flex h-full flex-col bg-background font-sans">
      <PaneHeader title="Speed test" detail={<ServerLine server={state.server} running={state.status === 'running'} />} />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex w-full max-w-[46rem] flex-col gap-6 px-6 py-8">
          <Announcer state={state} />
          {state.status === 'idle' && <Idle last={history[0] ?? null} />}
          {state.status === 'running' && <Running state={state} capturing={capturing} ghost={ghost} />}
          {state.status === 'done' && state.result && (
            <Done state={state} previous={history[1] ?? null}
              ghost={ghost?.at === state.result.at ? null : ghost} onShowOnMap={onShowOnMap} />
          )}
          {state.status === 'failed' && state.error && <Failed error={state.error} />}
          {state.status === 'cancelled' && <Cancelled />}
          {state.status !== 'running' && history.length > 0 && (
            <HistoryTable history={history} onClear={() => setHistory([])} />
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * The last run's trace, read when a test starts and held until the next one,
 * because the run in progress replaces it in the store the moment it finishes.
 */
function useGhost(status: SpeedStatus): LastTrace | null {
  const ghost = useRef<LastTrace | null>(lastTraceStore.get());
  const was = useRef(status);
  if (status === 'running' && was.current !== 'running') ghost.current = lastTraceStore.get();
  was.current = status;
  return ghost.current;
}

// --- the states ------------------------------------------------------------------

/** The page's one primary action: 40px like the app's other primary buttons, with its words. */
function RunButton() {
  return (
    <button
      type="button"
      onClick={startSpeedTest}
      autoFocus
      aria-label="Start the speed test"
      className="inline-flex h-10 items-center gap-2 self-start rounded-lg bg-primary px-5 text-sm font-semibold text-primary-foreground
        transition-colors duration-150 hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring
        focus-visible:ring-offset-2 focus-visible:ring-offset-background cursor-pointer"
    >
      <Play className="h-4 w-4" fill="currentColor" aria-hidden />
      Run test
    </button>
  );
}

function ConsentLine() {
  return (
    <p className="max-w-[34rem] text-xs leading-relaxed text-muted-foreground">
      Runs against Cloudflare, which sees this machine&rsquo;s public address. Uses up to {TEST_CAP_TEXT} of data.
      Results stay on this machine.
    </p>
  );
}

function Idle({ last }: { last: SpeedHistoryEntry | null }) {
  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-[34rem] text-[13px] leading-relaxed text-foreground">
        Measures download and upload, and how much the round trip rises while the link is busy.
      </p>
      <RunButton />
      <ConsentLine />
      {last && (
        <p className="text-xs text-muted-foreground">
          Last test {whenText(last.at, Date.now())}:{' '}
          <span className="font-mono tabular-nums text-foreground">
            <span className="text-speed-download">↓</span> {formatMbps(last.downMbps)} ·{' '}
            <span className="text-speed-upload">↑</span> {formatMbps(last.upMbps)} Mb/s
            {typeof last.rpm === 'number' && <> · {last.rpm} RPM</>}
          </span>
          {last.server && <> · <ServerIsp city={last.server} colo={null} isp={last.isp} inline /></>}
        </p>
      )}
    </div>
  );
}

function Running({ state, capturing, ghost }: { state: SpeedState; capturing: boolean; ghost: LastTrace | null }) {
  const phase = state.phase ?? 'connecting';
  const live = phase === 'download' || phase === 'upload' ? phase : null;
  const rttOf = (xs: SpeedState['loaded']['download']) => median(xs.map((s) => s.rttMs));
  return (
    <div className="flex w-full flex-col gap-5">
      <PhaseStrip phase={phase} done={false} rampsAtMs={state.rampsAtMs} durationMs={TRANSFER_MS} />
      <SpeedHeadline down={state.downloadMbps} up={state.uploadMbps} live={live} liveMbps={state.liveMbps} rpm={null} grade={null} />
      <LatencyBoxes
        idle={spread(state.loaded.idle.map((s) => s.ttfbMs))}
        download={spread(state.loaded.download.map((s) => s.ttfbMs))}
        upload={spread(state.loaded.upload.map((s) => s.ttfbMs))}
        rtt={{ idle: livePing(state), download: rttOf(state.loaded.download), upload: rttOf(state.loaded.upload) }}
        live={phase}
      />
      <Traces
        download={{ points: state.trace.download, p90: null, mean: null, loaded: state.loaded.download, live: phase === 'download' }}
        upload={{ points: state.trace.upload, p90: null, mean: null, loaded: state.loaded.upload, live: phase === 'upload' }}
        ghost={ghost}
      />
      <div className="flex flex-wrap items-center gap-4">
        <EmptyStateButton icon={Square} onClick={cancelSpeedTest}>Cancel</EmptyStateButton>
        {capturing && (
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Wifi className="h-3.5 w-3.5" aria-hidden />
            A capture is running, so this test&rsquo;s traffic will appear in it.
          </p>
        )}
      </div>
    </div>
  );
}

type TraceInput = Pick<Parameters<typeof ThroughputTrace>[0], 'points' | 'p90' | 'mean' | 'loaded' | 'live'>;

function Traces({ download, upload, ghost }: { download: TraceInput; upload: TraceInput; ghost: LastTrace | null }) {
  return (
    <section aria-label="Throughput" className="flex flex-col gap-3">
      <ThroughputTrace direction="download" durationMs={TRANSFER_MS} warmupMs={WARMUP_MS} ghost={ghost?.download ?? null} {...download} />
      <ThroughputTrace direction="upload" durationMs={TRANSFER_MS} warmupMs={WARMUP_MS} ghost={ghost?.upload ?? null} showTime {...upload} />
      {ghost && (
        <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <span aria-hidden className="inline-block h-px w-4 bg-muted-foreground/60" />
          The previous test, {whenText(ghost.at, Date.now())}
        </p>
      )}
    </section>
  );
}

function Done({ state, previous, ghost, onShowOnMap }: {
  state: SpeedState; previous: SpeedHistoryEntry | null; ghost: LastTrace | null; onShowOnMap?: () => void;
}) {
  const r = state.result!;
  const points = (trace: number[]) => trace.map((mbps, i) => ({ tMs: (i + 1) * SLICE_MS, mbps }));
  return (
    <div className="flex w-full flex-col gap-5">
      <PhaseStrip phase={null} done rampsAtMs={{ download: r.download.rampsAtMs, upload: r.upload.rampsAtMs }} durationMs={TRANSFER_MS} />
      <SpeedHeadline down={r.download.mbps} up={r.upload.mbps} live={null} liveMbps={0} rpm={r.summary.rpm} grade={r.grade} />
      <LatencyBoxes
        idle={r.summary.idle} download={r.summary.download} upload={r.summary.upload}
        rtt={{ idle: r.latency.idleMs, download: r.download.loadedLatencyMs, upload: r.upload.loadedLatencyMs }}
        live={null}
      />
      <Traces
        download={{ points: points(r.download.trace), p90: r.download.p90, mean: r.summary.downMeanMbps, loaded: r.download.loaded, live: false }}
        upload={{ points: points(r.upload.trace), p90: r.upload.p90, mean: r.summary.upMeanMbps, loaded: r.upload.loaded, live: false }}
        ghost={ghost}
      />
      <div className="flex flex-col gap-3 border-t border-border pt-4">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
          {previous && (
            <>
              <dt className="text-muted-foreground">Compared with the test {whenText(previous.at, Date.now())}</dt>
              <dd className="font-mono tabular-nums text-foreground">
                <span className="text-speed-download">↓</span> {changeText(r.download.mbps, previous.downMbps)} ·{' '}
                <span className="text-speed-upload">↑</span> {changeText(r.upload.mbps, previous.upMbps)} · ping {changeText(r.latency.idleMs, previous.pingMs)}
              </dd>
            </>
          )}
          <dt className="text-muted-foreground">Connections</dt>
          <dd className="font-mono tabular-nums text-foreground">
            {r.download.connections} <span className="text-speed-download">↓</span> / {r.upload.connections}{' '}
            <span className="text-speed-upload">↑</span>
          </dd>
        </dl>
        <div><EmptyStateButton icon={RotateCcw} primary onClick={startSpeedTest}>Test again</EmptyStateButton></div>
        <ServerFooter server={r.server} onShowOnMap={onShowOnMap} />
      </div>
    </div>
  );
}

/**
 * What went wrong, in the reader's words, with the machine's own words kept
 * underneath for anyone who wants them - this app's readers often do.
 *
 * Classified by WHERE it failed and WHAT failed rather than by matching error
 * strings: a refusal with an HTTP status is the server's, Cloudflare's 429 is
 * its own case, and anything else is the network - before any number arrived
 * that means Cloudflare could not be reached, during a transfer that the
 * connection dropped.
 */
function Failed({ error }: { error: NonNullable<SpeedState['error']> }) {
  const http = /\(HTTP (\d+)\)/.exec(error.message)?.[1] ?? null;
  const early = error.phase === 'connecting' || error.phase === 'latency';
  const phase = PHASE_LABEL[error.phase].toLowerCase();
  const { Icon, title, body } = error.rateLimited
    ? { Icon: ShieldAlert, title: 'Cloudflare is limiting tests right now',
      body: 'Too many tests have run from this address recently. Wait a few minutes and try again.' }
    : http !== null
      ? { Icon: AlertTriangle, title: `The test stopped during ${phase}`,
        body: `Cloudflare's test server returned an error (HTTP ${http}). Nothing was recorded; try again in a moment.` }
      : early
        ? { Icon: WifiOff, title: 'Could not reach Cloudflare',
          body: 'Check this machine\u2019s connection to the internet, then try again.' }
        : { Icon: WifiOff, title: `The connection dropped during ${phase}`,
          body: 'This happens when the network changes mid-test. Nothing was recorded; try again.' };
  return (
    <div role="alert" className="flex flex-col items-start gap-3">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-secondary">
        <Icon className="h-5 w-5 text-warning" aria-hidden />
      </div>
      <p className="text-[13px] font-semibold text-foreground">{title}</p>
      <p className="max-w-[26rem] text-xs leading-relaxed text-muted-foreground">{body}</p>
      {!error.rateLimited && http === null && (
        <p className="font-mono text-[11px] text-muted-foreground/80">{error.message}</p>
      )}
      <EmptyStateButton icon={RotateCcw} primary onClick={startSpeedTest}>Try again</EmptyStateButton>
    </div>
  );
}

function Cancelled() {
  return (
    <div className="flex flex-col items-start gap-3">
      <p className="text-[13px] font-semibold text-foreground">Test cancelled</p>
      <p className="text-xs text-muted-foreground">Nothing was recorded.</p>
      <RunButton />
    </div>
  );
}

// --- pieces ----------------------------------------------------------------------

/**
 * The server and the network the test ran from, as one line: "Cloudflare ·
 * Tel Aviv (TLV) — Bezeq", with a server glyph and a network glyph so the two
 * halves read apart. The ISP is Cloudflare's own AS organisation for this
 * address, from the test's `/meta`; absent, nothing is shown. The whole name
 * is the title, where the line has room only for the short one.
 */
export function ServerIsp({ city, colo, isp, inline = false }: {
  city: string | null; colo: string | null; isp: string | null; inline?: boolean;
}) {
  const where = city ? `${city}${colo ? ` (${colo})` : ''}` : colo;
  const short = shortIsp(isp);
  return (
    <span className={`${inline ? 'inline-flex' : 'flex'} min-w-0 items-center gap-1.5 font-sans font-normal normal-case`}
      title={[`Cloudflare${where ? ` · ${where}` : ''}`, isp].filter(Boolean).join(' — ')}>
      <Server className="h-3.5 w-3.5 shrink-0" aria-hidden />
      <span className="truncate">Cloudflare{where ? ` · ${where}` : ''}</span>
      {short && (
        <>
          <span aria-hidden className="shrink-0">—</span>
          <Network className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span className="truncate">{short}</span>
        </>
      )}
    </span>
  );
}

/** Who the test is talking to - shown as soon as it is known, before any number. */
function ServerLine({ server, running }: { server: SpeedServer | null; running: boolean }) {
  if (!server) return running ? <span className="font-sans font-normal text-muted-foreground">finding a server…</span> : null;
  return (
    <span className="text-muted-foreground">
      <ServerIsp city={server.coloCity} colo={server.colo} isp={server.isp} />
    </span>
  );
}

/**
 * Where the result came from, said once, quietly, under it - with a way to see
 * it on the Routing Map, or "location unknown" when the server could not be
 * placed (no guess: the globe shows no pin either).
 */
function ServerFooter({ server, onShowOnMap }: { server: SpeedServer; onShowOnMap?: () => void }) {
  const placed = server.coloLat !== null && server.coloLon !== null;
  return (
    <div className="flex flex-col items-start gap-1.5">
    {onShowOnMap && (placed ? (
      <button type="button"
        onClick={() => { requestMapFocus([server.coloLon!, server.coloLat!]); onShowOnMap(); }}
        className="inline-flex items-center gap-1 rounded-sm text-xs font-medium text-primary hover:underline cursor-pointer
          focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
        <MapPin className="h-3.5 w-3.5" aria-hidden /> Show the server on the map
      </button>
    ) : (
      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
        <MapPin className="h-3.5 w-3.5" aria-hidden /> Server location unknown
      </span>
    ))}
    <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
      <ServerIsp city={server.coloCity} colo={server.colo} isp={server.isp} inline />
      {server.ip && <span>{'·'} Your address <span className="font-mono">{server.ip}</span></span>}
    </p>
    {/* Why another speed test can read differently - said once, on demand,
        and as a fact about the route rather than an excuse: Ookla often picks
        a server inside the ISP's own network, a millisecond away, where this
        one crosses from the ISP to Cloudflare. */}
    <span className="text-[11px] text-muted-foreground">
      <Hint
        term="Comparing with another test?"
        explain={`This test ran against Cloudflare${server.coloCity ? ` in ${server.coloCity}` : ''}, reached through your ISP's link to Cloudflare. Tests against your ISP's own servers stay inside its network and can read higher.`}
      />
    </span>
    </div>
  );
}

function HistoryTable({ history, onClear }: { history: SpeedHistoryEntry[]; onClear: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const now = Date.now();
  const shown = history.slice(0, 10);
  const lat = shown.flatMap((h) => [h.pingMs, h.loadedDownMs ?? null, h.loadedUpMs ?? null])
    .filter((v): v is number => typeof v === 'number' && v > 0);
  const domain: [number, number] = lat.length ? [Math.min(...lat), Math.max(...lat)] : [1, 100];
  return (
    <section className="w-full" aria-label="Previous tests">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
          <History className="h-3.5 w-3.5" aria-hidden /> Previous tests
        </h3>
        {confirming ? (
          <span className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground">Clear {history.length} result{history.length === 1 ? '' : 's'}?</span>
            <button type="button" onClick={() => { onClear(); setConfirming(false); }}
              className="rounded px-1.5 py-0.5 font-semibold text-danger hover:bg-danger/10 cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">Clear</button>
            <button type="button" onClick={() => setConfirming(false)}
              className="rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">Keep</button>
          </span>
        ) : (
          <button type="button" onClick={() => setConfirming(true)}
            className="rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
            Clear history
          </button>
        )}
      </div>
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full whitespace-nowrap text-xs">
          <thead className="bg-secondary text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left font-medium">When</th>
              <th className="px-3 py-1.5 text-right font-medium"><span className="inline-flex items-center gap-1"><ArrowDown className="h-3 w-3 text-speed-download" aria-hidden />Download</span></th>
              <th className="px-3 py-1.5 text-right font-medium"><span className="inline-flex items-center gap-1"><ArrowUp className="h-3 w-3 text-speed-upload" aria-hidden />Upload</span></th>
              <th className="px-3 py-1.5 text-right font-medium" title="Idle ping. The strip runs from idle (hollow) to the worse loaded round trip (solid)">Ping</th>
              <th className="hidden px-3 py-1.5 text-right font-medium sm:table-cell">RPM</th>
              <th className="hidden px-3 py-1.5 text-center font-medium sm:table-cell">Grade</th>
              <th className="hidden px-3 py-1.5 text-left font-medium md:table-cell">Server and ISP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-card">
            {shown.map((h) => (
              <tr key={h.at}>
                <td className="px-3 py-1.5 text-muted-foreground" title={new Date(h.at).toLocaleString()}>{whenText(h.at, now)}</td>
                <td className="px-3 py-1.5 text-right font-mono tabular-nums text-foreground">{formatMbps(h.downMbps)} <span className="font-sans text-muted-foreground">Mb/s</span></td>
                <td className="px-3 py-1.5 text-right font-mono tabular-nums text-foreground">{formatMbps(h.upMbps)} <span className="font-sans text-muted-foreground">Mb/s</span></td>
                <td className="px-3 py-1.5 text-right font-mono tabular-nums text-foreground">
                  <span className="inline-flex items-center justify-end gap-2">
                    <PingStrip idle={h.pingMs} loaded={loadedOf(h)} domain={domain} />
                    <span>{fmtMsValue(h.pingMs)} <span className="font-sans text-muted-foreground">ms</span></span>
                  </span>
                </td>
                <td className="hidden px-3 py-1.5 text-right font-mono tabular-nums text-foreground sm:table-cell">
                  {typeof h.rpm === 'number' ? h.rpm : <span className="text-muted-foreground">–</span>}
                </td>
                <td className="hidden px-3 py-1.5 text-center font-mono sm:table-cell">{h.grade}</td>
                <td className="hidden max-w-[14rem] truncate px-3 py-1.5 text-muted-foreground md:table-cell"
                  title={[h.server, h.isp].filter(Boolean).join(' — ')}>
                  {h.server ?? '—'}{h.isp && <> — {shortIsp(h.isp)}</>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function loadedOf(h: SpeedHistoryEntry): number | null {
  const v = [h.loadedDownMs, h.loadedUpMs].filter((x): x is number => typeof x === 'number');
  return v.length ? Math.max(...v) : null;
}

/** Idle (hollow) to loaded (solid) on a log track shared by the visible rows. */
function PingStrip({ idle, loaded, domain }: { idle: number; loaded: number | null; domain: [number, number] }) {
  const [lo, hi] = domain;
  const span = Math.log10(hi) - Math.log10(lo);
  const x = (v: number) => 4 + (span > 0 ? ((Math.log10(Math.max(lo, v)) - Math.log10(lo)) / span) * 40 : 0);
  return (
    <svg width={48} height={8} viewBox="0 0 48 8" aria-hidden className="hidden shrink-0 sm:block">
      <line x1={0} x2={48} y1={4} y2={4} className="stroke-border" />
      {loaded !== null && <line x1={x(idle)} x2={x(loaded)} y1={4} y2={4} className="stroke-muted-foreground" strokeWidth={1.5} />}
      <circle cx={x(idle)} cy={4} r={2.5} className="fill-card stroke-muted-foreground" strokeWidth={1.2} />
      {loaded !== null && <circle cx={x(loaded)} cy={4} r={2.5} className="fill-foreground" />}
    </svg>
  );
}

/**
 * Says the phase and the final numbers once each, for a screen reader - never
 * every progress tick, which would be ten announcements a second.
 */
function Announcer({ state }: { state: SpeedState }) {
  const [text, setText] = useState('');
  const said = useRef('');
  useEffect(() => {
    let next = '';
    if (state.status === 'running' && state.phase) next = `Testing ${PHASE_LABEL[state.phase].toLowerCase()}`;
    else if (state.status === 'done' && state.result) {
      const r = state.result;
      next = `Test complete. Download ${formatMbps(r.download.mbps)} megabits per second, upload ${formatMbps(r.upload.mbps)}, ping ${Math.round(r.latency.idleMs)} milliseconds.`;
    } else if (state.status === 'failed') next = 'The speed test failed.';
    else if (state.status === 'cancelled') next = 'Speed test cancelled.';
    if (next !== said.current) {
      said.current = next;
      setText(next);
    }
  }, [state.status, state.phase, state.result]);
  return <div aria-live="polite" className="sr-only">{text}</div>;
}
