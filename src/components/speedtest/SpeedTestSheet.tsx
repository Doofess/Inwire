import React, { useEffect, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDown, ArrowUp, Globe, History, MapPin, Network, RotateCcw, Server, ShieldAlert, Square,
  WifiOff, Wifi,
} from 'lucide-react';
import { requestMapFocus } from '../../services/speedTest/mapOverlay';
import { PaneHeader } from '../common/PaneHeader';
import { EmptyStateButton } from '../common/EmptyState';
import { SpeedGauge, Sparkline } from './SpeedGauge';
import { formatMbps, TEST_CAP_MB, type BloatGrade } from '../../services/speedTest/method';
import {
  cancelSpeedTest, livePing, startSpeedTest, useSpeedTest, type SpeedState,
} from '../../services/speedTest/state';
import { changeText, shortIsp, speedHistoryStore, whenText, type SpeedHistoryEntry } from '../../services/speedTest/history';
import { usePreferenceValue } from '../../services/preferenceStore';
import type { SpeedPhase, SpeedServer } from '../../services/speedTest/protocol';

/**
 * The speed test's workspace sheet (ADR 0054): a big GO, a live dial, and the
 * results with their history - Ookla's shape, in this app's tokens and faces.
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

  return (
    <div className="flex h-full flex-col bg-background font-sans">
      <PaneHeader title="Speed test" detail={<ServerLine server={state.server} running={state.status === 'running'} />} />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex w-full max-w-[46rem] flex-col items-center gap-6 px-6 py-8">
          <Announcer state={state} />
          {state.status === 'idle' && <Idle last={history[0] ?? null} />}
          {state.status === 'running' && <Running state={state} capturing={capturing} />}
          {state.status === 'done' && state.result && <Done state={state} previous={history[1] ?? null} onShowOnMap={onShowOnMap} />}
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

// --- the states ------------------------------------------------------------------

/** The round GO - Ookla's one big control, and the only primary action on the page. */
function GoButton({ label = 'GO' }: { label?: string }) {
  return (
    <button
      type="button"
      onClick={startSpeedTest}
      autoFocus
      aria-label="Start the speed test"
      className="group relative flex h-40 w-40 items-center justify-center rounded-full border-2 border-primary
        bg-primary/5 text-primary transition-colors duration-200 hover:bg-primary hover:text-primary-foreground
        focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-ring/50 cursor-pointer"
    >
      <span className="text-4xl font-bold tracking-wide">{label}</span>
    </button>
  );
}

function ConsentLine() {
  return (
    <p className="max-w-[26rem] text-center text-xs leading-relaxed text-muted-foreground">
      Runs against Cloudflare, which sees this machine&rsquo;s public address. Uses up to {TEST_CAP_MB} MB of data.
      Results stay on this machine.
    </p>
  );
}

function Idle({ last }: { last: SpeedHistoryEntry | null }) {
  return (
    <>
      <GoButton />
      <ConsentLine />
      {last && (
        <p className="text-xs text-muted-foreground">
          Last test {whenText(last.at, Date.now())}:{' '}
          <span className="tabular-nums text-foreground">
            <span className="text-speed-download">↓</span> {formatMbps(last.downMbps)} ·{' '}
            <span className="text-speed-upload">↑</span> {formatMbps(last.upMbps)} Mb/s · {Math.round(last.pingMs)} ms
          </span>
          {last.server && <> · <ServerIsp city={last.server} colo={null} isp={last.isp} inline /></>}
        </p>
      )}
    </>
  );
}

function Running({ state, capturing }: { state: SpeedState; capturing: boolean }) {
  const ping = livePing(state);
  const transferring = state.phase === 'download' || state.phase === 'upload';
  const phase = state.phase ?? 'connecting';
  const icon = phase === 'upload' ? <ArrowUp className="h-3.5 w-3.5" />
    : phase === 'download' ? <ArrowDown className="h-3.5 w-3.5" />
      : phase === 'latency' ? <Activity className="h-3.5 w-3.5" /> : <Globe className="h-3.5 w-3.5" />;
  return (
    <>
      <Tiles state={state} />
      <div className="w-full">
        <SpeedGauge
          mbps={transferring ? state.liveMbps : 0}
          label={transferring ? PHASE_LABEL[phase] : phase === 'latency' ? 'Measuring ping' : 'Connecting to Cloudflare'}
          icon={icon}
          active={transferring}
          tone={phase === 'upload' ? 'upload' : 'download'}
          readout={transferring ? null : {
            value: ping === null ? '–' : fmtMsValue(ping),
            unit: 'ms',
          }}
        />
      </div>
      <div className="flex flex-col items-center gap-3">
        <Sparkline values={transferring ? state.spark : []} tone={phase === 'upload' ? 'upload' : 'download'} />
        <EmptyStateButton icon={Square} onClick={cancelSpeedTest}>Cancel</EmptyStateButton>
      </div>
      {capturing && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Wifi className="h-3.5 w-3.5" aria-hidden />
          A capture is running, so this test&rsquo;s traffic will appear in it.
        </p>
      )}
    </>
  );
}

function Done({ state, previous, onShowOnMap }: {
  state: SpeedState; previous: SpeedHistoryEntry | null; onShowOnMap?: () => void;
}) {
  const r = state.result!;
  return (
    <>
      <Tiles state={state} large />
      <div className="grid w-full grid-cols-1 gap-3 sm:grid-cols-2">
        <Detail
          label={<Hint term="Loaded latency" explain="Ping while the connection is busy downloading or uploading. The closer to the idle ping, the better calls and games hold up during a download." />}
          value={
            <span className="tabular-nums">
              <span className="text-speed-download">↓</span> {fmtMs(r.download.loadedLatencyMs)} ·{' '}
              <span className="text-speed-upload">↑</span> {fmtMs(r.upload.loadedLatencyMs)}
            </span>
          }
        />
        <Detail
          label={<Hint term="Bufferbloat" explain="How much the ping rises when the connection is busy. A+ means it barely moves; F means calls and games stutter while anything downloads." />}
          value={<GradeBadge grade={r.grade} />}
        />
        {previous && (
          <Detail
            wide
            label={<span>Compared with the test {whenText(previous.at, Date.now())}</span>}
            value={
              <span className="tabular-nums">
                <span className="text-speed-download">↓</span> {changeText(r.download.mbps, previous.downMbps)} ·{' '}
                <span className="text-speed-upload">↑</span> {changeText(r.upload.mbps, previous.upMbps)} · ping {changeText(r.latency.idleMs, previous.pingMs)}
              </span>
            }
          />
        )}
      </div>
      <EmptyStateButton icon={RotateCcw} primary onClick={startSpeedTest}>Test again</EmptyStateButton>
      <ServerFooter server={r.server} onShowOnMap={onShowOnMap} />
    </>
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
    <div role="alert" className="flex flex-col items-center gap-3 text-center">
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
    <div className="flex flex-col items-center gap-3 text-center">
      <p className="text-[13px] font-semibold text-foreground">Test cancelled</p>
      <p className="text-xs text-muted-foreground">Nothing was recorded.</p>
      <GoButton />
    </div>
  );
}

// --- pieces ----------------------------------------------------------------------

/** Ping, jitter, download, upload: filled in as each phase finishes, a dash until then. */
function Tiles({ state, large = false }: { state: SpeedState; large?: boolean }) {
  const ping = livePing(state);
  const jitterMs = state.result?.latency.jitterMs ?? state.liveJitterMs;
  const tiles: { key: string; icon: React.ReactNode; label: React.ReactNode; value: string | null; unit: string; live: boolean }[] = [
    { key: 'down', icon: <ArrowDown className="h-3.5 w-3.5 text-speed-download" />, label: 'Download', value: state.downloadMbps === null ? null : formatMbps(state.downloadMbps), unit: 'Mb/s', live: state.phase === 'download' },
    { key: 'up', icon: <ArrowUp className="h-3.5 w-3.5 text-speed-upload" />, label: 'Upload', value: state.uploadMbps === null ? null : formatMbps(state.uploadMbps), unit: 'Mb/s', live: state.phase === 'upload' },
    { key: 'ping', icon: <Activity className="h-3.5 w-3.5" />, label: 'Ping', value: ping === null ? null : fmtMsValue(ping), unit: 'ms', live: state.phase === 'latency' },
    {
      key: 'jitter', icon: <Activity className="h-3.5 w-3.5 opacity-60" />,
      label: <Hint term="Jitter" explain="How much the ping varies from one measurement to the next. Low jitter keeps calls and games smooth." />,
      value: jitterMs === null ? null : fmtMsValue(jitterMs), unit: 'ms', live: state.phase === 'latency',
    },
  ];
  return (
    <div className="grid w-full grid-cols-2 gap-3 md:grid-cols-4">
      {tiles.map((t) => (
        <div key={t.key}
          className={`rounded-lg border bg-card px-3 py-2.5 transition-colors duration-200 ${
            !t.live ? 'border-border' : t.key === 'up' ? 'border-speed-upload/70' : t.key === 'down' ? 'border-speed-download/70' : 'border-primary/50'}`}>
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            {t.icon}{t.label}
          </div>
          <div className="mt-1 flex items-baseline gap-1">
            {/* A pending figure is a quiet dash at the figure's own height, with no
                unit beside it - a long dash and "Mb/s" read as a rule with a label. */}
            <span className={`${large ? 'text-3xl' : 'text-2xl'} font-semibold tabular-nums leading-none ${t.value === null ? 'text-muted-foreground/50' : 'text-foreground'}`}>
              {t.value ?? '–'}
            </span>
            {t.value !== null && <span className="text-xs text-muted-foreground">{t.unit}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

function Detail({ label, value, wide = false }: { label: React.ReactNode; value: React.ReactNode; wide?: boolean }) {
  return (
    <div className={`flex min-w-0 items-center justify-between gap-3 rounded-lg border border-border bg-card px-3 py-2 ${wide ? 'sm:col-span-2' : ''}`}>
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className="min-w-0 text-sm text-foreground">{value}</span>
    </div>
  );
}

/** A term with a one-line explanation, on hover and on keyboard focus alike. */
function Hint({ term, explain }: { term: string; explain: string }) {
  return (
    <span tabIndex={0} aria-label={`${term}: ${explain}`}
      className="group relative cursor-help underline decoration-dotted underline-offset-2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm">
      {term}
      <span role="tooltip"
        className="pointer-events-none absolute bottom-full left-0 z-20 mb-1.5 hidden w-64 rounded-md border border-border bg-popover px-2.5 py-1.5
          text-[11px] font-normal leading-snug text-popover-foreground shadow-lg no-underline group-hover:block group-focus:block">
        {explain}
      </span>
    </span>
  );
}

const GRADE_TONE: Record<BloatGrade, string> = {
  'A+': 'bg-success/15 text-success border-success/40',
  A: 'bg-success/15 text-success border-success/40',
  B: 'bg-warning/15 text-warning border-warning/40',
  C: 'bg-warning/15 text-warning border-warning/40',
  D: 'bg-danger/15 text-danger border-danger/40',
  F: 'bg-danger/15 text-danger border-danger/40',
};
const GRADE_WORD: Record<BloatGrade, string> = {
  'A+': 'barely moves', A: 'small rise', B: 'some rise', C: 'noticeable', D: 'large', F: 'severe',
};

function GradeBadge({ grade }: { grade: BloatGrade }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`rounded border px-1.5 py-px text-xs font-bold ${GRADE_TONE[grade]}`}>{grade}</span>
      <span className="text-xs text-muted-foreground">{GRADE_WORD[grade]}</span>
    </span>
  );
}

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
    <div className="flex flex-col items-center gap-1.5">
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
    <p className="flex flex-wrap items-center justify-center gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
      <ServerIsp city={server.coloCity} colo={server.colo} isp={server.isp} inline />
      {server.ip && <span>{'·'} Your address <span className="font-mono">{server.ip}</span></span>}
    </p>
    </div>
  );
}

function HistoryTable({ history, onClear }: { history: SpeedHistoryEntry[]; onClear: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const now = Date.now();
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
        <table className="w-full text-xs">
          <thead className="bg-secondary text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left font-medium">When</th>
              <th className="px-3 py-1.5 text-right font-medium"><span className="inline-flex items-center gap-1"><ArrowDown className="h-3 w-3 text-speed-download" aria-hidden />Download</span></th>
              <th className="px-3 py-1.5 text-right font-medium"><span className="inline-flex items-center gap-1"><ArrowUp className="h-3 w-3 text-speed-upload" aria-hidden />Upload</span></th>
              <th className="px-3 py-1.5 text-right font-medium">Ping</th>
              <th className="hidden px-3 py-1.5 text-center font-medium sm:table-cell">Grade</th>
              <th className="hidden px-3 py-1.5 text-left font-medium md:table-cell">Server and ISP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-card">
            {history.slice(0, 10).map((h) => (
              <tr key={h.at}>
                <td className="px-3 py-1.5 text-muted-foreground" title={new Date(h.at).toLocaleString()}>{whenText(h.at, now)}</td>
                <td className="px-3 py-1.5 text-right tabular-nums text-foreground">{formatMbps(h.downMbps)} <span className="text-muted-foreground">Mb/s</span></td>
                <td className="px-3 py-1.5 text-right tabular-nums text-foreground">{formatMbps(h.upMbps)} <span className="text-muted-foreground">Mb/s</span></td>
                <td className="px-3 py-1.5 text-right tabular-nums text-foreground">{fmtMsValue(h.pingMs)} <span className="text-muted-foreground">ms</span></td>
                <td className="hidden px-3 py-1.5 text-center sm:table-cell">{h.grade}</td>
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

// --- formatting --------------------------------------------------------------------

function fmtMsValue(ms: number): string {
  return ms < 10 ? ms.toFixed(1) : Math.round(ms).toString();
}
function fmtMs(ms: number | null): string {
  return ms === null ? '—' : `${fmtMsValue(ms)} ms`;
}

