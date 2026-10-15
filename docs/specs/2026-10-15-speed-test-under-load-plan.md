# Speed test "Under Load" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the speed test's consumer dial with an instrument that answers "how does this link behave under load": two headline figures, latency boxes per phase, and a live throughput trace.

**Architecture:** The engine (`electron/speedTest/engine.ts`) already measures everything needed and throws half of it away. It now puts the raw slice trace, loaded-latency samples, ramp times and a summary into `SpeedResult`, built by a pure `summarise()` in `src/services/speedTest/stats.ts`. The reducer keeps the live trace and samples, bounded. Four SVG components draw them, and `SpeedGauge.tsx` goes.

**Tech Stack:** TypeScript, React 19, Tailwind 4, plain SVG (no chart dependency), plain-`tsx` assertion scripts, Playwright drives.

**Spec:** `C:\Users\Home Office\.claude\plans\sunny-rolling-codd.md`, section "Plan C".

## Global Constraints
- No new dependency. SVG by hand.
- `src/services/` imports no Electron and no `node:*`.
- **Headline:** the headline figure stays the **median** slice (`TransferFigure.mbps`), as ADR 0054 calibrated it. P90 and the mean are cursors on the trace only.
- **Responsiveness:** RPM is `rpm(P50 loaded RTT)` and is labelled "Responsiveness (approx.)". The bands are Low below 300, Medium from 300 to 1000, and High above 1000.
- **Grade:** the bracket input is `max(down, up)` loaded median RTT, the same input `bloatGrade` gets (`engine.ts:132`).
- **History:** new fields are optional and old entries render "–", never 0.
- **Colour:** only download (`text-speed-download`) and upload (`text-speed-upload`) are coloured. Grade colours come from the status tokens, and grids and axes are neutral.
- **Type:** numbers are `font-mono tabular-nums`.
- **Motion:** obeys `motionStore` through `<MotionConfig>`. Don't use a raw media query.
- **Width:** content is at most `max-w-[46rem]`.
- **Test windows:** every launch goes through `launchApp` (background, no focus steal).

## Review Focus
1. **A phase where every loaded probe failed.** It draws "no samples", and RPM shows "–", not 0 or NaN. *Test:* `scripts/speed-test/stats.ts` "empty phase".
2. **Old history entries** without `rpm` or loaded figures. They render "–" in the table and the dot strip. *Test:* `scripts/speed-test/method.ts` "old entry keeps no rpm".
3. **A transfer too short to pass warm-up**, i.e. a cap hit early. The mean falls back the way `transferFigure` does and never divides by zero. *Test:* `stats.ts` "short transfer mean".
4. **Latency spanning decades** (0.3 ms to 900 ms) on the log axis. Ticks are clamped and nothing is drawn outside the box. *Test:* `stats.ts` "log axis clamps".
5. **A stale ghost** from a trace stored by an older version, or a damaged one. It is dropped by the normaliser, not drawn. *Test:* `method.ts` "damaged last trace is dropped".

---

### Task 1: Engine and protocol carry the trace, samples, ramps and summary

**Files:**
- Modify: `src/services/speedTest/protocol.ts`
- Create: `src/services/speedTest/stats.ts`
- Modify: `src/services/speedTest/method.ts`. Add the RPM band and remove `GAUGE_MARKS` / `gaugeFraction` in Task 4, once nothing uses them.
- Modify: `electron/speedTest/engine.ts` (`idleLatency`, `transfer`, `runSpeedTest`)
- Test: `scripts/speed-test/stats.ts` (new), `scripts/speed-test/engine.ts` (extend)

**Interfaces (produces):**
```ts
// protocol.ts
export interface LatencySample { tMs: number; rttMs: number; ttfbMs: number }
export interface Spread { n: number; p10: number; p25: number; p50: number; p75: number; p90: number }
export interface SpeedSummary {
  idle: Spread | null; download: Spread | null; upload: Spread | null; // from ttfbMs
  rpm: number | null;                    // rpm(max(down,up) loaded median RTT); null if neither phase has samples
  downMeanMbps: number | null; upMeanMbps: number | null;
}
type Transfer = TransferFigure & {
  loadedLatencyMs: number | null; connections: number;
  trace: number[];          // Mb/s per SLICE_MS slice from t=0, partial last slice dropped
  loaded: LatencySample[];  // tMs from the transfer's start
  rampsAtMs: number[];      // elapsed ms of each spawn(RAMP_STEP)
};
// SpeedResult: download/upload become Transfer; latency gains `idle: LatencySample[]`; add `summary: SpeedSummary`
// events: progress gains `sliceMbps: number`; loaded gains `ttfbMs: number`, `tMs: number`; latency gains `ttfbMs: number`
// method.ts
export type RpmBand = 'Low' | 'Medium' | 'High';
export const RPM_BANDS = { mediumFrom: 300, highFrom: 1000 } as const; // cite Apple networkQuality / IETF draft-ietf-ippm-responsiveness
export function rpmBand(rpm: number): RpmBand;
// stats.ts
export function spread(values: readonly number[]): Spread | null;
export function meanPastWarmup(trace: readonly number[], warmupMs: number, sliceMs: number): number | null;
export function summarise(r: { idle: LatencySample[]; download: Transfer; upload: Transfer }, warmupMs: number): SpeedSummary;
export function logScale(minMs: number, maxMs: number, width: number): (ms: number) => number; // clamps into [0,width]
export function latencyDomain(spreads: (Spread | null)[]): [number, number]; // decade-padded, min 0.5 ms, max ≥ 2× min
```

- [ ] **Step 1: Write `scripts/speed-test/stats.ts`** with these assertions:
  - `spread([1..10])`: p50 is 5.5 and n is 10.
  - `spread([])` is null.
  - **"empty phase":** `summarise` with `download.loaded=[]` and `upload.loaded=[]` gives `download: null`, `upload: null` and `rpm: null`.
  - With down loaded RTTs of `[20,20,20]` and up of `[40,40,40]`, rpm is `1500`.
  - `rpmBand(299)` is `'Low'`, `rpmBand(300)` is `'Medium'`, `rpmBand(1000)` is `'Medium'` and `rpmBand(1001)` is `'High'`.
  - `meanPastWarmup([10,10,10,10,100,100,100,100], 400, 100)` is 100.
  - **"short transfer mean":** `meanPastWarmup([50,70], 1500, 100)` is 70, the second half, like `transferFigure`. `meanPastWarmup([], 1500, 100)` is null.
  - **"log axis clamps":** with `logScale(1, 100, 500)`, an input of 10 gives 250, an input of 0.01 gives 0, and an input of 1e6 gives 500.
  - `latencyDomain([null])` is `[0.5, 1000]`. When the spreads are null, the fallback domain is `[1, 100]`; pin that.
- [ ] **Step 2:** Run `npx tsx scripts/speed-test/stats.ts`. Expect it to FAIL because the module isn't found.
- [ ] **Step 3: Implement** `stats.ts` and `rpmBand` / `RPM_BANDS` in `method.ts`. `spread` uses `quantile`, and `summarise` takes `rpm` from `method.ts`.
- [ ] **Step 4:** Run `npx tsx scripts/speed-test/stats.ts`. Expect all PASS.
- [ ] **Step 5: Engine changes.**
  - In `idleLatency`, record `{tMs, rttMs: ms, ttfbMs: max(0.1, firstByteMs - serverTimeMs(timing))}` per sample, and emit `ttfbMs`.
  - In `transfer`:
    - the progress tick adds `sliceMbps = counter.mbpsOver(t-SLICE_MS, t)`;
    - the probe pushes a `LatencySample`;
    - `spawn` called from `ramp` pushes `elapsed()` to `rampsAtMs`;
    - on return, `trace = counter.slices.slice(0,-1).map(b => toMbps(b, SLICE_MS))`.
  - In `runSpeedTest`, add `latency.idle` and `summary: summarise(..., run.warmupMs)`. Make `warmupMs` readable, not private.
- [ ] **Step 6: Extend `scripts/speed-test/engine.ts`.** On its existing local run, assert:
  - `result.download.trace.length > 0` and is close to `transferMs/100`;
  - `result.download.loaded.length > 0`, and every `loaded[i].tMs` is in `[0, transferMs]`;
  - `result.summary.download?.n === result.download.loaded.length`;
  - `result.summary.rpm > 0`;
  - some `progress` event has `sliceMbps` as a number;
  - idle's `ttfbMs >= rttMs` holds against the local server (no cfL4 there, so they are equal; assert `>=`).
- [ ] **Step 7:** Run `npx tsx scripts/speed-test/engine.ts && npx tsx scripts/speed-test/stats.ts && npm run lint`. Expect PASS. (`method.ts` still compiles against the old dial until Task 4.)
- [ ] **Step 8: Commit:** "The speed test keeps its trace, its loaded samples and their spread".

### Task 2: Reducer, history and the last trace

**Files:**
- Modify: `src/services/speedTest/state.ts`, `src/services/speedTest/history.ts`
- Create: `scripts/speed-test/state.ts`, taking the reducer section out of `scripts/speed-test/method.ts`
- Modify: `scripts/speed-test/method.ts` (history cases)

**Interfaces (produces):**
```ts
// state.ts: SpeedState loses `spark`; gains
trace: { download: TracePoint[]; upload: TracePoint[] };   // TracePoint = { tMs: number; mbps: number } from progress.sliceMbps
loaded: { idle: LatencySample[]; download: LatencySample[]; upload: LatencySample[] };
rampsAtMs: { download: number[]; upload: number[] };       // from a rise in progress.connections
export const TRACE_POINTS = 200; export const SAMPLE_POINTS = 200;
// history.ts: SpeedHistoryEntry gains optional rpm?: number|null; loadedDownMs?: number|null; loadedUpMs?: number|null
export interface LastTrace { at: number; download: number[]; upload: number[]; warmupMs: number }
export const lastTraceStore;  // createPreferenceStore<LastTrace|null>('inwire.speedTestLastTrace.v1', normalizeLastTrace, null)
export function normalizeLastTrace(raw: unknown): LastTrace | null; // arrays of finite ≥0 numbers, ≤ 400 each, else null
```

- [ ] **Step 1: Write the `scripts/speed-test/state.ts` assertions** (keep every existing reducer check; its `spark` check becomes trace):
  - Two progress events with sliceMbps 500 and 900 give `trace.download` of `[{tMs:100,mbps:500},{tMs:200,mbps:900}]`.
  - Three `loaded` events land in `loaded.download` in order.
  - 300 progress events keep `TRACE_POINTS`, the newest.
  - Phase `upload` leaves `trace.download` intact, so the done view can still draw it.
  - Connections going from 12 to 14 append one `rampsAtMs.download`.
  - A `latency` event appends to `loaded.idle`.
  - A `phase: 'connecting'` (a new run) clears all of these, through `STARTING`.
- [ ] **Step 2: Add the history cases to `method.ts`:**
  - **"old entry keeps no rpm":** normalizing `{at,downMbps,upMbps,pingMs}` yields `rpm: null`.
  - `historyEntry(result)` carries `rpm` and the loaded medians.
  - **"damaged last trace is dropped":** `normalizeLastTrace({at:1,download:[1,'x'],upload:[],warmupMs:1500})` is null, and `normalizeLastTrace({at:1,download:[1,2],upload:[3],warmupMs:1500})` round-trips.
- [ ] **Step 3:** Run both scripts. Expect FAIL.
- [ ] **Step 4: Implement.** `recordResult` also sets `lastTraceStore` from `result.download.trace`, `result.upload.trace` and `WARMUP_MS`, but **only after** the sheet has read the previous trace for its ghost. So the sheet reads the ghost from `lastTraceStore` at the start of a run (a `useRef` captured when status becomes `running`), and `recordResult` overwrites it on done.
- [ ] **Step 5:** Run both scripts and `npm run lint`. Expect PASS. Lint may still fail in `SpeedTestSheet.tsx` / `SpeedTestSection.tsx` where they read `spark`. If so, replace `spark` with `trace[phase].map(p => p.mbps)` there for now; Task 3 rewrites them anyway.
- [ ] **Step 6: Commit:** "The speed test's state keeps the live trace and the loaded samples".

### Task 3: The four components and the sheet

**Files:**
- Create: `src/components/speedtest/SpeedHeadline.tsx`, `LatencyBoxes.tsx`, `ThroughputTrace.tsx`, `PhaseStrip.tsx`
- Modify: `src/components/speedtest/SpeedTestSheet.tsx` (replaces `Tiles`, the gauge, `Sparkline`, `Detail` and the loaded-latency / bufferbloat details), `SpeedTestSection.tsx`
- Delete: `src/components/speedtest/SpeedGauge.tsx`
- Modify: `scripts/speed-test/stubServer.ts`. Add `jitterMs` (default 4), drawn as `jitterMs * -ln(U)`, a long tail, in place of `Math.random()*1.5`.

**Component contracts.** Each one is a pure render of props and takes no store.
- **`SpeedHeadline`.**
  - Props: `{ down: number|null; up: number|null; live: 'download'|'upload'|null; liveMbps: number; rpm: number|null; grade: BloatGrade|null }`.
  - Draws two figures, Down and Up, at `text-5xl font-mono tabular-nums`, with the unit `Mb/s` in muted text.
  - A pending figure is a muted "–". The live one shows `liveMbps` in its colour.
  - The second line reads `Responsiveness (approx.) NNN RPM · Medium`, plus a grade letter in a status-toned square with the `GRADE_WORD` hint.
  - Before the run ends, RPM shows "–".
- **`LatencyBoxes`.**
  - Props: `{ idle, download, upload: Spread|null; idleRttMs: number|null; loadedRttMs: number|null; live: SpeedPhase|null }`.
  - Draws an SVG, `role="img"`, with `aria-label` "Latency: idle N ms, downloading N ms, uploading N ms" (or "no samples").
  - Three rows, each with a 90px label and a log axis from `latencyDomain`.
  - Each box is p25–p75, with whiskers at p10–p90 and a median tick.
  - The bloat-band thresholds (`idleRttMs` + 5/30/60/200/400) are faint ticks, each labelled with its grade letter.
  - A bracket from `idleRttMs` to `loadedRttMs` reads `+N ms under load`.
  - A caption: "Boxes: time to first byte. Figures: the server's round trip."
  - An empty phase reads "no samples" in muted italic.
- **`ThroughputTrace`.**
  - Props: `{ direction: 'download'|'upload'; points: {tMs,mbps}[]; durationMs: number; warmupMs: number; p90: number|null; mean: number|null; ghost: number[]|null; loaded: LatencySample[]; live: boolean }`.
  - Draws an SVG `aria-label={`${Dir} trace: ${formatMbps(last or median)} Mb/s`}`.
  - The trace is a step path in its direction's colour.
  - The warm-up band is `fill-muted`, labelled "not counted".
  - Dashed P90 and mean cursors carry their right-edge labels.
  - The ghost is a `stroke-muted-foreground/40` path.
  - Loaded dots sit on a secondary latency strip, 16px, under the trace and on the same x axis.
  - Two stacked traces (download, then upload), each 96px high.
- **`PhaseStrip`.**
  - Props: `{ phase: SpeedPhase|null; done: boolean; rampsAtMs: {download:number[];upload:number[]}; durationMs: number }`.
  - Four segments: Connect, Latency, Download and Upload. The current one is lit with `bg-primary/15 text-foreground`, and finished ones get a check.
  - The download and upload segments carry ramp ticks.

**The sheet.**
- **Running:** a `PhaseStrip`, a `SpeedHeadline`, a `LatencyBoxes` that fills in live (spreads from `spread(state.loaded.x.map(s=>s.ttfbMs))`), the two traces and Cancel.
- **Done:** the same, from `state.result`, with the footer. The footer holds the existing `ServerFooter`, a "Connections N ↓ / N ↑" line, the `changeText` deltas and Test again, as primary.
- **Idle:** the GO button stays, but it becomes a 40×40 rounded-lg primary "Run test" button, not a 160px ring. With it go the consent line and the history.
- **History table:** a column for RPM, plus a dot strip in the Ping column (idle dot, loaded dot, 48px log track).
- **`Announcer`:** unchanged.

**`SpeedTestSection`.** When done, it reads one line: `↓ N · ↑ N Mb/s · NNN RPM · A`. Running reads `Testing download… N Mb/s`, as today.

- [ ] **Step 1: Update `scripts/electron/speed-test-ui.ts`.**
  - The `svg[aria-label^="Download:"]` locators become `svg[aria-label^="Download trace:"]`, and the same for Upload.
  - Add `checkTrue('the latency boxes draw', locator('svg[aria-label^="Latency:"]').count()>0)` after Test again.
  - Add `checkTrue('responsiveness is labelled approximate', visible(/Responsiveness \(approx\.\)/))`.
- [ ] **Step 2: Update `scripts/electron/speed-test-shots.ts`.** `dialOn` uses `trace:`, and `'Measuring ping'` becomes waiting for the PhaseStrip's `Latency` segment carrying `aria-current="step"`.
- [ ] **Step 3: Implement** the four components, the sheet and the section, and delete `SpeedGauge.tsx`. Run `frontend-design` before writing the styles. Fix the comment at `registry.ts:382`.
- [ ] **Step 4:** Run `npm run lint && npm run build`, then `npx tsx scripts/electron/speed-test-ui.ts`. Expect all PASS.
- [ ] **Step 5: Screenshot pass.**
  - Run `npx tsx scripts/electron/speed-test-shots.ts --themes light,dark` (background).
  - Look at idle, running in each of latency, download and upload, done, failed and cancelled, and the section.
  - Fix what the screenshots show, then re-shoot.
- [ ] **Step 6: Commit:** "The speed test reads as an instrument: latency under load and a live trace".

### Task 4: Retire the dial's arithmetic, re-measure and document

**Files:**
- Modify: `src/services/speedTest/method.ts`. Remove `GAUGE_MARKS` and `gaugeFraction`.
- Modify: `scripts/speed-test/method.ts`. Drop the gauge checks at :92-96.
- Modify: `test/perf/ceilings.json`. Lower it to the measured size if the bundle fell.
- Modify: `docs/decisions/0054-*.md`. Add an amendment covering the latency-first look, the dial removed, the median kept as the headline, RPM approximate with its cited bands, the box spread from TTFB and why.
- Modify: `src/components/CLAUDE.md`. Describe the speed test sheet's layout, replacing any dial mention.
- [ ] **Step 1:** Remove the gauge code. Run `grep -rn "gaugeFraction\|GAUGE_MARKS\|SpeedGauge\|Sparkline" src scripts electron`; expect nothing.
- [ ] **Step 2:** Run `npm run build`, then `npx tsx scripts/perf/bundle-size.ts`. If it reports headroom, lower the ceiling to the measured figure.
- [ ] **Step 3:** Run `npm run lint && npm run check`. Expect all PASS.
- [ ] **Step 4:** Do one live run with `npx tsx scripts/electron/speed-test-drive.ts` against Cloudflare. Confirm the median download is within ADR 0054's calibration band of the last history entry. If it isn't, say so; don't tune.
- [ ] **Step 5: Commit:** "The dial's arithmetic goes, and ADR 0054 says what replaced it".
