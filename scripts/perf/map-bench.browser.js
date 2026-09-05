/**
 * Map render benchmark. Paste into the browser console of a DEV build with the
 * geo map open, or run it through the chrome-devtools MCP `evaluate_script`.
 *
 *   await nvMapBench()                  // 5 s globe drag, full report
 *   await nvMapBench({ seconds: 3 })
 *
 * Not a Node script and not part of `npm run check` - it drives a live map
 * through `window.__inwireMap`, which GeoMap.tsx exposes in dev builds only.
 *
 * Three numbers, and why all three:
 *
 *   - `fps` / `frameMs` from requestAnimationFrame. The honest end-to-end
 *     measure, but VSYNC-CAPPED: on a 144 Hz display a map costing 2 ms and one
 *     costing 6 ms both read 144. It only tells you something once frames drop.
 *     Also throttled to ZERO in a background tab, so measure in a foreground
 *     window or the numbers are fiction.
 *   - `renderMs`: median of `map._render()` + `gl.finish()`. CPU-side render
 *     cost plus a GPU sync. Sees cost under the vsync cap, but `finish()` on a
 *     discrete GPU under-reports GPU time.
 *   - `gpuMs`: EXT_disjoint_timer_query_webgl2 bracketing EVERY real frame the
 *     map renders during the drag, reported as p50/p95. The real GPU cost where
 *     the extension exists (Chrome on desktop GPUs; absent on software
 *     renderers, where `fps` is the truth anyway).
 *
 *     During the drag, not after it. The first version of this file timed one
 *     `_render()` after the gesture and read 5.4 ms on an RTX 4080 - then 0.05
 *     ms once the map had settled. The difference was tile fade and placement
 *     work still in flight, and it was misread as a permanent per-frame cost
 *     for an afternoon. Measure the frames the user actually sees.
 *
 * `arcRebuilds` counts ArcLayer.build() calls during the drag - the number that
 * Phase A1 of the performance plan exists to drive to zero.
 *
 * Compare conditions ABAB, never AB: `await nvMapAB('label', apply, restore)`
 * alternates twice and reports both medians, so a warm tile cache cannot be
 * mistaken for an optimisation.
 */
window.nvMapBench = async function nvMapBench({ seconds = 5 } = {}) {
  const map = window.__inwireMap;
  if (!map) throw new Error('window.__inwireMap missing - dev build with the map mounted?');
  const cv = map.getCanvas();
  const gl = map.painter.context.gl;
  const el = map.getCanvasContainer();

  // --- renderer identity, so a number is never read without knowing whose it is
  const dbg = gl.getExtension('WEBGL_debug_renderer_info');
  const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'hidden';

  // --- count arc buffer rebuilds
  const arcLayer = map.getLayer('inwire-arcs')?.implementation;
  let arcRebuilds = 0;
  const origBuild = arcLayer?.build;
  if (arcLayer && origBuild) arcLayer.build = function () { arcRebuilds++; return origBuild.apply(this, arguments); };

  // --- GPU timer queries around every frame the map really renders
  const tq = gl.getExtension('EXT_disjoint_timer_query_webgl2');
  const queries = [];
  const origRender = map._render;
  if (tq) {
    map._render = function (...a) {
      const q = gl.createQuery();
      gl.beginQuery(tq.TIME_ELAPSED_EXT, q);
      try { return origRender.apply(this, a); } finally { gl.endQuery(tq.TIME_ELAPSED_EXT); queries.push(q); }
    };
  }

  // --- drive a drag and sample rAF
  const r = el.getBoundingClientRect();
  const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  const fire = (type, x, y, buttons) => el.dispatchEvent(new MouseEvent(type, {
    bubbles: true, cancelable: true, clientX: x, clientY: y, button: 0, buttons, view: window,
  }));
  fire('mousedown', cx, cy, 1);
  const t0 = performance.now();
  let frames = 0; const deltas = []; let last = t0;
  await new Promise(res => {
    const step = () => {
      const now = performance.now(); const t = now - t0;
      frames++; deltas.push(now - last); last = now;
      fire('mousemove', cx + Math.sin(t / 300) * 220, cy + Math.cos(t / 500) * 60, 1);
      if (t < seconds * 1000) requestAnimationFrame(step); else res();
    };
    requestAnimationFrame(step);
  });
  fire('mouseup', cx, cy, 0);
  const elapsed = performance.now() - t0;
  if (arcLayer && origBuild) arcLayer.build = origBuild;
  map._render = origRender;

  deltas.sort((a, b) => a - b);
  const pct = q => +(deltas[Math.min(deltas.length - 1, Math.floor(deltas.length * q))] || 0).toFixed(1);

  // --- settled render cost, synchronous (not during interaction)
  const times = [];
  for (let i = 0; i < 20; i++) {
    const t = performance.now();
    map._render(0);
    gl.finish();
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);
  const renderMs = +times[10].toFixed(2);

  // --- collect the per-frame GPU times
  let gpuMs = null;
  if (tq) {
    await new Promise(r => setTimeout(r, 300));
    const samples = [];
    for (const q of queries) {
      if (gl.getQueryParameter(q, gl.QUERY_RESULT_AVAILABLE) && !gl.getParameter(tq.GPU_DISJOINT_EXT)) {
        samples.push(gl.getQueryParameter(q, gl.QUERY_RESULT) / 1e6);
      }
      gl.deleteQuery(q);
    }
    samples.sort((a, b) => a - b);
    const at = q => +(samples[Math.min(samples.length - 1, Math.floor(samples.length * q))] || 0).toFixed(2);
    gpuMs = samples.length ? { p50: at(0.5), p95: at(0.95), frames: samples.length } : null;
  }

  return {
    renderer,
    projection: map.getProjection()?.type,
    canvas: [cv.width, cv.height],
    megapixels: +(cv.width * cv.height / 1e6).toFixed(2),
    pixelRatio: map.getPixelRatio(),
    markers: document.querySelectorAll('.maplibregl-marker').length,
    arcSegments: arcLayer ? arcLayer.vertexCount / 6 : 0,
    fps: +(frames / (elapsed / 1000)).toFixed(1),
    frameMs: { p50: pct(0.5), p95: pct(0.95), p99: pct(0.99) },
    renderMsSettled: renderMs,
    gpuMs,
    arcRebuilds,
  };
};
'nvMapBench ready';

/** ABAB comparison. `apply`/`restore` are sync or async; each run is a fresh drag. */
window.nvMapAB = async function nvMapAB(label, apply, restore, { seconds = 3 } = {}) {
  const map = window.__inwireMap;
  const settle = () => new Promise(res => { let d = false; const f = () => { if (!d) { d = true; setTimeout(res, 400); } }; map.once('idle', f); setTimeout(f, 4000); map.triggerRepaint(); });
  const pick = r => ({ fps: r.fps, p95: r.frameMs.p95, gpu50: r.gpuMs?.p50 ?? null, gpu95: r.gpuMs?.p95 ?? null });
  const rows = [];
  for (let i = 0; i < 2; i++) {
    await settle(); rows.push(['A base', pick(await window.nvMapBench({ seconds }))]);
    await apply(); await settle(); rows.push(['B ' + label, pick(await window.nvMapBench({ seconds }))]);
    await restore();
  }
  await settle();
  return rows;
};
'nvMapBench ready';
