/**
 * Which kind of renderer the map is about to draw on.
 *
 * Two tiers, not the three a first draft planned, because the measurements
 * did not support three. On a discrete GPU the whole map costs ~0.1 ms a frame
 * and there is nothing to degrade. On a software rasterizer - Chrome falling
 * back to WARP or SwiftShader when GPU acceleration is off, which is what
 * remote desktop, VMs, driver crashes and GPU blocklists all produce - the same
 * frame costs 25+ ms.
 *
 * **Nothing here reduces resolution.** An earlier version dropped `pixelRatio`
 * to 0.66 on software, which bought about 20% and made every label and
 * coastline soft - a bad trade, and the wrong kind of answer: a map you cannot
 * read smoothly is not better than a map that reads sharply at 40 fps. What is
 * left are the two knobs that cost nothing anyone can see:
 *
 *   - no tile cross-fade (`fadeDuration: 0`): MapLibre's 300 ms default drives
 *     ~18 animated frames per tile arrival, for a fade nobody is watching
 *   - one land-wall fill instead of two: the wall is two translated copies of
 *     the whole water polygon, so the second is a full extra fill per frame for
 *     a second tone on a shadow
 *
 * Neither is worth applying on a GPU, where the whole frame is ~0.1 ms.
 *
 * Detection is by the renderer string, which is the honest signal here: the
 * failure being guarded against is "there is no GPU", and that is exactly what
 * the string says. It is NOT a proxy for "this GPU is slow" - an integrated
 * GPU reports as hardware and is treated as one, because an integrated GPU
 * still composites for free, and compositing was the cost, not rasterising.
 *
 * `tierForRenderer` is pure and asserted in `scripts/perf/render-tier.ts`;
 * `probeRenderTier` is the browser half and is memoised, because it spends a
 * WebGL context to ask.
 */

export type RenderTier = 'gpu' | 'software';

/**
 * The software rasterizers Chrome and Firefox fall back to. `Basic Render
 * Driver` is Microsoft WARP; SwiftShader is Chrome's own; llvmpipe is Mesa's.
 */
const SOFTWARE_RENDERERS = /swiftshader|basic render driver|llvmpipe|softpipe|software/i;

/**
 * Classifies a `WEBGL_debug_renderer_info` string.
 *
 * Unknown means `gpu`. A browser that hides its renderer string (Firefox with
 * privacy.resistFingerprinting, some enterprise policies) is not thereby slow,
 * and the degraded tier is the one that must never be applied by accident.
 */
export function tierForRenderer(renderer: string | null | undefined): RenderTier {
  if (!renderer) return 'gpu';
  return SOFTWARE_RENDERERS.test(renderer) ? 'software' : 'gpu';
}

let probed: RenderTier | null = null;

/**
 * Asks the browser which tier it is, once per page.
 *
 * Reads the renderer off a throwaway context and releases it straight away
 * with `WEBGL_lose_context`: contexts are a scarce per-process resource (this
 * app once ran out of them), and the answer does not change while the page is
 * open. Must run BEFORE the map is constructed, because `fadeDuration` is a
 * constructor option with no setter.
 */
export function probeRenderTier(): RenderTier {
  if (probed) return probed;
  let renderer: string | null = null;
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    if (gl) {
      const info = gl.getExtension('WEBGL_debug_renderer_info');
      if (info) renderer = String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL));
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  } catch {
    // No WebGL at all. The map will say so itself when it fails to construct;
    // this probe only decides how hard to try.
  }
  probed = tierForRenderer(renderer);
  return probed;
}

/** What each tier gets. Kept in one place so the trade-offs read as a set. */
export const TIER_SETTINGS: Record<RenderTier, {
  /** MapLibre `fadeDuration` for tile cross-fades, ms. */
  fadeDuration: number;
  /** How many of `LAND_LIFT`'s wall steps to draw. */
  wallSteps: number;
}> = {
  gpu: { fadeDuration: 300, wallSteps: 2 },
  software: { fadeDuration: 0, wallSteps: 1 },
};
