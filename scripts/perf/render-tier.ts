/**
 * Assertion tests for the map's render-tier classification.
 *
 *   npx tsx scripts/perf/render-tier.ts
 *
 * The degraded tier trades sharpness for frame rate, so the property that
 * matters most is the negative one: nothing that is not a software rasterizer
 * may ever be classified as one. The strings below are real - two of them were
 * read off this machine in the same afternoon, from two Chrome instances, one
 * on the GPU and one that had fallen back to WARP.
 */
import { tierForRenderer, TIER_SETTINGS } from '../../src/components/analytics/renderTier';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- Real strings -------------------------------------------------------------
check('RTX 4080 via ANGLE/D3D11 is a GPU',
  tierForRenderer('ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 (0x00002704) Direct3D11 vs_5_0 ps_5_0, D3D11)'), 'gpu');
check('Microsoft Basic Render Driver (WARP) is software',
  tierForRenderer('ANGLE (Microsoft, Microsoft Basic Render Driver (0x0000008C) Direct3D11 vs_5_0 ps_5_0, D3D11)'), 'software');
check('SwiftShader is software',
  tierForRenderer('ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)'), 'software');
check('llvmpipe is software', tierForRenderer('Mesa/X.org, llvmpipe (LLVM 15.0.7, 256 bits)'), 'software');
check('Apple M-series is a GPU', tierForRenderer('ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)'), 'gpu');
// An integrated GPU composites in hardware, which is the cost that mattered.
check('Intel UHD is a GPU, not software',
  tierForRenderer('ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)'), 'gpu');

// --- The negative property ---------------------------------------------------
check('a hidden renderer string is a GPU', tierForRenderer(null), 'gpu');
check('an undefined renderer string is a GPU', tierForRenderer(undefined), 'gpu');
check('an empty renderer string is a GPU', tierForRenderer(''), 'gpu');
check('an unrecognised renderer is a GPU', tierForRenderer('WebKit WebGL'), 'gpu');

// --- Settings are the right way round ----------------------------------------
// The negative property that matters most about the settings: no tier may buy
// frames by rendering fewer pixels than the display has. That was tried, it
// made the map soft, and it is not coming back by accident.
check('no tier reduces resolution',
  Object.values(TIER_SETTINGS).every(t => !('pixelRatioCap' in t)), true);
check('software has no tile cross-fade', TIER_SETTINGS.software.fadeDuration, 0);
check('gpu keeps the cross-fade', TIER_SETTINGS.gpu.fadeDuration > 0, true);
check('software draws at least one wall step', TIER_SETTINGS.software.wallSteps >= 1, true);
check('gpu draws every wall step', TIER_SETTINGS.gpu.wallSteps, 2);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All render-tier checks passed.');
process.exit(0);
