/**
 * What `html2canvas`, `dompurify` and `canvg` resolve to in the build.
 *
 * jsPDF imports all three lazily, and only from `doc.html()` and
 * `addSvgAsImage()` - neither of which the report calls. Vite still emits every
 * dynamic import it can resolve, so without the alias in `vite.config.ts` they
 * ship as a quarter of a megabyte of chunks nothing ever fetches.
 *
 * Throwing is the right behaviour if one of those paths is ever reached: jsPDF
 * catches a failed import and rejects with "Could not load html2canvas", which
 * names the problem, where an empty module would fail later and elsewhere.
 */
throw new Error('This module is not bundled with Inwire (see vite.config.ts).');

export {};
