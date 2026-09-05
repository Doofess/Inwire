import * as pdfjs from 'pdfjs-dist';
// Vite's `?url` suffix, which emits a hashed asset URL for the worker script.
//
// This is the same class of hazard `vite.config.ts` documents for maplibre: a
// library that ships its own worker as a separate asset, whose URL the
// dependency pre-bundler resolves wrongly and then fails silently. Handing
// pdfjs an explicit, bundler-produced URL sidesteps the guess entirely. If a
// PDF ever loads forever with no error, the proven next step is adding
// 'pdfjs-dist' to `optimizeDeps.exclude` beside maplibre-gl.
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

import type { ImportFailure } from './exportSchema';
import {
  PDF_REPORT_CREATOR_LEGACY,
  PDF_REPORT_SUBJECT,
  PDF_REPORT_SUBJECT_LEGACY,
} from './pdfReportFormat';
import { Fragment, fragmentsToRows } from './pdfTableLayout';

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

/**
 * Reading the packet table back out of an Inwire PDF report.
 *
 * This module is reached only through `await import()` from `tabularReaders.ts`
 * - both because pdfjs is around a megabyte, and because the `?url` import
 * above is Vite syntax that Node cannot evaluate, and the assertion scripts run
 * this package's siblings under Node.
 *
 * All this file does is get glyphs and their coordinates out of pdfjs. The
 * decision about which of those glyphs formed a table lives in
 * `pdfTableLayout.ts`, which has no pdfjs dependency and is therefore testable.
 *
 * Scope is deliberately narrow: **reports this app generated**. For our own
 * output the reconstruction is safe - we know the column headings and that the
 * table generator lays each cell down as one text run. For an arbitrary PDF it
 * is not, and a wrong guess produces plausible-looking packets that were never
 * on any wire. So anything unrecognised is refused rather than approximated.
 */

export async function readInwirePdf(
  file: File,
): Promise<{ ok: true; rows: string[][] } | { ok: false; failure: ImportFailure }> {
  // The loading task, not just the document: `destroy()` lives on the task,
  // and it is what tears down the worker's copy of the parsed file.
  let task: pdfjs.PDFDocumentLoadingTask;
  let doc: pdfjs.PDFDocumentProxy;
  try {
    const data = new Uint8Array(await file.arrayBuffer());
    task = pdfjs.getDocument({ data });
    doc = await task.promise;
  } catch (err) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message:
          'This PDF could not be opened. It may be corrupt, or password-protected. '
          + `(${err instanceof Error ? err.message : String(err)})`,
      },
    };
  }

  try {
    // Two-tier recognition. New reports announce themselves through document
    // properties; reports written before that existed are still recognisable by
    // their table header, which is why the layout scan is not gated on this.
    let announced = false;
    try {
      const meta = await doc.getMetadata();
      const info = meta.info as { Subject?: string; Creator?: string } | undefined;
      announced =
        info?.Subject === PDF_REPORT_SUBJECT
        || info?.Creator === 'Inwire'
        // Reports exported before the rename. See PDF_REPORT_SUBJECT_LEGACY.
        || info?.Subject === PDF_REPORT_SUBJECT_LEGACY
        || info?.Creator === PDF_REPORT_CREATOR_LEGACY;
    } catch {
      // Metadata is optional; fall through to the layout scan.
    }

    const pages: Fragment[][] = [];
    for (let pageNumber = 1; pageNumber <= doc.numPages; pageNumber++) {
      const page = await doc.getPage(pageNumber);
      const content = await page.getTextContent();

      const fragments: Fragment[] = [];
      for (const item of content.items) {
        if (!('str' in item)) continue;
        if (!item.str.trim()) continue;
        fragments.push({ text: item.str, x: item.transform[4], y: item.transform[5] });
      }
      pages.push(fragments);
    }

    const { rows, sawHeader } = fragmentsToRows(pages);

    if (rows.length <= 1) {
      return {
        ok: false,
        failure: {
          kind: 'no-table',
          message: announced || sawHeader
            ? 'This is an Inwire report, but its packet list is empty.'
            : 'This PDF has no Inwire packet table in it. PDF import only reads reports '
              + 'this app generated - any other PDF has no reliable table structure to read.',
        },
      };
    }

    return { ok: true, rows };
  } finally {
    // Frees the worker's copy of the document; without it every import leaks a
    // parsed PDF for the lifetime of the tab.
    await task.destroy();
  }
}
