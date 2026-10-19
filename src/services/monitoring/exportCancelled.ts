/**
 * The one error both monitoring exports throw when their signal aborts. It has a module of its own because
 * the Worker reaches `bundle.ts`, and importing it from `export.ts` drags the capture CSV writer and the
 * field registry into the Worker with it (`scripts/monitoring/bundle.ts` walks the Worker's graph).
 */

/** Thrown when the signal aborts; the UI tells it apart from a failure. */
export class ExportCancelled extends Error {
  constructor() {
    super('Export cancelled');
    this.name = 'ExportCancelled';
  }
}
