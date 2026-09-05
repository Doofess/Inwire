/**
 * The contract between the PDF writer and the PDF reader.
 *
 * Deliberately its own module with no imports. The writer lives in the export
 * components and the reader in `pdfTable.ts`, which pulls in a megabyte of
 * pdfjs and Vite-only syntax - so if the writer took these constants from the
 * reader, every export would eagerly load a PDF parser it never uses, and the
 * Node assertion script could not import the writer at all.
 *
 * Both halves have to move together: the reader finds the packet table by
 * matching these exact headings.
 */

/** Stamped into the report's document properties; the strong recognition signal. */
export const PDF_REPORT_SUBJECT = 'inwire-packet-report-v1';

/**
 * What reports written before the app was renamed announce themselves as.
 *
 * Read, never written. A user's export folder outlives a rename, and a reader
 * that only knows the current name silently stops recognising every report the
 * app produced up to that day - which presents as "this PDF has no packet
 * table in it", the least helpful possible way to say "you renamed the app".
 */
export const PDF_REPORT_SUBJECT_LEGACY = 'netview-packet-report-v1';

/** The creator string on those same older reports. See above. */
export const PDF_REPORT_CREATOR_LEGACY = 'NetView';

/** The Packet List table's headings, as written and as matched. */
export const PDF_PACKET_TABLE_HEAD = ['ID', 'Proto', 'Source', 'Destination', 'Length', 'Info'];

/** How many frames the packet-list table carries. A report is a document. */
export const PDF_PACKET_LIMIT = 100;

/** How much of each Info string survives into the table. */
export const PDF_INFO_LIMIT = 50;
