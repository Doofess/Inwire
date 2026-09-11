/**
 * A row the list can see but does not have yet.
 *
 * The packet list scrolls the whole capture, and most of a large capture is on
 * disk. A row whose chunk has not been read back renders as this: the right
 * height, in the right place, saying which of the two things is true.
 *
 * ## It must be exactly one row tall
 *
 * The virtualiser's arithmetic is `index * rowHeight` and nothing measures a
 * placeholder, so one that laid out taller than a real row would shift every
 * row below it and put the scroll position on the wrong frame. The height is
 * therefore set, not inherited - and it is the same `rowHeight` the window was
 * computed with rather than the CSS the density preference produces, because
 * those two are allowed to disagree for a frame after a density change and the
 * arithmetic is the half that has to win.
 *
 * ## No spinner
 *
 * `HexViewer` spins because it is one thing, in the middle of a pane, and the
 * wait is the whole content. Forty spinning rows in a table is a strobe, and
 * they would all resolve within a chunk read of each other. A dim rule that
 * pulses says "coming" without competing with the rows around it for
 * attention.
 *
 * `unavailable` is not dimmed the same way, because it is not a wait. It says
 * what happened, once, in the muted amber every other honest-loss message in
 * the app uses.
 */
import type { Row } from '../../lib/rowSource';

interface PlaceholderRowProps {
  row: Extract<Row, { state: 'loading' } | { state: 'unavailable' }>;
  columnCount: number;
  /** Position in the whole list, for the screen reader's "row N of M". */
  rowIndex: number;
  height: number;
}

export function PlaceholderRow({ row, columnCount, rowIndex, height }: PlaceholderRowProps) {
  const loading = row.state === 'loading';
  return (
    <tr
      role="row"
      aria-rowindex={rowIndex + 2}
      aria-busy={loading || undefined}
      style={{ height }}
    >
      <td
        colSpan={columnCount}
        className="px-2 overflow-hidden whitespace-nowrap"
        style={{ height, padding: 0 }}
      >
        {loading ? (
          <div className="flex items-center gap-2 px-2 opacity-40">
            {/* A bar rather than text: the row is about to be replaced by real
                content, and a word that flashes for 30 ms and vanishes reads
                as a glitch. */}
            <span className="h-[3px] w-16 rounded-full bg-current animate-pulse" />
            <span className="h-[3px] w-24 rounded-full bg-current animate-pulse" />
            <span className="h-[3px] flex-1 rounded-full bg-current animate-pulse" />
          </div>
        ) : (
          <div className="px-2 font-mono text-[11px] text-amber-600 dark:text-amber-400 truncate">
            Frame {(row.ordinal + 1).toLocaleString()} is not readable from the capture store.
          </div>
        )}
      </td>
    </tr>
  );
}
