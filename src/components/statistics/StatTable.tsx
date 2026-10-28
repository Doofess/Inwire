import React, { useMemo, useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { MICRO_LABEL } from '../common/typography';

/**
 * The sortable table the statistics tabs are made of.
 *
 * One component rather than three, because Conversations, Endpoints and
 * Resolved Addresses differ only in their columns: the sorting, the row
 * actions, the number formatting and the "nothing here yet" state are the same
 * question every time, and three copies of it is three places for them to
 * drift apart.
 *
 * Sorting is by an accessor rather than by the rendered cell. A column showing
 * "1.4 MB" has to sort by 1_400_000, and a column showing a host name has to
 * sort by the name while the row still knows the address behind it - both are
 * impossible to get right from the rendered string.
 */

export interface StatColumn<T> {
  key: string;
  label: string;
  align?: 'left' | 'right';
  /** What the cell shows. */
  render: (row: T) => React.ReactNode;
  /** What the column sorts by. Omit to make the column unsortable. */
  sortValue?: (row: T) => number | string;
  /** Rendered width hint, as a Tailwind class. */
  className?: string;
  /**
   * Pin the column to the table's right edge while the rest scrolls under it,
   * as a Tailwind `right-*` class naming the offset. For the one column that
   * answers the question the row exists for, so it cannot be scrolled out of
   * view at the 1024 minimum with a side panel open.
   */
  pinRight?: string;
}

/** The classes a pinned cell needs: opaque, so what scrolls under it is hidden. */
const pinned = (c: { pinRight?: string }, header: boolean) =>
  c.pinRight === undefined
    ? ''
    : `sticky ${c.pinRight} bg-card ${header ? 'z-10' : 'group-hover:bg-[color-mix(in_srgb,var(--accent)_60%,var(--card))]'} border-l border-border/40`;

interface StatTableProps<T> {
  rows: readonly T[];
  columns: readonly StatColumn<T>[];
  rowKey: (row: T) => string;
  /** Column sorted on first paint. Descending, since these are all "how much". */
  initialSort?: string;
  /** Left-click a row. */
  onRowClick?: (row: T) => void;
  /**
   * Right-click a row. The MENU belongs to the caller and wraps the whole
   * table in one trigger - the same arrangement the detail tree uses, and for
   * the same reason: one menu for a thousand rows rather than a thousand
   * menus. This only says which row the pointer was over.
   */
  onRowContextMenu?: (row: T) => void;
  empty: string;
}

export function StatTable<T>({
  rows,
  columns,
  rowKey,
  initialSort,
  onRowClick,
  onRowContextMenu,
  empty,
}: StatTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(initialSort ?? null);
  const [descending, setDescending] = useState(true);

  const sorted = useMemo(() => {
    const column = columns.find((c) => c.key === sortKey);
    if (!column?.sortValue) return rows;
    const value = column.sortValue;
    // A copy: `rows` is the caller's memo and sorting in place would reorder
    // the array it hands out next render as well.
    return [...rows].sort((a, b) => {
      const l = value(a);
      const r = value(b);
      const cmp = typeof l === 'number' && typeof r === 'number'
        ? l - r
        : String(l).localeCompare(String(r), undefined, { numeric: true });
      return descending ? -cmp : cmp;
    });
  }, [rows, columns, sortKey, descending]);

  const toggle = (key: string) => {
    if (key === sortKey) setDescending((d) => !d);
    else { setSortKey(key); setDescending(true); }
  };

  if (rows.length === 0) {
    return (
      <div className="py-10 text-center text-xs text-muted-foreground italic">{empty}</div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse font-mono text-[11px]">
        <thead className="sticky top-0 z-10 bg-card">
          <tr className={`border-b border-border ${MICRO_LABEL}`}>
            {columns.map((c) => (
              <th
                key={c.key}
                aria-sort={
                  sortKey === c.key ? (descending ? 'descending' : 'ascending') : 'none'
                }
                className={`px-2 py-1.5 font-bold ${c.align === 'right' ? 'text-right' : 'text-left'} ${c.className ?? ''} ${pinned(c, true)}`}
              >
                {c.sortValue ? (
                  <button
                    type="button"
                    onClick={() => toggle(c.key)}
                    className={`inline-flex items-center gap-1 cursor-pointer hover:text-foreground ${
                      c.align === 'right' ? 'flex-row-reverse' : ''
                    }`}
                  >
                    <span>{c.label}</span>
                    {sortKey === c.key &&
                      (descending ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />)}
                  </button>
                ) : (
                  c.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={() => onRowClick?.(row)}
              onContextMenu={() => onRowContextMenu?.(row)}
              className={`group border-b border-border/40 hover:bg-accent/60 ${onRowClick ? 'cursor-pointer' : ''}`}
            >
              {columns.map((c) => (
                <td
                  key={c.key}
                  className={`px-2 py-1 whitespace-nowrap truncate ${
                    c.align === 'right' ? 'text-right tabular-nums' : 'text-left'
                  } ${c.className ?? ''} ${pinned(c, false)}`}
                >
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** `1,234` - thousands separated, because these columns are compared down. */
export const count = (n: number) => n.toLocaleString();

/** `1.4 MB`. Bytes are compared across orders of magnitude, so a unit helps. */
export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** `12.34 s`, or `—` for a conversation with one frame in it. */
export function seconds(n: number): string {
  return n > 0 ? `${n.toFixed(3)} s` : '—';
}

/** Bits per second over a conversation's own duration. */
export function bitrate(byteCount: number, duration: number): string {
  if (duration <= 0) return '—';
  const bps = (byteCount * 8) / duration;
  if (bps < 1000) return `${bps.toFixed(0)} bps`;
  if (bps < 1e6) return `${(bps / 1000).toFixed(1)} kbps`;
  return `${(bps / 1e6).toFixed(2)} Mbps`;
}
