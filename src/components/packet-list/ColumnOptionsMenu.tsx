import React from 'react';
import { TbAdjustmentsHorizontal } from 'react-icons/tb';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
} from '../ui/dropdown-menu';
import {
  COLUMN_ALIGNS,
  COLUMN_ALIGN_LABELS,
  COLUMN_LABELS,
  HIDEABLE_COLUMNS,
  type ColumnAlign,
  type ColumnVisibility,
  type HideableColumn,
} from '../../lib/packetColumns';
import { TIME_FORMAT_LABELS, type TimeFormat } from '../../lib/formatTimeColumn';

/**
 * Which columns show, and how the Time column reads.
 *
 * The trigger is a VISIBLE BUTTON in the header row, not a right-click. A
 * context menu is an accelerator; it cannot be the only way in. Right-click is
 * unavailable from a keyboard, unavailable on touch, and nothing in this app
 * teaches that column headers have one - Chrome's network panel, which is the
 * right comparison, ships both.
 *
 * Radix rather than the hand-rolled div menu this app already had: that one has
 * no roles, no arrow keys, no Escape and no focus return, and it is why
 * `DropdownMenuCheckboxItem` had been sitting unused in the codebase.
 */

interface ColumnOptionsMenuProps {
  columns: ColumnVisibility;
  timeFormat: TimeFormat;
  align: ColumnAlign;
  onColumnsChange: (columns: ColumnVisibility) => void;
  onTimeFormatChange: (format: TimeFormat) => void;
  onAlignChange: (align: ColumnAlign) => void;
}

export const ColumnOptionsMenu: React.FC<ColumnOptionsMenuProps> = ({
  columns,
  timeFormat,
  align,
  onColumnsChange,
  onTimeFormatChange,
  onAlignChange,
}) => {
  const visibleCount = HIDEABLE_COLUMNS.filter((c) => columns[c]).length;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Column options"
          title="Column options"
          className="p-0.5 rounded shrink-0 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer"
        >
          <TbAdjustmentsHorizontal className="w-3.5 h-3.5" />
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>Columns</DropdownMenuLabel>
        {HIDEABLE_COLUMNS.map((column: HideableColumn) => {
          const checked = columns[column];
          // The last visible column cannot be turned off. A list with no
          // columns but Info is not a table, and there would be no header left
          // to reopen this menu from.
          const isLastVisible = checked && visibleCount === 1;
          return (
            <DropdownMenuCheckboxItem
              key={column}
              checked={checked}
              disabled={isLastVisible}
              onCheckedChange={(next) =>
                onColumnsChange({ ...columns, [column]: next })
              }
            >
              {COLUMN_LABELS[column]}
            </DropdownMenuCheckboxItem>
          );
        })}

        <DropdownMenuSeparator />
        <DropdownMenuLabel>Time format</DropdownMenuLabel>
        {/* Radio, not checkboxes: the formats are exclusive. */}
        <DropdownMenuRadioGroup
          value={timeFormat}
          onValueChange={(v) => onTimeFormatChange(v as TimeFormat)}
        >
          {(Object.keys(TIME_FORMAT_LABELS) as TimeFormat[]).map((format) => (
            <DropdownMenuRadioItem key={format} value={format}>
              {TIME_FORMAT_LABELS[format]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>

        <DropdownMenuSeparator />
        <DropdownMenuLabel>Text position</DropdownMenuLabel>
        {/* Applies to the text columns. No., Time and Length keep their right
            edge - see ColumnAlign for why that is not an oversight. */}
        <DropdownMenuRadioGroup
          value={align}
          onValueChange={(v) => onAlignChange(v as ColumnAlign)}
        >
          {COLUMN_ALIGNS.map((value) => (
            <DropdownMenuRadioItem key={value} value={value}>
              {COLUMN_ALIGN_LABELS[value]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
