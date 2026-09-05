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
  COLUMN_LABELS,
  HIDEABLE_COLUMNS,
  type ColumnVisibility,
  type HideableColumn,
} from '../../lib/packetColumns';
import { TIME_FORMAT_LABELS, type TimeFormat } from '../../lib/formatTimeColumn';
import { fieldDef } from '../../services/dissect/fieldRegistry';

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
 *
 * **Text position is not in here.** It used to be, as one setting applied to
 * every text column at once - which meant it could not be offered for No.,
 * Time or Length without also being able to break the digit alignment those
 * three exist to have. It lives on a right-click of the column header now, so
 * a choice reaches exactly the column it was made on, and every column can be
 * offered. That is an accelerator with no visible affordance, which is normally
 * the objection above - the difference is that it is not the ONLY way to do
 * anything, it is a per-column refinement of a default that is already right.
 */

interface ColumnOptionsMenuProps {
  columns: ColumnVisibility;
  timeFormat: TimeFormat;
  /**
   * Registry field names added from the detail tree's "Apply as Column".
   * Listed here because this is the only place they can be taken off again -
   * the tree adds them and has no idea what is already on the list.
   */
  customColumns: string[];
  onColumnsChange: (columns: ColumnVisibility) => void;
  onCustomColumnsChange: (columns: string[]) => void;
  onTimeFormatChange: (format: TimeFormat) => void;
}

export const ColumnOptionsMenu: React.FC<ColumnOptionsMenuProps> = ({
  columns,
  timeFormat,
  customColumns,
  onColumnsChange,
  onCustomColumnsChange,
  onTimeFormatChange,
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

        {customColumns.length > 0 && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Added fields</DropdownMenuLabel>
            {/* Unchecking one removes it outright rather than hiding it: an
                added column has no meaning apart from being shown, so a hidden
                one would be a setting with nothing to say. */}
            {customColumns.map((abbrev) => (
              <DropdownMenuCheckboxItem
                key={abbrev}
                checked
                onCheckedChange={() =>
                  onCustomColumnsChange(customColumns.filter((c) => c !== abbrev))
                }
              >
                <span className="truncate" title={abbrev}>
                  {fieldDef(abbrev)?.column?.label ?? fieldDef(abbrev)?.label ?? abbrev}
                </span>
              </DropdownMenuCheckboxItem>
            ))}
          </>
        )}

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

      </DropdownMenuContent>
    </DropdownMenu>
  );
};
