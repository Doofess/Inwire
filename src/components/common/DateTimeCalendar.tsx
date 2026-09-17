import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

/**
 * A month grid and a time field, drawn by this app rather than by the browser.
 *
 * `<input type="datetime-local">` is one line and was the wrong line. Its
 * calendar is an OS-level popup rendered outside the page: no selector reaches
 * it, it ignores every token in `index.css`, and it appeared as a light-grey
 * Windows panel hanging off a near-black app. `color-scheme` is the only thing
 * such a widget honours and it still would not have used this app's fonts,
 * spacing or accent.
 *
 * It also caused a bug. The native picker commits a value as you move around
 * it - its "Today" button writes today with whatever time is already in the
 * field, usually one that has passed - and the schedule's next tick saw a due
 * start and ran a capture. **This commits only on an explicit click**, which
 * removes that whole class of accident rather than guarding against it.
 *
 * Deliberately not a date-picker dependency. What is needed is a month grid and
 * two numbers; the libraries that do this bring a locale layer, a popover layer
 * and a styling layer, all of which this app already has its own answers for.
 */

const DAY_LABELS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'];
const MONTH_LABELS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

const sameDay = (a: Date, b: Date): boolean =>
  a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/**
 * The 42 cells of a month view, Monday first.
 *
 * Always six rows, so the panel does not change height between a month that
 * needs five and one that needs six - a grid that resizes under the pointer is
 * how somebody clicks the day next to the one they meant.
 */
function monthGrid(year: number, month: number): Date[] {
  const first = new Date(year, month, 1);
  // getDay() is Sunday-first; this app shows Monday-first, which is what the
  // rest of its date formatting uses.
  const lead = (first.getDay() + 6) % 7;
  const start = new Date(year, month, 1 - lead);
  return Array.from({ length: 42 }, (_, i) =>
    new Date(start.getFullYear(), start.getMonth(), start.getDate() + i));
}

const clampHour = (n: number): number => Math.min(23, Math.max(0, n));
const clampMinute = (n: number): number => Math.min(59, Math.max(0, n));

interface DateTimeCalendarProps {
  /** The current value, or null when the field is empty. */
  value: number | null;
  onChange: (next: number | null) => void;
  /** The app's clock, so "today" is highlighted without a timer in here. */
  now: number;
  /** Labels the confirm affordance - "Set start", "Set stop". */
  label: string;
}

export const DateTimeCalendar: React.FC<DateTimeCalendarProps> = ({
  value, onChange, now, label,
}) => {
  const today = new Date(now);
  const selected = value === null ? null : new Date(value);
  // The month being browsed is state of its own: scrolling through months must
  // not change the value, which is the other half of the native picker's bug.
  const [view, setView] = React.useState(() => {
    const base = selected ?? today;
    return { year: base.getFullYear(), month: base.getMonth() };
  });

  // The time is edited even before a day is chosen, so it is held here and
  // combined on selection rather than requiring a date first.
  const [hour, setHour] = React.useState(() => (selected ? selected.getHours() : today.getHours()));
  const [minute, setMinute] = React.useState(() => (selected ? selected.getMinutes() : 0));

  const commit = (day: Date, h = hour, m = minute) => {
    onChange(new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m, 0, 0).getTime());
  };

  const shiftMonth = (delta: number) => {
    const next = new Date(view.year, view.month + delta, 1);
    setView({ year: next.getFullYear(), month: next.getMonth() });
  };

  const cells = monthGrid(view.year, view.month);

  return (
    <div className="space-y-1.5 font-mono">
      <div className="flex items-center justify-between">
        <button
          type="button"
          aria-label="Previous month"
          className="p-1 rounded-sm text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => shiftMonth(-1)}
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <span className="text-[11px] font-bold tracking-wide">
          {MONTH_LABELS[view.month]} {view.year}
        </span>
        <button
          type="button"
          aria-label="Next month"
          className="p-1 rounded-sm text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => shiftMonth(1)}
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-7 gap-px">
        {DAY_LABELS.map((day) => (
          <span key={day} className="text-center text-[9px] uppercase text-muted-foreground py-0.5">
            {day}
          </span>
        ))}
        {cells.map((day) => {
          const outside = day.getMonth() !== view.month;
          const isToday = sameDay(day, today);
          const isSelected = selected !== null && sameDay(day, selected);
          return (
            <button
              key={day.getTime()}
              type="button"
              // A day in the past is not disabled: "Stop at" legitimately takes
              // one when reviewing, and the schedule itself decides what can
              // fire. A grid that greys out half its cells for a rule that only
              // applies to one of the two fields would be lying about the other.
              className={[
                'text-[11px] leading-none py-1 rounded-sm cursor-pointer',
                isSelected
                  ? 'bg-primary text-primary-foreground font-bold'
                  : isToday
                    ? 'text-primary font-bold hover:bg-accent'
                    : outside
                      ? 'text-muted-foreground/40 hover:bg-accent'
                      : 'text-foreground hover:bg-accent',
              ].join(' ')}
              onClick={() => commit(day)}
            >
              {day.getDate()}
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-1 pt-0.5">
        <span className="text-[9px] uppercase text-muted-foreground">{label}</span>
        <div className="ml-auto flex items-center gap-0.5">
          <input
            aria-label="Hour"
            className="w-9 rounded-sm border border-border bg-background px-1 py-0.5 text-center text-xs outline-none focus:border-primary"
            value={String(hour).padStart(2, '0')}
            onChange={(e) => {
              const next = clampHour(Number(e.target.value.replace(/\D/g, '')) || 0);
              setHour(next);
              // Only writes back when a day is already chosen: typing a time
              // must not invent a date the user never picked.
              if (selected) commit(selected, next, minute);
            }}
          />
          <span className="text-xs text-muted-foreground">:</span>
          <input
            aria-label="Minute"
            className="w-9 rounded-sm border border-border bg-background px-1 py-0.5 text-center text-xs outline-none focus:border-primary"
            value={String(minute).padStart(2, '0')}
            onChange={(e) => {
              const next = clampMinute(Number(e.target.value.replace(/\D/g, '')) || 0);
              setMinute(next);
              if (selected) commit(selected, hour, next);
            }}
          />
        </div>
      </div>

      <div className="flex items-center gap-1">
        <button
          type="button"
          className="flex-1 rounded-sm border border-border px-2 py-1 text-[10px] cursor-pointer hover:border-primary"
          // Moves the VIEW to this month and selects today at the time shown.
          // The native picker's equivalent quietly committed a past time, which
          // is what started a capture nobody asked for.
          onClick={() => {
            setView({ year: today.getFullYear(), month: today.getMonth() });
            commit(today);
          }}
        >
          Today
        </button>
        <button
          type="button"
          className="flex-1 rounded-sm border border-border px-2 py-1 text-[10px] cursor-pointer hover:border-primary"
          onClick={() => {
            const soon = new Date(now + 15 * 60_000);
            setView({ year: soon.getFullYear(), month: soon.getMonth() });
            setHour(soon.getHours());
            setMinute(soon.getMinutes());
            commit(soon, soon.getHours(), soon.getMinutes());
          }}
        >
          In 15 min
        </button>
        <button
          type="button"
          className="flex-1 rounded-sm border border-border px-2 py-1 text-[10px] cursor-pointer hover:border-destructive"
          onClick={() => onChange(null)}
        >
          Clear
        </button>
      </div>
    </div>
  );
};
