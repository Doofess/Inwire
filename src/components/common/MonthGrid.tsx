import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

/**
 * A month of days that marks a start and a stop, drawn by this app rather than
 * by the browser.
 *
 * It was `DateTimeCalendar`: a grid plus a time field and Today / In 15 min /
 * Clear, mounted twice behind two disclosures in the schedule panel. The owner
 * asked for the calendar to stay open - the column has the room - and one grid
 * that shows BOTH ends of a capture says more than two that each show one
 * dot: the start day filled, the stop day ringed, the days between tinted. The
 * time of day moved out into each section, where both times are always in
 * view, so this picks a DATE and nothing else.
 *
 * `<input type="datetime-local">` is still not the answer, for the reasons the
 * old header gave: its calendar is an OS popup no token reaches, and it commits
 * values as you move around it - which once started a capture nobody asked
 * for. **A day here commits only on an explicit pick** (click, Enter, Space).
 *
 * ## Keyboard: one tab stop, arrows inside
 *
 * The old grid was 42 buttons in the panel's vertical roving focus, so Down
 * walked a day at a time through a month. Now the grid is one stop: arrows move
 * a day or a week, PageUp/PageDown a month, Home/End the week, Enter or Space
 * picks. Every key it handles stops propagating - the window listens for Space
 * (capture on/off) and the arrows (packet selection), and neither may fire from
 * inside a calendar.
 *
 * Deliberately not a date-picker dependency: a month grid is forty lines, and
 * the libraries bring a locale, popover and styling layer this app already has.
 */

const DAY_LABELS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'];

const startOfDay = (d: Date): number => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
const sameDay = (a: Date, b: Date): boolean => startOfDay(a) === startOfDay(b);
const addDays = (d: Date, n: number): Date => new Date(d.getFullYear(), d.getMonth(), d.getDate() + n);

/**
 * The 42 cells of a month view, Monday first. Always six rows, so the panel
 * does not change height between months - a grid that resizes under the
 * pointer is how somebody clicks the day next to the one they meant.
 */
export function monthGrid(year: number, month: number): Date[] {
  const first = new Date(year, month, 1);
  const lead = (first.getDay() + 6) % 7;
  return Array.from({ length: 42 }, (_, i) => new Date(year, month, 1 - lead + i));
}

interface MonthGridProps {
  /** The start and stop to mark, epoch ms, or null. */
  start: number | null;
  stop: number | null;
  /** Which end a pick sets - it decides where the view opens and what is ringed. */
  target: 'start' | 'stop';
  onPickDay: (day: Date) => void;
  /** The app's clock, so "today" is marked without a timer in here. */
  now: number;
  /** Names the grid for a screen reader - "Start date", "Stop date". */
  label: string;
  /**
   * Shown but not pickable. The panel sets it when the end being picked is not
   * "At a time": a pick used to switch that end's mode behind the user's back,
   * at a time of day they had never seen.
   */
  disabled?: boolean;
}

export const MonthGrid: React.FC<MonthGridProps> = ({ start, stop, target, onPickDay, now, label, disabled = false }) => {
  const today = new Date(now);
  const startDay = start === null ? null : new Date(start);
  const stopDay = stop === null ? null : new Date(stop);
  const targetDay = (target === 'start' ? startDay : stopDay) ?? startDay ?? today;

  // The month on show, and the day the keyboard is on. Both are state of their
  // own - browsing must not change the schedule - but they FOLLOW the target:
  // switching from the start to the stop, or setting a date elsewhere, moves
  // the view to it. The old grid seeded its month once on mount, which was
  // fine behind a disclosure and wrong for one that never closes.
  const [focus, setFocus] = React.useState<Date>(targetDay);
  const [view, setView] = React.useState({ year: targetDay.getFullYear(), month: targetDay.getMonth() });
  const targetKey = startOfDay(targetDay);
  React.useEffect(() => {
    setFocus(new Date(targetKey));
    const d = new Date(targetKey);
    setView({ year: d.getFullYear(), month: d.getMonth() });
  }, [target, targetKey]);

  const gridRef = React.useRef<HTMLDivElement | null>(null);
  const moveFocus = (next: Date) => {
    setFocus(next);
    if (next.getMonth() !== view.month || next.getFullYear() !== view.year) {
      setView({ year: next.getFullYear(), month: next.getMonth() });
    }
    // The focused cell is the grid's one tab stop; move DOM focus with it
    // once React has re-rendered the new cell as `tabIndex=0`.
    requestAnimationFrame(() => {
      gridRef.current?.querySelector<HTMLButtonElement>('button[tabindex="0"]')?.focus();
    });
  };

  const shiftMonth = (delta: number) => {
    const next = new Date(view.year, view.month + delta, 1);
    setView({ year: next.getFullYear(), month: next.getMonth() });
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const moves: Record<string, () => Date> = {
      ArrowLeft: () => addDays(focus, -1),
      ArrowRight: () => addDays(focus, 1),
      ArrowUp: () => addDays(focus, -7),
      ArrowDown: () => addDays(focus, 7),
      PageUp: () => new Date(focus.getFullYear(), focus.getMonth() - 1, focus.getDate()),
      PageDown: () => new Date(focus.getFullYear(), focus.getMonth() + 1, focus.getDate()),
      Home: () => addDays(focus, -((focus.getDay() + 6) % 7)),
      End: () => addDays(focus, 6 - ((focus.getDay() + 6) % 7)),
    };
    if (moves[e.key]) {
      e.preventDefault();
      e.stopPropagation();
      moveFocus(moves[e.key]());
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      e.stopPropagation();
      onPickDay(focus);
    }
  };

  // The span between the two ends, tinted, when both are set and in order.
  const lo = startDay && stopDay && startOfDay(startDay) < startOfDay(stopDay) ? startOfDay(startDay) : null;
  const hi = lo !== null ? startOfDay(stopDay!) : null;
  const monthName = new Date(view.year, view.month, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });

  return (
    // `inert` rather than a `disabled` on 44 buttons: one attribute takes the
    // whole grid out of the tab order, the pointer and the accessibility tree.
    <div inert={disabled} className={disabled ? 'opacity-50' : undefined}>
      <div className="flex items-center justify-between">
        <button
          type="button"
          aria-label="Previous month"
          className="p-1 rounded-sm text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => shiftMonth(-1)}
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <span className="text-[11px] font-bold tracking-wide" aria-live="polite">{monthName}</span>
        <button
          type="button"
          aria-label="Next month"
          className="p-1 rounded-sm text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => shiftMonth(1)}
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-7 mt-1" aria-hidden>
        {DAY_LABELS.map((d) => (
          <span key={d} className="text-center text-[10px] uppercase text-muted-foreground py-0.5">{d}</span>
        ))}
      </div>
      <div
        ref={gridRef}
        role="grid"
        aria-label={label}
        className="grid grid-cols-7 gap-y-0.5 font-mono"
        onKeyDown={onKeyDown}
      >
        {monthGrid(view.year, view.month).map((day) => {
          const key = startOfDay(day);
          const outside = day.getMonth() !== view.month;
          const isStart = startDay !== null && sameDay(day, startDay);
          const isStop = stopDay !== null && sameDay(day, stopDay);
          const between = lo !== null && key > lo && key < hi!;
          const isToday = sameDay(day, today);
          const focused = sameDay(day, focus);
          return (
            <button
              key={key}
              type="button"
              role="gridcell"
              tabIndex={focused ? 0 : -1}
              aria-selected={isStart || isStop}
              aria-label={`${day.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' })}`
                + `${isStart ? ', start' : ''}${isStop ? ', stop' : ''}${isToday ? ', today' : ''}`}
              // A past day is not disabled: the schedule decides what can fire,
              // and says so in words, which a greyed cell cannot.
              className={[
                'relative text-[11px] leading-none py-1.5 cursor-pointer outline-none',
                'focus-visible:ring-1 focus-visible:ring-ring',
                between ? 'bg-primary/15' : '',
                isStart
                  ? 'bg-primary text-primary-foreground font-bold rounded-sm'
                  : isStop
                    ? 'ring-1 ring-inset ring-primary text-primary font-bold rounded-sm'
                    : isToday
                      ? 'text-primary font-bold hover:bg-accent rounded-sm'
                      : outside
                        ? 'text-muted-foreground/60 hover:bg-accent rounded-sm'
                        : 'text-foreground hover:bg-accent rounded-sm',
                // The end being picked is marked on its cell as well as in the
                // section, so "which one am I setting" is answered in the grid.
                (target === 'start' && isStart) || (target === 'stop' && isStop)
                  ? 'shadow-[0_0_0_2px_var(--color-primary)]' : '',
              ].join(' ')}
              onClick={() => { setFocus(day); onPickDay(day); }}
            >
              {day.getDate()}
            </button>
          );
        })}
      </div>
    </div>
  );
};
