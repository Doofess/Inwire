import React, { useState } from 'react';
import { CalendarDays, TriangleAlert, X } from 'lucide-react';

import { MonthGrid } from '../common/MonthGrid';
import { Section } from '../network/rows';
import { Segmented } from '../ui/segmented';
import { useRovingFocus } from '../common/useRovingFocus';
import {
  DEFAULT_SCHEDULE_PRESETS, EMPTY_SCHEDULE, applyPreset, atTime, defaultStartAt, defaultStopAt,
  describeDay, describeDuration, describePlan, formatClock, isScheduleEmpty,
  onDay, scheduleProblem, withStartAt, withStopAfter, withStopAt,
  type CaptureSchedule, type SchedulePreset,
} from '../../services/captureSchedule';

/**
 * When a capture starts, when it stops, and one calendar for both.
 *
 * ## What the redesign changed, and why
 *
 * Asked for by the owner - start and stop apart, the calendar kept open
 * because the column has the room - and designed with a UX pass that found
 * more than the layout wrong:
 *
 * - **Nothing said what would happen.** Two values, "Manually" and "Not Set",
 *   and a reader had to assemble the plan. A sentence at the top says it now,
 *   in every state (`describePlan`).
 * - **Start and stop were two rows of one card** with a calendar behind each
 *   chevron. They are two sections with a mode each - Start: Manual / At a
 *   time; Stop: Manual / After / At a time - so the three stop forms that
 *   `withStopAt` and `withStopAfter` already made exclusive are finally shown as
 *   exclusive.
 * - **One calendar, always open, showing both ends.** Two grids would spend
 *   400px to show two separate dots; one shows the start filled, the stop ringed
 *   and the days between tinted. Which end a pick sets is `target`, marked on
 *   the section's date row and in the calendar's title.
 * - **The duration chips and the presets were the same five values twice**,
 *   and saving a preset could only re-save one that existed, since nothing let
 *   you type a duration. The presets ARE the chips now, beside a minutes field
 *   that can save a new one.
 * - **Two checks were missing**: a stop before the start, and a stop already
 *   past - which stopped a capture on its first tick without a word.
 *
 * `DateTimeCalendar` and its Today / In 15 min / Clear buttons are gone: the
 * modes and the quick offsets replace them, and `MonthGrid` is only a grid.
 */
export interface CaptureSchedulePanelProps {
  schedule: CaptureSchedule;
  onScheduleChange: (next: CaptureSchedule) => void;
  presets: SchedulePreset[];
  onPresetsChange: (next: SchedulePreset[]) => void;
  /**
   * Frames currently in the buffer. A scheduled start discards them, and this
   * is what lets the warning name the number rather than saying "some".
   */
  bufferedPackets: number;
  /** The schedule hook's clock, so "already passed" updates without a timer here. */
  now: number;
  /** Whether a capture is running - the start is history then, not a setting. */
  isCapturing: boolean;
  /** When the running capture began, epoch ms. */
  startedAt: number | null;
}

type StartMode = 'manual' | 'time';
type StopMode = 'manual' | 'after' | 'time';

const START_MODES = [
  { value: 'manual', label: 'Manual' },
  { value: 'time', label: 'At a time' },
] as const;
const STOP_MODES = [
  { value: 'manual', label: 'Manual' },
  { value: 'after', label: 'After' },
  { value: 'time', label: 'At a time' },
] as const;

// 24px targets throughout (`h-6`): the first pass drew fields, chips and modes
// at 18-20px, under the smallest size a pointer reliably hits.
const fieldClass =
  'h-6 rounded-sm border border-border bg-background px-1 font-mono text-xs text-center '
  + 'text-foreground outline-none focus:border-primary placeholder:text-muted-foreground/60';
const helpClass = 'text-[11px] leading-snug text-muted-foreground';
const linkClass =
  'text-[11px] text-primary hover:underline cursor-pointer focus-visible:outline-none '
  + 'focus-visible:ring-1 focus-visible:ring-ring rounded-sm';
/**
 * One chip for both sections, in a three-column grid with the text centred.
 * The Stop chips used to carry `pr-4` for an × that was hidden most of the
 * time, so they sat lopsided beside the Start chips and wrapped 3 then 2.
 */
const chipClass = (on: boolean) =>
  `w-full h-6 rounded-sm border px-1 text-[11px] whitespace-nowrap text-center cursor-pointer transition-colors ${on
    ? 'border-primary bg-primary/15 text-primary font-semibold'
    : 'border-border hover:border-primary'}`;
const buttonClass =
  'h-6 rounded-sm border border-border px-2 text-[11px] cursor-pointer hover:border-primary '
  + 'disabled:opacity-50 disabled:cursor-not-allowed';

const capitalise = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A field's keys are its own: the panel's arrows and the window's Space must not fire. */
const keepKeys = (e: React.KeyboardEvent) => {
  if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', ' '].includes(e.key)) {
    e.stopPropagation();
  }
};

/**
 * Hour and minute for one end. Up/Down step by one, Shift+Up/Down step minutes
 * by fifteen, typing keeps the last two digits - so "1" then "4" is 14, not 1
 * then an invalid 14-and-something.
 */
const TimeFields: React.FC<{
  value: number;
  onChange: (next: number) => void;
  label: string;
}> = ({ value, onChange, label }) => {
  const d = new Date(value);
  const h = d.getHours();
  const m = d.getMinutes();
  const set = (nh: number, nm: number) => onChange(atTime(value, (nh + 24) % 24, (nm + 60) % 60));
  const field = (which: 'hour' | 'minute', current: number, max: number) => (
    <input
      aria-label={`${label} ${which}`}
      role="spinbutton"
      aria-valuenow={current}
      aria-valuemin={0}
      aria-valuemax={max}
      inputMode="numeric"
      className={`${fieldClass} w-9`}
      value={String(current).padStart(2, '0')}
      onChange={(e) => {
        const digits = e.target.value.replace(/\D/g, '').slice(-2);
        const n = Math.min(max, Number(digits) || 0);
        if (which === 'hour') set(n, m);
        else set(h, n);
      }}
      onKeyDown={(e) => {
        keepKeys(e);
        if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
        e.preventDefault();
        const step = (e.key === 'ArrowUp' ? 1 : -1) * (which === 'minute' && e.shiftKey ? 15 : 1);
        if (which === 'hour') set(h + step, m);
        else set(h, m + step);
      }}
    />
  );
  return (
    <span className="inline-flex items-center gap-0.5">
      {field('hour', h, 23)}
      <span className="text-xs text-muted-foreground">:</span>
      {field('minute', m, 59)}
    </span>
  );
};

/**
 * One end's date and time. The date is a button that points the calendar at
 * this end.
 *
 * **Picking is a fill and an icon, not a coloured border.** A primary border
 * and primary text is what a FOCUSED field looks like here, so the first pass
 * showed the date button and the hour field beside it both apparently focused,
 * and invited typing into a button.
 */
const WhenRow: React.FC<{
  value: number;
  now: number;
  picking: boolean;
  onPick: () => void;
  onChange: (next: number) => void;
  label: string;
}> = ({ value, now, picking, onPick, onChange, label }) => (
  <div className="flex items-center gap-2">
    <button
      type="button"
      aria-pressed={picking}
      aria-label={`${label} date, ${describeDay(value, now)}${picking ? ', set on the calendar below' : ''}`}
      title={picking ? 'The calendar below sets this date' : 'Set this date on the calendar below'}
      onClick={onPick}
      className={`flex-1 min-w-0 h-6 flex items-center gap-1.5 rounded-sm px-1.5 text-xs cursor-pointer
        border transition-colors ${picking
          ? 'border-transparent bg-primary/15 text-foreground'
          : 'border-border hover:border-primary'}`}
    >
      <CalendarDays className={`w-3 h-3 shrink-0 ${picking ? 'text-primary' : 'text-muted-foreground'}`} />
      {/* "Today", "Tomorrow", or "Sat, Sep 27": the day relative to now, which
          is the question - and short enough for the narrowest column, where
          the full date and "(today)" after it ran out of the box. */}
      <span className="truncate">{capitalise(describeDay(value, now))}</span>
    </button>
    <TimeFields value={value} onChange={onChange} label={label} />
  </div>
);

const Notice: React.FC<{ tone: 'error' | 'warning'; children: React.ReactNode }> = ({ tone, children }) => (
  <p className={`flex items-start gap-1 text-[11px] leading-snug ${
    tone === 'error' ? 'text-destructive' : 'text-warning'}`}>
    <TriangleAlert className="w-3 h-3 shrink-0 mt-0.5" />
    <span>{children}</span>
  </p>
);

export const CaptureSchedulePanel: React.FC<CaptureSchedulePanelProps> = ({
  schedule, onScheduleChange, presets, onPresetsChange, bufferedPackets, now,
  isCapturing, startedAt,
}) => {
  /** Which end a calendar pick sets. Follows whichever date row was last pressed. */
  const [target, setTarget] = useState<'start' | 'stop'>('start');
  const [customMinutes, setCustomMinutes] = useState('');
  /** The last preset deleted, and where it was - so a delete can be undone. */
  const [removed, setRemoved] = useState<{ preset: SchedulePreset; index: number } | null>(null);
  const onKeyDown = useRovingFocus('vertical');

  const startMode: StartMode = schedule.startAt === null ? 'manual' : 'time';
  const stopMode: StopMode = schedule.stopAt !== null
    ? 'time'
    : schedule.stopAfterMinutes !== null ? 'after' : 'manual';

  const setStartMode = (mode: StartMode) => {
    if (mode === 'manual') {
      onScheduleChange(withStartAt(schedule, null));
      if (target === 'start' && stopMode === 'time') setTarget('stop');
    } else {
      onScheduleChange(withStartAt(schedule, defaultStartAt(now)));
      setTarget('start');
    }
  };
  const setStopMode = (mode: StopMode) => {
    if (mode === 'manual') onScheduleChange(withStopAfter(schedule, null));
    else if (mode === 'after') onScheduleChange(withStopAfter(schedule, schedule.stopAfterMinutes ?? 30));
    else {
      onScheduleChange(withStopAt(schedule, defaultStopAt(schedule, now)));
      setTarget('stop');
    }
  };

  /**
   * Which end the calendar sets, and whether it can set one at all.
   *
   * **A pick only ever sets an end that is already "At a time".** The first
   * pass let a pick switch a Manual start, or an After stop, to "At a time" -
   * at a time of day the user had never seen, and in the After case throwing
   * the duration away. Nothing announced either. So the calendar follows the
   * end that has a date, and with neither it is shown and not pickable.
   */
  const isTimed = (end: 'start' | 'stop') =>
    end === 'start' ? !isCapturing && startMode === 'time' : stopMode === 'time';
  const preferred = isCapturing ? 'stop' : target;
  const other = preferred === 'start' ? 'stop' : 'start';
  const calendarTarget: 'start' | 'stop' = isTimed(preferred) ? preferred : isTimed(other) ? other : preferred;
  const calendarLive = isTimed(calendarTarget);

  const pickDay = (day: Date) => {
    if (!calendarLive) return;
    if (calendarTarget === 'start') onScheduleChange(withStartAt(schedule, onDay(schedule.startAt!, day)));
    else onScheduleChange(withStopAt(schedule, onDay(schedule.stopAt!, day)));
  };

  const problem = isCapturing ? null : scheduleProblem(schedule, now);
  const startMissed = problem === 'start-missed';
  const stopBeforeStart = problem === 'stop-before-start';
  const stopPassed = problem === 'stop-passed';
  const willDiscard = !isCapturing && schedule.startAt !== null && problem === null && bufferedPackets > 0;

  const custom = Number(customMinutes);
  const customValid = customMinutes !== '' && Number.isInteger(custom) && custom > 0 && custom <= 7 * 24 * 60;
  const alreadyPreset = (minutes: number) => presets.some((p) => p.stopAfterMinutes === minutes);
  /**
   * Two buttons, two actions. "Use and save" was one button doing both, whose
   * label turned into "Use" depending on what had been typed.
   */
  const applyCustom = () => {
    if (!customValid) return;
    onScheduleChange(withStopAfter(schedule, custom));
    setCustomMinutes('');
  };
  const saveCustom = () => {
    if (!customValid || alreadyPreset(custom)) return;
    onPresetsChange([
      ...presets,
      { id: `preset-${Date.now().toString(36)}`, name: `Capture for ${describeDuration(custom)}`, stopAfterMinutes: custom },
    ]);
    applyCustom();
  };
  const removePreset = (preset: SchedulePreset) => {
    setRemoved({ preset, index: presets.findIndex((p) => p.id === preset.id) });
    onPresetsChange(presets.filter((p) => p.id !== preset.id));
  };
  const undoRemove = () => {
    if (removed === null) return;
    const next = [...presets];
    next.splice(Math.min(removed.index, next.length), 0, removed.preset);
    onPresetsChange(next);
    setRemoved(null);
  };

  return (
    <div className="p-2 space-y-2" onKeyDown={onKeyDown}>
      {/* **The plan, in words**, always. It is the one line that answers "what
          happens if I walk away now", which the panel never said - so it is
          marked as the panel's headline, and turns red when the schedule will
          not do what it says. It is a live region, which is why `describePlan`
          carries no ticking countdown: that was read aloud every second. */}
      <div
        className={`flex items-start gap-2 rounded-lg border border-l-2 px-3 py-2 ${problem !== null
          ? 'border-destructive/40 border-l-destructive bg-destructive/5'
          : 'border-border border-l-primary bg-primary/5'}`}
      >
        <p
          role="status"
          className={`flex-1 min-w-0 text-xs leading-snug ${problem !== null ? 'text-destructive' : 'text-foreground'}`}
        >
          {describePlan(schedule, now, isCapturing, startedAt)}
        </p>
        {/* Clear sits beside the plan it clears. It was a link under the
            calendar, a screen away from anything it described. */}
        {!isScheduleEmpty(schedule) && (
          <button type="button" className={`${linkClass} shrink-0`} onClick={() => onScheduleChange(EMPTY_SCHEDULE)}>
            Clear
          </button>
        )}
      </div>

      <Section title="Start">
        <div className="px-3 py-2 space-y-2">
          {isCapturing ? (
            <p className={helpClass}>
              Started {startedAt !== null ? `${describeDay(startedAt, now)} at ${formatClock(startedAt)}` : 'by hand'}.
              The start is set again once this capture stops.
            </p>
          ) : (
            <>
              <Segmented
                value={startMode}
                onValueChange={setStartMode}
                options={START_MODES}
                ariaLabel="How the capture starts"
                size="md"
              />
              {startMode === 'manual' ? (
                <p className={helpClass}>Starts when you press Start.</p>
              ) : (
                <WhenRow
                  value={schedule.startAt!}
                  now={now}
                  picking={calendarLive && calendarTarget === 'start'}
                  onPick={() => setTarget('start')}
                  onChange={(next) => onScheduleChange(withStartAt(schedule, next))}
                  label="Start"
                />
              )}
              <div className="grid grid-cols-3 items-center gap-1">
                <span className={`${helpClass} col-span-3`}>Start in</span>
                {[5, 15, 60].map((minutes) => (
                  <button
                    key={minutes}
                    type="button"
                    className={chipClass(false)}
                    onClick={() => {
                      // To the minute, so the fields read cleanly and the start
                      // lands on a real minute boundary.
                      const at = Math.ceil((now + minutes * 60_000) / 60_000) * 60_000;
                      onScheduleChange(withStartAt(schedule, at));
                      setTarget('start');
                    }}
                  >
                    {describeDuration(minutes)}
                  </button>
                ))}
              </div>
              {startMissed && (
                <Notice tone="error">
                  {formatClock(schedule.startAt!)} has passed, so nothing will start. Pick a later time.
                </Notice>
              )}
              {willDiscard && (
                /* **The warning is the confirm.** The Start button asks before
                   discarding a buffer; a timer cannot, so the cost is stated
                   here, live, while the schedule is being set. */
                <Notice tone="warning">
                  {bufferedPackets.toLocaleString()} packet{bufferedPackets === 1 ? '' : 's'} in the
                  buffer will be discarded when this starts.
                </Notice>
              )}
            </>
          )}
        </div>
      </Section>

      <Section title="Stop">
        {/* A floor on the height, sized to the tallest mode (After, measured at 145px), so the
            calendar below does not jump ~100px under the pointer when the mode
            changes - the hazard `MonthGrid`'s fixed six rows exist to avoid. */}
        <div className="px-3 py-2 space-y-2 min-h-[145px]">
          <Segmented
            value={stopMode}
            onValueChange={setStopMode}
            options={STOP_MODES}
            ariaLabel="How the capture stops"
            size="md"
          />

          {stopMode === 'manual' && <p className={helpClass}>Runs until you press Stop.</p>}

          {stopMode === 'after' && (
            <>
              {/* **The presets are the chips.** They were five chips AND five
                  preset rows holding the same five durations - two controls for
                  one value. A preset's name is its tooltip; the chip says the
                  duration, which is what is being chosen.

                  The × is a hover affordance on chips that are NOT applied. On
                  the applied chip an × reads as "unselect" and it deleted the
                  preset, which is why it is never drawn there. Every delete -
                  the × or Delete on a focused chip - can be undone. */}
              <div className="grid grid-cols-3 gap-1">
                {presets.map((preset) => {
                  const applied = schedule.stopAfterMinutes === preset.stopAfterMinutes;
                  return (
                    <span key={preset.id} className="group relative">
                      <button
                        type="button"
                        title={`${preset.name} - Delete removes it`}
                        aria-pressed={applied}
                        aria-keyshortcuts="Delete"
                        className={chipClass(applied)}
                        onClick={() => onScheduleChange(applyPreset(schedule, preset))}
                        onKeyDown={(e) => {
                          if (e.key === 'Delete' || e.key === 'Backspace') {
                            e.preventDefault();
                            removePreset(preset);
                          }
                        }}
                      >
                        {describeDuration(preset.stopAfterMinutes)}
                      </button>
                      {!applied && (
                        <button
                          type="button"
                          tabIndex={-1}
                          aria-label={`Delete preset ${preset.name}`}
                          title="Delete this duration"
                          className="absolute right-0.5 top-1/2 -translate-y-1/2 p-0.5 rounded-sm
                            text-muted-foreground hover:text-destructive cursor-pointer opacity-0
                            group-hover:opacity-100 transition-opacity"
                          onClick={() => removePreset(preset)}
                        >
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </span>
                  );
                })}
              </div>

              {removed !== null && (
                <p className={`${helpClass} flex items-center gap-1.5`}>
                  <span>Removed {describeDuration(removed.preset.stopAfterMinutes)}.</span>
                  <button type="button" className={linkClass} onClick={undoRemove}>Undo</button>
                </p>
              )}

              <div className="flex flex-wrap items-center gap-1">
                <input
                  aria-label="Custom duration in minutes"
                  inputMode="numeric"
                  placeholder="e.g. 90"
                  className={`${fieldClass} w-16`}
                  value={customMinutes}
                  onChange={(e) => setCustomMinutes(e.target.value.replace(/\D/g, '').slice(0, 5))}
                  onKeyDown={(e) => {
                    keepKeys(e);
                    if (e.key === 'Enter') applyCustom();
                  }}
                />
                <span className={`${helpClass} mr-auto`}>min</span>
                <button type="button" disabled={!customValid} className={buttonClass} onClick={applyCustom}>
                  Set
                </button>
                <button
                  type="button"
                  disabled={!customValid || alreadyPreset(custom)}
                  title={customValid && alreadyPreset(custom) ? 'Already a preset' : 'Set it, and keep it as a preset'}
                  className={buttonClass}
                  onClick={saveCustom}
                >
                  Save
                </button>
              </div>

              {presets.length < DEFAULT_SCHEDULE_PRESETS.length && (
                <button
                  type="button"
                  className={linkClass}
                  onClick={() => {
                    // Merged, not replaced: restoring the defaults must not
                    // throw away durations somebody saved.
                    const have = new Set(presets.map((p) => p.id));
                    onPresetsChange([...presets, ...DEFAULT_SCHEDULE_PRESETS.filter((p) => !have.has(p.id))]);
                    setRemoved(null);
                  }}
                >
                  Restore default durations
                </button>
              )}
            </>
          )}

          {stopMode === 'time' && (
            <WhenRow
              value={schedule.stopAt!}
              now={now}
              picking={calendarLive && calendarTarget === 'stop'}
              onPick={() => setTarget('stop')}
              onChange={(next) => onScheduleChange(withStopAt(schedule, next))}
              label="Stop"
            />
          )}

          {stopBeforeStart && (
            <Notice tone="error">
              Stops before it starts, so nothing will run. Pick a stop after {formatClock(schedule.startAt!)}.
            </Notice>
          )}
          {stopPassed && (
            <Notice tone="error">
              {formatClock(schedule.stopAt!)} has passed. Pick a later stop.
            </Notice>
          )}
        </div>
      </Section>

      {/* **Always open**, which is the owner's call and the column's room. The
          heading stays "Calendar" whichever end it sets - a heading that
          changed with the target moved text out from under the reader's eye -
          and the note names the end. */}
      <Section
        title="Calendar"
        note={calendarLive
          ? <>Sets the <span className="font-semibold text-primary">{calendarTarget}</span> date</>
          : 'Set Start or Stop to "At a time" to pick a day'}
      >
        <div className="px-3 py-2">
          <MonthGrid
            start={schedule.startAt}
            stop={schedule.stopAt}
            target={calendarTarget}
            onPickDay={pickDay}
            now={now}
            label={calendarTarget === 'start' ? 'Start date' : 'Stop date'}
            disabled={!calendarLive}
          />
        </div>
      </Section>
    </div>
  );
};
