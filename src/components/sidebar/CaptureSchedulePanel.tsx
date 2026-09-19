import React, { useState } from 'react';
import { ChevronDown, Trash, TriangleAlert } from 'lucide-react';

import { DateTimeCalendar } from '../common/DateTimeCalendar';
import { Section } from '../network/rows';
import { useRovingFocus } from '../common/useRovingFocus';
import {
  DEFAULT_SCHEDULE_PRESETS, describeDuration, formatStamp, isStartMissed,
  withStartAt, withStopAfter, withStopAt, applyPreset, START_GRACE_MS,
  type CaptureSchedule, type SchedulePreset,
} from '../../services/captureSchedule';

/**
 * A start time, a stop time, and the presets that fill them.
 *
 * This was a Radix dropdown off the rail, and almost everything that was odd
 * about it was the dropdown rather than the schedule.
 *
 * ## The cap is gone, so the calendars simply stay open
 *
 * `CaptureSchedulePicker` held ONE calendar between the two rows and a single
 * `editing: 'start' | 'stop' | null` slot deciding which field it was editing,
 * and the comment said why outright: *"two month grids stacked would make the
 * panel taller than the header it hangs from."* That is a sentence about a menu
 * hanging off a 36px button. A column is as tall as the window, so the slot
 * becomes two independent disclosures and both can be open at once - which is
 * the state somebody setting a window of time is actually in.
 *
 * ## The summary comes out of the tooltip
 *
 * `describeSchedule(...)` was computed in `ActivityRail` for one purpose: to
 * fill the rail button's `title`. "Stops in 14:58" was a fact the app knew,
 * updated every second, and showed only to somebody who happened to hover a
 * 36px icon. It is the header's `detail` now, which is the single most useful
 * thing this conversion buys and cost nothing to move.
 *
 * ## Every Radix workaround is deleted rather than ported
 *
 * Three `DropdownMenuItem`s - Clear schedule, each preset row, Restore
 * defaults - existed because *"a bare button inside the panel is skipped by
 * Radix's roving focus, which would leave the one destructive control here as
 * the only one the arrow keys cannot reach."* Outside a menu a button is an
 * ordinary tab stop and `useRovingFocus` reaches it, so they are buttons. The
 * three `onSelect={(e) => { e.preventDefault(); ... }}` handlers went with
 * them: each existed only to stop the menu closing.
 *
 * With the items went the `<div className="flex items-center gap-1 pr-1">`
 * that held each preset's trash button OUTSIDE the tinted row - a
 * `DropdownMenuItem` is a full-width row that cannot contain a second
 * focusable, which is why deleting a preset meant aiming at a target sitting
 * beyond the highlight that named it. The trash is inside the row now.
 *
 * And `w-80 max-h-[32rem] ... border-0 shadow-lg`, whose comment blamed the
 * mono theme's near-white `--border` for drawing "a hard rectangle around the
 * panel". There is no floating panel to outline: this one shares the rail's
 * border, which is the seam.
 *
 * ## Clear schedule keeps its focus ring, and loses its `!`
 *
 * The two `!` prefixes beat the primitive's own `focus:bg-accent`; there is no
 * primitive. The RING stays, and its comment's argument survives intact because
 * it was never about Radix: a 10% opacity shift on a saturated fill is not a
 * focus indicator, so a keyboard user reaching the one destructive control here
 * could not see that they had.
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
}

const fieldClass =
  'w-full rounded-sm border border-border bg-background px-2 py-1 font-mono text-xs '
  + 'text-foreground outline-none focus:border-primary disabled:opacity-50';

const rowLabelClass =
  'text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground';

/**
 * The interface panel's selection language, stated once here.
 *
 * A tinted accent ground, accent text, and a bar that scales out of the left
 * edge - so a selection reads as MOVING between rows rather than appearing on
 * one. Copied deliberately: the two panels open from adjacent buttons in the
 * rail's capture group, and "this is the one you picked" must not be said two
 * different ways a centimetre apart.
 *
 * **It is on the presets and not on the two value rows.** Those rows are not a
 * choice among alternatives - they are two fields, each holding one value -
 * and marking the one whose calendar happens to be open as "selected" said
 * something the chevron already says, in the vocabulary reserved for a picked
 * item.
 */
const selectedRowClass = 'bg-primary/15 text-primary font-semibold';
const accentBarClass =
  'absolute left-0 top-1 bottom-1 w-0.5 origin-center rounded-full bg-primary '
  + 'transition-transform duration-150 ease-out';

export const CaptureSchedulePanel: React.FC<CaptureSchedulePanelProps> = ({
  schedule, onScheduleChange, presets, onPresetsChange, bufferedPackets, now,
}) => {
  const [newPresetName, setNewPresetName] = useState('');
  /**
   * Two disclosures, not one slot.
   *
   * The single `editing` slot was the height cap wearing a state variable.
   * Setting a window of time means holding both ends in view, and the column
   * has the room, so neither field closes the other.
   */
  const [startOpen, setStartOpen] = useState(false);
  const [stopOpen, setStopOpen] = useState(false);
  const onKeyDown = useRovingFocus('vertical');

  const willDiscard = schedule.startAt !== null && bufferedPackets > 0;
  // A start too far in the past can no longer fire, and has to say so. Silently
  // keeping a time that will never happen is how somebody sets a schedule,
  // watches nothing occur, and concludes the feature is broken.
  const startMissed = isStartMissed(schedule, now);
  // Only a duration is worth saving: an absolute stop is a moment, and a moment
  // saved as a preset is wrong by tomorrow.
  const canSavePreset = schedule.stopAfterMinutes !== null;

  const removePreset = (id: string) => onPresetsChange(presets.filter((p) => p.id !== id));

  const savePreset = () => {
    const minutes = schedule.stopAfterMinutes;
    if (minutes === null) return;
    const name = newPresetName.trim() || `Capture for ${describeDuration(minutes)}`;
    onPresetsChange([
      ...presets,
      { id: `preset-${Date.now().toString(36)}`, name, stopAfterMinutes: minutes },
    ]);
    setNewPresetName('');
  };

  const fields = [
    {
      key: 'start' as const,
      label: 'Starting Time',
      value: schedule.startAt,
      open: startOpen,
      toggle: () => setStartOpen((v) => !v),
      // A duration is a stop, so the row may not answer "Not Set" while a
      // preset below it is highlighted as applied and the line beneath says
      // when the capture ends - three statements about one field, one of them
      // wrong. `withStopAfter` clears `stopAt`, so this field is empty in
      // exactly the case where the OTHER form of the same answer is set.
      empty: 'Manually',
      onChange: (next: number | null) => onScheduleChange(withStartAt(schedule, next)),
    },
    {
      key: 'stop' as const,
      label: 'Stopping Time',
      value: schedule.stopAt,
      open: stopOpen,
      toggle: () => setStopOpen((v) => !v),
      empty: schedule.stopAfterMinutes !== null
        ? `${describeDuration(schedule.stopAfterMinutes)} after start`
        : 'Not Set',
      onChange: (next: number | null) => onScheduleChange(withStopAt(schedule, next)),
    },
  ];

  return (
    <div className="p-2 space-y-2" onKeyDown={onKeyDown}>
      <Section title="When">
        {fields.map((field) => (
          /* **One cell per field, and its notices live inside it.**

             `Section` lays its children out `divide-y`, so a notice rendered as
             a SIBLING would read as another fact in the list rather than as
             something attached to the field above it. Inside the cell it is
             unambiguously about that field, which is what the collapsed layout
             had nowhere to put. */
          <div key={field.key}>
            <button
              type="button"
              aria-expanded={field.open}
              onClick={field.toggle}
              className="group relative w-full flex items-center gap-2 px-3 py-2
                font-mono text-xs cursor-pointer transition-colors hover:bg-accent/60
                focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring
                focus-visible:ring-inset"
            >
              <span className={rowLabelClass}>{field.label}</span>
              <span className="ml-auto truncate">
                {field.value !== null ? formatStamp(field.value) : field.empty}
              </span>
              <ChevronDown
                aria-hidden
                className={`w-3.5 h-3.5 shrink-0 text-muted-foreground transition-transform
                  duration-150 ${field.open ? 'rotate-180' : ''}`}
              />
            </button>

            {field.open && (
              <div className="px-3 pb-2">
                <DateTimeCalendar
                  value={field.value}
                  now={now}
                  label={field.key === 'start' ? 'Starts at' : 'Stops at'}
                  onChange={field.onChange}
                />
              </div>
            )}

            {field.key === 'start' && startMissed && (
              <p className="flex items-start gap-1 px-3 pb-2 text-[10px] leading-tight
                text-destructive">
                <TriangleAlert className="w-3 h-3 shrink-0 mt-px" />
                <span>
                  That time has already passed, so nothing will start. Pick one more than{' '}
                  {Math.round(START_GRACE_MS / 60_000)} minutes ahead.
                </span>
              </p>
            )}
            {field.key === 'start' && willDiscard && !startMissed && (
              /* **The warning is the confirm.** Starting with frames in the
                 buffer normally asks first - the Start button puts up "Discard
                 N captured packets?" and waits. A timer cannot answer that, so
                 the cost is stated here, live, while the schedule is being set.
                 The consent is given at the moment of the decision rather than
                 removed. */
              <p className="flex items-start gap-1 px-3 pb-2 text-[10px] leading-tight
                text-warning">
                <TriangleAlert className="w-3 h-3 shrink-0 mt-px" />
                <span>
                  {bufferedPackets.toLocaleString()} captured packet
                  {bufferedPackets === 1 ? '' : 's'} will be discarded when this starts.
                </span>
              </p>
            )}
          </div>
        ))}
      </Section>

      {/* The five durations, which are the fastest way to set a stop and the
          only control here that needs no calendar at all. */}
      <div className="flex flex-wrap gap-1 px-1">
        {[5, 15, 30, 60, 120].map((minutes) => {
          const applied = schedule.stopAfterMinutes === minutes;
          return (
            <button
              key={minutes}
              type="button"
              // Too small to carry the accent bar, so a chip takes the other
              // half of the same language - the tinted ground and the accent
              // text - rather than inventing a third way to say "this one".
              className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] cursor-pointer
                transition-colors ${applied
                  ? 'border-primary bg-primary/15 text-primary font-semibold'
                  : 'border-border hover:border-primary'}`}
              onClick={() => onScheduleChange(withStopAfter(schedule, minutes))}
            >
              {describeDuration(minutes)}
            </button>
          );
        })}
      </div>

      <Section
        title="Presets"
        // The explanation was the ELSE branch of a fork that swapped it for the
        // save row. Promoted to permanent, it explains the disabled row instead
        // of replacing it - so the reason is on screen at the moment somebody
        // wonders why they cannot type in the box.
        note="A preset is a duration. An absolute stop time would be stale tomorrow."
      >
        {presets.length === 0 && (
          <p className="px-3 py-2 text-[10px] leading-tight text-muted-foreground">
            No presets. Set a duration above to save one, or restore the defaults.
          </p>
        )}

        {presets.map((preset) => {
          // The schedule holds a DURATION, not a preset id, so "applied" is a
          // question about minutes - and two presets naming the same duration
          // both light up, because both of them are applied. Remembering which
          // one was clicked would make this a memory of an action rather than a
          // statement about the schedule, and the two disagree the moment the
          // duration is changed by the chips above.
          const applied = schedule.stopAfterMinutes === preset.stopAfterMinutes;
          return (
            <div
              key={preset.id}
              className={`group relative flex items-center ${applied ? selectedRowClass : ''}`}
            >
              <span
                aria-hidden
                className={`${accentBarClass} ${applied ? 'scale-y-100' : 'scale-y-0'}`}
              />
              <button
                type="button"
                onClick={() => onScheduleChange(applyPreset(schedule, preset))}
                className="flex-1 min-w-0 text-left px-3 py-2 font-mono text-xs cursor-pointer
                  transition-colors hover:bg-accent/60 focus-visible:outline-none
                  focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset"
              >
                <span className="block truncate">{preset.name}</span>
              </button>
              {/* **Inside the row, not beside it.** It sat outside the tinted
                  item because a `DropdownMenuItem` is a full-width row that
                  cannot hold a second focusable - so deleting a preset meant
                  aiming at a target that sat beyond the highlight naming what
                  would be deleted. */}
              <button
                type="button"
                aria-label={`Delete preset ${preset.name}`}
                title="Delete preset"
                className="mr-1 p-1 rounded-sm text-muted-foreground hover:text-destructive
                  cursor-pointer opacity-0 group-hover:opacity-100 group-focus-within:opacity-100
                  focus-visible:opacity-100 transition-opacity"
                onClick={() => removePreset(preset.id)}
              >
                <Trash className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}

        {/* **Always mounted, disabled when there is nothing to save.** It was a
            fork: the input appeared only once a duration existed, and the
            sentence explaining why took its place otherwise. Swapping a control
            for its own explanation means the explanation is gone at the moment
            the control works, and the control is gone at the moment somebody
            wants to know why. The note on this Section carries the reason
            permanently, and this row simply greys out. */}
        <div className="flex items-center gap-1 px-3 py-2">
          <input
            className={fieldClass}
            disabled={!canSavePreset}
            aria-label="Name for the saved preset"
            placeholder={canSavePreset
              ? `Capture for ${describeDuration(schedule.stopAfterMinutes!)}`
              : 'Set a duration first'}
            value={newPresetName}
            onChange={(e) => setNewPresetName(e.target.value)}
            // **Two reasons now, and the second is new.** It stopped Radix's
            // typeahead swallowing keystrokes; it also stops the roving-focus
            // handler on this panel's container, whose Home and End would
            // otherwise jump the FOCUS out of this field rather than moving the
            // caret in it - and stops `useKeyboardNavigation`'s window-level
            // Space from toggling the capture mid-word.
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === 'Enter') savePreset();
            }}
          />
          <button
            type="button"
            disabled={!canSavePreset}
            className="rounded-sm border border-border px-2 py-1 font-mono text-xs
              cursor-pointer hover:border-primary disabled:opacity-50
              disabled:cursor-not-allowed"
            onClick={savePreset}
          >
            Save
          </button>
        </div>

        {presets.length < DEFAULT_SCHEDULE_PRESETS.length && (
          <button
            type="button"
            className="w-full text-left px-3 py-2 font-mono text-xs text-muted-foreground
              cursor-pointer hover:bg-accent/60 focus-visible:outline-none
              focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset"
            onClick={() => {
              // Merged, not replaced: restoring the defaults should not throw
              // away presets the user made.
              const have = new Set(presets.map((p) => p.id));
              onPresetsChange([
                ...presets,
                ...DEFAULT_SCHEDULE_PRESETS.filter((p) => !have.has(p.id)),
              ]);
            }}
          >
            Restore default presets
          </button>
        )}
      </Section>
    </div>
  );
};
