import React from 'react';
import { TbTrash, TbAlertTriangle } from 'react-icons/tb';

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import {
  DEFAULT_SCHEDULE_PRESETS, describeDuration, isScheduleEmpty, withStartAt,
  withStopAfter, withStopAt, applyPreset,
  type CaptureSchedule, type SchedulePreset,
} from '../../services/captureSchedule';

interface CaptureSchedulePickerProps {
  schedule: CaptureSchedule;
  onScheduleChange: (next: CaptureSchedule) => void;
  presets: SchedulePreset[];
  onPresetsChange: (next: SchedulePreset[]) => void;
  /**
   * Frames currently in the buffer. A scheduled start discards them, and this
   * is what lets the warning name the number rather than saying "some".
   */
  bufferedPackets: number;
  children: React.ReactNode;
  align?: 'start' | 'center' | 'end';
}

/**
 * `datetime-local` wants `YYYY-MM-DDTHH:mm` in LOCAL time.
 *
 * `toISOString` is UTC and would show somebody in a non-zero offset a time that
 * is not the one they set, so the offset is subtracted before slicing. This is
 * the standard round-trip for that input and it is easy to get subtly wrong in
 * a way that only shows up outside UTC.
 */
function toLocalInputValue(epochMs: number): string {
  const local = new Date(epochMs - new Date(epochMs).getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

/** The inverse: an empty field is null, not `NaN`. */
function fromLocalInputValue(value: string): number | null {
  if (value === '') return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

const fieldClass =
  'w-full rounded-sm border border-border bg-background px-2 py-1 font-mono text-xs '
  + 'text-foreground outline-none focus:border-primary';
const rowLabelClass =
  'text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground';

/**
 * The Schedule capture dropdown: a start time, a stop time, and presets.
 *
 * Built from the same primitives as `CaptureInterfacePicker`, and rendered from
 * the same button class in the header, so the two controls beside each other
 * read as one pair rather than two designs.
 *
 * ## Two fields, one answer
 *
 * The stop can be an absolute time or a duration from a preset, and setting
 * either clears the other (`withStopAt` / `withStopAfter`). A menu offering two
 * different answers to "when does this end" is a menu somebody will set both
 * halves of and then be surprised by.
 *
 * ## The warning is the confirm
 *
 * Starting with frames in the buffer normally asks first - the Start button
 * puts up "Discard N captured packets?" and waits. A timer cannot answer that,
 * so the cost is stated here, live, while the schedule is being set. The
 * consent is given at the moment of the decision rather than removed; the
 * alternative was a scheduled capture that silently declined to run, or one
 * that discarded a capture with no warning anywhere.
 */
export const CaptureSchedulePicker: React.FC<CaptureSchedulePickerProps> = ({
  schedule,
  onScheduleChange,
  presets,
  onPresetsChange,
  bufferedPackets,
  children,
  align = 'start',
}) => {
  const [newPresetName, setNewPresetName] = React.useState('');

  const willDiscard = schedule.startAt !== null && bufferedPackets > 0;
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

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{children}</DropdownMenuTrigger>
      {/* border-0 and the heavier shadow for the same reason the interface
          picker uses them: under the mono theme --border is near-white, which
          draws a hard rectangle around the panel. */}
      <DropdownMenuContent
        align={align}
        className="w-80 max-h-[32rem] overflow-y-auto border-0 shadow-lg"
      >
        <DropdownMenuLabel className={rowLabelClass}>Schedule capture</DropdownMenuLabel>
        <DropdownMenuSeparator />

        {/* The fields are not DropdownMenuItems: an item closes the menu and
            steals arrow keys, and both are wrong for a text field somebody is
            typing a date into. */}
        <div className="px-2 py-1.5 space-y-1" onKeyDown={(e) => e.stopPropagation()}>
          <label className={`${rowLabelClass} block`} htmlFor="schedule-start">
            Start from
          </label>
          <input
            id="schedule-start"
            type="datetime-local"
            className={fieldClass}
            value={schedule.startAt === null ? '' : toLocalInputValue(schedule.startAt)}
            onChange={(e) => onScheduleChange(withStartAt(schedule, fromLocalInputValue(e.target.value)))}
          />
          <p className="text-[10px] leading-tight text-muted-foreground">
            Leave empty to start the capture yourself.
          </p>
          {willDiscard && (
            <p className="flex items-start gap-1 text-[10px] leading-tight text-amber-500">
              <TbAlertTriangle className="w-3 h-3 shrink-0 mt-px" />
              <span>
                {bufferedPackets.toLocaleString()} captured packet
                {bufferedPackets === 1 ? '' : 's'} will be discarded when this starts.
              </span>
            </p>
          )}
        </div>

        <div className="px-2 py-1.5 space-y-1" onKeyDown={(e) => e.stopPropagation()}>
          <label className={`${rowLabelClass} block`} htmlFor="schedule-stop">
            Stop at
          </label>
          <input
            id="schedule-stop"
            type="datetime-local"
            className={fieldClass}
            value={schedule.stopAt === null ? '' : toLocalInputValue(schedule.stopAt)}
            onChange={(e) => onScheduleChange(withStopAt(schedule, fromLocalInputValue(e.target.value)))}
          />
          {schedule.stopAfterMinutes !== null && (
            <p className="text-[10px] leading-tight text-muted-foreground">
              Set by a preset: stops {describeDuration(schedule.stopAfterMinutes)} after the
              capture starts.
            </p>
          )}
        </div>

        {!isScheduleEmpty(schedule) && (
          <DropdownMenuItem
            onSelect={(e) => {
              e.preventDefault();
              onScheduleChange({ startAt: null, stopAt: null, stopAfterMinutes: null });
            }}
            className="font-mono text-xs text-muted-foreground"
          >
            Clear schedule
          </DropdownMenuItem>
        )}

        <DropdownMenuSeparator />
        <DropdownMenuLabel className={rowLabelClass}>Presets</DropdownMenuLabel>

        {presets.length === 0 && (
          <p className="px-2 py-1 text-[10px] leading-tight text-muted-foreground">
            No presets. Set a duration below to save one, or restore the defaults.
          </p>
        )}

        {presets.map((preset) => (
          <div key={preset.id} className="flex items-center gap-1 pr-1">
            <DropdownMenuItem
              className="flex-1 font-mono text-xs"
              onSelect={(e) => {
                e.preventDefault();
                onScheduleChange(applyPreset(schedule, preset));
              }}
            >
              <span className="truncate">{preset.name}</span>
            </DropdownMenuItem>
            <button
              type="button"
              aria-label={`Delete preset ${preset.name}`}
              title="Delete preset"
              className="p-1 rounded-sm text-muted-foreground hover:text-destructive cursor-pointer"
              onClick={() => removePreset(preset.id)}
            >
              <TbTrash className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}

        <div className="px-2 py-1.5 space-y-1" onKeyDown={(e) => e.stopPropagation()}>
          {/* Only offered when there is a duration to save, and it says why
              rather than presenting a disabled control with no explanation. */}
          {canSavePreset ? (
            <div className="flex items-center gap-1">
              <input
                className={fieldClass}
                placeholder={`Capture for ${describeDuration(schedule.stopAfterMinutes!)}`}
                value={newPresetName}
                onChange={(e) => setNewPresetName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') savePreset(); }}
              />
              <button
                type="button"
                className="rounded-sm border border-border px-2 py-1 font-mono text-xs cursor-pointer hover:border-primary"
                onClick={savePreset}
              >
                Save
              </button>
            </div>
          ) : (
            <p className="text-[10px] leading-tight text-muted-foreground">
              Apply a preset, or set one below, to save a new one. A preset is a
              duration - an absolute stop time would be stale tomorrow.
            </p>
          )}
          <div className="flex flex-wrap gap-1 pt-0.5">
            {[5, 15, 30, 60, 120].map((minutes) => (
              <button
                key={minutes}
                type="button"
                className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] cursor-pointer hover:border-primary"
                onClick={() => onScheduleChange(withStopAfter(schedule, minutes))}
              >
                {describeDuration(minutes)}
              </button>
            ))}
          </div>
        </div>

        {presets.length < DEFAULT_SCHEDULE_PRESETS.length && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="font-mono text-xs text-muted-foreground"
              onSelect={(e) => {
                e.preventDefault();
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
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
