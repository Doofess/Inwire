import React from 'react';
import { MICRO_LABEL } from './typography';
import { usePreferenceValue } from '../../services/preferenceStore';
import {
  isModified,
  resetSetting,
  settingAnchorId,
  settingByLabel,
  type SettingEntry,
} from '../../lib/settingsIndex';

/**
 * The shape a Settings panel is built out of: sections of labelled rows.
 *
 * These lived inside `InterfaceSettingsPanel` with a note saying they were
 * deliberately local, had one consumer, and could move the day something else
 * wanted them. Appearance is that day - it now carries a colour-set picker and
 * two map switches, and a settings row that looks almost like the Interface
 * tab's is worse than one that is literally the same component.
 *
 * Presentation only. Every value these controls change lives in a module-level
 * preference store, so the row here and a control elsewhere that changes the
 * same setting are the same value rather than two copies that drift. See
 * services/preferenceStore.
 */

export const SECTION_CLASS = MICRO_LABEL;

interface SettingRowProps {
  label: string;
  description?: string;
  /** Set when the control is a single focusable element that can own the label. */
  htmlFor?: string;
  /**
   * Set when the row's control is disabled. The row's Reset follows it: a Reset
   * that works beside a greyed control changes a value the row says it cannot.
   * Disabled rather than hidden, so the row does not jump.
   */
  disabled?: boolean;
  children: React.ReactNode;
}

/**
 * One setting: name, explanation, control.
 *
 * A row whose label is in the settings index with a preference behind it also
 * says when its value is not the default - a 2px accent bar at the left edge
 * and a Reset beside the label. Looked up by label, so the panels pass nothing
 * extra and a row cannot be marked without being searchable.
 */
export function SettingRow(props: SettingRowProps) {
  const entry = settingByLabel(props.label);
  return entry?.pref
    ? <TrackedSettingRow {...props} entry={entry} />
    : <SettingRowShell {...props} modified={false} />;
}

/** The only place the store is subscribed to, so a row with no preference calls no hook. */
function TrackedSettingRow({ entry, ...props }: SettingRowProps & { entry: SettingEntry }) {
  usePreferenceValue(entry.pref!.store);
  const modified = isModified(entry);
  return (
    <SettingRowShell {...props} modified={modified} onReset={() => resetSetting(entry)} />
  );
}

function SettingRowShell({
  label,
  description,
  htmlFor,
  children,
  disabled,
  modified,
  onReset,
}: SettingRowProps & { modified: boolean; onReset?: () => void }) {
  return (
    <div id={settingAnchorId(label)} className="relative flex items-start justify-between gap-6 py-2.5">
      {/* Inside the pane's own padding (p-5), so it sits in the gutter rather
          than pushing the row in. Decorative: the Reset beside the label is
          what says the same thing to a screen reader. */}
      {modified && (
        <span aria-hidden className="absolute -left-3 inset-y-0 w-0.5 rounded-full bg-primary" />
      )}
      <div className="min-w-0">
        <div className="flex items-baseline gap-2">
          {htmlFor ? (
            <label htmlFor={htmlFor} className="text-xs font-semibold text-foreground cursor-pointer">
              {label}
            </label>
          ) : (
            <div className="text-xs font-semibold text-foreground">{label}</div>
          )}
          {modified && onReset && (
            <button
              type="button"
              onClick={onReset}
              disabled={disabled}
              aria-label={`Reset ${label} to default`}
              className="text-[11px] text-muted-foreground hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-muted-foreground rounded-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring"
            >
              Reset
            </button>
          )}
        </div>
        {description && (
          <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{description}</p>
        )}
      </div>
      <div className="shrink-0 pt-0.5">{children}</div>
    </div>
  );
}

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className={SECTION_CLASS}>{title}</h3>
      <div className="mt-1 divide-y divide-border/60">{children}</div>
    </section>
  );
}
