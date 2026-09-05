import React from 'react';

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

export const SECTION_CLASS = 'text-[10px] font-bold uppercase tracking-widest text-muted-foreground';

/** One setting: name, explanation, control. */
export function SettingRow({
  label,
  description,
  htmlFor,
  children,
}: {
  label: string;
  description?: string;
  /** Set when the control is a single focusable element that can own the label. */
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-2.5">
      <div className="min-w-0">
        {htmlFor ? (
          <label htmlFor={htmlFor} className="text-xs font-semibold text-foreground cursor-pointer">
            {label}
          </label>
        ) : (
          <div className="text-xs font-semibold text-foreground">{label}</div>
        )}
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
