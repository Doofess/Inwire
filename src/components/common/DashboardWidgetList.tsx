import React, { useRef, useState } from 'react';
import {
  TbGripVertical,
  TbChevronUp,
  TbChevronDown,
  TbChevronRight,
  TbPlus,
  TbMinus,
} from 'react-icons/tb';
import { Switch } from '../ui/switch';
import { Segmented } from '../ui/segmented';
import {
  WIDGET_TYPES,
  dashboardStore,
  widgetTitle,
  type WidgetInstance,
  type WidgetTypeId,
} from '../../services/dashboardPrefs';
import { usePreferenceStore } from '../../services/preferenceStore';
import { WIDGET_RENDERERS } from '../analytics/dashboardWidgets';

/**
 * The dashboard's widgets: which are shown, in what order, and how each is drawn.
 *
 * The dashboard is a FIXED set - one widget per type, nothing to create and
 * nothing to destroy. So this is a list of six rows, and everything it offers
 * is non-destructive: reorder, rename, switch off, and configure. A widget
 * switched off is unmounted and stops recalculating as packets arrive, which is
 * the whole of what deleting one would have achieved, minus the half that could
 * not be undone.
 *
 * Reordering is offered as BOTH a drag and a pair of buttons, and the buttons
 * are not a consolation prize. Native HTML5 drag fires no keyboard events and
 * exposes nothing to assistive tech, so a drag-only list is a setting some
 * people simply cannot change. It is also unreliable on a trackpad.
 *
 * Dragging happens here rather than on the live widgets on purpose: the
 * dashboard column is scrolling live data, and a drag gesture inside it would
 * compete with that for the same pointer.
 *
 * Each row opens to reveal that widget's own settings, generated from the type
 * catalogue in `dashboardPrefs` rather than written out per widget - so adding
 * a setting to a type is one entry there and no change at all here.
 */
export const DashboardWidgetList: React.FC = () => {
  const [dashboard, patchDashboard] = usePreferenceStore(dashboardStore);
  const widgets = dashboard.widgets;

  const [dragging, setDragging] = useState<WidgetTypeId | null>(null);
  const [expanded, setExpanded] = useState<WidgetTypeId | null>(null);
  const [announcement, setAnnouncement] = useState('');
  /** What just moved, so focus can follow the ITEM rather than the position. */
  const buttonRefs = useRef(new Map<string, HTMLButtonElement>());

  const write = (next: WidgetInstance[]) => patchDashboard({ widgets: next });

  const update = (type: WidgetTypeId, patch: Partial<WidgetInstance>) =>
    write(widgets.map((w) => (w.type === type ? { ...w, ...patch } : w)));

  const patchConfig = (type: WidgetTypeId, key: string, value: string | number) =>
    write(
      widgets.map((w) =>
        w.type === type ? { ...w, config: { ...w.config, [key]: value } } : w,
      ),
    );

  const move = (type: WidgetTypeId, delta: number, viaKeyboard: boolean) => {
    const from = widgets.findIndex((w) => w.type === type);
    const to = from + delta;
    if (from < 0 || to < 0 || to >= widgets.length) return;
    const next = [...widgets];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    write(next);
    setAnnouncement(`${widgetTitle(moved)} moved to position ${to + 1} of ${widgets.length}`);
    if (viaKeyboard) {
      // Focus follows the widget, not the slot. Re-focusing by position would
      // land on whatever row slid into it, and a second press would then move
      // the wrong widget.
      requestAnimationFrame(() =>
        buttonRefs.current.get(`${type}:${delta > 0 ? 'down' : 'up'}`)?.focus(),
      );
    }
  };

  const reorderTo = (type: WidgetTypeId, targetType: WidgetTypeId) => {
    if (type === targetType) return;
    const moved = widgets.find((w) => w.type === type);
    if (!moved) return;
    const next = widgets.filter((w) => w.type !== type);
    next.splice(next.findIndex((w) => w.type === targetType), 0, moved);
    write(next);
  };

  return (
    <>
      <ul role="list" className="mt-1 space-y-1">
        {widgets.map((widget, index) => {
          const spec = WIDGET_TYPES[widget.type];
          const Icon = WIDGET_RENDERERS[widget.type].icon;
          const isOpen = expanded === widget.type;
          const hasOptions = spec.options.length > 0;
          return (
            <li
              key={widget.type}
              aria-setsize={widgets.length}
              aria-posinset={index + 1}
              draggable
              onDragStart={() => setDragging(widget.type)}
              onDragEnd={() => setDragging(null)}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (dragging) reorderTo(dragging, widget.type);
                setDragging(null);
              }}
              className={`rounded-md border border-border bg-muted/30 ${
                dragging === widget.type ? 'opacity-50' : ''
              }`}
            >
              <div className="flex items-center gap-2 px-2 py-1.5">
                <TbGripVertical
                  aria-hidden
                  className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0 cursor-grab"
                />
                <Icon className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />

                {/* Renaming in place. The name is the only thing that
                    distinguishes a widget somebody has repurposed - a breakdown
                    switched to bytes and called "Bandwidth" - from what it
                    shipped as. */}
                <input
                  value={widget.title ?? ''}
                  placeholder={spec.label}
                  onChange={(e) => update(widget.type, { title: e.target.value || undefined })}
                  maxLength={40}
                  aria-label={`Name for ${spec.label}`}
                  className="flex-1 min-w-0 bg-transparent text-xs text-foreground placeholder:text-muted-foreground/70 outline-none focus:underline underline-offset-2"
                />

                <div className="flex items-center gap-0.5 shrink-0">
                  <button
                    type="button"
                    ref={(n) => { if (n) buttonRefs.current.set(`${widget.type}:up`, n); }}
                    onClick={() => move(widget.type, -1, true)}
                    disabled={index === 0}
                    // Named per widget: six rows of "Move up" all announce
                    // identically, with no way to tell which is which.
                    aria-label={`Move ${widgetTitle(widget)} up`}
                    className="p-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                  >
                    <TbChevronUp className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    ref={(n) => { if (n) buttonRefs.current.set(`${widget.type}:down`, n); }}
                    onClick={() => move(widget.type, 1, true)}
                    disabled={index === widgets.length - 1}
                    aria-label={`Move ${widgetTitle(widget)} down`}
                    className="p-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                  >
                    <TbChevronDown className="w-3.5 h-3.5" />
                  </button>
                </div>

                <Switch
                  checked={widget.enabled}
                  onCheckedChange={(enabled) => update(widget.type, { enabled })}
                  aria-label={`Show ${widgetTitle(widget)}`}
                  className="ml-1 shrink-0"
                />

                {/* Omitted, not disabled, for a widget with nothing to set. A
                    disclosure that opens onto an empty panel is worse than no
                    disclosure. */}
                {hasOptions ? (
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : widget.type)}
                    aria-expanded={isOpen}
                    aria-label={`${isOpen ? 'Hide' : 'Show'} settings for ${widgetTitle(widget)}`}
                    className="p-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer shrink-0"
                  >
                    <TbChevronRight
                      className={`w-3.5 h-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`}
                    />
                  </button>
                ) : (
                  <span className="w-[26px] shrink-0" aria-hidden />
                )}
              </div>

              {isOpen && hasOptions && (
                <div className="px-2 pb-2 pt-0.5 space-y-2 border-t border-border/60 mt-0.5">
                  <p className="text-[10px] text-muted-foreground leading-snug pt-1.5">
                    {spec.description}
                  </p>
                  {spec.options.map((option) =>
                    option.kind === 'choice' ? (
                      <div key={option.id} className="flex items-center justify-between gap-3">
                        <span className="text-[11px] text-foreground">{option.label}</span>
                        <Segmented
                          size="sm"
                          ariaLabel={`${option.label} for ${widgetTitle(widget)}`}
                          value={String(widget.config[option.id] ?? option.fallback)}
                          onValueChange={(next) => patchConfig(widget.type, option.id, next)}
                          options={option.choices}
                        />
                      </div>
                    ) : option.kind === 'text' ? (
                      // Full width on its own row rather than beside the label:
                      // a display filter is long, and the settings column is
                      // narrow enough that an inline field would show six
                      // characters of it.
                      <div key={option.id} className="space-y-1">
                        <span className="text-[11px] text-foreground">{option.label}</span>
                        <input
                          type="text"
                          aria-label={`${option.label} for ${widgetTitle(widget)}`}
                          value={String(widget.config[option.id] ?? option.fallback)}
                          maxLength={option.maxLength}
                          placeholder={option.placeholder}
                          onChange={(e) => patchConfig(widget.type, option.id, e.target.value)}
                          className="w-full bg-background border border-border rounded px-2 py-1 text-[11px] font-mono outline-none focus:border-primary"
                        />
                      </div>
                    ) : (
                      <div key={option.id} className="flex items-center justify-between gap-3">
                        <span className="text-[11px] text-foreground">{option.label}</span>
                        <div className="flex items-center gap-1">
                          <button
                            type="button"
                            aria-label={`Fewer ${option.label.toLowerCase()} for ${widgetTitle(widget)}`}
                            disabled={Number(widget.config[option.id]) <= option.min}
                            onClick={() =>
                              patchConfig(widget.type, option.id, Number(widget.config[option.id]) - 1)
                            }
                            className="p-1 rounded border border-border text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                          >
                            <TbMinus className="w-3 h-3" />
                          </button>
                          <span className="w-6 text-center text-[11px] font-mono tabular-nums text-foreground">
                            {String(widget.config[option.id] ?? option.fallback)}
                          </span>
                          <button
                            type="button"
                            aria-label={`More ${option.label.toLowerCase()} for ${widgetTitle(widget)}`}
                            disabled={Number(widget.config[option.id]) >= option.max}
                            onClick={() =>
                              patchConfig(widget.type, option.id, Number(widget.config[option.id]) + 1)
                            }
                            className="p-1 rounded border border-border text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                          >
                            <TbPlus className="w-3 h-3" />
                          </button>
                        </div>
                      </div>
                    ),
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {/*
        Without this, pressing the arrow buttons changes the visual order and
        announces nothing at all - the control appears to do nothing.
      */}
      <span role="status" aria-live="polite" className="sr-only">
        {announcement}
      </span>

      <p className="text-[11px] text-muted-foreground mt-2 leading-snug">
        Drag to reorder, or use the arrow buttons. Switching a widget off unmounts it, so it stops
        recalculating as packets arrive.
      </p>
    </>
  );
};
