import React, { useRef, useState } from 'react';
import { TbGripVertical, TbChevronUp, TbChevronDown } from 'react-icons/tb';
import { Switch } from '../ui/switch';
import { dashboardStore, type DashboardWidgetId } from '../../services/dashboardPrefs';
import { usePreferenceStore } from '../../services/preferenceStore';
import { WIDGETS_BY_ID } from '../analytics/dashboardWidgets';

/**
 * The dashboard's widgets: which are shown, and in what order.
 *
 * Reordering is offered as BOTH a drag and a pair of buttons, and the buttons
 * are not a consolation prize. Native HTML5 drag fires no keyboard events and
 * exposes nothing to assistive tech, so a drag-only list is a setting that some
 * people simply cannot change. It is also unreliable on a trackpad.
 *
 * Dragging happens here rather than on the live widgets on purpose: the
 * dashboard column is scrolling live data, and a drag gesture inside it would
 * compete with that for the same pointer.
 */
export const DashboardWidgetList: React.FC = () => {
  const [dashboard, patchDashboard] = usePreferenceStore(dashboardStore);
  const { order, disabled } = dashboard;
  const disabledSet = new Set(disabled);

  const [dragging, setDragging] = useState<DashboardWidgetId | null>(null);
  /** What just moved, so focus can follow the ITEM rather than the position. */
  const buttonRefs = useRef(new Map<string, HTMLButtonElement>());
  const [announcement, setAnnouncement] = useState('');

  const move = (id: DashboardWidgetId, delta: number, viaKeyboard: boolean) => {
    const from = order.indexOf(id);
    const to = from + delta;
    if (from < 0 || to < 0 || to >= order.length) return;
    const next = [...order];
    next.splice(from, 1);
    next.splice(to, 0, id);
    patchDashboard({ order: next });
    setAnnouncement(`${WIDGETS_BY_ID[id].label} moved to position ${to + 1} of ${order.length}`);
    if (viaKeyboard) {
      // Focus follows the widget, not the slot. Re-focusing by position would
      // land on whatever row slid into it, and a second press would then move
      // the wrong widget.
      requestAnimationFrame(() => buttonRefs.current.get(`${id}:${delta > 0 ? 'down' : 'up'}`)?.focus());
    }
  };

  const reorderTo = (id: DashboardWidgetId, targetId: DashboardWidgetId) => {
    if (id === targetId) return;
    const next = order.filter((w) => w !== id);
    next.splice(next.indexOf(targetId), 0, id);
    patchDashboard({ order: next });
  };

  const toggle = (id: DashboardWidgetId, enabled: boolean) => {
    patchDashboard({
      disabled: enabled ? disabled.filter((w) => w !== id) : [...disabled, id],
    });
  };

  return (
    <>
      <ul role="list" className="mt-1 space-y-1">
        {order.map((id, index) => {
          const widget = WIDGETS_BY_ID[id];
          if (!widget) return null;
          const Icon = widget.icon;
          const enabled = !disabledSet.has(id);
          return (
            <li
              key={id}
              aria-setsize={order.length}
              aria-posinset={index + 1}
              draggable
              onDragStart={() => setDragging(id)}
              onDragEnd={() => setDragging(null)}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (dragging) reorderTo(dragging, id);
                setDragging(null);
              }}
              className={`flex items-center gap-2 rounded-md border border-border bg-muted/30 px-2 py-1.5 ${
                dragging === id ? 'opacity-50' : ''
              }`}
            >
              <TbGripVertical
                aria-hidden
                className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0 cursor-grab"
              />
              <Icon className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
              <span className="text-xs text-foreground flex-1 min-w-0 truncate">{widget.label}</span>

              <div className="flex items-center gap-0.5 shrink-0">
                <button
                  type="button"
                  ref={(n) => { if (n) buttonRefs.current.set(`${id}:up`, n); }}
                  onClick={() => move(id, -1, true)}
                  disabled={index === 0}
                  // Named per widget: five rows of "Move up" all announce
                  // identically, and there is no way to tell which is which.
                  aria-label={`Move ${widget.label} up`}
                  className="p-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                >
                  <TbChevronUp className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  ref={(n) => { if (n) buttonRefs.current.set(`${id}:down`, n); }}
                  onClick={() => move(id, 1, true)}
                  disabled={index === order.length - 1}
                  aria-label={`Move ${widget.label} down`}
                  className="p-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 disabled:pointer-events-none transition-colors cursor-pointer"
                >
                  <TbChevronDown className="w-3.5 h-3.5" />
                </button>
              </div>

              <Switch
                checked={enabled}
                onCheckedChange={(next) => toggle(id, next)}
                aria-label={`Show ${widget.label}`}
                className="ml-1 shrink-0"
              />
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
