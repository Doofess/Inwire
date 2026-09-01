import React from 'react';
import {
  TbMap2,
  TbActivity,
  TbChartPie,
  TbNetwork,
  TbAlertTriangle,
} from 'react-icons/tb';
import type { Packet } from '../../types/packet';
import type { DashboardWidgetId } from '../../services/dashboardPrefs';
import { DASHBOARD_WIDGET_IDS } from '../../services/dashboardPrefs';
import { GeoMap } from './GeoMap';
import { TrafficTimelineChart } from './TrafficTimelineChart';
import { ProtocolDonutChart } from './ProtocolDonutChart';
import { NetworkMatrix } from './NetworkMatrix';
import { AnomalyAlertsPanel } from './AnomalyAlertsPanel';

/**
 * The analytics widgets, as data.
 *
 * The dashboard needs to reorder them, switch them off, list them in a settings
 * panel and draw them as icons in a rail. None of that is possible while they
 * are five hand-written JSX blocks.
 *
 * Everything a widget might need is in ONE context type, supplied once, rather
 * than each entry carrying its own props. Per-widget props would force either a
 * discriminated union the caller narrows five ways - which is the `switch` this
 * exists to delete - or `any`. With a single context, adding a widget that
 * needs a new callback is a compile error at the one place the context is
 * built, which is the pressure you want.
 */

/** How much room a widget has been given. */
export type WidgetVariant = 'card' | 'full';

/**
 * The frame a widget is being drawn in, and its way out of it.
 *
 * `onExpand` is here rather than on the context because it is per-widget: the
 * dashboard is what opens the overlay, for both the expand button on a card and
 * the icon rail, which is what makes those two the same window. A widget with
 * no expanded form of its own simply ignores it.
 */
export interface WidgetFrame {
  variant: WidgetVariant;
  onExpand?: () => void;
}

export interface DashboardWidgetContext {
  packets: Packet[];
  isDark: boolean;
  themeKey?: string;
  isCapturing: boolean;
  appliedFilter: string;
  onSelectProtocol: (protocol: string) => void;
  onOpenStatistics: () => void;
  onFilterHost: (ip: string) => void;
  onInspectPacket: (packet: Packet) => void;
  onFilterAnomaly: (type: string) => void;
}

export interface DashboardWidget {
  readonly id: DashboardWidgetId;
  /**
   * The widget's name, in one place.
   *
   * This is an ACCESSIBLE NAME, not tooltip copy. The rail renders icon-only
   * buttons, and a Radix tooltip wires `aria-describedby` rather than
   * `aria-labelledby` - so an icon button with a tooltip and no text child has
   * no accessible name at all. This string is what stops that, and it is on the
   * registry so a new widget cannot be added without one.
   */
  readonly label: string;
  readonly icon: React.ComponentType<{ className?: string }>;
  /** The wrapper the full column gives it. */
  readonly cardClassName: string;
  render(ctx: DashboardWidgetContext, frame: WidgetFrame): React.ReactNode;
}

export const DASHBOARD_WIDGETS: readonly DashboardWidget[] = [
  {
    id: 'geo',
    label: 'Geo map',
    icon: TbMap2,
    // A shape rather than a height. The column is draggable now, so the map
    // scales with it instead of staying 256px tall in a 640px-wide card; 11/8
    // is what 256px was at the default width, so an untouched dashboard is
    // unchanged. `shrink-0` still matters - the column is a flex column, and
    // without it a tall stack of widgets would squeeze the ratio away.
    cardClassName: 'aspect-[11/8] shrink-0 rounded-lg overflow-hidden border border-border',
    render: (ctx, frame) => (
      <GeoMap
        packets={ctx.packets}
        isDark={ctx.isDark}
        themeKey={ctx.themeKey}
        variant={frame.variant}
        onExpand={frame.onExpand}
      />
    ),
  },
  {
    id: 'timeline',
    label: 'Traffic timeline',
    icon: TbActivity,
    cardClassName: '',
    render: (ctx, frame) => (
      <TrafficTimelineChart
        packets={ctx.packets}
        isCapturing={ctx.isCapturing}
        isDark={ctx.isDark}
        themeKey={ctx.themeKey}
        variant={frame.variant}
        onExpand={frame.onExpand}
      />
    ),
  },
  {
    id: 'protocols',
    label: 'Protocol breakdown',
    icon: TbChartPie,
    cardClassName: '',
    render: (ctx) => (
      <ProtocolDonutChart
        packets={ctx.packets}
        onSelectProtocol={ctx.onSelectProtocol}
        selectedProtocolFilter={ctx.appliedFilter}
        onOpenStatistics={ctx.onOpenStatistics}
      />
    ),
  },
  {
    id: 'talkers',
    label: 'Top talkers',
    icon: TbNetwork,
    cardClassName: '',
    render: (ctx) => (
      <NetworkMatrix packets={ctx.packets} onFilterHost={ctx.onFilterHost} />
    ),
  },
  {
    id: 'alerts',
    // The only widget with no header of its own, so the rail could not have
    // taken a name or an icon from it even if the others were consistent.
    label: 'Alerts',
    icon: TbAlertTriangle,
    cardClassName: 'mt-auto',
    render: (ctx) => (
      <AnomalyAlertsPanel
        packets={ctx.packets}
        onInspectPacket={ctx.onInspectPacket}
        onFilterAnomaly={ctx.onFilterAnomaly}
      />
    ),
  },
];

export const WIDGETS_BY_ID = Object.fromEntries(
  DASHBOARD_WIDGETS.map((w) => [w.id, w]),
) as Record<DashboardWidgetId, DashboardWidget>;

// The registry and the id list must not drift apart: the ids drive validation
// and persistence, the registry drives rendering, and a widget in one but not
// the other is either an unrenderable preference or an unreachable widget.
if (DASHBOARD_WIDGETS.length !== DASHBOARD_WIDGET_IDS.length) {
  throw new Error('dashboardWidgets: registry and DASHBOARD_WIDGET_IDS disagree');
}
