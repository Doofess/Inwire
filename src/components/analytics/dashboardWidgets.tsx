import React from 'react';
import {
  TbMap2,
  TbActivity,
  TbChartPie,
  TbNetwork,
  TbAlertTriangle,
  TbRulerMeasure,
} from 'react-icons/tb';
import type { Packet } from '../../types/packet';
import type { WidgetConfig, WidgetTypeId } from '../../services/dashboardPrefs';
import { WIDGET_TYPE_IDS } from '../../services/dashboardPrefs';
import { GeoMap } from './GeoMap';
import { TrafficTimelineChart, type TimelineChart, type TimelineMetric } from './TrafficTimelineChart';
import { ProtocolBreakdown, type BreakdownChart, type BreakdownMetric } from './ProtocolBreakdown';
import { PacketSizeChart, type SizeChart } from './PacketSizeChart';
import { NetworkMatrix, type TalkersView } from './NetworkMatrix';
import { AnomalyAlertsPanel } from './AnomalyAlertsPanel';

/**
 * How each widget type is drawn, as data.
 *
 * The other half of the type catalogue: `services/dashboardPrefs.ts` holds what
 * a type is called and what it can be configured with, because that half has to
 * run under `tsx` for the assertion script. This holds the half that cannot -
 * an icon and a component - because importing GeoMap imports `maplibre-gl` at
 * module scope, and there is no browser for it to attach to in a script.
 *
 * Everything a widget might need is in ONE context type, supplied once, rather
 * than each entry carrying its own props. Per-widget props would force either a
 * discriminated union the caller narrows six ways - which is the `switch` this
 * exists to delete - or `any`. With a single context, adding a widget that
 * needs a new callback is a compile error at the one place the context is
 * built, which is the pressure you want.
 *
 * Widgets render their BODY only. The card around it - frame, heading, icon,
 * the header control, the empty state - is `WidgetCard`, drawn by the
 * dashboard, so that a dashboard somebody builds out of six widgets is six of
 * the same card rather than six different ones. See WidgetCard for what that
 * inconsistency actually looked like.
 */

export interface DashboardWidgetContext {
  packets: Packet[];
  isDark: boolean;
  themeKey?: string;
  isCapturing: boolean;
  appliedFilter: string;
  onSelectProtocol: (protocol: string) => void;
  onFilterHost: (ip: string) => void;
  onInspectPacket: (packet: Packet) => void;
}

/**
 * The frame a widget is being drawn in, and its way out of it.
 *
 * Only the map has a way out: it is the one widget with an expanded window,
 * because it is the one whose subject is bigger than a card. Everything else is
 * read at card size, in the column or in the popout bubble the collapsed rail
 * gives it - which is the same card at the same width.
 */
export interface WidgetFrame {
  onExpand?: () => void;
  /** `full` only ever comes from the map's own window. Defaults to `card`. */
  variant?: WidgetVariant;
}

/**
 * How much room a widget has been given.
 *
 * Down to one consumer - the map, which is the only widget with two sizes to
 * be in. Kept as a shared name rather than folded into GeoMap because the
 * dashboard is what decides it, and a prop the dashboard sets should be typed
 * where the dashboard can see it.
 */
export type WidgetVariant = 'card' | 'full';

export interface WidgetRenderer {
  readonly icon: React.ComponentType<{ className?: string }>;
  /**
   * The shape the card holds whether or not it has data.
   *
   * A widget that sized itself to its contents made the whole column jump as
   * packets arrived: the protocol card was a 40px header stub until the first
   * packet landed and then four times that. An aspect ratio where the content
   * scales with the column, a computed height where it is a list of rows.
   */
  readonly cardClassName?: string;
  readonly cardHeight?: (config: WidgetConfig) => number;
  /**
   * One line, shown with the type's icon when there is nothing to draw.
   *
   * Absent means this widget always has something to say - which is true of
   * exactly one of them: "zero threats active" is the alert panel's answer,
   * not the absence of one.
   */
  readonly emptyMessage?: string;
  /** The body reaches the card's edge, and the heading grows a divider. */
  readonly bleed?: boolean;
  render(ctx: DashboardWidgetContext, config: WidgetConfig, frame: WidgetFrame): React.ReactNode;
}

/**
 * How tall a card holding `rows` rows of `rowPx` should be.
 *
 * The header is 34px and the body's bottom padding 14px, both from WidgetCard.
 * Capped because past roughly twelve rows a card stops being a card and starts
 * being a page: the body scrolls beyond that rather than growing further.
 */
function listHeight(rows: number, rowPx: number): number {
  return Math.min(48 + rows * rowPx, 48 + 12 * rowPx);
}

export const WIDGET_RENDERERS: Record<WidgetTypeId, WidgetRenderer> = {
  geo: {
    icon: TbMap2,
    // A shape rather than a height, so the map scales with a column that can be
    // dragged instead of staying 256px tall in a 640px-wide card. 11/8 is what
    // 256px was at the default width, so an untouched dashboard is unchanged.
    cardClassName: 'aspect-[11/8] shrink-0',
    bleed: true,
    // Deliberately no emptyMessage. The map is not empty without packets - the
    // world is still there, and replacing it with a placeholder would hide the
    // basemap, the projection switcher and the location counter behind a line
    // of text saying that nothing had been located, which the counter already
    // says while leaving the map on screen.
    render: (ctx, _config, frame) => (
      <GeoMap
        packets={ctx.packets}
        isDark={ctx.isDark}
        themeKey={ctx.themeKey}
        variant={frame.variant ?? 'card'}
        onExpand={frame.onExpand}
      />
    ),
  },

  timeseries: {
    icon: TbActivity,
    // 2/1 gives the plot the same ~120px it had at the column's default width,
    // once the heading and the axis readout below it are taken off.
    cardClassName: 'aspect-[2/1] shrink-0',
    emptyMessage: 'No traffic yet. The chart fills in as packets arrive.',
    render: (ctx, config) => (
      <TrafficTimelineChart
        packets={ctx.packets}
        isCapturing={ctx.isCapturing}
        isDark={ctx.isDark}
        themeKey={ctx.themeKey}
        metric={config.metric as TimelineMetric}
        chart={config.chart as TimelineChart}
        intervalSeconds={Number(config.interval ?? 1)}
        overlayFilter={String(config.filter ?? '')}
      />
    ),
  },

  breakdown: {
    icon: TbChartPie,
    cardHeight: (config) =>
      config.chart === 'donut'
        ? 152
        : listHeight(config.top as number, config.chart === 'table' ? 22 : 34),
    emptyMessage: 'No packets to break down yet.',
    render: (ctx, config) => (
      <ProtocolBreakdown
        packets={ctx.packets}
        metric={config.metric as BreakdownMetric}
        chart={config.chart as BreakdownChart}
        top={config.top as number}
        onSelectProtocol={ctx.onSelectProtocol}
        selectedProtocolFilter={ctx.appliedFilter}
        themeKey={ctx.themeKey}
      />
    ),
  },

  sizes: {
    icon: TbRulerMeasure,
    // Seven buckets, always - so unlike the ranked lists this one has a height
    // that does not depend on anything the user can set.
    cardHeight: (config) => (config.chart === 'table' ? listHeight(7, 22) : 168),
    emptyMessage: 'No frames measured yet.',
    render: (ctx, config) => (
      <PacketSizeChart packets={ctx.packets} chart={config.chart as SizeChart} />
    ),
  },

  talkers: {
    icon: TbNetwork,
    cardHeight: (config) => listHeight(config.top as number, 30),
    emptyMessage: 'No conversations yet.',
    render: (ctx, config) => (
      <NetworkMatrix
        packets={ctx.packets}
        onFilterHost={ctx.onFilterHost}
        view={config.view as TalkersView}
        top={config.top as number}
      />
    ),
  },

  alerts: {
    icon: TbAlertTriangle,
    // Bleeding, so the alert tint reaches the card's own edges instead of being
    // a second bordered box inside it. See AnomalyAlertsPanel.
    bleed: true,
    // Tall enough for the worst case it actually draws: a status line, a
    // two-line clamped title, a target line and the button. At 150 that
    // overflowed the moment a real alert carried an IPv6 address.
    cardHeight: () => 172,
    // Deliberately no emptyMessage. An empty buffer is not an absence of an
    // answer here - "zero threats active" IS the answer, and replacing it with
    // "nothing to show" would be strictly less informative.
    render: (ctx) => (
      <AnomalyAlertsPanel packets={ctx.packets} onInspectPacket={ctx.onInspectPacket} />
    ),
  },
};

// The two halves of the catalogue must not drift apart: one drives validation
// and persistence, the other drives rendering, and a type in one but not the
// other is either an unrenderable preference or an unreachable widget.
for (const id of WIDGET_TYPE_IDS) {
  if (!WIDGET_RENDERERS[id]) {
    throw new Error(`dashboardWidgets: no renderer for widget type "${id}"`);
  }
}
