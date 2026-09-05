import React from 'react';
import {
  headerOption,
  widgetTitle,
  type WidgetConfig,
  type WidgetInstance,
  type WidgetTypeId,
} from '../../services/dashboardPrefs';
import { WIDGET_RENDERERS, type DashboardWidgetContext } from './dashboardWidgets';
import { WidgetCard } from './WidgetCard';
import { Segmented } from '../ui/segmented';

/**
 * One widget instance, framed and ready to place.
 *
 * There are two places a widget is drawn - the dashboard column, and the popout
 * bubble a collapsed rail icon gives it - and they must be the same widget
 * rather than two renderings that agree. So there is one call, here, and the
 * callers differ only in where they put the result.
 *
 * That is what makes the claim the rail rests on true by construction rather
 * than by inspection: the bubble IS the card, at the same width, from the same
 * code, not a preview of it.
 */

interface RenderedWidgetProps {
  widget: WidgetInstance;
  context: DashboardWidgetContext;
  /** Writes the widget's settings. The header control is a real setting. */
  onConfigChange: (type: WidgetTypeId, patch: WidgetConfig) => void;
  /** Only ever supplied for the map. See dashboardWidgets. */
  onExpand?: () => void;
}

export const RenderedWidget: React.FC<RenderedWidgetProps> = ({
  widget,
  context,
  onConfigChange,
  onExpand,
}) => {
  const renderer = WIDGET_RENDERERS[widget.type];
  const option = headerOption(widget.type);
  const title = widgetTitle(widget);

  return (
    <WidgetCard
      icon={renderer.icon}
      title={title}
      bleed={renderer.bleed}
      className={renderer.cardClassName}
      style={renderer.cardHeight ? { height: renderer.cardHeight(widget.config) } : undefined}
      // One test for every widget: nothing has been captured, so there is
      // nothing any of them can show. A per-widget predicate would be more
      // precise and would earn nothing - with packets in the buffer, every one
      // of these has rows.
      isEmpty={!!renderer.emptyMessage && context.packets.length === 0}
      emptyMessage={renderer.emptyMessage}
      onExpand={onExpand}
      controls={
        option && (
          <Segmented
            size="sm"
            ariaLabel={`${option.label} for ${title}`}
            value={String(widget.config[option.id] ?? option.fallback)}
            onValueChange={(next) => onConfigChange(widget.type, { [option.id]: next })}
            options={option.choices}
          />
        )
      }
    >
      {renderer.render(context, widget.config, { onExpand })}
    </WidgetCard>
  );
};
