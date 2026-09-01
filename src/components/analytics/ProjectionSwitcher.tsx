import React from 'react';
import { TbWorld, TbMap } from 'react-icons/tb';
import type { MapProjectionMode } from '../../services/mapPrefs';

interface ProjectionSwitcherProps {
  mode: MapProjectionMode;
  onChange: (mode: MapProjectionMode) => void;
}

/**
 * Globe / flat toggle, styled as one more of the map's floating round controls.
 *
 * A single button that shows the mode you would switch TO, rather than a
 * two-segment control showing both. At this size - one 36px circle in a stack
 * with the zoom buttons - a segmented pair would either be too small to read or
 * too wide to belong, and there are only two states, so the toggle is
 * unambiguous. Same shell as ZoomControls' buttons, deliberately: it sits
 * directly above them and anything else would read as a different kind of
 * object.
 *
 * The icon shows the DESTINATION, and the label says so ("Switch to globe"),
 * because a control showing its current state and a control showing its next
 * state are indistinguishable at a glance when there are only two - so the
 * wording carries what the icon cannot.
 */
export const ProjectionSwitcher: React.FC<ProjectionSwitcherProps> = ({ mode, onChange }) => {
  const next: MapProjectionMode = mode === 'globe' ? 'mercator' : 'globe';
  const label = next === 'globe' ? 'Switch to globe view' : 'Switch to flat view';
  const Icon = next === 'globe' ? TbWorld : TbMap;

  return (
    <button
      type="button"
      onClick={() => onChange(next)}
      aria-label={label}
      title={label}
      // aria-pressed would be wrong: this is not a toggle that is "on" or
      // "off", it is a switch between two peers.
      className="flex h-9 w-9 items-center justify-center rounded-full border border-border
                 bg-card/80 text-foreground shadow-sm backdrop-blur-sm transition-colors
                 hover:bg-accent active:scale-95 cursor-pointer"
    >
      <Icon className="h-4 w-4" />
    </button>
  );
};
