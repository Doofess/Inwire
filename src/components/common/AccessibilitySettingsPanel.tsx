import React from 'react';
import { Button } from '../ui/button';
import { Segmented } from '../ui/segmented';
import { motionStore, type MotionSetting } from '../../services/interfacePrefs';
import { usePreferenceValue } from '../../services/preferenceStore';
import { tourStore } from '../../services/tourPrefs';
import { Section, SettingRow } from './settingsLayout';

/**
 * The settings that decide whether the app is usable, as opposed to how it
 * looks.
 *
 * The line between this tab and Appearance is not "text here, colour there" -
 * it is who the setting is FOR. Appearance offers choices between things that
 * are all fine; these offer a way out for someone the default does not work
 * for.
 *
 * There used to be a typeface picker at the top of this tab, and Atkinson
 * Hyperlegible on it was the clearest case of that rule. It is deleted: the app
 * is set in one family in two cuts, and a picker that moved the sans and not
 * the mono re-created the seam it exists to close. The loss is a real one and
 * is recorded in CLAUDE.md and in the header of scripts/accessibility/fonts.ts
 * rather than glossed here.
 *
 * Animations moved here from the Interface tab. Only the row moved:
 * `motionStore` is a module-level store, so the key, the stored value and every
 * other reader are untouched and nobody's setting resets.
 */

const MOTION_OPTIONS = [
  { value: 'system' as MotionSetting, label: 'Follow system' },
  { value: 'always' as MotionSetting, label: 'Always' },
  { value: 'never' as MotionSetting, label: 'Never' },
];

export const AccessibilitySettingsPanel: React.FC = () => {
  const [motion, setMotion] = usePreferenceValue(motionStore);
  const [tour] = usePreferenceValue(tourStore);

  return (
    <div>
      <Section title="Motion">
        <SettingRow
          label="Animations"
          description="Pulsing map markers, alert indicators, map camera movement and panel transitions."
        >
          <Segmented
            ariaLabel="Animations"
            value={motion}
            onValueChange={setMotion}
            options={MOTION_OPTIONS}
          />
        </SettingRow>
      </Section>

      <Section title="Getting started">
        <SettingRow
          label="Tutorial"
          description={
            tour.completed
              ? 'The walkthrough that highlights the path from installing the driver to reading your first packet. You have already been through it.'
              : 'The walkthrough that highlights the path from installing the driver to reading your first packet. It runs the next time this page loads.'
          }
        >
          {/* The reason skipping the tour is allowed to retire it for good: it
              is never a dead end while this button exists. Closing Settings is
              deliberate - the tour points at the header and the panes, and it
              cannot highlight anything behind an open modal. */}
          <Button
            variant="outline"
            size="xs"
            onClick={() => tourStore.set({ completed: false })}
            disabled={!tour.completed}
          >
            {tour.completed ? 'Replay tutorial' : 'Queued for next load'}
          </Button>
        </SettingRow>
      </Section>
    </div>
  );
};
