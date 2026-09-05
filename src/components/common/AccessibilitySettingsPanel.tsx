import React from 'react';
import { Button } from '../ui/button';
import { Segmented } from '../ui/segmented';
import { FONT_OPTIONS } from '../../lib/fontOptions';
import { fontStore } from '../../services/accessibilityPrefs';
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
 * for. That is why the typeface picker is here and not beside the theme picker,
 * and it is what Hyperlegible is doing on the list.
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

const FONT_CHOICES = FONT_OPTIONS.map((f) => ({
  value: f.id,
  label: f.label,
  hint: f.hint,
}));

export const AccessibilitySettingsPanel: React.FC = () => {
  const [font, setFont] = usePreferenceValue(fontStore);
  const [motion, setMotion] = usePreferenceValue(motionStore);
  const [tour] = usePreferenceValue(tourStore);

  return (
    <div>
      <Section title="Reading">
        <SettingRow
          label="Typeface"
          description="Applies to the interface - menus, settings and labels. The packet list, hex dump and protocol tree stay monospaced whatever is chosen here, because their columns only line up if every character is the same width."
        >
          <Segmented
            ariaLabel="Interface typeface"
            value={font}
            onValueChange={setFont}
            options={FONT_CHOICES}
          />
        </SettingRow>
      </Section>

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
