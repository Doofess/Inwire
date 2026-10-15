import React from 'react';
import { useTheme } from 'next-themes';
import { Check } from 'lucide-react';
import { SYSTEM_THEME_OPTION, THEME_OPTIONS } from '../../lib/themeOptions';
import { Switch } from '../ui/switch';
import { Segmented } from '../ui/segmented';
import { usePreferenceValue } from '../../services/preferenceStore';
import {
  followSystemThemeStore,
  packetColorSetStore,
} from '../../services/themePrefs';
import {
  PACKET_COLOR_SET_SPECS,
  PACKET_COLOR_SETS,
  getPacketThemeForApp,
} from '../../services/packetThemes';
import { arcProtocolColorStore, mapSkinStore } from '../../services/mapPrefs';
import { Section, SettingRow } from './settingsLayout';

/**
 * Settings -> Appearance: colour, and only colour.
 *
 * The division with the Interface tab is deliberate and holds in both
 * directions: this tab owns what things are COLOURED, that one owns everything
 * else about the UI - what is on screen, how dense it is, how often it redraws.
 * A control belongs here if the answer it changes is a hex value.
 *
 * Four decisions, in the order they matter:
 *
 *   1. The app theme, which is the ground everything else is derived from.
 *   2. Which of three colour sets the packet list derives its fills with.
 *   3. Whether the map's connection arcs encode protocol.
 *   4. Which of two basemap skins the map is painted in.
 *
 * Nothing here has a Save button, for the same reason the Interface tab does
 * not: settings apply as they are changed. It matters more on this tab than
 * anywhere else, because two of these four controls change something the modal
 * is currently covering, and the swatch strip below is what answers for the
 * one that is not visible at all.
 */

const COLOR_SET_OPTIONS = PACKET_COLOR_SETS.map((value) => ({
  value,
  label: PACKET_COLOR_SET_SPECS[value].label,
}));

/**
 * The rules shown in the preview strip, and why these six.
 *
 * They are the FREQUENT_RULES that `scripts/themes/packet-themes.ts` holds to
 * the strict separation floor - the traffic that actually fills a capture. A
 * preview of twenty swatches would be a colour chart; six is the comparison a
 * reader makes on every screen, which is the thing a colour set is chosen on.
 */
const PREVIEW_RULES: { id: string; label: string }[] = [
  { id: 'color-tcp', label: 'TCP' },
  { id: 'color-udp', label: 'UDP' },
  { id: 'color-icmp', label: 'ICMP' },
  { id: 'color-arp', label: 'ARP' },
  { id: 'color-bad-tcp', label: 'Bad TCP' },
  { id: 'color-broadcast', label: 'Broadcast' },
];

const MAP_SKIN_OPTIONS = [
  { value: 'colorful' as const, label: 'Colourful' },
  { value: 'muted' as const, label: 'Theme-synced' },
];

export const AppearanceSettingsPanel: React.FC = () => {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const [followsSystem, setFollowsSystem] = usePreferenceValue(followSystemThemeStore);
  const [colorSet, setColorSet] = usePreferenceValue(packetColorSetStore);
  const [arcProtocolColors, setArcProtocolColors] = usePreferenceValue(arcProtocolColorStore);
  const [mapSkin, setMapSkin] = usePreferenceValue(mapSkinStore);

  // The same derivation the packet list runs, against the theme that is live
  // right now - so the strip shows the chosen set on the chosen theme rather
  // than a set of reference colours that would be right on neither.
  const preview = getPacketThemeForApp(resolvedTheme, colorSet);

  return (
    <div>
      <Section title="Theme">
        <div className="py-2.5">
          <div className="text-xs font-semibold text-foreground">App theme</div>
          <p className="text-[11px] text-muted-foreground mt-0.5 mb-2 leading-snug">
            The window, panels and charts. System follows Windows: Light or Dark, and High Contrast when Windows asks for it.
          </p>
          {/* Three across: the two themes plus System, which is a mode over
              them rather than a third palette - see useSystemThemePreference.
              Picking a theme by name turns following off, because choosing one
              IS saying "not whatever the OS says".

              The count tracks THEME_OPTIONS and has to be corrected by hand
              when that list changes: it was `grid-cols-5` for four themes, and
              cutting two left three buttons laid out across five columns, so
              the right 40% of a `max-w-5xl` row was empty. */}
          <div className="grid grid-cols-3 gap-2">
            {[...THEME_OPTIONS, SYSTEM_THEME_OPTION].map(({ value, label, icon: Icon }) => {
              const isSystem = value === SYSTEM_THEME_OPTION.value;
              const isActive = isSystem ? followsSystem : !followsSystem && theme === value;
              return (
                <button
                  key={value}
                  onClick={() => {
                    setFollowsSystem(isSystem);
                    if (!isSystem) setTheme(value);
                  }}
                  className={`relative flex flex-col items-center gap-1.5 py-3 px-1 rounded-lg border text-[11px] font-medium transition-colors ${
                    isActive
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent hover:text-foreground'
                  }`}
                >
                  {isActive && <Check className="w-3.5 h-3.5 absolute top-1.5 right-1.5" />}
                  <Icon className="w-5 h-5" />
                  <span className="text-center leading-tight">{label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </Section>

      <Section title="Packet colours">
        <SettingRow
          label="Colour set"
          description="How the packet list derives its row colours from the theme. Default is restrained and separates rows mostly by lightness; Vibrant is the same nine hues at roughly double the strength; Colourblind swaps in the Okabe-Ito set and leans on lightness harder still."
        >
          <Segmented
            ariaLabel="Packet colour set"
            value={colorSet}
            onValueChange={setColorSet}
            options={COLOR_SET_OPTIONS}
          />
        </SettingRow>

        {/* The list itself is behind this modal, so a picker with no preview
            would be three words and a guess. These are the real fills, from the
            same function the list calls. */}
        <div className="py-2.5">
          <div
            className="flex flex-wrap gap-1.5 rounded-lg border border-border p-2"
            style={{ background: preview.surface.background }}
          >
            {PREVIEW_RULES.map(({ id, label }) => {
              const colors = preview.rules[id];
              if (!colors) return null;
              return (
                <span
                  key={id}
                  className="rounded px-2 py-1 text-[10px] font-mono"
                  style={{ background: colors.background, color: colors.color }}
                >
                  {label}
                </span>
              );
            })}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1.5 leading-snug">
            The six most common rows, on this theme&apos;s own ground. Every set clears the same
            contrast and separation floors - they differ in how loud they are, not in how readable.
          </p>
        </div>
      </Section>

      <Section title="Map">
        <SettingRow
          label="Colour arcs by protocol"
          description="On, each connection arc takes the hue of the protocol carrying most of its traffic, matching the protocol chart. Off, every arc is the theme's accent, and the map shows where traffic goes without also encoding what it is."
          htmlFor="setting-arc-protocol-colors"
        >
          <Switch
            id="setting-arc-protocol-colors"
            checked={arcProtocolColors}
            onCheckedChange={setArcProtocolColors}
          />
        </SettingRow>

        <SettingRow
          label="Basemap skin"
          description="Colourful draws a fixed globe - green land, blue sea - that stays the same under every theme. Theme-synced builds the map out of the app's own tokens instead, so it recedes into the panel around it and changes when the theme does."
        >
          <Segmented
            ariaLabel="Basemap skin"
            value={mapSkin}
            onValueChange={setMapSkin}
            options={MAP_SKIN_OPTIONS}
          />
        </SettingRow>
      </Section>
    </div>
  );
};
