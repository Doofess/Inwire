import React from 'react';
import { useTheme } from 'next-themes';
import { Check } from 'lucide-react';
import { SYSTEM_THEME_OPTION, THEME_OPTIONS } from '../../lib/themeOptions';
import { Switch } from '../ui/switch';
import { Segmented } from '../ui/segmented';
import { usePreferenceValue } from '../../services/preferenceStore';
import {
  accentColorStore,
  followSystemThemeStore,
  packetColorSetStore,
} from '../../services/themePrefs';
import { ACCENTS, type AccentId } from '../../lib/accents';
import {
  PACKET_COLOR_SET_SPECS,
  PACKET_COLOR_SETS,
  getPacketThemeForApp,
} from '../../services/packetThemes';
import { arcProtocolColorStore, mapSkinStore } from '../../services/mapPrefs';
import { Section, SettingRow } from './settingsLayout';
import { settingAnchorId } from '../../lib/settingsIndex';

/**
 * Settings -> Appearance: colour, and only colour.
 *
 * The division with the Interface tab is deliberate and holds in both
 * directions: this tab owns what things are COLOURED, that one owns everything
 * else about the UI - what is on screen, how dense it is, how often it redraws.
 * A control belongs here if the answer it changes is a hex value.
 *
 * Five decisions, in the order they matter:
 *
 *   1. The app theme, which is the ground everything else is derived from.
 *   2. The accent, one of seven swatches (`lib/accents.ts`, ADR 0056).
 *   3. Which of three colour sets the packet list derives its fills with.
 *   4. Whether the map's connection arcs encode protocol.
 *   5. Which of two basemap skins the map is painted in.
 *
 * Nothing here has a Save button, for the same reason the Interface tab does
 * not: settings apply as they are changed. It matters more on this tab than
 * anywhere else, because most of these controls change something the modal
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

/**
 * A theme drawn small: the title row and rail in the chrome colour, the rail's
 * active cell, a side bar strip, and three packet rows with the middle one
 * selected. The wrapper carries the theme's own class and `theme-scope`, so
 * every colour inside resolves to that theme whatever the document is in -
 * which is why the light block is selected by `.light` as well as `:root`, and
 * why `theme-scope` exists (index.css says what it fixes).
 */
const ThemeMiniature: React.FC<{ theme: string; accent: AccentId; style?: React.CSSProperties }> = ({
  theme,
  accent,
  style,
}) => (
  <div
    aria-hidden
    style={style}
    data-accent-color={accent}
    className={`${theme} theme-scope absolute inset-0 flex flex-col overflow-hidden bg-background`}
  >
    <div className="h-[6px] shrink-0 bg-secondary border-b border-border" />
    <div className="flex flex-1 min-h-0">
      <div className="w-[9px] shrink-0 flex flex-col items-center gap-[2px] pt-[3px] bg-secondary border-r border-border">
        <div className="w-[6px] h-[5px] rounded-[1px] bg-primary/20" />
        <div className="w-[3px] h-[3px] rounded-full bg-muted-foreground/60" />
      </div>
      <div className="w-[17px] shrink-0 flex flex-col gap-[3px] p-[3px] bg-card border-r border-border">
        <div className="h-[2px] w-full rounded-full bg-muted-foreground/50" />
        <div className="h-[2px] w-2/3 rounded-full bg-muted-foreground/50" />
      </div>
      <div className="flex-1 flex flex-col gap-[2px] py-[4px]">
        <div className="h-[6px] flex items-center px-[3px]">
          <div className="h-[2px] w-3/5 rounded-full bg-foreground/50" />
        </div>
        <div className="h-[6px] flex items-center px-[3px] bg-selection ring-1 ring-inset ring-primary">
          <div className="h-[2px] w-1/2 rounded-full bg-primary" />
        </div>
        <div className="h-[6px] flex items-center px-[3px]">
          <div className="h-[2px] w-2/5 rounded-full bg-foreground/50" />
        </div>
      </div>
    </div>
  </div>
);

/** System is Light and Dark at once, so its tile is both, cut on the diagonal. */
const SYSTEM_SPLIT: React.CSSProperties = { clipPath: 'polygon(100% 0, 100% 100%, 0 100%)' };

/**
 * The accent swatches, a radiogroup with a roving tab stop: one Tab reaches
 * the group, arrows move the choice and apply it, as the APG radio pattern
 * does. Each dot is painted from the table for the theme that is live, not
 * from `--primary`, because the dots are seven accents at once and the token
 * is only ever one.
 */
const AccentPicker: React.FC<{ theme: string }> = ({ theme }) => {
  const [accent, setAccent] = usePreferenceValue(accentColorStore);
  const refs = React.useRef<(HTMLButtonElement | null)[]>([]);
  const move = (from: number, step: number) => {
    const next = (from + step + ACCENTS.length) % ACCENTS.length;
    setAccent(ACCENTS[next].id);
    refs.current[next]?.focus();
  };
  return (
    <div role="radiogroup" aria-label="Accent colour" className="flex items-center gap-2.5">
      {ACCENTS.map((a, i) => {
        const checked = a.id === accent;
        return (
          <button
            key={a.id}
            ref={(el) => { refs.current[i] = el; }}
            role="radio"
            aria-checked={checked}
            aria-label={a.label}
            title={a.label}
            tabIndex={checked ? 0 : -1}
            onClick={() => setAccent(a.id)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); move(i, 1); }
              else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); move(i, -1); }
            }}
            style={{ background: a.primary[theme] ?? a.primary.light }}
            className={`grid place-items-center w-5 h-5 rounded-full transition-shadow focus-visible:outline-2 focus-visible:outline-offset-[5px] focus-visible:outline-ring ${
              checked ? 'ring-2 ring-offset-2 ring-offset-background ring-foreground/70' : 'hover:ring-2 hover:ring-offset-2 hover:ring-offset-background hover:ring-border'
            }`}
          >
            {checked && <Check className="w-3 h-3" strokeWidth={3} style={{ color: a.primaryForeground[theme] ?? a.primaryForeground.light }} />}
          </button>
        );
      })}
    </div>
  );
};

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
  const [accent] = usePreferenceValue(accentColorStore);

  // The same derivation the packet list runs, against the theme that is live
  // right now - so the strip shows the chosen set on the chosen theme rather
  // than a set of reference colours that would be right on neither.
  const preview = getPacketThemeForApp(resolvedTheme, colorSet);

  return (
    <div>
      <Section title="Theme">
        <div id={settingAnchorId("App theme")} className="py-2.5">
          <div className="text-xs font-semibold text-foreground">App theme</div>
          <p className="text-[11px] text-muted-foreground mt-0.5 mb-2 leading-snug">
            The window, panels and charts. System follows Windows: Light or Dark, and High Contrast when Windows asks for it.
          </p>
          {/* Five across: the four themes plus System, which is a mode over
              them rather than a fifth palette - see useSystemThemePreference.
              Picking a theme by name turns following off, because choosing one
              IS saying "not whatever the OS says".

              The count tracks THEME_OPTIONS and has to be corrected by hand
              when that list changes: cutting four themes to two once left
              three buttons laid out across five columns, so the right 40% of a
              `max-w-5xl` row was empty. */}
          <div className="grid grid-cols-5 gap-2">
            {[...THEME_OPTIONS, SYSTEM_THEME_OPTION].map(({ value, label, icon: Icon }) => {
              const isSystem = value === SYSTEM_THEME_OPTION.value;
              const isActive = isSystem ? followsSystem : !followsSystem && theme === value;
              return (
                <button
                  key={value}
                  aria-pressed={isActive}
                  onClick={() => {
                    setFollowsSystem(isSystem);
                    if (!isSystem) setTheme(value);
                  }}
                  className={`flex flex-col items-center gap-2 pt-2.5 pb-2 px-1 rounded-lg border text-[11px] font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring ${
                    isActive
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent hover:text-foreground'
                  }`}
                >
                  <div className="relative w-[72px] h-[44px] rounded-[5px] overflow-hidden ring-1 ring-border">
                    {isSystem ? (
                      <>
                        <ThemeMiniature theme="light" accent={accent} />
                        <ThemeMiniature theme="dark" accent={accent} style={SYSTEM_SPLIT} />
                      </>
                    ) : (
                      <ThemeMiniature theme={value} accent={accent} />
                    )}
                  </div>
                  <span className="flex items-center gap-1 leading-tight">
                    {isActive ? <Check className="w-3.5 h-3.5" /> : <Icon className="w-3.5 h-3.5" />}
                    {label}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
        <div id={settingAnchorId("Accent colour")} className="py-2.5">
          <div className="text-xs font-semibold text-foreground">Accent colour</div>
          <p className="text-[11px] text-muted-foreground mt-0.5 mb-2.5 leading-snug">
            The selected row, the active rail button, focus rings and the download trace. Each one is checked for contrast in every theme.
          </p>
          <AccentPicker theme={resolvedTheme ?? 'light'} />
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
