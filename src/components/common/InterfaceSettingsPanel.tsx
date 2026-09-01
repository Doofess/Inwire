import React from 'react';
import { Switch } from '../ui/switch';
import { Segmented } from '../ui/segmented';
import {
  layoutStore,
  minimapStore,
  motionStore,
  packetListStore,
  performanceStore,
  nameResolutionStore,
  resetInterfacePreferences,
  type DashboardRefresh,
  type FollowMode,
  type ListDensity,
  type MotionSetting,
  type PaneArrangement,
} from '../../services/interfacePrefs';
import { usePreferenceStore, usePreferenceValue } from '../../services/preferenceStore';
import { dashboardStore, type DashboardMode } from '../../services/dashboardPrefs';
import { DashboardWidgetList } from './DashboardWidgetList';

/**
 * Settings -> Interface: how the app looks and behaves as a UI.
 *
 * Distinct from Appearance, which owns theme colour. Nothing here is about
 * capture adapters - those stay in Driver Info.
 *
 * The panel is a VIEW, not the owner. Every value lives in a module-level
 * store, so the control that changes it here and the control that changes it in
 * place - a divider, a rail button, a column menu - are the same value rather
 * than two copies that drift. See services/preferenceStore.
 *
 * Nothing here has a Save button. Settings apply as they are changed, which is
 * the same decision the display-filter panel documents, and it matters more
 * here: this modal COVERS most of what these settings control, so the only way
 * to see a layout change is for it to have happened already.
 */

const SECTION_CLASS = 'text-[10px] font-bold uppercase tracking-widest text-muted-foreground';

/**
 * One setting: name, explanation, control.
 *
 * Deliberately local rather than in components/common. It has one consumer, and
 * a file in a shared directory announces itself as a shared primitive; this can
 * move the day something else wants it.
 */
function SettingRow({
  label,
  description,
  htmlFor,
  children,
}: {
  label: string;
  description?: string;
  /** Set when the control is a single focusable element that can own the label. */
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-2.5">
      <div className="min-w-0">
        {htmlFor ? (
          <label htmlFor={htmlFor} className="text-xs font-semibold text-foreground cursor-pointer">
            {label}
          </label>
        ) : (
          <div className="text-xs font-semibold text-foreground">{label}</div>
        )}
        {description && (
          <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{description}</p>
        )}
      </div>
      <div className="shrink-0 pt-0.5">{children}</div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className={SECTION_CLASS}>{title}</h3>
      <div className="mt-1 divide-y divide-border/60">{children}</div>
    </section>
  );
}

const ARRANGEMENT_OPTIONS = [
  { value: 'side-by-side' as PaneArrangement, label: 'Side by side' },
  { value: 'stacked' as PaneArrangement, label: 'Stacked' },
];

const FOLLOW_OPTIONS = [
  { value: 'always' as FollowMode, label: 'Always' },
  { value: 'reading' as FollowMode, label: 'Pause while reading' },
  { value: 'never' as FollowMode, label: 'Never' },
];

const DENSITY_OPTIONS = [
  { value: 'compact' as ListDensity, label: 'Compact' },
  { value: 'default' as ListDensity, label: 'Default' },
  { value: 'comfortable' as ListDensity, label: 'Comfortable' },
];

const REFRESH_OPTIONS = [
  { value: '500' as const, label: 'Live' },
  { value: '2000' as const, label: 'Relaxed' },
  // "Paused", not "Manual": there is no refresh button yet, and a label that
  // implies one would be describing a feature that is not there. The way back
  // is this control.
  { value: '0' as const, label: 'Paused' },
];

const BUFFER_OPTIONS = [
  { value: '10000' as const, label: '10k' },
  { value: '25000' as const, label: '25k' },
  { value: '50000' as const, label: '50k' },
];

const DASHBOARD_MODE_OPTIONS = [
  { value: 'full' as DashboardMode, label: 'Full' },
  { value: 'icons' as DashboardMode, label: 'Icon rail' },
  { value: 'hidden' as DashboardMode, label: 'Hidden' },
];

const MOTION_OPTIONS = [
  { value: 'system' as MotionSetting, label: 'Follow system' },
  { value: 'always' as MotionSetting, label: 'Always' },
  { value: 'never' as MotionSetting, label: 'Never' },
];

export const InterfaceSettingsPanel: React.FC = () => {
  const [layout, patchLayout] = usePreferenceStore(layoutStore);
  const [list, patchList] = usePreferenceStore(packetListStore);
  const [minimap, setMinimap] = usePreferenceValue(minimapStore);
  const [perf, patchPerf] = usePreferenceStore(performanceStore);
  const [motion, setMotion] = usePreferenceValue(motionStore);
  const [dashboard, patchDashboard] = usePreferenceStore(dashboardStore);
  const [nameResolution, patchNameResolution] = usePreferenceStore(nameResolutionStore);

  return (
    <div>
      <Section title="Layout">
        <SettingRow
          label="Packet detail panes"
          description="The protocol tree and byte view below the packet list."
          htmlFor="setting-panes"
        >
          <Switch
            id="setting-panes"
            checked={layout.panes}
            onCheckedChange={(panes) => patchLayout({ panes })}
          />
        </SettingRow>

        <SettingRow
          label="Pane arrangement"
          description="Whether the protocol tree and byte view sit beside each other or above and below."
        >
          <Segmented
            ariaLabel="Pane arrangement"
            value={layout.arrangement}
            onValueChange={(arrangement) => patchLayout({ arrangement })}
            options={ARRANGEMENT_OPTIONS}
            disabled={!layout.panes}
          />
        </SettingRow>
        <SettingRow
          label="Dashboard"
          description="The analytics column on the right. The icon rail fits in narrower windows than the full column does, where today the dashboard disappears entirely."
        >
          <Segmented
            ariaLabel="Dashboard"
            value={dashboard.mode}
            onValueChange={(mode) => patchDashboard({ mode })}
            options={DASHBOARD_MODE_OPTIONS}
          />
        </SettingRow>

        <div className="py-2.5">
          <div className="text-xs font-semibold text-foreground">Widgets</div>
          <DashboardWidgetList />
        </div>
      </Section>

      <Section title="Packet list">
        <SettingRow
          label="Follow live capture"
          description="Whether the list scrolls to keep the newest packet in view while capturing."
        >
          <Segmented
            ariaLabel="Follow live capture"
            value={list.follow}
            onValueChange={(follow) => patchList({ follow })}
            options={FOLLOW_OPTIONS}
          />
        </SettingRow>

        <SettingRow
          label="Packet list density"
          description="Row height and text size in the list. Does not affect the detail panes."
        >
          <Segmented
            ariaLabel="Packet list density"
            value={list.density}
            onValueChange={(density) => patchList({ density })}
            options={DENSITY_OPTIONS}
          />
        </SettingRow>

        <SettingRow
          label="Minimap"
          description="The overview strip beside the scrollbar. It redraws on every packet, so turning it off is the single largest saving available while capturing."
          htmlFor="setting-minimap"
        >
          <Switch id="setting-minimap" checked={minimap} onCheckedChange={setMinimap} />
        </SettingRow>
      </Section>

      <Section title="Performance">
        <SettingRow
          label="Dashboard refresh"
          description="How often the panels on the right recalculate. Relaxed is a quarter of the work for the same panels; Paused holds them at their last values until you change this back."
        >
          <Segmented
            ariaLabel="Dashboard refresh"
            value={String(perf.dashboardRefreshMs) as '500' | '2000' | '0'}
            onValueChange={(v) =>
              patchPerf({ dashboardRefreshMs: Number(v) as DashboardRefresh })
            }
            options={REFRESH_OPTIONS}
          />
        </SettingRow>

        <SettingRow
          label="Buffer size"
          description="How many packets are kept before the oldest are dropped. A smaller buffer makes every calculation in the app proportionally cheaper."
        >
          <Segmented
            ariaLabel="Buffer size"
            value={String(perf.packetBufferCap) as '10000' | '25000' | '50000'}
            onValueChange={(v) => patchPerf({ packetBufferCap: Number(v) })}
            options={BUFFER_OPTIONS}
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

      <Section title="Privacy">
        <p className="text-[11px] text-muted-foreground pb-1 leading-snug">
          These lookups send the public addresses in your capture to third-party services. Both are
          off until you turn them on.
        </p>

        <SettingRow
          label="Locate addresses"
          description="Sends the public IP addresses in your capture to get.geojs.io, in batches, as they first appear - and asks it once per launch where this machine is. Without this the map has nothing to plot."
          htmlFor="setting-geoip"
        >
          <Switch
            id="setting-geoip"
            checked={nameResolution.geoIp}
            onCheckedChange={(geoIp) => patchNameResolution({ geoIp })}
          />
        </SettingRow>

        <SettingRow
          label="Reverse DNS"
          description="Sends each public IPv4 address in your capture to cloudflare-dns.com as a PTR query, one address per request, to find host names."
          htmlFor="setting-rdns"
        >
          <Switch
            id="setting-rdns"
            checked={nameResolution.reverseDns}
            onCheckedChange={(reverseDns) => patchNameResolution({ reverseDns })}
          />
        </SettingRow>

        <p className="text-[11px] text-muted-foreground pt-2 leading-snug">
          MAC vendor names come from a table built into NetView. Nothing is sent for those, and all
          protocol dissection happens on this machine.
        </p>
      </Section>

      <div className="pt-3 mt-1 border-t border-border flex items-center justify-between gap-4">
        <p className="text-[11px] text-muted-foreground leading-snug">
          Restores the settings above, apart from Privacy. Your theme, filters, pane sizes and the
          two lookup switches are left alone - tidying a layout is not consent to start sending
          addresses again.
        </p>
        <button
          type="button"
          onClick={resetInterfacePreferences}
          className="shrink-0 rounded-full px-3 py-1.5 text-[11px] font-semibold border border-border text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer"
        >
          Reset interface settings
        </button>
      </div>
    </div>
  );
};
