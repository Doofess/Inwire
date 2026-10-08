import React from 'react';
import { Switch } from '../ui/switch';
import { Segmented } from '../ui/segmented';
import {
  layoutStore,
  minimapStore,
  packetListStore,
  performanceStore,
  nameResolutionStore,
  resetInterfacePreferences,
  type DashboardRefresh,
  type FollowMode,
  type ListDensity,
  type PaneArrangement,
} from '../../services/interfacePrefs';
import { usePreferenceStore, usePreferenceValue } from '../../services/preferenceStore';
import { Section, SettingRow } from './settingsLayout';
import { AVERAGE_FRAME_BYTES, currentBufferBudget, framesForBudget } from '../../services/bufferBudget';
import { shardsFor } from '../../services/pipeline/threads';

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

/**
 * The buffer budget, in megabytes.
 *
 * It used to be a count of packets - 10k / 25k / 50k / 100k. A frame cost
 * 2,342 B when those were chosen and costs 740 B now, so the largest was about
 * 74 MB: the setting was rationing a resource nobody was short of, in a unit
 * that says nothing about the one they are.
 */
/**
 * 'Auto' leads, because it is the answer for almost every machine.
 *
 * The explicit sizes stay as overrides rather than being replaced: somebody
 * running a capture beside a VM has a reason to hold the buffer down that the
 * machine's RAM cannot tell them.
 *
 * **The value is the string 'auto', and the handler no longer does `Number(v)`
 * unconditionally.** It did, which turns 'auto' into `NaN` - and `Segmented` is
 * a Radix `RadioGroup`, so a `NaN` budget would have rendered a control with
 * nothing selected AND written a `NaN` into the stored preference.
 */
const BUFFER_OPTIONS = [
  { value: 'auto', label: 'Auto' },
  { value: String(128 * 1024 * 1024), label: '128 MB' },
  { value: String(256 * 1024 * 1024), label: '256 MB' },
  { value: String(512 * 1024 * 1024), label: '512 MB' },
  { value: String(1024 * 1024 * 1024), label: '1 GB' },
  { value: String(2048 * 1024 * 1024), label: '2 GB' },
];


/** Dissection threads (ADR 0053 phase 3): auto first, for the reason the buffer's is. */
const THREAD_OPTIONS = [
  { value: 'auto' as const, label: 'Auto' },
  { value: '1' as const, label: '1' },
];

/** The TCP shards `auto` resolves to on this machine; 0 is one core. */
const THREAD_CORES = shardsFor('auto', typeof navigator === 'undefined' ? 1 : navigator.hardwareConcurrency ?? 1);

/**
 * Animations live in the Accessibility tab now, not here.
 *
 * `motionStore` is still listed in INTERFACE_STORES and is still reset by this
 * tab's Reset button - the setting belongs to the interface, the CONTROL
 * belongs beside the other things somebody changes because the default does not
 * work for them. Only the row moved; the key and the stored value did not, so
 * nobody's choice was reset by the move.
 */

export const InterfaceSettingsPanel: React.FC = () => {
  const [layout, patchLayout] = usePreferenceStore(layoutStore);
  const [list, patchList] = usePreferenceStore(packetListStore);
  const [minimap, setMinimap] = usePreferenceValue(minimapStore);
  const [perf, patchPerf] = usePreferenceStore(performanceStore);
  const [nameResolution, patchNameResolution] = usePreferenceStore(nameResolutionStore);

  return (
    <div>
      <Section title="Layout">
        {/* **The "Packet detail panes" switch was here and is in the title
            row.** `TitleRow.tsx`, beside the caption buttons, which is where
            every editor puts a layout toggle - and the distinction that moved
            it is the one this panel exists to make: a SETTING is chosen once
            and a CONTROL is reached for mid-task. Showing and hiding the panes
            is the second, and it was two clicks and a modal away.

            The preference itself is unchanged and still persists; `layout.panes`
            is still read right below, to grey out an arrangement that has
            nothing to arrange. That row stays here because choosing beside-vs-
            stacked really is a setting. */}
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
        {/* **Two widget controls stood here and both are gone.** First a
            three-way Dashboard mode - full, icons, hidden - whose description
            began "The analytics column on the right"; then, after the dock
            replaced that column, a reorderable list of every widget with its
            per-widget settings, generated from the widget catalogue.

            There is no dock and no catalogue. The three widgets that survived
            are surfaces with their own homes - the map is a view, the two charts
            are a tab of the Statistics pane - and each carries its own controls
            where it is drawn, which is what this list existed to substitute for
            on a 352px card that had room for one. */}
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
          description={
            `Memory the captured frames may use before the oldest are dropped - about `
            + `${framesForBudget(currentBufferBudget(perf.packetBufferBytes), AVERAGE_FRAME_BYTES).toLocaleString()} packets at this `
            + `capture's average. A smaller buffer makes every calculation in the app `
            + `proportionally cheaper. Frame data and analysis state are held separately and `
            + `add roughly 60 MB on top of this.`
          }
        >
          <Segmented
            ariaLabel="Buffer size"
            value={String(perf.packetBufferBytes)}
            onValueChange={(v) => patchPerf({
              packetBufferBytes: v === 'auto' ? 'auto' : Number(v),
            })}
            options={BUFFER_OPTIONS}
          />
        </SettingRow>

        <SettingRow
          label="Dissection threads"
          description={
            THREAD_CORES > 0
              ? `Auto dissects a live capture's TCP on ${THREAD_CORES} cores beside the one that merges it, `
                + `which is what keeps the list live through a download faster than one core can read. `
                + `1 dissects on one core, as before. Takes effect when the next capture starts.`
              : 'This machine has too few cores to spare, so Auto dissects on one, as 1 does. '
                + 'Takes effect when the next capture starts.'
          }
        >
          <Segmented
            ariaLabel="Dissection threads"
            value={String(perf.dissectionThreads) as 'auto' | '1'}
            onValueChange={(v) => patchPerf({ dissectionThreads: v === '1' ? 1 : 'auto' })}
            options={THREAD_OPTIONS}
          />
        </SettingRow>
      </Section>

      {/* Wireshark keeps these under View -> Name Resolution, and so did this
          app, in the hamburger menu beside the views they changed. That menu is
          gone - everything in it either had a permanent control already or has
          one now - and these two came here rather than to the rail.

          **The number that used to justify that no longer does.** The rail was
          630px against the 640 it gets, leaving 10px and no room for an icon;
          it is 494 against 624 now - six icons were deleted, and the status bar
          took 24 of what they freed - so there is room for two more.
          `scripts/session/view.ts` holds that arithmetic and prints the slack.

          The placement stands on its own argument, which is the one below: the
          other half of name resolution is already here, and these two belong
          with it rather than with the views.

          Here rather than anywhere else because the other half of name
          resolution is already here. The split is the point of the two sections:
          these two are answered entirely out of the capture, and the two below
          send an address to somebody. Keeping them apart is what lets the
          Privacy heading mean something. */}
      <Section title="Name resolution">
        <p className="text-[11px] text-muted-foreground pb-1 leading-snug">
          Both are passive: every name they show was already in the capture. Nothing is sent.
        </p>

        <SettingRow
          label="Resolve network addresses"
          description="Shows host names instead of IP addresses in the packet list's address columns and in the statistics tables, where the capture itself carried the name - from DNS responses, mDNS, NetBIOS and the like."
          htmlFor="setting-resolve-network"
        >
          <Switch
            id="setting-resolve-network"
            checked={nameResolution.network}
            onCheckedChange={(network) => patchNameResolution({ network })}
          />
        </SettingRow>

        <SettingRow
          label="Resolve transport ports"
          description="Shows service names beside port numbers in the statistics tables - 443 as https, 53 as domain. From a table built into Inwire."
          htmlFor="setting-resolve-transport"
        >
          <Switch
            id="setting-resolve-transport"
            checked={nameResolution.transport}
            onCheckedChange={(transport) => patchNameResolution({ transport })}
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
          description="Sends the public IP addresses in your capture to get.geojs.io, in batches, as they first appear - and asks it once per launch where this machine is. Also lets the Network panel's Public identity section ask ipapi.co about this connection. Without this the map has nothing to plot."
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
          MAC vendor names come from a table built into Inwire. Nothing is sent for those, and all
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
