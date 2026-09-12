import React from 'react';
import { TbRefresh, TbAlertTriangle } from 'react-icons/tb';
import { Switch } from '../ui/switch';
import { Section, SettingRow } from './settingsLayout';
import { DRIVER_ACTION_BUTTON_CLASS } from './DriverInfoPanel';
import { usePreferenceStore } from '../../services/preferenceStore';
import { updateStore, shouldPrompt, type UpdatePrefs } from '../../services/updatePrefs';
import {
  actionLabel, canApply, EMPTY_SNAPSHOT, installedLabel, isBusy, normalizeSnapshot, stateLabel,
  withAgentRow,
  type UpdateComponent, type UpdateSnapshot,
} from '../../services/updateCenter';

/**
 * Everything that updates, in one list.
 *
 * ## Why a Settings section and not a tab of its own
 *
 * There is no top-level tab bar to add a tab to - the top level is the header,
 * the packet-list grid and a stack of modals, and every "tab" in this app is
 * already a section of one. Driver Info is the hardware section and the
 * driver-missing banner that links here lives in it, so this sits directly
 * after it. `AppMenu`'s own rule settles the remaining option: the menu holds
 * "only what has no permanent control elsewhere", and this is a permanent
 * control.
 *
 * ## The panel decides nothing
 *
 * Every state, every label and every enabled button is a pure function in
 * `services/updateCenter.ts`, asserted by `scripts/electron/update-center.ts`.
 * What is here is the arrangement. That split is the reason the wording of a
 * row can be held to "not checked" never reading as "up to date", which is the
 * one thing this tab must not get wrong.
 */

interface UpdateCenterPanelProps {
  /** From `hello`. The agent's row is composed here because its version is here. */
  agentVersion: string | null;
  agentOutdated: boolean;
  /** Opens Driver Info, for the row that says capture will not work without it. */
  onShowDriverInfo?: () => void;
}

function lastCheckedLabel(at: number | null): string {
  if (at === null) return 'Not checked yet';
  const seconds = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (seconds < 60) return 'Checked just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `Checked ${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `Checked ${hours} hour${hours === 1 ? '' : 's'} ago`;
  return `Checked on ${new Date(at).toLocaleDateString()}`;
}

/**
 * Said before the UAC prompt, not after.
 *
 * Npcap's wizard is not ours and does not look like us, and it carries a
 * licence somebody has to accept. Being told that a window is about to appear
 * is the difference between a step and a surprise.
 */
const NPCAP_NOTICE =
  "Npcap's installer will open and ask you to accept its licence. "
  + 'Windows will ask for permission first.';

const Row: React.FC<{
  component: UpdateComponent;
  busy: boolean;
  onApply: (id: string) => void;
}> = ({ component, busy, onApply }) => {
  const actionable = canApply(component);
  const failed = component.state.kind === 'failed';
  const reboot = component.state.kind === 'reboot-required';

  return (
    <div className="flex items-start justify-between gap-6 py-2.5">
      <div className="min-w-0">
        <div className="text-xs font-semibold text-foreground">{component.displayName}</div>
        <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">
          {installedLabel(component)}
          {' · '}
          <span className={failed ? 'text-rose-500' : reboot ? 'text-amber-500' : undefined}>
            {stateLabel(component.state)}
          </span>
        </p>
        {component.id === 'npcap' && actionable && (
          <p className="text-[11px] text-muted-foreground mt-1 leading-snug">{NPCAP_NOTICE}</p>
        )}
      </div>
      <div className="shrink-0 pt-0.5">
        {actionable && (
          <button
            type="button"
            onClick={() => onApply(component.id)}
            disabled={busy}
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <span>{actionLabel(component)}</span>
          </button>
        )}
      </div>
    </div>
  );
};

export const UpdateCenterPanel: React.FC<UpdateCenterPanelProps> = ({
  agentVersion,
  agentOutdated,
  onShowDriverInfo,
}) => {
  const [prefs, patchPrefs] = usePreferenceStore<UpdatePrefs>(updateStore);
  const [raw, setRaw] = React.useState<UpdateSnapshot>(EMPTY_SNAPSHOT);

  React.useEffect(() => {
    const bridge = window.inwire;
    if (!bridge) return;

    let live = true;
    const accept = (state: unknown): void => {
      const next = normalizeSnapshot(state);
      // A snapshot that does not parse is ignored rather than rendered. The
      // previous one was at least true when it arrived.
      if (live && next !== null) setRaw(next);
    };

    void bridge.getUpdateState?.().then(accept).catch(() => {});
    // The disposer is why this method returns one - the panel remounts every
    // time somebody opens Settings, and without it the listeners accumulate.
    const stop = bridge.onUpdateState?.(accept);
    return () => {
      live = false;
      stop?.();
    };
  }, []);

  const snapshot = withAgentRow(raw, agentVersion, agentOutdated);
  const busy = isBusy(snapshot);
  const driverMissing = snapshot.components.some(
    (component) => component.id === 'npcap' && component.installed === null,
  );

  const check = React.useCallback(() => {
    void window.inwire?.checkForUpdates?.().catch(() => {});
  }, []);

  const apply = React.useCallback((id: string) => {
    void window.inwire?.applyUpdate?.(id).catch(() => {});
  }, []);

  return (
    <div>
      {driverMissing && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2.5 text-xs mb-5">
          <div className="font-semibold text-foreground">Npcap is not installed</div>
          <p className="mt-1 text-muted-foreground leading-relaxed">
            Inwire cannot capture anything without it. Installing it from the list below is the
            whole fix; nothing else has to change.
          </p>
          {onShowDriverInfo && (
            <button
              type="button"
              onClick={onShowDriverInfo}
              className="mt-2 text-xs font-medium text-primary hover:underline cursor-pointer"
            >
              Driver Info has the rest of the detail
            </button>
          )}
        </div>
      )}

      {shouldPrompt(prefs) && (
        <div className="rounded-md border border-border bg-muted/30 px-3 py-2.5 text-xs mb-5">
          <div className="font-semibold text-foreground">Check for updates automatically?</div>
          <p className="mt-1 text-muted-foreground leading-relaxed">
            Inwire would ask its update feed once, shortly after launch. It sends nothing about you
            or your capture - but it is an outbound request, and in a packet analyzer you would see
            it. Everything here works on demand if you would rather it did not.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              onClick={() => patchPrefs({ asked: true, automatic: true })}
              className={DRIVER_ACTION_BUTTON_CLASS}
            >
              <span>Check automatically</span>
            </button>
            <button
              type="button"
              onClick={() => patchPrefs({ asked: true, automatic: false })}
              className="px-3.5 py-1.5 rounded-full text-xs font-medium text-muted-foreground hover:text-foreground cursor-pointer"
            >
              Only when I ask
            </button>
          </div>
        </div>
      )}

      <Section title="Components">
        {snapshot.components.length === 0 ? (
          <p className="text-[11px] text-muted-foreground py-2 leading-snug">
            Nothing to show yet.
          </p>
        ) : (
          snapshot.components.map((component) => (
            <Row key={component.id} component={component} busy={busy} onApply={apply} />
          ))
        )}
      </Section>

      <Section title="Checking">
        <SettingRow
          label="Check automatically on launch"
          description="Asks the update feed once, shortly after Inwire starts. Off by default: an update check is an outbound request, and this app is the one that would show it to you."
          htmlFor="setting-auto-update"
        >
          <Switch
            id="setting-auto-update"
            checked={prefs.automatic}
            onCheckedChange={(automatic) => patchPrefs({ automatic, asked: true })}
          />
        </SettingRow>

        <div className="flex items-center justify-between gap-4 py-2.5">
          <p className="text-[11px] text-muted-foreground leading-snug">
            {snapshot.checking ? 'Checking...' : lastCheckedLabel(snapshot.lastChecked)}
          </p>
          <button
            type="button"
            onClick={check}
            disabled={busy}
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <TbRefresh className="w-3.5 h-3.5" />
            <span>Check now</span>
          </button>
        </div>
      </Section>

      <p className="text-[11px] text-muted-foreground leading-snug flex gap-2">
        <TbAlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
        <span>
          Npcap is downloaded from npcap.com and installed by its own installer, which shows its
          own licence. Inwire never installs it silently, and uninstalling Inwire leaves it alone -
          other tools on this machine may be using it.
        </span>
      </p>
    </div>
  );
};
