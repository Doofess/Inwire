import React from 'react';
import { TbRefresh, TbAlertTriangle } from 'react-icons/tb';
import { Switch } from '../ui/switch';
import { Section, SettingRow } from './settingsLayout';
import { DRIVER_ACTION_BUTTON_CLASS } from './DriverInfoPanel';
import { usePreferenceStore } from '../../services/preferenceStore';
import { updateStore, shouldPrompt, type UpdatePrefs } from '../../services/updatePrefs';
import {
  actionLabel, canApply, canReinstall, EMPTY_SNAPSHOT, installedLabel, isBusy,
  namesAdminOnlyCheckbox, normalizeSnapshot,
  stateLabel, withAgentRow,
  type UpdateComponent, type UpdateSnapshot,
} from '../../services/updateCenter';
import {
  decideDriverAccess, driverAccessAdvice, driverAccessLabel, type DriverAccess,
} from '../../services/npcapAccess';

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
  /**
   * The Npcap device object's DACL, from `hello` - the half of the
   * driver-access answer only a SYSTEM process can read. Null on an older
   * agent, on a machine with no driver, and while nothing is connected; the
   * registry half arrives on the Npcap row and covers all three. ADR 0033.
   */
  agentNpcapAccess?: string | null;
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

/**
 * The same warning, plus the one instruction Inwire cannot carry out itself.
 *
 * The checkbox is Npcap's, on Npcap's page, and the only way to reach it is
 * for a person to tick it: passing a flag instead would mean `/S`, which is
 * the OEM silent-install feature the free licence does not grant (ADR 0032).
 * So the option is named exactly as its own wizard spells it - anything
 * paraphrased sends somebody looking for a checkbox that is not there.
 */
const NPCAP_ADMIN_ONLY_NOTICE =
  "In Npcap's installer, tick “Restrict Npcap driver's access to Administrators only” "
  + 'and finish the install as usual. Windows will ask for permission first, and Npcap '
  + 'will show its own licence.';

const Row: React.FC<{
  component: UpdateComponent;
  busy: boolean;
  onApply: (id: string) => void;
  /** The Npcap row only, and only once there is a driver to describe. */
  driverAccess?: DriverAccess;
}> = ({ component, busy, onApply, driverAccess }) => {
  const actionable = canApply(component);
  const failed = component.state.kind === 'failed';
  const reboot = component.state.kind === 'reboot-required';

  // Only ever non-null for `all-users`. `unknown` gets the plain statement of
  // fact above and no advice: recommending a kernel-driver reinstall on the
  // strength of having failed to read anything would be advice about a state
  // nobody established.
  const advice = driverAccess === undefined ? null : driverAccessAdvice(driverAccess);
  const offerReinstall = advice !== null && canReinstall(component);

  // Not `offerReinstall`, which is a button's question and was once wrongly
  // read as this one - `namesAdminOnlyCheckbox` says why, and is in `services/`
  // so the wording is held by the fast suite rather than only by the drive
  // script. The advice paragraph above is unchanged: its text says Npcap "is
  // installed with its capture devices open", which is not true of a row with
  // no driver, whereas a notice about a window that is about to appear is.
  const nameCheckbox = namesAdminOnlyCheckbox(component, driverAccess);

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
        {driverAccess !== undefined && (
          <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">
            <span className={driverAccess === 'all-users' ? 'text-amber-500' : undefined}>
              {driverAccessLabel(driverAccess)}
            </span>
          </p>
        )}
        {advice !== null && (
          <p className="text-[11px] text-muted-foreground mt-1 leading-snug">{advice}</p>
        )}
        {component.id === 'npcap' && (actionable || offerReinstall) && (
          <p className="text-[11px] text-muted-foreground mt-1 leading-snug">
            {nameCheckbox ? NPCAP_ADMIN_ONLY_NOTICE : NPCAP_NOTICE}
          </p>
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
        {/* Not shown beside the Update button: `canApply` and `canReinstall`
            are mutually exclusive by construction, because a reinstall is only
            offered against a component that is already up to date. */}
        {offerReinstall && (
          <button
            type="button"
            onClick={() => onApply(component.id)}
            disabled={busy}
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <span>Reinstall with admin-only</span>
          </button>
        )}
      </div>
    </div>
  );
};

export const UpdateCenterPanel: React.FC<UpdateCenterPanelProps> = ({
  agentVersion,
  agentOutdated,
  agentNpcapAccess,
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

  /**
   * The two halves, combined once for the whole panel.
   *
   * The registry value comes down on the Npcap row from main; the DACL comes
   * up from the agent over the pipe. `decideDriverAccess` prefers the DACL
   * because it is what the kernel enforces - the registry can say
   * "administrators only" about a device whose descriptor still grants
   * Everyone, and that is the one direction a wrong answer must not go.
   */
  const npcapRow = snapshot.components.find((component) => component.id === 'npcap');
  const driverAccess = decideDriverAccess(npcapRow?.adminOnly, agentNpcapAccess);
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
            <Row
              key={component.id}
              component={component}
              busy={busy}
              onApply={apply}
              driverAccess={component.id === 'npcap' && component.installed !== null
                ? driverAccess
                : undefined}
            />
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
