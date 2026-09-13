import React, { useMemo, useState } from 'react';
import {
  TbNetwork, TbRefresh, TbEye, TbEyeOff, TbDeviceDesktop, TbAddressBook,
  TbRouter, TbClock, TbWorld, TbPlugConnected, TbShield,
} from 'react-icons/tb';
import { useNameResolutionPreference } from '../../lib/nameResolution';
import { usePreferenceValue } from '../../services/preferenceStore';
import { networkPanelStore } from '../../services/interfacePrefs';
import { resolveMacVendor } from '../../services/macVendors';
import type { AgentAdapter } from '../../services/agentProtocol';
import type { NetworkFacts } from '../../services/networkFacts';
import { Row, Section, Empty, Compare, CompareHeader, Value } from './rows';
import { PublicIdentity } from './PublicIdentity';

/**
 * What this machine's network actually looks like - configured, and observed.
 *
 * This replaces the ISP panel, which answered one question ("who is my
 * provider") by asking a third party, while the machine's own configuration -
 * its addresses, its gateway, its resolvers, its lease - was never shown at
 * all, even though the agent is running on that machine with the access to
 * read it. The ISP answer is still here; it is now the last of seven sections
 * rather than the whole panel.
 *
 * The organising idea is the **pairing**. The OS says how the machine was told
 * to behave; the capture shows what actually happened. Most of the time they
 * agree and the panel is a reference. When they disagree it is a diagnosis: a
 * resolver being queried that is not configured, a gateway MAC that is not the
 * one in the neighbour table, no DNS at all but a DoH endpoint being contacted.
 *
 * Three rules the sections all follow:
 *
 *   - **Every section works with no agent**, reading "agent not connected" for
 *     the OS half while the capture half still populates from an imported file.
 *     The panel is as useful on somebody else's capture as on a live one.
 *   - **Only the last section reaches the internet**, and it is still behind
 *     the same consent switch it always was. Everything above it is read from
 *     this machine or from the capture, and asks nobody.
 *   - **Nothing is ever guessed.** A value the providers could not supply is an
 *     em dash. In a panel whose whole purpose is comparison, an invented value
 *     does not read as a bug - it reads as a finding.
 */

type NetworkSection =
  | 'adapter' | 'addresses' | 'gateway' | 'dhcp' | 'router' | 'neighbour' | 'public';

const SECTIONS: {
  id: NetworkSection; label: string; icon: React.ComponentType<{ className?: string }>;
}[] = [
  { id: 'adapter', label: 'Adapter', icon: TbDeviceDesktop },
  { id: 'addresses', label: 'Addresses', icon: TbAddressBook },
  { id: 'gateway', label: 'Gateway & DNS', icon: TbRouter },
  { id: 'dhcp', label: 'DHCP', icon: TbClock },
  { id: 'router', label: 'IPv6 router', icon: TbWorld },
  { id: 'neighbour', label: 'Neighbour', icon: TbPlugConnected },
  // Last, and the only one that asks anybody anything.
  { id: 'public', label: 'Public identity', icon: TbShield },
];

interface NetworkPaneProps {
  /**
   * No longer a prop.
   *
   * Network described the machine rather than the capture, so it had nothing to
   * hand back on the way out - unlike Statistics, where every row is a filter and
   * leaving IS the second half of the action. A pane with nothing to return is
   * left through the rail or Escape, and needed no callback at all.
   */
  adapters: AgentAdapter[];
  facts: NetworkFacts;
  /** Which adapters the capture is running on, so the right one leads. */
  captureInterfaces: string[];
  agentConnected: boolean;
  onRefresh: () => void;
}

/** A MAC whose second-least-significant bit of the first octet is set. */
function isLocallyAdministered(mac: string): boolean {
  const first = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}

function formatEpoch(seconds: number | null): string | null {
  if (seconds === null || !Number.isFinite(seconds)) return null;
  return new Date(seconds * 1000).toLocaleString();
}

/** "in 42 minutes", "expired 3 minutes ago" - a lease is only useful as a countdown. */
function countdown(seconds: number | null): string | null {
  if (seconds === null || !Number.isFinite(seconds)) return null;
  const delta = seconds * 1000 - Date.now();
  const minutes = Math.round(Math.abs(delta) / 60000);
  const amount = minutes < 60
    ? `${minutes} minute${minutes === 1 ? '' : 's'}`
    : `${Math.round(minutes / 60)} hour${Math.round(minutes / 60) === 1 ? '' : 's'}`;
  return delta >= 0 ? `in ${amount}` : `expired ${amount} ago`;
}

export const NetworkPane: React.FC<NetworkPaneProps> = ({
  adapters, facts, captureInterfaces, agentConnected, onRefresh,
}) => {
  const [section, setSection] = useState<NetworkSection>('adapter');
  const [nameResolution, patchNameResolution] = useNameResolutionPreference();
  const [panel, setPanel] = usePreferenceValue(networkPanelStore);
  const hidden = panel.hideSensitive;

  /**
   * The adapter this panel is about.
   *
   * The one being captured on, if the capture named one - otherwise the first
   * that is up and has an address, which is what somebody opening this panel
   * before starting a capture means by "my network".
   */
  const adapter = useMemo(() => {
    const captured = adapters.find((a) => captureInterfaces.includes(a.id));
    if (captured) return captured;
    return adapters.find((a) => a.status === 'up' && (a.ipv4.length > 0 || a.ipv6.length > 0))
      ?? adapters[0] ?? null;
  }, [adapters, captureInterfaces]);

  const noAgent = <Empty>The agent is not connected, so this machine&rsquo;s own
    configuration cannot be read. Anything the capture itself reveals is still shown.</Empty>;

  const setHidden = (next: boolean) => setPanel({ ...panel, hideSensitive: next });

  /*
   * A pane, not a dialog. Same conversion as Statistics: the `fixed inset-0`
   * scrim, the centred 90vh panel, its border, shadow and entrance animation, and
   * the close button are all gone.
   *
   * The filter row above is hidden while this view is active, which is App's
   * decision rather than this component's: a display filter acts on the capture,
   * and this surface is about the machine - so the control would have been a
   * control with nothing in view to act on.
   */
  return (
    <div className="flex-1 min-w-0 flex flex-col overflow-hidden bg-card text-card-foreground">

        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <TbNetwork className="w-7 h-7 shrink-0 text-primary" />
            <div className="min-w-0">
              <div className="font-bold text-base">Network</div>
              <p className="text-xs text-muted-foreground truncate">
                How this machine is configured, and what the capture shows
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            {/* Masks addresses and MACs for screen-sharing. Remembered, because
                somebody who shares their screen once tends to do it again, and
                a switch that resets is one they will forget the second time. */}
            <button onClick={() => setHidden(!hidden)}
              title={hidden ? 'Show addresses and MACs' : 'Hide addresses and MACs'}
              className={`p-1.5 rounded-md transition-colors ${hidden
                ? 'bg-primary/15 text-primary' : 'hover:bg-accent text-muted-foreground'}`}>
              {hidden ? <TbEyeOff className="w-4 h-4" /> : <TbEye className="w-4 h-4" />}
            </button>
            <button onClick={onRefresh} disabled={!agentConnected}
              title={agentConnected ? 'Re-read from this machine' : 'The agent is not connected'}
              className="p-1.5 rounded-md hover:bg-accent text-muted-foreground
                hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed">
              <TbRefresh className="w-4 h-4" />
            </button>
            {/* The close button stood here, beside Refresh. */}
          </div>
        </div>

        <div className="flex min-h-0 flex-1">
          <nav className="w-40 shrink-0 border-r border-border p-2 flex flex-col gap-1">
            {SECTIONS.map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => setSection(id)}
                className={`flex items-center gap-2 px-2.5 py-2 rounded-md text-xs font-medium
                  text-left transition-colors ${section === id
                    ? 'bg-accent text-foreground'
                    : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground'}`}>
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{label}</span>
              </button>
            ))}
          </nav>

          <div className="flex-1 min-w-0 p-4 overflow-y-auto space-y-4">

            {section === 'adapter' && (
              <Section title="Capture adapter">
                {adapter === null ? noAgent : (
                  <>
                    <Row label="Name" value={adapter.name} source={adapter.source.adapter} />
                    <Row label="Description" value={adapter.description} source={adapter.source.adapter} />
                    <Row label="MAC address" value={adapter.mac} sensitive hidden={hidden}
                      source={adapter.source.adapter}>
                      {adapter.mac === null ? <Value value={null} /> : (
                        <span className="flex flex-wrap items-baseline gap-x-2">
                          <span className="font-mono">{hidden ? '••:••:••:••:••:••' : adapter.mac}</span>
                          {/* The vendor, from the OUI this app already carries for
                              the packet list. Worth showing because it is the half
                              that identifies the hardware. */}
                          <span className="text-muted-foreground">{resolveMacVendor(adapter.mac) ?? ''}</span>
                          {/* A locally administered MAC is a randomised one - what
                              Windows and phones use for privacy on Wi-Fi. Worth
                              saying, because it means this address is not the
                              card's and will not persist. */}
                          {isLocallyAdministered(adapter.mac) && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/15
                              text-amber-600 dark:text-amber-400">
                              locally administered / randomised
                            </span>
                          )}
                        </span>
                      )}
                    </Row>
                    <Row label="Status" value={adapter.status} source={adapter.source.adapter} />
                    <Row label="Link speed"
                      value={adapter.speedMbps === null ? null
                        : adapter.speedMbps >= 1000
                          ? `${(adapter.speedMbps / 1000).toFixed(adapter.speedMbps % 1000 ? 1 : 0)} Gbps`
                          : `${adapter.speedMbps} Mbps`}
                      source={adapter.source.adapter} />
                    <Row label="MTU" value={adapter.mtu} source={adapter.source.adapter} />
                    {adapters.length > 1 && (
                      <Row label="Other adapters" value={`${adapters.length - 1} more known`} />
                    )}
                  </>
                )}
              </Section>
            )}

            {section === 'addresses' && (adapter === null ? (
              <Section title="Addresses">{noAgent}</Section>
            ) : (
              <>
                <Section title="IPv4">
                  {adapter.ipv4.length === 0
                    ? <Empty>No IPv4 address.</Empty>
                    : adapter.ipv4.map((entry) => (
                        <Row key={entry.address} label="Address" sensitive hidden={hidden}
                          source={adapter.source.addresses}
                          value={entry.prefixLength === null ? entry.address
                            : `${entry.address}/${entry.prefixLength}`} />
                      ))}
                  {adapter.ipv4.map((entry) => entry.broadcast && (
                    <Row key={`b-${entry.address}`} label="Broadcast" value={entry.broadcast}
                      sensitive hidden={hidden} source={adapter.source.addresses} />
                  ))}
                </Section>

                {/* Grouped, because a machine routinely holds four or five IPv6
                    addresses and only one or two of them mean anything to
                    somebody reading a capture. The temporary ones are marked
                    because they rotate - a capture from yesterday will not
                    match the address held today. */}
                <Section title="IPv6"
                  note="Temporary addresses rotate; a capture taken earlier will carry a different one.">
                  {adapter.ipv6.length === 0 ? <Empty>No IPv6 address.</Empty> : (
                    (['global', 'ula', 'link-local', 'loopback'] as const).flatMap((scope) =>
                      adapter.ipv6.filter((e) => e.scope === scope).map((entry) => (
                        <Row key={entry.address}
                          label={scope === 'link-local' ? 'Link-local'
                            : scope === 'ula' ? 'Unique local' : 'Global'}
                          sensitive hidden={hidden} source={adapter.source.addresses}>
                          <span className="flex flex-wrap items-baseline gap-x-2">
                            <Value value={entry.prefixLength === null ? entry.address
                              : `${entry.address}/${entry.prefixLength}`}
                              sensitive hidden={hidden} />
                            {entry.temporary === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px]
                                bg-sky-500/15 text-sky-600 dark:text-sky-400">temporary</span>
                            )}
                            {/* Three states, and the third is honest: macOS
                                exposes nothing cheap that answers this, so
                                "unknown" is said rather than "not temporary". */}
                            {entry.temporary === null && (
                              <span className="text-[10px] text-muted-foreground/60">
                                temporary: not known on this platform
                              </span>
                            )}
                          </span>
                        </Row>
                      )))
                  )}
                </Section>
              </>
            ))}

            {section === 'gateway' && (
              <>
                <Section title="Gateway">
                  <CompareHeader />
                  <Compare label="IPv4 gateway"
                    configured={<Value value={adapter?.gatewayV4 ?? null} sensitive hidden={hidden} />}
                    observed={<Value value={facts.gatewayAddresses.find((a) => a.includes('.')) ?? null}
                      sensitive hidden={hidden} />} />
                  <Compare label="IPv6 gateway"
                    configured={<Value value={adapter?.gatewayV6 ?? null} sensitive hidden={hidden} />}
                    observed={<Value value={facts.gatewayAddresses.find((a) => a.includes(':')) ?? null}
                      sensitive hidden={hidden} />} />
                  {/* The comparison worth having. A gateway MAC that is not the
                      one the OS holds is what ARP spoofing looks like from
                      here - so it is highlighted rather than merely printed. */}
                  <Compare label="Gateway MAC"
                    warn={adapter?.gatewayMac != null && facts.gatewayMac != null
                      && adapter.gatewayMac !== facts.gatewayMac}
                    note={adapter?.gatewayMac != null && facts.gatewayMac != null
                      && adapter.gatewayMac !== facts.gatewayMac
                      ? 'The capture is sending off-link traffic to a different MAC than the one the OS holds for the gateway.'
                      : undefined}
                    configured={<span className="flex flex-col gap-0.5">
                      <Value value={adapter?.gatewayMac ?? null} sensitive hidden={hidden} />
                      {adapter?.gatewayMac && (
                        <span className="text-[10px] text-muted-foreground">
                          {resolveMacVendor(adapter.gatewayMac) ?? ''}</span>)}
                    </span>}
                    observed={<span className="flex flex-col gap-0.5">
                      <Value value={facts.gatewayMac} sensitive hidden={hidden} />
                      {facts.gatewayMac && (
                        <span className="text-[10px] text-muted-foreground">
                          {resolveMacVendor(facts.gatewayMac) ?? ''}</span>)}
                    </span>} />
                </Section>

                <Section title="DNS">
                  <CompareHeader />
                  <Compare label="Servers"
                    // A resolver that was queried but is not configured is the
                    // finding: a browser with its own settings, or something
                    // redirected. Highlighted, not just listed.
                    warn={facts.dnsServers.some((s) => adapter !== null
                      && adapter.dnsServers.length > 0 && !adapter.dnsServers.includes(s))}
                    note={facts.dnsServers.some((s) => adapter !== null
                      && adapter.dnsServers.length > 0 && !adapter.dnsServers.includes(s))
                      ? 'A resolver was queried that this machine is not configured to use.'
                      : undefined}
                    configured={adapter === null || adapter.dnsServers.length === 0
                      ? <Value value={null} />
                      : <span className="flex flex-col gap-0.5">{adapter.dnsServers.map((s) =>
                          <Value key={s} value={s} sensitive hidden={hidden} />)}</span>}
                    observed={facts.dnsServers.length === 0
                      ? <Value value={null} />
                      : <span className="flex flex-col gap-0.5">{facts.dnsServers.map((s) =>
                          <Value key={s} value={s} sensitive hidden={hidden} />)}</span>} />
                  <Row label="DNS suffix" value={adapter?.dnsSuffix ?? null}
                    source={adapter?.source.dns} />
                  {/* The other half of "no DNS was queried". Without this the
                      capture looks like a machine that never resolved anything.

                      A Compare rather than a Row even though only one side can
                      ever answer: an ordinary row puts its value in the first
                      column, which is the one headed "Configured (OS)" - so a
                      DoH endpoint the capture found would read as one the
                      machine is set up to use, which is close to the opposite
                      of what it means. */}
                  <Compare label="Encrypted DNS"
                    configured={<span className="text-muted-foreground/60"
                      title="The OS does not record this">—</span>}
                    observed={facts.encryptedDns.length === 0
                      ? <Value value={null} />
                      : <span className="flex flex-col gap-0.5">{facts.encryptedDns.map((e) =>
                          <span key={e} className="font-mono break-all">{e}</span>)}</span>} />
                  {facts.dnsServers.length === 0 && facts.encryptedDns.length > 0 && (
                    <div className="px-3 py-2 text-[11px] text-amber-600 dark:text-amber-400
                      bg-amber-500/10 border-l-2 border-amber-500">
                      No plain DNS was queried in this capture, but an encrypted-DNS endpoint was
                      contacted. Name resolution is happening where a packet capture cannot read it.
                    </div>
                  )}
                </Section>
              </>
            )}

            {section === 'dhcp' && (
              <Section title="DHCP">
                <CompareHeader />
                <Compare label="Enabled"
                  configured={<Value value={adapter === null || adapter.dhcpEnabled === null
                    ? null : adapter.dhcpEnabled ? 'yes' : 'no (static)'} />}
                  observed={<Value value={facts.dhcpServer !== null ? 'lease seen in capture' : null} />} />
                <Compare label="Server"
                  warn={adapter?.dhcpServer != null && facts.dhcpServer != null
                    && adapter.dhcpServer !== facts.dhcpServer}
                  note={adapter?.dhcpServer != null && facts.dhcpServer != null
                    && adapter.dhcpServer !== facts.dhcpServer
                    ? 'The capture shows a lease from a different server than the one configured.'
                    : undefined}
                  configured={<Value value={adapter?.dhcpServer ?? null} sensitive hidden={hidden} />}
                  observed={<Value value={facts.dhcpServer} sensitive hidden={hidden} />} />
                <Row label="Lease obtained" value={formatEpoch(adapter?.leaseObtained ?? null)}
                  source={adapter?.source.dhcp} />
                <Row label="Lease expires" source={adapter?.source.dhcp}>
                  {adapter?.leaseExpires == null ? <Value value={null} /> : (
                    <span className="flex flex-wrap items-baseline gap-x-2">
                      <span className="font-mono">{formatEpoch(adapter.leaseExpires)}</span>
                      <span className="text-muted-foreground">{countdown(adapter.leaseExpires)}</span>
                    </span>
                  )}
                </Row>
                {!agentConnected && noAgent}
              </Section>
            )}

            {section === 'router' && (
              <Section title="IPv6 router"
                note="From Router Advertisements. Nothing on this machine records where its IPv6 configuration came from.">
                {facts.router === null ? (
                  <Empty>No Router Advertisement in this capture.</Empty>
                ) : (
                  <>
                    <Row label="Router" value={facts.router.address} sensitive hidden={hidden}
                      source="capture" />
                    <Row label="Advertised prefixes" source="capture"
                      value={facts.router.prefixes.length ? facts.router.prefixes.join(', ') : null}
                      sensitive hidden={hidden} />
                    <Row label="Router lifetime" source="capture"
                      value={facts.router.routerLifetime === null ? null
                        : `${facts.router.routerLifetime} s${facts.router.routerLifetime === 0
                          ? ' (not a default router)' : ''}`} />
                    <Row label="Prefix valid for" source="capture"
                      value={facts.router.prefixValidLifetime === null ? null
                        : `${facts.router.prefixValidLifetime} s`} />
                    <Row label="Recursive DNS (RDNSS)" source="capture"
                      value={facts.router.rdnss.length ? facts.router.rdnss.join(', ') : null}
                      sensitive hidden={hidden} />
                    <Row label="Configuration" source="capture"
                      value={facts.router.managed
                        ? 'DHCPv6 for addresses and other settings (M)'
                        : facts.router.other
                          ? 'SLAAC for addresses, DHCPv6 for other settings (O)'
                          : 'SLAAC only'} />
                  </>
                )}
              </Section>
            )}

            {section === 'neighbour' && (
              <>
                <Section title="Switch / neighbour">
                  {facts.neighbour === null ? (
                    <Empty>No neighbour LLDP seen in this capture.</Empty>
                  ) : (
                    <>
                      <Row label="System name" value={facts.neighbour.systemName} source="capture" />
                      <Row label="MAC" value={facts.neighbour.mac} sensitive hidden={hidden}
                        source="capture" />
                      <Row label="Port" value={facts.neighbour.portId} source="capture" />
                      <Row label="Port description" value={facts.neighbour.portDescription}
                        source="capture" />
                      <Row label="Management address" value={facts.neighbour.managementAddress}
                        sensitive hidden={hidden} source="capture" />
                    </>
                  )}
                </Section>

                {/* Not a neighbour, and it matters that the two are separated.
                    Windows runs an LLDP agent, so an LLDP frame in a capture is
                    as likely to be this machine introducing itself as a switch -
                    and reporting that as a neighbour would name the machine as
                    its own upstream device. */}
                {facts.selfAdvertisedName !== null && (
                  <Section title="This host's own LLDP"
                    note="This machine advertises itself over LLDP. It is not a neighbour.">
                    <Row label="Advertised name" value={facts.selfAdvertisedName}
                      sensitive hidden={hidden} source="capture" />
                  </Section>
                )}
              </>
            )}

            {section === 'public' && (
              <PublicIdentity allowed={nameResolution.geoIp} hidden={hidden}
                onAllow={() => patchNameResolution({ geoIp: true })} />
            )}
          </div>
        </div>
    </div>
  );
};
