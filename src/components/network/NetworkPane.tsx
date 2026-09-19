import React, { useEffect, useMemo, useState } from 'react';
// Seven of the twelve glyphs here were the nav's, one per section, and went
// with it. What is left is the two header actions.
import { RefreshCw, Eye, EyeOff } from 'lucide-react';
import { useNameResolutionPreference } from '../../lib/nameResolution';
import { usePreferenceValue } from '../../services/preferenceStore';
import { networkPanelStore } from '../../services/interfacePrefs';
import { resolveMacVendor } from '../../services/macVendors';
import type { AgentAdapter } from '../../services/agentProtocol';
import type { NetworkFacts } from '../../services/networkFacts';
import { Row, Section, Empty, Compare, Value } from './rows';
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

/**
 * **There was a `SECTIONS` table and a `w-40` nav built from it, and both are
 * deleted.**
 *
 * The nav showed one section at a time, which is a space-saving device for a
 * two-column sheet - and in a column the scarce axis is horizontal, not
 * vertical, so it was saving the wrong thing. It also prevented what this panel
 * is for: scrolling from Gateway to DHCP to see whether the same disagreement
 * shows up twice. Each `Section` already carries its own heading, so the order
 * and the labels the table held are in the markup where they are read.
 */

/**
 * The two controls that used to sit in this pane's own header.
 *
 * Exported separately because the header belongs to the side bar's shell now,
 * and the shell renders it ABOVE the scroller this panel is inside. They reach
 * the same preference store the panel does rather than being threaded through
 * it, so there is no state here to keep in step - `networkPanelStore` is the
 * single writer either way.
 */
export const NetworkPanelActions: React.FC<{
  agentConnected: boolean;
  onRefresh: () => void;
}> = ({ agentConnected, onRefresh }) => {
  const [panel, setPanel] = usePreferenceValue(networkPanelStore);
  const hidden = panel.hideSensitive;
  return (
    <>
      {/* Masks addresses and MACs for screen-sharing. Remembered, because
          somebody who shares their screen once tends to do it again, and a
          switch that resets is one they will forget the second time. */}
      <button
        type="button"
        onClick={() => setPanel({ ...panel, hideSensitive: !hidden })}
        title={hidden ? 'Show addresses and MACs' : 'Hide addresses and MACs'}
        className={`p-1 rounded transition-colors cursor-pointer ${hidden
          ? 'bg-primary/15 text-primary' : 'hover:bg-accent text-muted-foreground'}`}
      >
        {hidden ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
      </button>
      <button
        type="button"
        onClick={onRefresh}
        disabled={!agentConnected}
        title={agentConnected ? 'Re-read from this machine' : 'The agent is not connected'}
        className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground
          disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
      >
        <RefreshCw className="w-3.5 h-3.5" />
      </button>
    </>
  );
};

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
  /**
   * No longer a prop, for the second time.
   *
   * The first deletion was `onClose` - a pane describing the MACHINE has
   * nothing to hand back on the way out. This one is `onRefresh`, and it left
   * for a different reason: the control that used it lives in the side bar's
   * header, which is above this scroller and outside this component.
   * `NetworkPanelActions` owns it.
   */
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

/**
 * "in 42 minutes", "expired 3 minutes ago" - a lease is only useful as a
 * countdown.
 *
 * **`now` is a parameter rather than a `Date.now()` inside**, and that is a
 * defect this panel's own conversion created rather than one it inherited. It
 * read the clock at render, which was survivable while this was a sheet: a
 * sheet is a detour, you open it and you leave. As a side bar panel it sits
 * open for hours beside a running capture, and `adapter_config` is only sent
 * when something CHANGES - so nothing forces a re-render and "expires in 42
 * minutes" quietly becomes false with no tell at all. In a column where every
 * other value refreshes itself, a frozen one reads as a live one.
 */
function countdown(seconds: number | null, now: number): string | null {
  if (seconds === null || !Number.isFinite(seconds)) return null;
  const delta = seconds * 1000 - now;
  const minutes = Math.round(Math.abs(delta) / 60000);
  const amount = minutes < 60
    ? `${minutes} minute${minutes === 1 ? '' : 's'}`
    : `${Math.round(minutes / 60)} hour${Math.round(minutes / 60) === 1 ? '' : 's'}`;
  return delta >= 0 ? `in ${amount}` : `expired ${amount} ago`;
}

export const NetworkPane: React.FC<NetworkPaneProps> = ({
  adapters, facts, captureInterfaces, agentConnected,
}) => {
  /**
   * Whether the one section that reaches the internet has been asked for.
   *
   * Per mount rather than persisted, deliberately: consent to make a request is
   * given for a sitting, and a panel that remembered it would reach out on the
   * next launch with nobody watching.
   */
  const [showPublic, setShowPublic] = useState(false);

  /**
   * A minute hand, and it exists only while a lease is on screen.
   *
   * The DHCP lease is the one value here that goes stale by the clock rather
   * than by an agent message. A minute is the resolution `countdown` reports
   * in, so a faster tick would repaint for nothing, and the effect is keyed on
   * whether there is a lease at all - no lease, no interval, which is the same
   * discipline the adapter panel's sampling follows: nothing runs while nothing
   * is showing it.
   */
  const [now, setNow] = useState(() => Date.now());
  const [nameResolution, patchNameResolution] = useNameResolutionPreference();
  const [panel] = usePreferenceValue(networkPanelStore);
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

  const hasLease = adapter?.leaseExpires !== null && adapter?.leaseExpires !== undefined;
  useEffect(() => {
    if (!hasLease) return;
    const id = window.setInterval(() => setNow(Date.now()), 60_000);
    return () => window.clearInterval(id);
  }, [hasLease]);

  /**
   * Why there is nothing to show, and the two reasons are not the same.
   *
   * It was one sentence blaming the link, rendered wherever an adapter was
   * missing - so a CONNECTED agent that had not sent an `adapter_config`
   * snapshot yet, which is every stub run and the first second of every real
   * one, claimed the agent was not there. That is the shape `Empty`'s own
   * comment exists to prevent: "'the agent is not connected' and 'the capture
   * did not show this' are completely different statements, and a panel that
   * rendered one blank area for both would leave the reader unable to tell a
   * missing agent from a quiet network."
   */
  const noAdapter = (
    <Empty>
      {agentConnected
        ? 'The agent has not reported this machine’s adapter configuration. '
          + 'Anything the capture itself reveals is still shown.'
        : 'The agent is not connected, so this machine’s own configuration '
          + 'cannot be read. Anything the capture itself reveals is still shown.'}
    </Empty>
  );

  /*
   * **A side bar panel, and it is the fourth container this has had.** A modal
   * with a scrim, then briefly a rail view, then a Settings tab, then a sheet
   * taking the workspace card, and now the column beside it. Every one of those
   * is gone from this file - no `fixed inset-0`, no scrim, no 90vh panel, no
   * header, no ground; it renders as a plain column filling whatever it is
   * handed, and `sidebar/SideBar.tsx` is the only thing that renders it.
   *
   * **The test that decided all four is the same one and its answer has not
   * changed**: "is this a way of looking at the capture?" No. Network describes
   * the MACHINE - its adapters, its DNS, its public identity - and nothing in it
   * changes when a packet arrives. So it is not in `APP_VIEWS`, has no `Ctrl+n`,
   * and `viewPrefs.ts` still lands a stored `'network'` back on Packets.
   *
   * What kept moving is the half that answer does NOT settle: *not a view* was
   * read as *therefore a Settings tab*, and Settings is where the app is
   * configured while this configures nothing. Then as a sheet it covered the
   * capture in order to describe the machine it was captured on - which is the
   * one arrangement that made "Observed (capture)" unreadable beside its
   * subject. The column is where both halves are true at once: it is not a view,
   * and it sits next to the frames it is comparing against.
   */
  return (
    /* **No header and no ground of its own.** The side bar's card supplies
       both: `PaneHeader` at a fixed `h-9`, and `bg-card` on the column. The
       28px icon, the title, the subtitle and the two action buttons that stood
       here are the shell's now - `SettingsPane`'s root check enforces the same
       shape for the same reason, that a card inside a card is a card in a card.

       **The `w-40` nav is deleted rather than replaced.** It showed one section
       at a time, which was a space-saving device for a two-column sheet - and
       in a column the scarce axis is horizontal, not vertical. It also actively
       prevented the thing this panel is for: scrolling from Gateway to DHCP to
       see whether the same disagreement shows up twice. A comparison panel
       should be readable as a whole. */
    <div className="p-2 space-y-2">

                          <Section title="Capture adapter">
                {adapter === null ? noAdapter : (
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
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-warning/15
                              text-warning-muted">
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

            {adapter === null ? (
              <Section title="Addresses">{noAdapter}</Section>
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
                            {/* A pill in a fixed sky shade, for a fact that is
                                neither a warning nor a success - so it had
                                nothing in the theme to take and reached for the
                                palette instead. In a column its ground was also
                                competing with the address beside it for width.
                                Muted text says the same thing and moves between
                                Day and Night like everything around it. */}
                            {entry.temporary === true && (
                              <span className="text-[10px] text-muted-foreground/60">
                                temporary
                              </span>
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
            )}

            <>
                <Section title="Gateway">
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
                    <div className="px-3 py-2 text-[11px] text-warning-muted
                      bg-warning/10 border-l-2 border-warning">
                      No plain DNS was queried in this capture, but an encrypted-DNS endpoint was
                      contacted. Name resolution is happening where a packet capture cannot read it.
                    </div>
                  )}
                </Section>
              </>

            <Section title="DHCP">
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
                      <span className="text-muted-foreground">{countdown(adapter.leaseExpires, now)}</span>
                    </span>
                  )}
                </Row>
                {!agentConnected && noAdapter}
              </Section>

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

            {/* **Last, and behind a press, and that is a consent property
                rather than a layout one.**

                `PublicIdentity` is the only section here that reaches the
                internet. Today it is mounted only when its nav item is chosen,
                so deleting the nav and stacking everything would have mounted
                it on every open - an outbound lookup nobody asked for, in the
                app whose standing direction is "no outbound connection the user
                did not ask for".

                A disclosure is STRONGER than the nav it replaces, not merely
                equivalent: a nav item says nothing about reaching out, and a
                labelled button that says so does. Mounting is what starts the
                request, so the guard has to be on the mount rather than on a
                CSS class. */}
            {showPublic ? (
              <PublicIdentity allowed={nameResolution.geoIp} hidden={hidden}
                onAllow={() => patchNameResolution({ geoIp: true })} />
            ) : (
              <button
                type="button"
                onClick={() => setShowPublic(true)}
                className="w-full rounded-lg border border-border px-3 py-2 text-left
                  cursor-pointer transition-colors hover:bg-accent/60
                  focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                <span className="text-[11px] font-semibold uppercase tracking-wider
                  text-muted-foreground">
                  Public identity
                </span>
                <span className="mt-0.5 block text-[11px] text-muted-foreground/70">
                  How this machine looks from the outside. Opening this asks a
                  third party; nothing else on this panel leaves the machine.
                </span>
              </button>
            )}
    </div>
  );
};
