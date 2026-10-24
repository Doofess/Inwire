/**
 * What the status bar's outbound item says. In its own module so the words
 * can be asserted under plain tsx without rendering the component.
 *
 * It reads as the state of a setting - "Lookups off" - rather than as a claim
 * ("no lookups"), and when something is on it names which, because "lookups
 * on" does not tell you which third party is learning an address. The
 * abbreviations are the bar's width budget at the 1024px minimum; the tooltip
 * spells both out.
 */
export function outboundLabel(geoIp: boolean, reverseDns: boolean): string {
  const on = [geoIp && 'geo-IP', reverseDns && 'rDNS'].filter(Boolean);
  return on.length === 0 ? 'Lookups off' : `Lookups: ${on.join(', ')}`;
}
