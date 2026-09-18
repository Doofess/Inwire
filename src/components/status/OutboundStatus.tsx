import React from 'react';
import { StatusItem } from './StatusItem';

/**
 * Whether this app is making requests of its own.
 *
 * **The one item in the bar that is deliberately present in its quiet state**,
 * and the reason is specific to what this app is. Inwire shows you your own
 * traffic, so a request it makes unbidden appears in your own capture as a
 * mystery to chase - which is why both lookups are off by default and why
 * CLAUDE.md's standing direction is "no outbound connection the user did not
 * ask for".
 *
 * An indicator that only appears when the answer is bad is not a claim, it is
 * an alarm - and the useful thing here is the claim. "Nothing is going out" is
 * what somebody watching their own wire wants confirmed.
 *
 * **It says it in words, and it carries no glyph.** It was a globe when a
 * lookup was on and a shield when none was, which is two pictures for a fact
 * that is three short words - and a glyph in a strip where every other item
 * spells out what it means made the one item about *this app's* behaviour the
 * one item you had to hover to read. So the state is the TEXT: `no lookups`
 * against `geo-IP`, `rDNS` or both. That also keeps the bar's rule that a state
 * is never carried by hue alone, now that there is no glyph to put the warning
 * colour on - the two states differ in what they say, not in what colour they
 * say it in. See `StatusItem`'s `TONE`.
 *
 * Two switches, two endpoints, and they are genuinely independent:
 * `geoIp` gates get.geojs.io and ipapi.co, `reverseDns` gates the DoH resolver
 * at cloudflare-dns.com. The visible text names whichever are on rather than
 * summarising, because "lookups enabled" does not tell you which third party
 * is learning an address. The abbreviations are the bar's width budget at the
 * 1024px minimum; the tooltip spells both out.
 *
 * The basemap tiles are the one outbound thing this cannot speak for: they load
 * whenever the Routing Map is shown, behind neither switch. That gap is
 * recorded in `electron/csp.ts` and in CLAUDE.md's Direction section as
 * something to close, and this item deliberately does not paper over it - which
 * is why the quiet label says what it says rather than "offline".
 */
export interface OutboundStatusProps {
  geoIp: boolean;
  reverseDns: boolean;
}

export const OutboundStatus: React.FC<OutboundStatusProps> = ({
  geoIp,
  reverseDns,
}) => {
  const on = [geoIp && 'geo-IP', reverseDns && 'rDNS'].filter(Boolean) as string[];
  const spelt = [geoIp && 'geo-IP', reverseDns && 'reverse DNS'].filter(Boolean) as string[];

  if (on.length === 0) {
    return (
      <StatusItem
        label="No outbound lookups are enabled"
        title={
          'No lookups leave this machine: geo-IP and reverse DNS are both off. '
          + '(The Routing Map’s basemap tiles are '
          + 'the exception and load whenever that view is shown.)'
        }
      >
        no lookups
      </StatusItem>
    );
  }

  return (
    <StatusItem
      tone="attention"
      label={`Outbound lookups enabled: ${spelt.join(' and ')}`}
      title={
        `${spelt.join(' and ')} ${spelt.length === 1 ? 'is' : 'are'} enabled, so this app `
        + 'makes requests that will appear in your own capture.'
      }
    >
      {on.join(' · ')}
    </StatusItem>
  );
};
