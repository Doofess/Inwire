import { themePalette, type Hue } from './themePalettes';
import type { ProtocolType } from '../types/packet';

/**
 * The colour a protocol is drawn in, anywhere the unit is a protocol.
 *
 * The app had no such thing. Every surface that wanted to distinguish protocols
 * either invented its own colours or gave up: the geo map drew every connection
 * in one hardcoded sky blue, the protocol donut painted every bar the accent
 * behind a comment explaining that it deliberately would not colour per
 * protocol, and the traffic timeline coloured by metric instead. So "which
 * protocol is this" was a question the dashboard could not answer visually.
 *
 * Colours come from the active theme's own palette rather than a table of their
 * own, which is the whole point: a QUIC line on the map and a QUIC bar in the
 * donut are the same colour as each other, and both are recognisably part of
 * whichever theme is loaded rather than a fixed hue pasted on top of it.
 *
 * **Boundary with `ColorRulesEngine`.** That stays the authority for colouring
 * an individual packet in the list, where the unit is a *packet* and Wireshark's
 * first-match-wins chain means a retransmitted RST is "Bad TCP" rather than
 * "TCP" - an ordering a protocol map cannot express. This is the authority for
 * aggregates, where the unit is a protocol and that nuance does not apply. The
 * two share the same nine hues, so they agree without being the same mechanism.
 */

/**
 * Twelve protocols onto nine hues, so some share. The shares are chosen, not
 * left over:
 *
 *   - HTTP, HTTPS and TLS share green because they are one thing to anyone
 *     reading a map - web traffic, encrypted or not.
 *   - SSH and MQTT share yellow as the two remaining application protocols,
 *     both uncommon enough that telling them apart on a world map is not worth
 *     spending a hue that TCP, UDP or QUIC could use.
 *
 * Everything that matters at a glance - TCP vs UDP vs QUIC vs DNS vs ICMP vs
 * ARP - gets a hue to itself.
 */
const HUE_BY_PROTOCOL: Record<ProtocolType, Hue> = {
  HTTP: 'green',
  HTTPS: 'green',
  TLS: 'green',
  TCP: 'blue',
  UDP: 'cyan',
  QUIC: 'magenta',
  DNS: 'violet',
  ICMP: 'red',
  ARP: 'orange',
  SSH: 'yellow',
  MQTT: 'yellow',
  CUSTOM: 'neutral',
};

/**
 * The colour for a protocol under a theme.
 *
 * Keyed by resolved theme name rather than a light/dark boolean, so a theme
 * whose palette is not merely "the dark one" gets its own colours - which is
 * what lets Colorblind Safe supply Okabe-Ito here instead of inheriting generic
 * hues, and Mono supply greys.
 *
 * Anything unrecognised - a protocol added to the union without a hue, or a
 * string arriving from data rather than the type - returns the neutral rather
 * than `undefined`, because every caller here is handing the result to a
 * renderer that cannot do anything sensible with a missing colour.
 */
export function protocolColor(protocol: string, resolvedTheme: string | undefined): string {
  const palette = themePalette(resolvedTheme);
  const hue = HUE_BY_PROTOCOL[protocol as ProtocolType] ?? 'neutral';
  return palette.hues[hue];
}

/** Exported for the assertion script, which checks every protocol has a hue. */
export { HUE_BY_PROTOCOL };
