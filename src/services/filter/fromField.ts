/**
 * Building a display filter from a row of the dissected tree.
 *
 * This is the half of the field registry that pays for the other half. A tree
 * row that carries an `abbrev` names the same thing the filter language names,
 * so "Apply as filter" is a lookup rather than a special case per protocol -
 * and a row without one is display-only and offers nothing, which is exactly
 * the distinction the registry was introduced to make visible
 * (docs/decisions/0002-field-registry.md).
 *
 * The value comes from `Packet.fields`, never from the row's rendered text.
 * The tree shows "0x0002 (2)" for a transaction id and "TCP (6)" for a
 * protocol number; both are for reading. Filtering on either string would
 * produce an expression that matches nothing, which is the worst of the
 * available failures because it looks like an answer.
 */

import { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import { parseFilter } from './parser';
import { unknownNames } from './compile';

/** How a new term joins whatever is already in the filter bar. */
export type FilterCombine = 'replace' | 'not' | 'and' | 'or';

export const COMBINE_LABELS: Record<FilterCombine, string> = {
  replace: 'Selected',
  not: 'Not Selected',
  and: '…and Selected',
  or: '…or Selected',
};

/** Quotes and escapes a string literal for the filter language. */
function quote(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * The `field == value` term for one tree row, or null when the frame carries
 * no value for it - a grouping node, a generated comment, or a field the
 * dissector registered but did not publish for this particular frame.
 */
export function fieldTerm(packet: Packet, abbrev: string | undefined): string | null {
  if (!abbrev) return null;
  const value = fieldValue(packet, abbrev);
  if (value === undefined) return null;

  // A number goes in bare - a `bool` field is 0/1 on the wire and reads as
  // `== 1`, which is what Wireshark writes and what the shipped colour rules
  // already use. Everything else is quoted, addresses included: an unquoted
  // `10.0.0.0/8` would be read as a network, and quoting removes any chance
  // that a value which merely looks like one changes the term's meaning.
  return typeof value === 'number' ? `${abbrev} == ${value}` : `${abbrev} == ${quote(value)}`;
}

/** The first of `abbrevs` the frame carries a value for, as a term. */
function firstTerm(packet: Packet, abbrevs: string[]): string | null {
  for (const abbrev of abbrevs) {
    const term = fieldTerm(packet, abbrev);
    if (term) return term;
  }
  return null;
}

/** True when the strict filter language accepts `name` as a bare protocol. */
function isFilterProtocol(name: string): boolean {
  try {
    return unknownNames(parseFilter(name)).length === 0;
  } catch {
    return false;
  }
}

/**
 * The terms the packet list's row menu offers: this frame's source, its
 * destination and its protocol. Each is null when the frame gives nothing to
 * filter on, and the menu disables that item rather than hiding it.
 *
 * Addresses are the most specific layer the frame has - IPv6, then IPv4, then
 * the Ethernet MAC - so an IPv6 row never gets `ip.src` (which matches
 * nothing) and an ARP row filters on its MACs. The protocol is the outermost
 * dissected layer, as a bare name (`dns`, `tls`); when that is not a name the
 * filter language knows, the coarse label is matched with `proto ==`.
 */
export function rowFilterTerms(packet: Packet): {
  source: string | null;
  destination: string | null;
  protocol: string | null;
} {
  const layers = (packet.frameProtocols ?? []).filter(p => p !== 'data');
  const top = layers[layers.length - 1];
  const label = packet.protocolLabel ?? packet.protocol;
  return {
    source: firstTerm(packet, ['ipv6.src', 'ip.src', 'eth.src']),
    destination: firstTerm(packet, ['ipv6.dst', 'ip.dst', 'eth.dst']),
    protocol: top && isFilterProtocol(top) ? top : label ? `proto == ${quote(label)}` : null,
  };
}

/**
 * Joins a new term onto the expression already in the filter bar.
 *
 * `and`/`or` parenthesise both sides. Without that,
 * `tcp || udp` + and + `ip.ttl == 1` would bind as `tcp || (udp && ...)`,
 * which is not the filter the user asked for and is not visibly wrong.
 */
export function combineFilter(current: string, term: string, how: FilterCombine): string {
  const existing = current.trim();
  switch (how) {
    case 'replace': return term;
    case 'not': return `!(${term})`;
    case 'and': return existing ? `(${existing}) && (${term})` : term;
    case 'or': return existing ? `(${existing}) || (${term})` : term;
  }
}
