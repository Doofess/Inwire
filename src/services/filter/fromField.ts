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
  const value = packet.fields?.[abbrev];
  if (value === undefined) return null;

  // A number goes in bare - a `bool` field is 0/1 on the wire and reads as
  // `== 1`, which is what Wireshark writes and what the shipped colour rules
  // already use. Everything else is quoted, addresses included: an unquoted
  // `10.0.0.0/8` would be read as a network, and quoting removes any chance
  // that a value which merely looks like one changes the term's meaning.
  return typeof value === 'number' ? `${abbrev} == ${value}` : `${abbrev} == ${quote(value)}`;
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
