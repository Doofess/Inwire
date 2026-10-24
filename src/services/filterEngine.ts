/**
 * The display-filter engine's public face.
 *
 * The language itself lives in `services/filter/`: a tokenizer, a
 * recursive-descent parser and a compiler that resolves every field name
 * against `dissect/fieldRegistry` once and returns a closure. This module is
 * the API the app has always called - it caches nothing and decides nothing,
 * it only chooses between the strict compiler and the one convenience the
 * filter *bar* has that a colour rule must not: a bare word that names nothing
 * is treated as a free-text search there, and as "matches no packet" here.
 *
 * `DEFAULT_FILTER_PRESETS` used to live here. The presets are user-editable
 * and grouped now, so they moved to services/filterPresets.ts alongside the
 * storage and reordering logic that owns them.
 */

import { Packet } from '../types/packet';
import { compile, unknownNames, FilterSyntaxError, type FilterContext } from './filter/compile';
import { parseFilter } from './filter/parser';
import { knownFieldNames, protocolNames } from './filter/fields';
import { columnFields } from './dissect/fieldRegistry';

export interface FilterValidationResult {
  isValid: boolean;
  errorMessage?: string;
  /**
   * Names the expression uses that this build never produces. The filter is
   * still valid and still compiles - it simply cannot match - which is the
   * case for the colour rules carried over from Wireshark's defaults that
   * mention protocols Inwire does not dissect.
   */
  warnings?: string[];
  matchedCount?: number;
}

export class FilterEngine {
  /**
   * Applies a display filter typed into the filter bar.
   *
   * Unlike `compileFilter`, this falls back to a free-text search over the
   * summary columns when the expression is not a filter at all - a bare word
   * that names no field, no protocol and no layer, or something that does not
   * parse. Typing a hostname into the bar and getting the frames that mention
   * it is a habit worth keeping; letting a *colour rule* do the same is what
   * made the shipped "DCERPC" rule paint any frame whose Info contained those
   * letters, so the strict path does not have it.
   */
  public static filterPackets(packets: Packet[], filterString: string, context?: FilterContext): Packet[] {
    const trimmed = filterString.trim();
    if (!trimmed) return packets;

    let matcher: (p: Packet) => boolean;
    try {
      matcher = isFreeText(trimmed) ? freeTextMatcher(trimmed) : compile(trimmed, context);
    } catch {
      matcher = freeTextMatcher(trimmed);
    }

    return packets.filter(packet => {
      try {
        return matcher(packet);
      } catch {
        return false;
      }
    });
  }

  /**
   * Checks a filter without throwing, for the bar's inline error and for the
   * preset editor's "save" gate.
   */
  public static validateFilter(
    filterString: string,
    /**
     * Hold the expression to the grammar with no free-text escape. The filter
     * bar and the preset editor go through `filterPackets`, which searches the
     * summary columns for a bare word, so a lone unrecognised word is valid
     * there. A colour rule is compiled strictly and has no such fallback, so
     * its editor asks for this and gets told the word will never match.
     */
    options?: { strict?: boolean },
  ): FilterValidationResult {
    const trimmed = filterString.trim();
    if (!trimmed) return { isValid: true };
    if (!options?.strict && isFreeText(trimmed)) return { isValid: true };

    try {
      const ast = parseFilter(trimmed);
      // Compiling is what catches a bad regex or a malformed range, neither of
      // which the grammar can see.
      compile(trimmed);

      const unknown = unknownNames(ast);
      const typos = unknown.filter(u => u.kind === 'field');
      if (typos.length > 0) {
        const names = typos.map(u => `"${u.name}"`).join(', ');
        return { isValid: false, errorMessage: `Unknown field ${names} in filter expression` };
      }

      // Three outcomes, not two. A tree-only field is spelled correctly and is
      // on screen in the detail tree - it is simply not published to the filter
      // - so it is neither a typo to reject nor "not dissected", which would be
      // false about a value the user can see. Saying which of the three it is
      // is the whole point of the split.
      const treeOnly = unknown.filter(u => u.kind === 'tree-only').map(u => u.name);
      const notDissected = unknown.filter(u => u.kind === 'undissected' || u.kind === 'protocol')
        .map(u => u.name);
      const warnings = [
        ...treeOnly.map(n => `${n} is shown in the packet detail tree but is not a `
          + 'filterable field in this build - this can never match'),
        ...notDissected.map(n => `${n} is not dissected by Inwire - this can never match`),
      ];
      return warnings.length > 0 ? { isValid: true, warnings } : { isValid: true };
    } catch (e) {
      const message = e instanceof FilterSyntaxError
        ? `${e.message} (at character ${e.pos + 1})`
        : (e as Error).message || 'Invalid filter expression';
      return { isValid: false, errorMessage: message };
    }
  }

  /**
   * Compiles a filter into a predicate. Throws on bad syntax; a name this
   * build does not produce compiles to "never matches" rather than throwing,
   * so one unimplemented protocol in a rule does not disable the rule.
   */
  public static compileFilter(filterStr: string, context?: FilterContext): (p: Packet) => boolean {
    return compile(filterStr.trim(), context);
  }

  /**
   * Autocomplete candidates for what has been typed so far.
   *
   * Generated from the field registry, so a field is suggestible the moment it
   * is registered and no list has to be kept in step by hand.
   */
  public static getSuggestions(input: string): string[] {
    const token = input.split(/[\s(){}&|!]+/).pop()?.toLowerCase() ?? '';
    if (!token) return STARTERS.slice(0, 8);

    // Built once. The two halves are already shared (see `fields.ts`); this is
    // the concatenation of them, which was the third array allocated per
    // keystroke. One pass rather than two, because the second `filter` was
    // re-testing `startsWith` on every name it had just rejected.
    const names = suggestionNames ??= [...protocolNames(), ...knownFieldNames()];
    const starts: string[] = [];
    const inside: string[] = [];
    for (const name of names) {
      if (name.startsWith(token)) starts.push(name);
      else if (name.includes(token)) inside.push(name);
      if (starts.length >= 12) break;
    }
    return starts.length >= 12 ? starts.slice(0, 12) : [...starts, ...inside].slice(0, 12);
  }

  /** The fields "Apply as column" offers, from the registry. */
  public static columnCatalogue() {
    return columnFields();
  }
}

/**
 * Every completable name, protocols first, built on the first keystroke.
 *
 * Module scope rather than a static field so it is shared across every caller,
 * and lazy so importing this file for a check that never completes anything
 * costs nothing. Safe to hold because both halves are immutable - see the note
 * above `knownFieldNames` in `filter/fields.ts`.
 */
let suggestionNames: readonly string[] | undefined;

/** Openers offered when there is nothing to complete yet. */
const STARTERS = [
  'ip.addr == ', 'tcp.port == ', 'udp.port == ', 'proto == ',
  'dns', 'tls', 'quic', 'tcp.analysis.flags',
];

/**
 * True when the text is a single bare word that names nothing the engine
 * knows - "google", "44100" - and so was meant as a search rather than as a
 * filter. Anything with an operator, a parenthesis or a second term is a
 * filter and is held to the grammar.
 */
function isFreeText(expression: string): boolean {
  if (!/^[A-Za-z0-9_.:%-]+$/.test(expression)) return false;
  try {
    const unknown = unknownNames(parseFilter(expression));
    return unknown.length === 1 && unknown[0].kind === 'protocol';
  } catch {
    return true;
  }
}

function freeTextMatcher(text: string): (p: Packet) => boolean {
  const needle = text.toLowerCase();
  return (p) =>
    p.protocol.toLowerCase().includes(needle) ||
    (p.protocolLabel?.toLowerCase().includes(needle) ?? false) ||
    p.source.toLowerCase().includes(needle) ||
    p.destination.toLowerCase().includes(needle) ||
    p.info.toLowerCase().includes(needle) ||
    p.status.toLowerCase().includes(needle);
}
