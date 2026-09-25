/**
 * Which colour rule a frame matched, for a file rather than for the list.
 *
 * The Colour rule column and Excel's row fills say what the packet list says.
 * The list's engine cannot be asked: it caches its answer in `colorSlot` on
 * the frame it is handed, and an export's frames are either the list's own
 * objects (the window) or rows read off disk that no engine has seen. So each
 * export holds an engine of its own and hands it a shallow copy with the cache
 * cleared - the same arrangement `report/analysis.ts` uses, for the same
 * reason: an export must never write into a frame the list is painting from.
 *
 * ## Match before anonymising
 *
 * An anonymised frame has lost its field bag, so a rule that tests
 * `tcp.flags.reset` matches nothing on it. A caller that anonymises matches
 * the real frame here first and hands the writers the answers alongside the
 * anonymised page (`ExportWriter.write`'s `rules`).
 */
import type { ColorRule, Packet } from '../../types/packet';
import { ColorRulesEngine, DEFAULT_COLOR_RULES } from '../colorRules';
import { FilterEngine } from '../filterEngine';

export class RuleMatcher {
  private readonly engine: ColorRulesEngine;
  /**
   * The chain, compiled again for the case the engine will not cache: it packs
   * a rule's position into a byte, and past 254 enabled rules it stops
   * caching, which is also what `matchedRuleIfKnown` reads. Built only then.
   */
  private fallback: { rule: ColorRule; matches: (p: Packet) => boolean }[] | null = null;

  constructor(private readonly rules: readonly ColorRule[] = DEFAULT_COLOR_RULES) {
    this.engine = new ColorRulesEngine([...rules]);
  }

  /** The first enabled rule the frame matches, or null. Never touches `packet`. */
  match(packet: Packet): ColorRule | null {
    const copy: Packet = { ...packet, colorSlot: undefined };
    this.engine.resolve(copy);
    const known = this.engine.matchedRuleIfKnown(copy);
    if (known !== undefined) return known;
    return this.walk(copy);
  }

  /** The rules a caller should list, in chain order: the enabled ones. */
  enabledRules(): ColorRule[] {
    return this.rules.filter((r) => r.enabled);
  }

  private walk(packet: Packet): ColorRule | null {
    if (this.fallback === null) {
      this.fallback = this.enabledRules().map((rule) => {
        try {
          return { rule, matches: FilterEngine.compileFilter(rule.filter) };
        } catch {
          return { rule, matches: () => false };
        }
      });
    }
    for (const { rule, matches } of this.fallback) {
      try {
        if (matches(packet)) return rule;
      } catch {
        // A rule that cannot be evaluated does not match, as in the engine.
      }
    }
    return null;
  }
}
