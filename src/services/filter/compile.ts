/**
 * Turns a parsed filter into a predicate over one packet.
 *
 * Everything that can be decided without a packet is decided here, once:
 * which reader a name resolves to, whether a literal is a number, a CIDR or a
 * string, and what a regex compiles to. The returned closure then does only
 * the comparison. The engine this replaced re-ran the regexes that answered
 * those questions for every packet, which is most of why filtering a 50k
 * buffer was slow enough to be felt.
 *
 * ## Operator semantics
 *
 * `==` is **equality**. It used to mean "equal or contains", so
 * `ip.src == 10.0.0.1` also matched `110.0.0.10` and `info == "GET"` matched
 * every frame whose Info merely mentioned it - a filter that silently answers
 * a wider question than it was asked is worse than one that errors. Substring
 * and pattern matching are now spelled out: `contains` (case-sensitive, as in
 * Wireshark), `icontains` (case-insensitive) and `matches` / `~` (regex).
 *
 * Equality on a string is case-sensitive except for the types where case
 * carries no meaning - protocol names, addresses and MACs - so `proto == tls`
 * and `ip.src == 2001:DB8::1` both work.
 *
 * A field the frame does not carry never matches, under any operator
 * including `!=`: a frame with no `ip.ttl` is not a frame whose TTL differs.
 * A field that occurs more than once (`ip.addr` is either end of the frame)
 * matches when any occurrence does, and `!=` is the negation of that - "no
 * occurrence equals", not "some occurrence differs".
 */

import { Packet } from '../../types/packet';
import { cidrMatcher } from '../addressFormat';
import { CompareOp, FieldRef, Literal, Node, SetEntry, parseFilter } from './parser';
import { FilterSyntaxError } from './lexer';
import { FieldResolution, FilterContext, isUndissected, layerPresence, resolveField, Scalar } from './fields';

export type { FilterContext };
export type Predicate = (p: Packet) => boolean;

const ALWAYS_FALSE: Predicate = () => false;

/** A decimal or 0x-prefixed hex integer, or null when the text is neither. */
function parseNumericLiteral(text: string): number | null {
  const t = text.trim();
  if (/^[+-]?0x[0-9a-f]+$/i.test(t)) {
    const negative = t.startsWith('-');
    const value = parseInt(t.replace(/^[+-]/, '').slice(2), 16);
    return negative ? -value : value;
  }
  if (/^[+-]?\d+$/.test(t)) return Number(t);
  if (/^[+-]?\d*\.\d+$/.test(t)) return Number(t);
  return null;
}

/**
 * True for a right-hand side that is a network rather than a name: it has a
 * prefix length and starts like an address. `matches "a/b"` never reaches
 * here because a quoted literal is always a string.
 */
function looksLikeCidr(text: string): boolean {
  if (!text.includes('/')) return false;
  const [addr, bits] = text.split('/');
  if (!/^\d+$/.test(bits ?? '')) return false;
  return /^\d+\.\d+\.\d+\.\d+$/.test(addr) || /^[0-9a-f:]+$/i.test(addr);
}

function compareNumbers(a: number, b: number, op: CompareOp): boolean {
  switch (op) {
    case '==': return a === b;
    case '!=': return a !== b;
    case '>': return a > b;
    case '<': return a < b;
    case '>=': return a >= b;
    case '<=': return a <= b;
    default: return false;
  }
}

function compareText(a: string, b: string, op: CompareOp, ci: boolean): boolean {
  const l = ci ? a.toLowerCase() : a;
  const r = ci ? b.toLowerCase() : b;
  switch (op) {
    case '==': return l === r;
    case '!=': return l !== r;
    case '>': return l > r;
    case '<': return l < r;
    case '>=': return l >= r;
    case '<=': return l <= r;
    default: return false;
  }
}

/**
 * The bytes a `name[offset:length]` slice refers to.
 *
 * Only the link layer is addressable this way today, which is all the shipped
 * Broadcast rule (`eth[0] & 1` - the multicast bit of the destination MAC)
 * needs. A slice on any other layer would need that layer's offset within the
 * frame, which the summary pass does not keep; it reads as absent rather than
 * as zero, so a rule written against it matches nothing instead of matching
 * everything.
 */
function readSlice(p: Packet, f: FieldRef): number | null {
  if (f.name !== 'eth' && f.name !== 'frame') return null;
  const { offset, length } = f.slice!;
  if (offset + length > p.rawBytes.length) return null;
  let value = 0;
  for (let i = 0; i < length; i++) value = (value << 8) | p.rawBytes[offset + i];
  return value >>> 0;
}

/**
 * The resolution's reader with the context bound, when it reads one.
 *
 * Bound to the context OBJECT, so the reader sees whatever `context.marked` is
 * when it runs. Every other reader is returned as it is.
 */
function bindContext(res: FieldResolution, context: FilterContext | undefined): (p: Packet) => Scalar[] {
  const read = res.read;
  return res.contextual === true ? (p) => read(p, context) : read as (p: Packet) => Scalar[];
}

function buildReader(f: FieldRef, context: FilterContext | undefined): { read: (p: Packet) => Scalar[]; res: FieldResolution | null } {
  if (f.slice) {
    return {
      read: (p) => {
        const v = readSlice(p, f);
        return v === null ? [] : [v];
      },
      res: null,
    };
  }
  const res = resolveField(f.name);
  return { read: bindContext(res, context), res };
}

function buildCompare(f: FieldRef, op: CompareOp, v: Literal, context: FilterContext | undefined): Predicate {
  const { read, res } = buildReader(f, context);
  const ci = res?.ci ?? false;

  if (op === 'matches') {
    let re: RegExp;
    try {
      re = new RegExp(v.text, 'i');
    } catch (e) {
      throw new FilterSyntaxError(`Invalid regular expression: ${(e as Error).message}`, v.pos);
    }
    return (p) => read(p).some((value) => re.test(String(value)));
  }

  if (op === 'contains' || op === 'icontains') {
    const needle = op === 'icontains' ? v.text.toLowerCase() : v.text;
    return (p) => read(p).some((value) => {
      const hay = op === 'icontains' ? String(value).toLowerCase() : String(value);
      return hay.includes(needle);
    });
  }

  // A network on the right-hand side compares networks, not text. Decided
  // here rather than per packet, and before the numeric path, so that
  // `ip.dst != 224.0.0.0/4` means "is not multicast" instead of being true
  // for every address that is not that literal string.
  if (!v.quoted && looksLikeCidr(v.text)) {
    // The network parsed once, here, rather than for every address of every frame.
    const inCidr = cidrMatcher(v.text);
    const inside = (p: Packet) =>
      read(p).some((value) => typeof value === 'string' && inCidr(value));
    return op === '!=' ? (p) => (read(p).length > 0 ? !inside(p) : false) : inside;
  }

  const num = v.quoted ? null : parseNumericLiteral(v.text);
  const text = v.text;

  const matchesOne = (value: Scalar, effective: CompareOp): boolean =>
    typeof value === 'number' && num !== null
      ? compareNumbers(value, num, effective)
      : compareText(String(value), text, effective, ci);

  if (op === '!=') {
    return (p) => {
      const values = read(p);
      if (values.length === 0) return false;
      return !values.some((value) => matchesOne(value, '=='));
    };
  }

  return (p) => read(p).some((value) => matchesOne(value, op));
}

function buildMember(f: FieldRef, entries: SetEntry[], negated: boolean, context: FilterContext | undefined): Predicate {
  const { read, res } = buildReader(f, context);
  const ci = res?.ci ?? false;

  const ranges: { from: number; to: number }[] = [];
  const singles: { num: number | null; text: string }[] = [];

  for (const entry of entries) {
    if (entry.to) {
      const from = parseNumericLiteral(entry.from.text);
      const to = parseNumericLiteral(entry.to.text);
      if (from === null || to === null || to < from) {
        throw new FilterSyntaxError(`Invalid range "${entry.from.text}..${entry.to.text}"`, entry.from.pos);
      }
      ranges.push({ from, to });
    } else {
      singles.push({
        num: entry.from.quoted ? null : parseNumericLiteral(entry.from.text),
        text: entry.from.text,
      });
    }
  }

  const inSet = (value: Scalar): boolean => {
    if (typeof value === 'number') {
      if (ranges.some((r) => value >= r.from && value <= r.to)) return true;
      return singles.some((s) => s.num !== null && s.num === value);
    }
    return singles.some((s) => compareText(value, s.text, '==', ci));
  };

  return (p) => {
    const values = read(p);
    // A field the frame does not carry is neither in the set nor out of it.
    if (values.length === 0) return false;
    const hit = values.some(inSet);
    return negated ? !hit : hit;
  };
}

function buildBitmask(f: FieldRef, mask: Literal, context: FilterContext | undefined): Predicate {
  const { read } = buildReader(f, context);
  const m = parseNumericLiteral(mask.text);
  if (m === null) throw new FilterSyntaxError(`Expected a numeric mask, found "${mask.text}"`, mask.pos);
  return (p) => read(p).some((value) => typeof value === 'number' && (value & m) !== 0);
}

/** The analysis verdicts the reference also files as `tcp.analysis.retransmission`. */
const RETRANSMISSION_KINDS = new Set(['retransmission', 'fast_retransmission', 'spurious_retransmission']);

function buildPresent(f: FieldRef, context: FilterContext | undefined): Predicate {
  if (f.slice) {
    const { read } = buildReader(f, context);
    return (p) => read(p).length > 0;
  }

  // A bare `tcp.analysis.flags` asks whether any analysis flag fired; a bare
  // `tcp.analysis.retransmission` asks about that one. Some of these are also
  // registered fields with a value (`bytes_in_flight`), so both are checked.
  if (f.name.startsWith('tcp.analysis.')) {
    const which = f.name.slice('tcp.analysis.'.length);
    const { read } = buildReader(f, context);
    if (which === 'flags') return (p) => (p.analysisFlags?.length ?? 0) > 0;
    // The reference sets the generic verdict on a fast and a spurious
    // retransmission too, so `tcp.analysis.retransmission` - the filter
    // everyone types for "show me retransmissions" - matches all three.
    if (which === 'retransmission') {
      return (p) => (p.analysisFlags?.some((k) => RETRANSMISSION_KINDS.has(k)) ?? false) || read(p).length > 0;
    }
    return (p) => (p.analysisFlags?.includes(which) ?? false) || read(p).length > 0;
  }

  const layer = layerPresence(f.name);
  if (layer) return layer;

  const res = resolveField(f.name);
  // A name nothing in this build produces matches nothing, rather than
  // falling through to a substring search over the summary columns the way
  // the old engine did - which made `dcerpc` in a shipped colour rule paint
  // any frame whose Info happened to contain those letters.
  if (!res.known) return ALWAYS_FALSE;
  const read = bindContext(res, context);
  return (p) => read(p).length > 0;
}

function build(node: Node, context: FilterContext | undefined): Predicate {
  switch (node.t) {
    case 'or': {
      const l = build(node.l, context), r = build(node.r, context);
      return (p) => l(p) || r(p);
    }
    case 'xor': {
      const l = build(node.l, context), r = build(node.r, context);
      return (p) => l(p) !== r(p);
    }
    case 'and': {
      const l = build(node.l, context), r = build(node.r, context);
      return (p) => l(p) && r(p);
    }
    case 'not': {
      const e = build(node.e, context);
      return (p) => !e(p);
    }
    case 'present': return buildPresent(node.f, context);
    case 'compare': return buildCompare(node.f, node.op, node.v, context);
    case 'member': return buildMember(node.f, node.set, node.negated, context);
    case 'bitmask': return buildBitmask(node.f, node.mask, context);
  }
}

/**
 * Compiles a filter expression. Throws `FilterSyntaxError` on bad syntax.
 *
 * `context` carries what lives outside the packet (`FilterContext`). The
 * predicate keeps the object and reads it on every call, so a caller that
 * replaces `context.marked` is seen by a predicate it compiled earlier.
 */
export function compile(expression: string, context?: FilterContext): Predicate {
  return build(parseFilter(expression), context);
}

export interface FilterIssue {
  name: string;
  pos: number;
  /**
   * `field` - an unknown name used with an operator. Nothing in this build
   *   produces it and it belongs to no protocol we recognise, so it is almost
   *   certainly a typo and is reported as an error.
   * `undissected` - a name belonging to a protocol Inwire knows of and does
   *   not decode (`ospf.msg`, `sctp.chunk_type`). Legitimate, matches nothing.
   * `protocol` - a bareword presence test for something unrecognised.
   */
  kind: 'field' | 'undissected' | 'protocol' | 'tree-only';
}

/**
 * Names in the expression that this build cannot produce.
 *
 * Split by how it was used and by what it names, because the three deserve
 * different treatment. `tpc.port == 80` is a typo and should stop the user;
 * `ospf.msg != 1` is one of Wireshark's default colour rules and should be
 * kept, quietly matching nothing until an OSPF dissector exists.
 */
export function unknownNames(node: Node): FilterIssue[] {
  const out: FilterIssue[] = [];

  const visitField = (f: FieldRef, kind: FilterIssue['kind']) => {
    if (f.slice) return;
    if (kind === 'protocol') {
      if (f.name.startsWith('tcp.analysis.')) return;
      if (layerPresence(f.name)) return;
    }
    const res = resolveField(f.name);
    if (res.known) return;
    // Registered but tree-only is its own answer, and not a typo: the name is
    // spelled correctly and the field is on screen in the detail tree. Telling
    // someone "unknown field" about a name they just read off a packet would be
    // the app calling itself a liar.
    if (res.treeOnly === true) {
      out.push({ name: f.name, pos: f.pos, kind: 'tree-only' });
      return;
    }
    out.push({ name: f.name, pos: f.pos, kind: isUndissected(f.name) ? 'undissected' : kind });
  };

  const walk = (n: Node): void => {
    switch (n.t) {
      case 'or': case 'and': case 'xor': walk(n.l); walk(n.r); break;
      case 'not': walk(n.e); break;
      case 'present': visitField(n.f, 'protocol'); break;
      case 'compare': visitField(n.f, 'field'); break;
      case 'member': visitField(n.f, 'field'); break;
      case 'bitmask': visitField(n.f, 'field'); break;
    }
  };

  walk(node);
  return out;
}

export { FilterSyntaxError };
