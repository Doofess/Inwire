/**
 * Recursive-descent parser for the display-filter language.
 *
 * Grammar, loosest binding first:
 *
 *   expr    := orExpr
 *   orExpr  := xorExpr (('||' | 'or') xorExpr)*
 *   xorExpr := andExpr ('xor' andExpr)*
 *   andExpr := unary (('&&' | 'and') unary)*
 *   unary   := ('!' | 'not') unary | primary
 *   primary := '(' expr ')'
 *            | fieldRef compareOp value
 *            | fieldRef ['not'] 'in' setLiteral
 *            | fieldRef '&' number
 *            | fieldRef                       -- presence test
 *   fieldRef:= word ('[' slice ']')?
 *
 * The parser deliberately knows nothing about which fields exist or what type
 * they are; it produces a tree of names and literal texts. Resolution against
 * the field registry happens in compile.ts, so the same tree can be walked for
 * a compiled predicate, for validation, and (later) for pretty-printing a
 * filter built by clicking a row in the detail tree.
 */

import { FilterSyntaxError, Token, tokenize } from './lexer';

export type CompareOp =
  | '==' | '!=' | '>' | '<' | '>=' | '<='
  | 'contains' | 'icontains' | 'matches';

/** A `word`-shaped or quoted right-hand side, uninterpreted. */
export interface Literal {
  text: string;
  /** A quoted literal is always a string, never a number or a CIDR. */
  quoted: boolean;
  pos: number;
}

/** One entry of a `{ ... }` set: a single value or an inclusive range. */
export interface SetEntry {
  from: Literal;
  /** Present for `3..5`; the entry is then a range. */
  to?: Literal;
}

/**
 * A byte slice on a layer, as in the Broadcast rule's `eth[0] & 1`.
 * `length` is 1 unless the filter wrote `eth[0:2]`.
 */
export interface Slice {
  offset: number;
  length: number;
}

export interface FieldRef {
  name: string;
  slice?: Slice;
  pos: number;
}

export type Node =
  | { t: 'or'; l: Node; r: Node }
  | { t: 'xor'; l: Node; r: Node }
  | { t: 'and'; l: Node; r: Node }
  | { t: 'not'; e: Node }
  | { t: 'present'; f: FieldRef }
  | { t: 'compare'; f: FieldRef; op: CompareOp; v: Literal }
  | { t: 'member'; f: FieldRef; set: SetEntry[]; negated: boolean }
  | { t: 'bitmask'; f: FieldRef; mask: Literal };

/** Worded operators the language accepts alongside the symbols. */
const WORD_OPS: Record<string, CompareOp> = {
  eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=',
  contains: 'contains', icontains: 'icontains', matches: 'matches',
};

const SYMBOL_OPS = new Set<string>(['==', '!=', '>', '<', '>=', '<=']);

class Parser {
  private i = 0;
  constructor(private readonly tokens: Token[]) {}

  private peek(ahead = 0): Token {
    return this.tokens[Math.min(this.i + ahead, this.tokens.length - 1)];
  }

  private next(): Token {
    return this.tokens[this.i++];
  }

  /** True when the token at `ahead` is the given lower-cased keyword. */
  private isWord(text: string, ahead = 0): boolean {
    const t = this.peek(ahead);
    return t.kind === 'word' && t.text.toLowerCase() === text;
  }

  private isOp(text: string, ahead = 0): boolean {
    const t = this.peek(ahead);
    return t.kind === 'op' && t.text === text;
  }

  parse(): Node {
    const node = this.parseOr();
    const rest = this.peek();
    if (rest.kind !== 'eof') {
      throw new FilterSyntaxError(`Unexpected "${rest.text || 'end of input'}"`, rest.pos);
    }
    return node;
  }

  private parseOr(): Node {
    let left = this.parseXor();
    while (this.isOp('||') || this.isWord('or')) {
      this.next();
      left = { t: 'or', l: left, r: this.parseXor() };
    }
    return left;
  }

  private parseXor(): Node {
    let left = this.parseAnd();
    while (this.isWord('xor')) {
      this.next();
      left = { t: 'xor', l: left, r: this.parseAnd() };
    }
    return left;
  }

  private parseAnd(): Node {
    let left = this.parseUnary();
    while (this.isOp('&&') || this.isWord('and')) {
      this.next();
      left = { t: 'and', l: left, r: this.parseUnary() };
    }
    return left;
  }

  private parseUnary(): Node {
    // `not` is only a negation when something follows it that can be negated.
    // `x not in {1}` is handled inside parsePrimary, which has already
    // consumed `x` by the time it looks at `not`.
    if (this.isOp('!') || this.isWord('not')) {
      this.next();
      return { t: 'not', e: this.parseUnary() };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): Node {
    const t = this.peek();

    if (t.kind === 'lparen') {
      this.next();
      const inner = this.parseOr();
      const close = this.next();
      if (close.kind !== 'rparen') {
        throw new FilterSyntaxError('Expected ")"', close.pos);
      }
      return inner;
    }

    if (t.kind !== 'word') {
      throw new FilterSyntaxError(
        t.kind === 'eof' ? 'Expression ended early' : `Expected a field name, found "${t.text}"`,
        t.pos,
      );
    }

    const f = this.parseFieldRef();

    // field op value
    const op = this.peek();
    if (op.kind === 'op' && SYMBOL_OPS.has(op.text)) {
      this.next();
      return { t: 'compare', f, op: op.text as CompareOp, v: this.parseLiteral() };
    }
    if (op.kind === 'op' && op.text === '~') {
      this.next();
      return { t: 'compare', f, op: 'matches', v: this.parseLiteral() };
    }
    if (op.kind === 'op' && op.text === '&') {
      this.next();
      return { t: 'bitmask', f, mask: this.parseLiteral() };
    }
    if (op.kind === 'word') {
      const worded = WORD_OPS[op.text.toLowerCase()];
      if (worded) {
        this.next();
        return { t: 'compare', f, op: worded, v: this.parseLiteral() };
      }
      if (op.text.toLowerCase() === 'in') {
        this.next();
        return { t: 'member', f, set: this.parseSet(), negated: false };
      }
      if (op.text.toLowerCase() === 'not' && this.isWord('in', 1)) {
        this.next();
        this.next();
        return { t: 'member', f, set: this.parseSet(), negated: true };
      }
    }

    return { t: 'present', f };
  }

  private parseFieldRef(): FieldRef {
    const name = this.next();
    if (this.peek().kind !== 'lbracket') {
      return { name: name.text.toLowerCase(), pos: name.pos };
    }
    this.next(); // [
    const body = this.next();
    if (body.kind !== 'word') throw new FilterSyntaxError('Expected a byte offset', body.pos);
    const close = this.next();
    if (close.kind !== 'rbracket') throw new FilterSyntaxError('Expected "]"', close.pos);

    // `[n]` or `[n:len]`. The lexer keeps `0:2` as one word because `:` is a
    // word character (it has to be, for MAC and IPv6 literals).
    const parts = body.text.split(':');
    const offset = Number(parts[0]);
    const length = parts.length > 1 ? Number(parts[1]) : 1;
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 1) {
      throw new FilterSyntaxError(`Invalid byte slice "[${body.text}]"`, body.pos);
    }
    return { name: name.text.toLowerCase(), slice: { offset, length }, pos: name.pos };
  }

  private parseLiteral(): Literal {
    const t = this.next();
    if (t.kind === 'string') return { text: t.text, quoted: true, pos: t.pos };
    if (t.kind === 'word') return { text: t.text, quoted: false, pos: t.pos };
    throw new FilterSyntaxError(
      t.kind === 'eof' ? 'Expected a value' : `Expected a value, found "${t.text}"`,
      t.pos,
    );
  }

  private parseSet(): SetEntry[] {
    const open = this.next();
    if (open.kind !== 'lbrace') throw new FilterSyntaxError('Expected "{"', open.pos);

    const entries: SetEntry[] = [];
    while (this.peek().kind !== 'rbrace') {
      if (this.peek().kind === 'eof') throw new FilterSyntaxError('Expected "}"', this.peek().pos);
      const first = this.parseLiteral();

      // `3..5` arrives as the single word "3..5"; `3 .. 5` as three tokens.
      const dotted = !first.quoted && first.text.match(/^(.+?)\.\.(.+)$/);
      if (dotted) {
        entries.push({
          from: { text: dotted[1], quoted: false, pos: first.pos },
          to: { text: dotted[2], quoted: false, pos: first.pos },
        });
      } else if (this.isWord('..')) {
        this.next();
        entries.push({ from: first, to: this.parseLiteral() });
      } else {
        entries.push({ from: first });
      }

      if (this.peek().kind === 'comma') this.next();
    }
    this.next(); // }

    if (entries.length === 0) throw new FilterSyntaxError('Empty set', open.pos);
    return entries;
  }
}

export function parseFilter(input: string): Node {
  return new Parser(tokenize(input)).parse();
}

export { FilterSyntaxError };
