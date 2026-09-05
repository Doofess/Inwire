/**
 * Tokenizer for the display-filter language.
 *
 * The old engine had no tokenizer: it re-ran a set of regexes over the raw
 * string at every level of the expression and again for every packet, which is
 * why `ip.dst != 224.0.0.0/4` needed a special case to stop the CIDR being read
 * as a string, and why `==` quietly meant "contains". One pass over the text
 * producing typed tokens removes that whole class of problem.
 *
 * The one thing this lexer does differently from a conventional one is that it
 * has a single `word` token for both field names and unquoted values. That is
 * deliberate: `224.0.0.0/4`, `ff00::/8`, `00:11:22:33:44:55`, `0x80`, `3..5`
 * and `tcp.flags.syn` all have the same shape, and deciding which is which
 * needs to know whether it sits on the left or the right of an operator -
 * which is the parser's job, not the lexer's. So `.`, `:`, `/`, `%` and `-`
 * are all word characters, and the parser interprets.
 */

export type TokenKind =
  | 'word'
  | 'string'
  | 'op'
  | 'lparen'
  | 'rparen'
  | 'lbrace'
  | 'rbrace'
  | 'lbracket'
  | 'rbracket'
  | 'comma'
  | 'eof';

export interface Token {
  kind: TokenKind;
  /** For a `string`, the unescaped contents; otherwise the source text. */
  text: string;
  /** Byte offset of the token's first character, for error messages. */
  pos: number;
}

/** Raised by the lexer and the parser; carries where in the input it gave up. */
export class FilterSyntaxError extends Error {
  constructor(message: string, public readonly pos: number) {
    super(message);
    this.name = 'FilterSyntaxError';
  }
}

/**
 * Characters that may appear inside an unquoted word.
 *
 * `-` is included so `len > -1` and `Time-Exceeded` lex as one token; `:` for
 * MAC and IPv6 literals; `/` for CIDR; `%` for an IPv6 zone id; `*` and `?`
 * so a glob-ish value reaches the compiler rather than ending the token early.
 */
const WORD = /[A-Za-z0-9_.:/%*?+-]/;

/** Two-character operators, checked before the single-character ones. */
const OPS2 = ['&&', '||', '==', '!=', '>=', '<='];
const OPS1 = ['!', '<', '>', '&', '~'];

export function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < input.length) {
    const c = input[i];

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i++;
      continue;
    }

    if (c === '(') { tokens.push({ kind: 'lparen', text: c, pos: i++ }); continue; }
    if (c === ')') { tokens.push({ kind: 'rparen', text: c, pos: i++ }); continue; }
    if (c === '{') { tokens.push({ kind: 'lbrace', text: c, pos: i++ }); continue; }
    if (c === '}') { tokens.push({ kind: 'rbrace', text: c, pos: i++ }); continue; }
    if (c === '[') { tokens.push({ kind: 'lbracket', text: c, pos: i++ }); continue; }
    if (c === ']') { tokens.push({ kind: 'rbracket', text: c, pos: i++ }); continue; }
    if (c === ',') { tokens.push({ kind: 'comma', text: c, pos: i++ }); continue; }

    if (c === '"' || c === "'") {
      const start = i;
      const quote = c;
      let value = '';
      i++;
      let closed = false;
      while (i < input.length) {
        if (input[i] === '\\' && i + 1 < input.length) {
          value += input[i + 1];
          i += 2;
          continue;
        }
        if (input[i] === quote) { i++; closed = true; break; }
        value += input[i++];
      }
      if (!closed) throw new FilterSyntaxError('Unterminated string', start);
      tokens.push({ kind: 'string', text: value, pos: start });
      continue;
    }

    const two = input.slice(i, i + 2);
    if (OPS2.includes(two)) {
      tokens.push({ kind: 'op', text: two, pos: i });
      i += 2;
      continue;
    }

    // A single `=` is accepted as `==`. Nothing in the language uses
    // assignment, and enough shipped presets were written that way that
    // rejecting it would only produce errors nobody can act on.
    if (c === '=') {
      tokens.push({ kind: 'op', text: '==', pos: i++ });
      continue;
    }

    if (OPS1.includes(c)) {
      tokens.push({ kind: 'op', text: c, pos: i++ });
      continue;
    }

    if (WORD.test(c)) {
      const start = i;
      while (i < input.length && WORD.test(input[i])) i++;
      tokens.push({ kind: 'word', text: input.slice(start, i), pos: start });
      continue;
    }

    throw new FilterSyntaxError(`Unexpected character "${c}"`, i);
  }

  tokens.push({ kind: 'eof', text: '', pos: input.length });
  return tokens;
}
