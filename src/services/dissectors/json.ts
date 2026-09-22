/**
 * JSON, as a tree.
 *
 * Reached from `mediaType.ts` when a body's Content-Type says so, which is
 * the same handoff TLS already performs on the other side of the connection:
 * a layer that knows what it is holding names the next dissector, and the
 * next dissector never has to guess.
 *
 * ## The field names are the reference's, not this file's
 *
 * `json.object`, `json.member`, `json.key`, `json.array` and the five
 * `json.value.*` names were each checked against `tshark -G fields`. That is
 * the registry's promise applied to a layer neither fixture contains: a
 * filter learnt in Wireshark - `json.key == "error"` - has to answer the same
 * here.
 *
 * ## Two bounds, and the second one is about the stack
 *
 * A body is already capped at a megabyte by `http1.ts`, and a megabyte of
 * JSON is still perhaps a hundred thousand nodes - more tree rows than any
 * pane can draw and more objects than one frame's detail view should hold.
 * `MAX_NODES` stops at twenty thousand and says so.
 *
 * `MAX_DEPTH` is the one that matters for correctness rather than for size.
 * A megabyte of `[[[[[[...` is valid JSON, one node deep per two bytes, and
 * a recursive parser meeting it blows the Worker's stack - which does not
 * throw somewhere catchable, it takes the Worker down and with it the whole
 * capture. **The depth is checked BEFORE the recursive call**, never after,
 * because a check after the call has already made it.
 */
import type { ProtocolField } from '../../types/packet';

const MAX_NODES = 20_000;
const MAX_DEPTH = 64;

/** How much of a long string value one row shows. */
const MAX_STRING = 512;

interface Walk {
  text: string;
  at: number;
  nodes: number;
  /** Set once a bound was hit, so the caller can say which. */
  stopped: 'nodes' | 'depth' | 'syntax' | null;
}

const decoder = new TextDecoder('utf-8', { fatal: false });

export interface JsonTree {
  rows: ProtocolField[];
  /** Null when the whole document was read. */
  stopped: 'nodes' | 'depth' | 'syntax' | null;
  /** What the top-level value is, for the layer's summary line. */
  kind: 'object' | 'array' | 'value';
}

/**
 * Reads `bytes` as JSON and returns the tree.
 *
 * Never throws: a body that is not JSON after all - a truncated download, an
 * error page served with the wrong Content-Type - has to become a row saying
 * so, because it arrives through a content-type guess and a guess being
 * wrong is an ordinary event rather than an exceptional one.
 */
export function dissectJson(bytes: Uint8Array): JsonTree {
  const text = decoder.decode(bytes);
  const walk: Walk = { text, at: 0, nodes: 0, stopped: null };
  skipSpace(walk);
  const first = walk.text[walk.at];
  const kind = first === '{' ? 'object' : first === '[' ? 'array' : 'value';

  const rows: ProtocolField[] = [];
  const value = readValue(walk, 0);
  if (value !== null) rows.push(value);
  if (walk.stopped === null) {
    skipSpace(walk);
    // Trailing bytes after a complete value mean this was not one JSON
    // document. Said out loud rather than ignored: it is how a reader finds
    // out that a `Content-Type: application/json` was not telling the truth.
    if (walk.at < walk.text.length) fail(walk);
  }
  if (walk.stopped !== null) {
    rows.push({
      name: '[JSON not fully read]', generated: true, value: STOPPED_REASON[walk.stopped],
    });
  }
  return { rows, stopped: walk.stopped, kind };
}

const STOPPED_REASON: Record<NonNullable<Walk['stopped']>, string> = {
  nodes: `more than ${MAX_NODES.toLocaleString()} values; the rest is not drawn`,
  depth: `nested deeper than ${MAX_DEPTH} levels; the rest is not drawn`,
  syntax: 'the bytes are not valid JSON from this point on',
};

/**
 * Records a syntax failure, but only when nothing has failed yet.
 *
 * **The first bound hit is the one worth reporting, and saying so takes
 * code.** Unwinding from a depth stop, every enclosing array finds neither a
 * comma nor a bracket - it is at the end of the input - and a plain
 * assignment would overwrite 'depth' with 'syntax' once per level, so a
 * document stopped by its nesting would report itself as malformed instead.
 * Caught by the 4,000-bracket body in `scripts/http/dissect.ts`.
 */
function fail(walk: Walk): void {
  if (walk.stopped === null) walk.stopped = 'syntax';
}

function skipSpace(walk: Walk): void {
  while (walk.at < walk.text.length) {
    const c = walk.text[walk.at];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') walk.at++;
    else break;
  }
}

/** One value, with its own children. Returns null once a bound has been hit. */
function readValue(walk: Walk, depth: number): ProtocolField | null {
  if (walk.stopped !== null) return null;
  if (walk.nodes >= MAX_NODES) { walk.stopped = 'nodes'; return null; }
  // **Before the recursive call, not after.** See this file's header.
  if (depth > MAX_DEPTH) { walk.stopped = 'depth'; return null; }
  walk.nodes++;

  skipSpace(walk);
  const c = walk.text[walk.at];
  if (c === undefined) { fail(walk); return null; }

  if (c === '{') return readObject(walk, depth);
  if (c === '[') return readArray(walk, depth);
  if (c === '"') {
    const text = readString(walk);
    if (text === null) return null;
    return {
      name: 'String value',
      value: text.length > MAX_STRING ? `${text.slice(0, MAX_STRING)}...` : text,
      abbrev: 'json.value.string',
    };
  }
  if (walk.text.startsWith('true', walk.at)) { walk.at += 4; return { name: 'True value', value: true, abbrev: 'json.value.true' }; }
  if (walk.text.startsWith('false', walk.at)) { walk.at += 5; return { name: 'False value', value: false, abbrev: 'json.value.false' }; }
  if (walk.text.startsWith('null', walk.at)) { walk.at += 4; return { name: 'Null value', value: 'null', abbrev: 'json.value.null' }; }

  const number = readNumber(walk);
  if (number === null) { fail(walk); return null; }
  return { name: 'Number value', value: number, abbrev: 'json.value.number' };
}

function readObject(walk: Walk, depth: number): ProtocolField | null {
  walk.at++; // '{'
  const members: ProtocolField[] = [];
  skipSpace(walk);
  if (walk.text[walk.at] === '}') { walk.at++; return { name: 'Object', value: '', abbrev: 'json.object', children: members }; }

  for (;;) {
    skipSpace(walk);
    if (walk.text[walk.at] !== '"') { fail(walk); break; }
    const key = readString(walk);
    if (key === null) break;
    skipSpace(walk);
    if (walk.text[walk.at] !== ':') { fail(walk); break; }
    walk.at++;
    const value = readValue(walk, depth + 1);
    if (value === null) break;
    members.push({
      // The reference puts the key in the member's own label, which is what
      // makes a collapsed object readable at all.
      name: `Member Key: ${key}`,
      value: scalarOf(value),
      abbrev: 'json.member',
      children: [{ name: 'Key', value: key, abbrev: 'json.key' }, value],
    });
    skipSpace(walk);
    if (walk.text[walk.at] === ',') { walk.at++; continue; }
    if (walk.text[walk.at] === '}') { walk.at++; break; }
    fail(walk);
    break;
  }
  return { name: 'Object', value: '', abbrev: 'json.object', children: members };
}

function readArray(walk: Walk, depth: number): ProtocolField | null {
  walk.at++; // '['
  const items: ProtocolField[] = [];
  skipSpace(walk);
  if (walk.text[walk.at] === ']') { walk.at++; return { name: 'Array', value: '', abbrev: 'json.array', children: items }; }

  for (;;) {
    const value = readValue(walk, depth + 1);
    if (value === null) break;
    items.push(value);
    skipSpace(walk);
    if (walk.text[walk.at] === ',') { walk.at++; continue; }
    if (walk.text[walk.at] === ']') { walk.at++; break; }
    fail(walk);
    break;
  }
  return { name: 'Array', value: '', abbrev: 'json.array', children: items };
}

/**
 * A member's own row shows its value when that value is a scalar, and nothing
 * when it is a container - an object's row cannot usefully show its contents
 * on one line, and trying is how a tree ends up with a megabyte in a cell.
 */
function scalarOf(value: ProtocolField): string | number | boolean {
  return value.children === undefined ? value.value : '';
}

/** A JSON string, escapes and all, or null on a malformed one. */
function readString(walk: Walk): string | null {
  walk.at++; // opening quote
  let out = '';
  for (;;) {
    const c = walk.text[walk.at];
    if (c === undefined) { fail(walk); return null; }
    walk.at++;
    if (c === '"') return out;
    if (c !== '\\') { out += c; continue; }
    const escape = walk.text[walk.at];
    walk.at++;
    switch (escape) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'u': {
        const hex = walk.text.slice(walk.at, walk.at + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) { fail(walk); return null; }
        out += String.fromCharCode(Number.parseInt(hex, 16));
        walk.at += 4;
        break;
      }
      default: fail(walk); return null;
    }
  }
}

function readNumber(walk: Walk): number | null {
  const start = walk.at;
  if (walk.text[walk.at] === '-') walk.at++;
  while (walk.at < walk.text.length && /[0-9.eE+-]/.test(walk.text[walk.at])) walk.at++;
  if (walk.at === start) return null;
  const parsed = Number(walk.text.slice(start, walk.at));
  return Number.isFinite(parsed) ? parsed : null;
}
