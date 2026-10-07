/**
 * XML, drawn as its own structure: what WS-Discovery is, on UDP 3702.
 *
 *   <soap:Envelope
 *     xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 *     <soap:Body>
 *       <wsd:Probe>
 *
 * Every Windows machine on a network announces itself and looks for printers,
 * scanners and media devices with SOAP-over-UDP multicast to
 * 239.255.255.250:3702, and the reference shows it as `UDP/XML` with the
 * document as a tree - which element, which action, which device type was
 * asked for. Here it was a UDP payload of a few hundred bytes.
 *
 * **The tree is the reference's, which is a rendering of the source text
 * rather than a parsed document**: each row is the markup as written. An
 * element with attributes is its opening `<name`, with each attribute a row
 * beneath it and the last carrying the tag's `>` or `/>`; one without is its
 * whole tag, `<b>` or `<e/>`. Its content - child elements, text, comments,
 * CDATA sections - nests under it, ending with the closing tag as a row of
 * its own. Text loses its leading whitespace and keeps its trailing, and text
 * that is only whitespace is not drawn. Entities stay as written. A payload
 * that does not open with markup is one `xml.unknown` row.
 *
 * Bounded (`MAX_NODES`): a hostile document of a million empty tags would
 * otherwise be a million rows.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

const MAX_NODES = 4000;
const decoder = new TextDecoder('utf-8', { fatal: false });

const LT = 0x3c;
const GT = 0x3e;
const isSpace = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;

/** The index of `needle` at or after `from`, or -1. */
function indexOf(b: Uint8Array, needle: string, from: number, end: number): number {
  const first = needle.charCodeAt(0);
  outer: for (let i = from; i <= end - needle.length; i++) {
    if (b[i] !== first) continue;
    for (let k = 1; k < needle.length; k++) if (b[i + k] !== needle.charCodeAt(k)) continue outer;
    return i;
  }
  return -1;
}

const startsWith = (b: Uint8Array, at: number, text: string) => {
  for (let k = 0; k < text.length; k++) if (b[at + k] !== text.charCodeAt(k)) return false;
  return true;
};

/** A row of literal markup: the text is the row. */
function raw(b: Uint8Array, from: number, to: number, abbrev?: string): ProtocolField {
  return { name: decoder.decode(b.subarray(from, to)), value: '', ...(abbrev ? { abbrev } : {}), rawBytesRange: [from, to - 1] };
}

/**
 * One tag's attributes: `[from, to)` of each, in order. Quoted values may
 * hold `>`, so the tag's end is found by walking them, not by searching.
 * Returns where the tag's `>` is, or -1 when the document ends inside it.
 */
function readAttributes(b: Uint8Array, at: number, end: number, out: [number, number][]): number {
  let p = at;
  while (p < end) {
    while (p < end && isSpace(b[p])) p++;
    if (p >= end) return -1;
    if (b[p] === GT) return p;
    if (b[p] === 0x2f /* / */ && b[p + 1] === GT) return p + 1;
    const from = p;
    while (p < end && b[p] !== 0x3d /* = */ && b[p] !== GT && !isSpace(b[p])) p++;
    while (p < end && isSpace(b[p])) p++;
    if (b[p] === 0x3d) {
      p++;
      while (p < end && isSpace(b[p])) p++;
      const quote = b[p];
      if (quote === 0x22 || quote === 0x27) {
        p++;
        while (p < end && b[p] !== quote) p++;
        p++;
      } else {
        while (p < end && !isSpace(b[p]) && b[p] !== GT) p++;
      }
    }
    out.push([from, Math.min(p, end)]);
  }
  return -1;
}

export function dissectXml(b: Uint8Array, start: number, end: number): ProtocolLayer {
  const top: ProtocolField[] = [];
  let first = start;
  while (first < end && isSpace(b[first])) first++;
  if (first >= end || b[first] !== LT) {
    top.push(raw(b, start, end, 'xml.unknown'));
    return { name: 'eXtensible Markup Language', summary: 'eXtensible Markup Language', fields: top };
  }

  /** Open elements, innermost last: each one's row, to close it into. */
  const open: ProtocolField[] = [];
  const into = () => (open.length > 0 ? open[open.length - 1].children! : top);
  let nodes = 0;
  let p = first;
  while (p < end && nodes < MAX_NODES) {
    nodes++;
    if (b[p] !== LT) {
      // Text, up to the next markup. Only whitespace is not a row.
      const stop = indexOf(b, '<', p, end);
      const textEnd = stop < 0 ? end : stop;
      let from = p;
      while (from < textEnd && isSpace(b[from])) from++;
      if (from < textEnd) into().push(raw(b, from, textEnd, 'xml.cdata'));
      p = textEnd;
      continue;
    }
    if (startsWith(b, p, '<!--')) {
      const close = indexOf(b, '-->', p + 4, end);
      const stop = close < 0 ? end : close + 3;
      into().push(raw(b, p, stop, 'xml.comment'));
      p = stop;
      continue;
    }
    if (startsWith(b, p, '<![CDATA[')) {
      const close = indexOf(b, ']]>', p + 9, end);
      const stop = close < 0 ? end : close + 3;
      into().push(raw(b, p, stop, 'xml.cdatasection'));
      p = stop;
      continue;
    }
    if (startsWith(b, p, '<!')) {
      // A DOCTYPE, with any internal subset in brackets.
      let q = p + 2;
      let depth = 0;
      while (q < end && !(b[q] === GT && depth === 0)) {
        if (b[q] === 0x5b) depth++;
        else if (b[q] === 0x5d) depth--;
        q++;
      }
      const stop = Math.min(end, q + 1);
      into().push(raw(b, p, stop, 'xml.dtdtag'));
      p = stop;
      continue;
    }
    if (startsWith(b, p, '<?')) {
      const close = indexOf(b, '?>', p + 2, end);
      const stop = close < 0 ? end : close + 2;
      let nameEnd = p + 2;
      while (nameEnd < stop && !isSpace(b[nameEnd]) && b[nameEnd] !== 0x3f) nameEnd++;
      const target = decoder.decode(b.subarray(p + 2, nameEnd));
      if (target === 'xml') {
        // The declaration: each pseudo-attribute a row named for itself.
        const attrs: [number, number][] = [];
        readAttributes(b, nameEnd, close < 0 ? end : close, attrs);
        const children: ProtocolField[] = attrs.map(([from, to]) => {
          const key = decoder.decode(b.subarray(from, to)).split('=')[0].trim();
          const row = raw(b, from, to);
          return /^(version|encoding|standalone)$/.test(key) ? { ...row, abbrev: `xml.xmlpi.xml.${key}` } : row;
        });
        if (close >= 0) children.push(raw(b, close, stop));
        into().push({ ...raw(b, p, nameEnd, 'xml.xmlpi.xml'), rawBytesRange: [p, stop - 1], children });
      } else {
        into().push(raw(b, p, stop));
      }
      p = stop;
      continue;
    }
    if (b[p + 1] === 0x2f /* / */) {
      const close = indexOf(b, '>', p, end);
      const stop = close < 0 ? end : close + 1;
      const element = open.pop();
      if (element !== undefined) {
        element.children!.push(raw(b, p, stop));
        element.rawBytesRange = [element.rawBytesRange![0], stop - 1];
      } else {
        top.push(raw(b, p, stop));
      }
      p = stop;
      continue;
    }
    // An element's opening tag.
    let nameEnd = p + 1;
    while (nameEnd < end && !isSpace(b[nameEnd]) && b[nameEnd] !== GT && !(b[nameEnd] === 0x2f && b[nameEnd + 1] === GT)) nameEnd++;
    const attrs: [number, number][] = [];
    const tagEnd = readAttributes(b, nameEnd, end, attrs);
    const stop = tagEnd < 0 ? end : tagEnd + 1;
    const selfClosing = tagEnd > 0 && b[tagEnd - 1] === 0x2f;
    let element: ProtocolField;
    if (attrs.length === 0) {
      element = { ...raw(b, p, stop, 'xml.tag'), children: [] };
    } else {
      // The last attribute's row runs to the tag's end, `>` or `/>` and all.
      attrs[attrs.length - 1][1] = stop;
      element = {
        ...raw(b, p, nameEnd, 'xml.tag'), rawBytesRange: [p, stop - 1],
        children: attrs.map(([from, to]) => raw(b, from, to, 'xml.attribute')),
      };
    }
    into().push(element);
    if (!selfClosing && tagEnd >= 0) open.push(element);
    p = stop;
  }
  // Rows with nothing under them are leaves, not empty folders.
  const prune = (rows: ProtocolField[]) => {
    for (const row of rows) {
      if (row.children === undefined) continue;
      if (row.children.length === 0) delete row.children;
      else prune(row.children);
    }
  };
  prune(top);
  return { name: 'eXtensible Markup Language', summary: 'eXtensible Markup Language', fields: top };
}
