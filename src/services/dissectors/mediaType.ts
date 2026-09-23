/**
 * What to do with a message body, decided by its media type.
 *
 * **The same registry shape as `dissectors/dispatch.ts`**, which is the
 * argument for having built that one first: an entry says what it claims and
 * what it produces, the table is scanned in order, and adding a body format
 * is a registration rather than another arm of a growing `if`. The key is a
 * MIME type rather than a number, which is the only difference that matters.
 *
 * ## The layer names are the reference's protocols, and so are the tokens
 *
 * `tshark -G protocols` calls these `json`, `data-text-lines`, `media` and
 * `data`, and `PROTOCOL_NAME_MAP` in `pcapParser.ts` maps each layer name
 * onto the matching token - so a frame's protocol chain reads
 * `eth:ethertype:ip:tcp:http:json`, exactly as the reference writes it, and
 * the bareword `json` answers in the filter bar.
 *
 * `data-text-lines` lexes as one word because `-` is a word character in
 * `filter/lexer.ts`, which was checked rather than hoped for.
 *
 * ## What is deliberately NOT built
 *
 * **No DOM for XML.** The reference's own XML dissector is a large tree this
 * build has no fixture for, and `text/*` covering XML as line-based text is
 * what the reference does for `application/xhtml+xml` anyway. A half-built
 * XML tree would be worse than a line count.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import { dissectJson } from './json';

export interface MediaEntry {
  /** Exact media types this claims, lower-cased, without parameters. */
  types?: readonly string[];
  /** For families - `text/*`, anything `+json` - where a list cannot do it. */
  claims?(type: string): boolean;
  /** The `frameProtocols` token, for the comment above and for the gate. */
  token: string;
  dissect(bytes: Uint8Array, type: string): ProtocolLayer;
}

/** How much text one line-based row shows, and how many lines are drawn. */
const MAX_LINES = 200;
const MAX_LINE = 512;

const decoder = new TextDecoder('utf-8', { fatal: false });

function previewLine(line: string): string {
  const clean = line.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '.');
  return clean.length > MAX_LINE ? `${clean.slice(0, MAX_LINE)}...` : clean;
}

export const MEDIA_DISSECTORS: readonly MediaEntry[] = [
  {
    types: ['application/json', 'text/json', 'application/problem+json'],
    // `application/vnd.api+json`, `application/ld+json` and every other
    // vendor tree that ends `+json` is JSON, which is what the suffix is FOR
    // (RFC 6839) - and listing them is a losing game.
    claims: (type) => type.endsWith('+json'),
    token: 'json',
    dissect(bytes, type) {
      const tree = dissectJson(bytes);
      return {
        name: 'JavaScript Object Notation',
        summary: `JavaScript Object Notation: ${type}`,
        fields: tree.rows,
      };
    },
  },
  {
    claims: (type) => (
      type.startsWith('text/')
      || type === 'application/javascript' || type === 'application/ecmascript'
      || type === 'application/xml' || type.endsWith('+xml')
    ),
    token: 'data-text-lines',
    dissect(bytes) {
      const text = decoder.decode(bytes);
      // A trailing newline makes an empty last element, which is not a line.
      const lines = text.split(/\r?\n/);
      if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
      const rows: ProtocolField[] = lines.slice(0, MAX_LINES).map((line) => ({
        name: 'Line', value: previewLine(line), abbrev: 'data.text',
      }));
      if (lines.length > MAX_LINES) {
        rows.push({
          name: '[Lines not drawn]', generated: true,
          value: `${lines.length - MAX_LINES} more, of ${lines.length}`,
        });
      }
      return {
        name: 'Line-based text data',
        summary: `Line-based text data (${lines.length} line${lines.length === 1 ? '' : 's'})`,
        fields: rows,
      };
    },
  },
];

/**
 * The `Data` layer, for bytes nothing claimed.
 *
 * **Not only for message bodies.** The reference raises this for any payload
 * that reaches the end of its dissector chain unclaimed - a TCP segment on a
 * port nobody registered, a UDP datagram of an unknown protocol, the bytes
 * after an ICMP header - and it is the single commonest thing in both
 * fixtures that this build had no layer for: 2,183 frames on `inwire`, 237 on
 * `bulk`.
 *
 * It was registered and unreachable before this, because the only caller was
 * the HTTP body path and neither capture carries cleartext HTTP. That is what
 * a registered name emitted on zero frames looks like from the inside, and it
 * is why the audit that found it looked for exactly that shape.
 *
 * **`data.data` is `FT_BYTES`**, so the value is hex rather than a text
 * preview. A preview was what the body path drew, and it is wrong for the
 * same reason `media.type` and `http.file_data` are traps: the name says one
 * thing and the dictionary says another.
 *
 * Colon-separated, because that is the reference's `show` and `show` is what
 * the measurement compares - its `showname` runs the same bytes together, so
 * reading the human-facing line would have produced a mismatch on every
 * frame. `icmp.data` two files over already draws it this way.
 */
export function dataLayer(bytes: Uint8Array): ProtocolLayer {
  const hex = hexColons(bytes, 0, bytes.length);
  return {
    name: 'Data',
    summary: `Data (${bytes.length} byte${bytes.length === 1 ? '' : 's'})`,
    fields: [
      { name: 'Data', value: hex, abbrev: 'data.data' },
      { name: 'Length', value: bytes.length, abbrev: 'data.len' },
    ],
  };
}

/**
 * The catch-all for a message body, which is two different protocols in the
 * reference and is kept as two here.
 *
 * `media` is "a body whose type was declared and which nothing decodes";
 * `data` is "bytes with no type at all". They are not interchangeable: the
 * first says the sender told us and we did not implement it, the second says
 * nobody said anything - and those lead a reader to different next steps.
 *
 * **`media.type` is `FT_BYTES` in the reference**, not a string. It holds the
 * body, not the MIME type its name suggests, which is the same trap
 * `http.file_data` carries and was found the same way: by reading the
 * dictionary rather than the name.
 */
function fallbackLayer(bytes: Uint8Array, type: string | undefined): ProtocolLayer {
  const preview = previewLine(decoder.decode(bytes.subarray(0, MAX_LINE)));
  if (type === undefined || type.length === 0) return dataLayer(bytes);
  return {
    name: 'Media Type',
    summary: `Media Type: ${type} (${bytes.length} byte${bytes.length === 1 ? '' : 's'})`,
    fields: [
      { name: 'Media type', value: preview, abbrev: 'media.type' },
      { name: 'Length', value: bytes.length, abbrev: 'data.len' },
    ],
  };
}

/**
 * The layer a body produces, or null when there is no body to produce one
 * from.
 *
 * `contentType` is the whole header value; the parameters after the first
 * `;` - `charset`, `boundary` - are not part of the key and are stripped
 * here rather than at every call site.
 */
export function dissectMediaType(bytes: Uint8Array, contentType: string | undefined): ProtocolLayer | null {
  if (bytes.length === 0) return null;
  const type = (contentType ?? '').split(';')[0].trim().toLowerCase();
  if (type.length > 0) {
    for (const entry of MEDIA_DISSECTORS) {
      const claimed = entry.types?.includes(type) === true || entry.claims?.(type) === true;
      if (claimed) return entry.dissect(bytes, type);
    }
  }
  return fallbackLayer(bytes, type);
}
