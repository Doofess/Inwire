/**
 * GSS-API (RFC 2743) and SPNEGO (RFC 4178): the envelope a Windows sign-in
 * travels in. An SMB2 Session Setup's security blob, an HTTP `Negotiate`
 * header and a DCE/RPC auth verifier all hold one, and inside it is the
 * mechanism actually signing in - NTLMSSP here (`dissectors/ntlmssp.ts`).
 *
 *   60 .. 06 <SPNEGO OID> a0 <negTokenInit>   the first token: the mechanisms offered
 *   a1 <negTokenTarg>                          every later one: the result, the token
 *
 * Drawn as the reference draws it: GSS-API's OID, SPNEGO inside it, NTLMSSP
 * inside SPNEGO where the token that held it is, and SPNEGO's mechListMIC
 * after that - three protocols, each a layer of the frame's chain, nested by
 * `dissect/nestedLayers.ts`. Checked against `tshark -T pdml` by
 * `scripts/ntlmssp/dissect.ts`.
 *
 * **One deliberate difference.** The reference reads a token after the first
 * by the conversation's memory of the first: a negTokenTarg on a connection
 * whose negTokenInit it did not see is an "Unknown header", and once a
 * Kerberos OID has been answered it reads every later token as Kerberos. This
 * reads each token by what it is - a negTokenTarg by its tag, an NTLMSSP
 * message by its signature - so it needs no state, and draws the same tree
 * wherever the reference saw the whole exchange.
 *
 * Not read: a Kerberos token inside SPNEGO is drawn as its bytes, where the
 * reference goes on into Kerberos.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import { headingFor } from '../dissect/nestedLayers';
import { dissectNtlmssp, looksLikeNtlmssp, ntlmsspVerifier } from './ntlmssp';

const GSS_LAYER = 'GSS-API Generic Security Service Application Program Interface';
const SPNEGO_LAYER = 'Simple Protected Negotiation';
const SPNEGO_OID = '1.3.6.1.5.5.2';
const NTLMSSP_OID = '1.3.6.1.4.1.311.2.2.10';

/** The mechanisms a Windows network offers, by the reference's names. */
const OID_NAMES: Record<string, string> = {
  [SPNEGO_OID]: 'SPNEGO - Simple Protected Negotiation',
  [NTLMSSP_OID]: 'NTLMSSP - Microsoft NTLM Security Support Provider',
  '1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
  '1.2.840.113554.1.2.2': 'KRB5 - Kerberos 5',
  '1.2.840.48018.1.2.2': 'MS KRB5 - Microsoft Kerberos 5',
  '1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
  '1.3.6.1.5.2.5': 'KRB5 - IAKERB',
};
const ROOTS = ['itu-t', 'iso', 'joint-iso-itu-t'];
const NEG_RESULTS = ['accept-completed', 'accept-incomplete', 'reject', 'request-mic'];

interface Tlv { tag: number; from: number; to: number; next: number }

/** One DER element at `p`, or null when it does not fit before `end`. */
function tlv(b: Uint8Array, p: number, end: number): Tlv | null {
  if (p + 2 > end) return null;
  const tag = b[p];
  let length = b[p + 1];
  let from = p + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 3 || from + n > end) return null;
    length = 0;
    for (let i = 0; i < n; i++) length = (length << 8) | b[from + i];
    from += n;
  }
  if (from + length > end) return null;
  return { tag, from, to: from + length, next: from + length };
}

/** The elements of a constructed value, in order. */
function children(b: Uint8Array, from: number, to: number): Tlv[] {
  const out: Tlv[] = [];
  for (let p = from; p < to;) {
    const t = tlv(b, p, to);
    if (t === null) break;
    out.push(t);
    p = t.next;
  }
  return out;
}

function oidText(b: Uint8Array, from: number, to: number): string {
  if (from >= to) return '';
  const arcs: number[] = [Math.min(2, Math.floor(b[from] / 40)), b[from] - Math.min(2, Math.floor(b[from] / 40)) * 40];
  let v = 0;
  for (let p = from + 1; p < to; p++) {
    v = v * 128 + (b[p] & 0x7f);
    if ((b[p] & 0x80) === 0) { arcs.push(v); v = 0; }
  }
  return arcs.join('.');
}
/** An OID as the reference shows one: dotted, and its name or its root's. */
function oidShown(dotted: string): string {
  const name = OID_NAMES[dotted];
  if (name !== undefined) return `${dotted} (${name})`;
  const [root, ...rest] = dotted.split('.');
  return `${dotted} (${[ROOTS[Number(root)] ?? root, ...rest].join('.')})`;
}

export interface GssResult {
  /** What the carrier appends to its Info: `, NTLMSSP_NEGOTIATE`, or nothing. */
  info: string;
  /** GSS-API, SPNEGO and NTLMSSP as the frame's chain names them; each after the first is nested in the one before. */
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
}

/** What a mechanism token turned out to be. */
interface Inner { info: string; layers: ProtocolLayer[]; fields: Record<string, string | number> }
const NOTHING: Inner = { info: '', layers: [], fields: {} };

function ntlmInner(b: Uint8Array, from: number, to: number): Inner | null {
  const ntlm = dissectNtlmssp(b, from, to);
  return ntlm === null ? null : { info: `, ${ntlm.info}`, layers: [ntlm.layer], fields: ntlm.fields };
}

/**
 * A security blob as SMB2, HTTP and DCE/RPC carry one: a GSS-API initial
 * token, a bare SPNEGO token, or an NTLMSSP message on its own. Null for
 * anything else.
 */
export function dissectSecurityBlob(b: Uint8Array, start: number, end: number): GssResult | null {
  if (looksLikeNtlmssp(b, start, end)) return ntlmInner(b, start, end);
  const first = b[start];
  if (first !== 0x60 && first !== 0xa0 && first !== 0xa1) return null;
  const outer = tlv(b, start, end);
  if (outer === null) return null;

  const rows: ProtocolField[] = [];
  const gss: ProtocolLayer = { name: GSS_LAYER, summary: GSS_LAYER, rawBytesRange: [start, outer.to - 1], fields: rows };
  let inner: Inner = NOTHING;
  if (first === 0x60) {
    const oid = tlv(b, outer.from, outer.to);
    if (oid === null || oid.tag !== 0x06) return null;
    const dotted = oidText(b, oid.from, oid.to);
    const oidRow: ProtocolField = { name: 'OID', value: oidShown(dotted), abbrev: 'gss-api.OID', rawBytesRange: [oid.from, oid.to - 1] };
    rows.push(oidRow);
    if (dotted === SPNEGO_OID) {
      inner = spnego(b, oid.next, outer.to);
      if (inner.layers[0] !== undefined) rows.push(headingFor(inner.layers[0]));
    } else if (dotted === NTLMSSP_OID && ntlmInner(b, oid.next, outer.to) !== null) {
      inner = ntlmInner(b, oid.next, outer.to)!;
      oidRow.children = [headingFor(inner.layers[0])];
    } else {
      rows.push({ name: 'Token object', value: hexColons(b, outer.from, outer.to), abbrev: 'gss-api.token_object', rawBytesRange: [outer.from, outer.to - 1] });
    }
  } else {
    inner = spnego(b, start, outer.next);
    if (inner.layers[0] !== undefined) rows.push(headingFor(inner.layers[0]));
  }
  return { info: inner.info, layers: [gss, ...inner.layers], fields: inner.fields };
}

/** A SPNEGO token at `from`: negTokenInit (`a0`) or negTokenTarg (`a1`). */
function spnego(b: Uint8Array, from: number, to: number): Inner {
  const token = tlv(b, from, to);
  if (token === null || (token.tag !== 0xa0 && token.tag !== 0xa1)) return NOTHING;
  const sequence = tlv(b, token.from, token.to);
  const elements = sequence !== null && sequence.tag === 0x30 ? children(b, sequence.from, sequence.to) : [];
  const init = token.tag === 0xa0;
  const rows: ProtocolField[] = [];
  const nested: ProtocolLayer[] = [];
  const fields: Record<string, string | number> = {};
  let info = '';
  /** An NTLMSSP message in a token, drawn after the token's row. */
  const mechanism = (t: Tlv) => {
    const ntlm = ntlmInner(b, t.from, t.to);
    if (ntlm === null) return;
    rows.push(headingFor(ntlm.layers[0]));
    nested.push(...ntlm.layers);
    Object.assign(fields, ntlm.fields);
    info += ntlm.info;
  };
  const octets = (element: Tlv): Tlv | null => {
    const t = tlv(b, element.from, element.to);
    return t !== null && t.tag === 0x04 ? t : null;
  };
  const mic = (element: Tlv) => {
    const t = octets(element);
    if (t === null) return;
    rows.push({ name: 'mechListMIC', value: hexColons(b, t.from, t.to), abbrev: 'spnego.mechListMIC', rawBytesRange: [t.from, Math.max(t.from, t.to - 1)] });
    const verifier = ntlmsspVerifier(b, t.from, t.to);
    if (verifier !== null) rows.push(verifier);
  };

  for (const element of elements) {
    const field = element.tag & 0x1f;
    if (init) {
      if (field === 0) {
        const list = tlv(b, element.from, element.to);
        const oids = list !== null && list.tag === 0x30 ? children(b, list.from, list.to).filter((o) => o.tag === 0x06) : [];
        rows.push({
          name: 'mechTypes', value: `${oids.length} item${oids.length === 1 ? '' : 's'}`, abbrev: 'spnego.mechTypes',
          rawBytesRange: [element.from, element.to - 1],
          children: oids.map((o): ProtocolField => ({
            name: 'MechType', value: oidShown(oidText(b, o.from, o.to)), abbrev: 'spnego.MechType', rawBytesRange: [o.from, o.to - 1],
          })),
        });
      } else if (field === 1) {
        const bits = tlv(b, element.from, element.to);
        if (bits !== null && bits.tag === 0x03 && bits.to > bits.from) {
          rows.push({ name: 'reqFlags', value: hexColons(b, bits.from + 1, bits.to), abbrev: 'spnego.reqFlags', rawBytesRange: [bits.from, bits.to - 1] });
        }
      } else if (field === 2) {
        const t = octets(element);
        if (t === null) continue;
        rows.push({ name: 'mechToken', value: hexColons(b, t.from, t.to), abbrev: 'spnego.mechToken', rawBytesRange: [t.from, Math.max(t.from, t.to - 1)] });
        mechanism(t);
      } else if (field === 3) {
        const hints = tlv(b, element.from, element.to);
        if (hints !== null && hints.tag === 0x30) {
          const hintRows: ProtocolField[] = [];
          for (const hint of children(b, hints.from, hints.to)) {
            const value = tlv(b, hint.from, hint.to);
            if (value === null) continue;
            if ((hint.tag & 0x1f) === 0) {
              hintRows.push({ name: 'hintName', value: String.fromCharCode(...b.subarray(value.from, value.to)), abbrev: 'spnego.hintName', rawBytesRange: [value.from, Math.max(value.from, value.to - 1)] });
            } else if ((hint.tag & 0x1f) === 1) {
              hintRows.push({ name: 'hintAddress', value: hexColons(b, value.from, value.to), abbrev: 'spnego.hintAddress', rawBytesRange: [value.from, Math.max(value.from, value.to - 1)] });
            }
          }
          rows.push({ name: 'negHints', value: '', abbrev: 'spnego.negHints_element', rawBytesRange: [element.from, element.to - 1], children: hintRows });
        } else mic(element);
      } else if (field === 4) mic(element);
    } else if (field === 0) {
      const v = tlv(b, element.from, element.to);
      if (v === null || v.tag !== 0x0a || v.to === v.from) continue;
      const result = b[v.to - 1];
      rows.push({ name: 'negResult', value: `${NEG_RESULTS[result] ?? 'Unknown'} (${result})`, abbrev: 'spnego.negResult', rawBytesRange: [v.from, v.to - 1] });
    } else if (field === 1) {
      const v = tlv(b, element.from, element.to);
      if (v === null || v.tag !== 0x06) continue;
      rows.push({ name: 'supportedMech', value: oidShown(oidText(b, v.from, v.to)), abbrev: 'spnego.supportedMech', rawBytesRange: [v.from, v.to - 1] });
    } else if (field === 2) {
      const t = octets(element);
      if (t === null) continue;
      rows.push({ name: 'responseToken', value: hexColons(b, t.from, t.to), abbrev: 'spnego.responseToken', rawBytesRange: [t.from, Math.max(t.from, t.to - 1)] });
      mechanism(t);
    } else if (field === 3) mic(element);
  }

  const layer: ProtocolLayer = {
    name: SPNEGO_LAYER, summary: SPNEGO_LAYER, rawBytesRange: [from, token.to - 1],
    fields: [{
      name: init ? 'negTokenInit' : 'negTokenTarg', value: '',
      abbrev: init ? 'spnego.negTokenInit_element' : 'spnego.negTokenTarg_element',
      rawBytesRange: [token.from, token.to - 1], children: rows,
    }],
  };
  return { info, layers: [layer, ...nested], fields };
}
