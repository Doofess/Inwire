/**
 * Just enough X.509 to say who a certificate is for, who issued it, and
 * whether it is in date. A TLS 1.2 Certificate message carries the chain in
 * the clear (TLS 1.3 encrypts it), and the four facts a person actually reads
 * off a certificate - subject, issuer, validity, alternative names - are all
 * near the top of a DER structure whose shape has not changed since 1988.
 *
 * This is a DER walker, not an ASN.1 library: it follows the fixed nesting
 * of a v3 certificate (RFC 5280 §4.1) and reads the handful of fields it
 * wants, returning nulls rather than throwing when a certificate is
 * truncated or built from an extension it does not know.
 */

export interface CertificateSummary {
  subjectCN: string | null;
  subject: string;
  issuerCN: string | null;
  issuer: string;
  notBefore: Date | null;
  notAfter: Date | null;
  /** dNSName entries of subjectAltName. */
  dnsNames: string[];
  /** The public-key algorithm OID's friendly name, e.g. rsaEncryption, id-ecPublicKey. */
  keyType: string | null;
  serialHex: string | null;
  selfSigned: boolean;
}

interface Tlv {
  tag: number;
  start: number;   // first byte of the content
  end: number;     // one past the content
  next: number;    // one past the whole TLV
}

function readTlv(b: Uint8Array, offset: number, end: number): Tlv | null {
  if (offset + 2 > end) return null;
  const tag = b[offset];
  let p = offset + 1;
  let len = b[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > end) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[p++];
  }
  if (p + len > end) return null;
  return { tag, start: p, end: p + len, next: p + len };
}

/** Children of a constructed TLV, in order. */
function children(b: Uint8Array, tlv: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = tlv.start;
  while (p < tlv.end) {
    const c = readTlv(b, p, tlv.end);
    if (!c) break;
    out.push(c);
    p = c.next;
  }
  return out;
}

const OID_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress',
  '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448', '1.2.840.113549.1.1.10': 'rsassaPss',
  '2.5.29.17': 'subjectAltName',
};

function decodeOid(b: Uint8Array, tlv: Tlv): string {
  const parts: number[] = [];
  let value = 0;
  for (let p = tlv.start; p < tlv.end; p++) {
    value = value * 128 + (b[p] & 0x7f);
    if ((b[p] & 0x80) === 0) {
      if (parts.length === 0) { parts.push(Math.floor(value / 40), value % 40); }
      else parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

const utf8 = new TextDecoder();
function decodeString(b: Uint8Array, tlv: Tlv): string {
  // PrintableString, UTF8String, IA5String, T61 all decode acceptably as UTF-8
  // for the names that occur in practice; BMPString (0x1e) is UTF-16BE.
  if (tlv.tag === 0x1e) {
    let s = '';
    for (let p = tlv.start; p + 1 < tlv.end; p += 2) s += String.fromCharCode((b[p] << 8) | b[p + 1]);
    return s;
  }
  return utf8.decode(b.subarray(tlv.start, tlv.end));
}

/** "CN=example.com, O=Example, C=US" and the CN alone. */
function decodeName(b: Uint8Array, name: Tlv): { text: string; cn: string | null } {
  const parts: string[] = [];
  let cn: string | null = null;
  for (const rdn of children(b, name)) {          // SET
    for (const atv of children(b, rdn)) {         // SEQUENCE { oid, value }
      const [oid, value] = children(b, atv);
      if (!oid || !value) continue;
      const key = OID_NAMES[decodeOid(b, oid)] ?? decodeOid(b, oid);
      const text = decodeString(b, value);
      parts.push(`${key}=${text}`);
      if (key === 'CN' && cn === null) cn = text;
    }
  }
  return { text: parts.join(', '), cn };
}

function decodeTime(b: Uint8Array, tlv: Tlv): Date | null {
  const s = utf8.decode(b.subarray(tlv.start, tlv.end));
  // UTCTime YYMMDDHHMMSSZ (0x17) or GeneralizedTime YYYYMMDDHHMMSSZ (0x18).
  const m = tlv.tag === 0x17
    ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/)
    : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/);
  if (!m) return null;
  let year = Number(m[1]);
  if (tlv.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)));
}

/**
 * Summarises one DER certificate. Returns null when the bytes do not start a
 * certificate at all; partial results when they start one and run out.
 */
export function summarizeCertificate(b: Uint8Array): CertificateSummary | null {
  const cert = readTlv(b, 0, b.length);
  if (!cert || cert.tag !== 0x30) return null;
  const [tbs] = children(b, cert);
  if (!tbs || tbs.tag !== 0x30) return null;

  const fields = children(b, tbs);
  let i = 0;
  // Optional explicit [0] version.
  if (fields[i] && fields[i].tag === 0xa0) i++;
  const serial = fields[i++];
  i++; // signature algorithm
  const issuer = fields[i++];
  const validity = fields[i++];
  const subject = fields[i++];
  const spki = fields[i++];

  const out: CertificateSummary = {
    subjectCN: null, subject: '', issuerCN: null, issuer: '',
    notBefore: null, notAfter: null, dnsNames: [], keyType: null, serialHex: null, selfSigned: false,
  };
  if (serial && serial.tag === 0x02) {
    out.serialHex = Array.from(b.subarray(serial.start, serial.end)).map((x) => x.toString(16).padStart(2, '0')).join(':');
  }
  if (issuer && issuer.tag === 0x30) { const n = decodeName(b, issuer); out.issuer = n.text; out.issuerCN = n.cn; }
  if (validity && validity.tag === 0x30) {
    const [nb, na] = children(b, validity);
    if (nb) out.notBefore = decodeTime(b, nb);
    if (na) out.notAfter = decodeTime(b, na);
  }
  if (subject && subject.tag === 0x30) { const n = decodeName(b, subject); out.subject = n.text; out.subjectCN = n.cn; }
  if (spki && spki.tag === 0x30) {
    const [alg] = children(b, spki);
    const [oid] = alg ? children(b, alg) : [];
    if (oid && oid.tag === 0x06) { const o = decodeOid(b, oid); out.keyType = OID_NAMES[o] ?? o; }
  }
  // Extensions live in explicit [3] after the optional issuer/subject unique ids.
  for (; i < fields.length; i++) {
    if (fields[i].tag !== 0xa3) continue;
    const [extList] = children(b, fields[i]);
    if (!extList) break;
    for (const ext of children(b, extList)) {
      const parts = children(b, ext);
      const oid = parts[0];
      const value = parts[parts.length - 1];
      if (!oid || !value || decodeOid(b, oid) !== '2.5.29.17') continue;
      const san = readTlv(b, value.start, value.end); // OCTET STRING wraps a SEQUENCE
      if (!san) continue;
      for (const gn of children(b, san)) {
        if (gn.tag === 0x82) out.dnsNames.push(utf8.decode(b.subarray(gn.start, gn.end))); // [2] dNSName
      }
    }
  }
  out.selfSigned = out.subject !== '' && out.subject === out.issuer;
  return out;
}
