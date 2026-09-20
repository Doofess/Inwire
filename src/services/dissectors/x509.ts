/**
 * X.509, as far as the questions a person opens a certificate to answer.
 *
 * A TLS 1.2 Certificate message carries the chain in the clear (TLS 1.3
 * encrypts it), and a v3 certificate's shape has not changed since 1988 - so
 * this is a DER walker rather than an ASN.1 library: it follows the fixed
 * nesting of RFC 5280 §4.1 and returns nulls rather than throwing when a
 * certificate is truncated or built from an extension it does not know.
 *
 * ## What it read before, and why that was the wrong stopping point
 *
 * Subject, issuer, validity, dNSNames, key algorithm, serial. Every one of
 * those answers "who is this for" and none of them answers **"what is it
 * allowed to do"** - which is the half a certificate exists to state and the
 * half an analyst is usually looking for. The signature algorithm was skipped
 * outright (`i++`), the public key itself was never read so there was no key
 * SIZE, and subjectAltName was filtered to `[2] dNSName`, so an IP-address SAN
 * - the ordinary case on an internal service - read as a certificate with no
 * names at all.
 *
 * Basic constraints, key usage, extended key usage, authority information
 * access and CRL distribution points are all read now, under the reference's
 * own field names. That last point is what made it worth doing properly: they
 * are `x509ce.cA`, `x509ce.KeyUsage`, `x509ce.KeyPurposeId` and
 * `pkix1implicit.accessMethod` there, so the filters are portable rather than
 * ours - see `dissect/fieldRegistry.ts`, where the three layer tokens are
 * added for the same reason.
 *
 * **Nothing here validates anything.** Not the signature, not the chain, not
 * the name against the SNI beyond the string comparison `tls.ts` already did.
 * Reading what a certificate SAYS and deciding whether to believe it are
 * different jobs, and only the first is a dissector's.
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
  /** rfc822Name entries - a certificate issued to a mailbox rather than a host. */
  emailNames: string[];
  /** uniformResourceIdentifier entries. */
  uriNames: string[];
  /**
   * iPAddress entries, formatted.
   *
   * A SAN of 4 bytes is IPv4 and one of 16 is IPv6, which is the whole of
   * RFC 5280's rule for the field and is why no version byte is needed. These
   * were dropped entirely before, so an internal service whose certificate
   * names only its address read as a certificate with no names at all.
   */
  ipNames: string[];
  /** The public-key algorithm OID's friendly name, e.g. rsaEncryption, id-ecPublicKey. */
  keyType: string | null;
  /**
   * The key's size in bits, which is the number anybody actually judges a
   * certificate's strength by - and the one fact that needed the SPKI BIT
   * STRING to be opened rather than its algorithm read off the front.
   */
  keyBits: number | null;
  /** The OID the certificate was signed WITH, which was skipped outright. */
  signatureAlgorithm: string | null;
  /** `2` for a v3 certificate: the encoded value, as the reference reports it. */
  version: number | null;
  serialHex: string | null;
  selfSigned: boolean;
  /** basicConstraints: null when the extension is absent, which is not `false`. */
  isCa: boolean | null;
  /** basicConstraints pathLenConstraint, when present. */
  pathLen: number | null;
  /** keyUsage, as the reference's raw bit-string byte and as readable names. */
  keyUsageHex: string | null;
  keyUsage: string[];
  /** extendedKeyUsage OIDs, named where known. */
  extKeyUsage: string[];
  /** authorityInfoAccess: the access method and where it points. */
  accessDescriptions: { method: string; location: string }[];
  /** cRLDistributionPoints, flattened to the URIs that are all anybody uses. */
  crlDistributionPoints: string[];
  /** Every extension's id and criticality, in order, named where known. */
  extensions: { id: string; name: string; critical: boolean }[];
}

interface Tlv {
  tag: number;
  start: number;   // first byte of the content
  end: number;     // one past the content
  next: number;    // one past the whole TLV
}

/**
 * Reads one TLV. A second implementation of `dissectors/ber.ts`'s `readBer`,
 * and deliberately not replaced by it.
 *
 * `ber.ts` is the general reader - SNMP, LDAP and Kerberos all drive it - and
 * it is the stricter of the two: it rejects the high-tag-number form, and
 * `berChildren` caps a constructed value at **128 children**. That cap is
 * right for a PDU and wrong here, because a shared-hosting certificate's
 * subjectAltName routinely carries more than 128 dNSNames, and truncating that
 * list silently is exactly the kind of wrong answer this file's header refuses.
 *
 * So the duplication is kept, and the pieces that must not diverge are the
 * OID arithmetic in `decodeOid` below and the length handling here. Anything
 * learnt about BER belongs in both.
 */
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
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
};

/**
 * The certificate extensions worth naming, by OID.
 *
 * Every certificate carries a handful of these and a reader who has to look
 * up `2.5.29.15` to find out it is the key usage is a reader the tree has not
 * helped. An extension with no entry is shown by its OID, which is honest and
 * still filterable.
 */
const EXTENSION_NAMES: Record<string, string> = {
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.31': 'cRLDistributionPoints',
  '2.5.29.32': 'certificatePolicies',
  '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.37': 'extKeyUsage',
  '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
  '1.3.6.1.4.1.11129.2.4.2': 'signedCertificateTimestampList',
};

/**
 * RFC 5280 §4.2.1.3's key usage bits, in the order they are numbered.
 *
 * Bit 0 is the MOST significant bit of the first content byte, which is the
 * one thing about a DER BIT STRING that catches everybody: `0xa0` with five
 * unused trailing bits is bits 0 and 2, so digitalSignature and
 * keyEncipherment - not "bits 5 and 7".
 */
const KEY_USAGE_BITS = [
  'digitalSignature', 'contentCommitment', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

/** The extended key usages that occur on a certificate anybody will capture. */
const KEY_PURPOSE_NAMES: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  '2.5.29.37.0': 'anyExtendedKeyUsage',
};

/** authorityInfoAccess methods (RFC 5280 §4.2.2.1). */
const ACCESS_METHOD_NAMES: Record<string, string> = {
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'caIssuers',
};

/**
 * An object identifier, in dotted form.
 *
 * The first group is two arcs, `40 * x + y`, and **x is capped at 2 rather
 * than divided out**: an OID under `2.x` may have a second arc above 39, and
 * the division carries the excess into the wrong place - `2.100.3` encodes its
 * first group as 180 and decodes to `4.20.3` uncapped. `dissectors/ber.ts`'s
 * `berOid` is the same rule, and this is a deliberate second copy: see the note
 * on `readTlv` above for why this file does not import it.
 */
function decodeOid(b: Uint8Array, tlv: Tlv): string {
  const groups: number[] = [];
  let value = 0;
  for (let p = tlv.start; p < tlv.end; p++) {
    value = value * 128 + (b[p] & 0x7f);
    if ((b[p] & 0x80) === 0) {
      groups.push(value);
      value = 0;
    }
  }
  if (groups.length === 0) return '';
  const x = Math.min(2, Math.floor(groups[0] / 40));
  return [x, groups[0] - x * 40, ...groups.slice(1)].join('.');
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

/**
 * A `GeneralName`, which is a CHOICE and therefore identified by its context
 * tag rather than by position (RFC 5280 §4.2.1.6).
 *
 * `[2] dNSName` was the only one read before. `[1] rfc822Name` and
 * `[6] uniformResourceIdentifier` are IA5Strings like it; `[7] iPAddress` is
 * raw octets, four of them or sixteen, and is why an internal service's
 * certificate used to read as having no names at all.
 */
function decodeGeneralName(b: Uint8Array, gn: Tlv): { kind: string; value: string } | null {
  if (gn.tag === 0x82) return { kind: 'dns', value: utf8.decode(b.subarray(gn.start, gn.end)) };
  if (gn.tag === 0x81) return { kind: 'email', value: utf8.decode(b.subarray(gn.start, gn.end)) };
  if (gn.tag === 0x86) return { kind: 'uri', value: utf8.decode(b.subarray(gn.start, gn.end)) };
  if (gn.tag === 0x87) {
    const n = gn.end - gn.start;
    if (n === 4) return { kind: 'ip', value: Array.from(b.subarray(gn.start, gn.end)).join('.') };
    if (n === 16) {
      const groups: string[] = [];
      for (let p = gn.start; p < gn.end; p += 2) groups.push((((b[p] << 8) | b[p + 1]) >>> 0).toString(16));
      // Left in full form: `addressFormat.ts`'s RFC 5952 collapser is the
      // renderer's, and this module deliberately imports nothing.
      return { kind: 'ip', value: groups.join(':') };
    }
  }
  return null;
}

/** An INTEGER's value, for the small ones (version, path length). */
function smallInt(b: Uint8Array, tlv: Tlv): number | null {
  if (tlv.end - tlv.start === 0 || tlv.end - tlv.start > 4) return null;
  let v = 0;
  for (let p = tlv.start; p < tlv.end; p++) v = (v << 8) | b[p];
  return v;
}

/**
 * How many bits a public key is, from the SPKI.
 *
 * For RSA the BIT STRING wraps `SEQUENCE { modulus INTEGER, exponent INTEGER }`
 * and the answer is the modulus's bit length with DER's leading zero removed -
 * a 2048-bit modulus encodes as 257 bytes, and reporting 2056 would be wrong
 * in the direction that flatters the certificate. For an EC key the BIT STRING
 * is the point itself, uncompressed: one prefix byte and two coordinates, so
 * the field size is `(length - 1) / 2` bytes.
 */
function publicKeyBits(b: Uint8Array, spki: Tlv, keyOid: string): number | null {
  const parts = children(b, spki);
  const bits = parts[1];
  if (!bits || bits.tag !== 0x03 || bits.end - bits.start < 2) return null;
  // The first content byte of a BIT STRING counts its unused trailing bits.
  const start = bits.start + 1;
  if (keyOid === '1.2.840.113549.1.1.1') {
    const rsa = readTlv(b, start, bits.end);
    if (!rsa || rsa.tag !== 0x30) return null;
    const [modulus] = children(b, rsa);
    if (!modulus || modulus.tag !== 0x02) return null;
    let p = modulus.start;
    while (p < modulus.end && b[p] === 0) p++;      // DER's sign padding
    if (p >= modulus.end) return null;
    let leading = 8;
    for (let bit = 7; bit >= 0; bit--) { if (b[p] & (1 << bit)) break; leading--; }
    return (modulus.end - p - 1) * 8 + leading;
  }
  if (keyOid === '1.2.840.10045.2.1') {
    const n = bits.end - start;
    return n > 1 ? ((n - 1) / 2) * 8 : null;
  }
  return null;
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

  const out: CertificateSummary = {
    subjectCN: null, subject: '', issuerCN: null, issuer: '',
    notBefore: null, notAfter: null,
    dnsNames: [], emailNames: [], uriNames: [], ipNames: [],
    keyType: null, keyBits: null, signatureAlgorithm: null, version: null,
    serialHex: null, selfSigned: false,
    isCa: null, pathLen: null, keyUsageHex: null, keyUsage: [], extKeyUsage: [],
    accessDescriptions: [], crlDistributionPoints: [], extensions: [],
  };

  // **The optional explicit [0] version, which was skipped rather than read.**
  // Its absence means v1, and a v1 certificate on the wire in 2026 is itself
  // the finding - so "absent" has to be distinguishable from "not looked at",
  // which is why this is `0` rather than null when the tag is missing.
  if (fields[i] && fields[i].tag === 0xa0) {
    const [v] = children(b, fields[i]);
    out.version = v ? smallInt(b, v) : null;
    i++;
  } else {
    out.version = 0;
  }
  const serial = fields[i++];
  const signature = fields[i++];
  const issuer = fields[i++];
  const validity = fields[i++];
  const subject = fields[i++];
  const spki = fields[i++];

  if (serial && serial.tag === 0x02) {
    out.serialHex = Array.from(b.subarray(serial.start, serial.end)).map((x) => x.toString(16).padStart(2, '0')).join(':');
  }
  // `i++ // signature algorithm` is what this used to be. It is the one field
  // that says how the certificate was signed, which is the whole of what a
  // deprecation - sha1WithRSAEncryption - looks like from the outside.
  if (signature && signature.tag === 0x30) {
    const [oid] = children(b, signature);
    if (oid && oid.tag === 0x06) { const o = decodeOid(b, oid); out.signatureAlgorithm = OID_NAMES[o] ?? o; }
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
    if (oid && oid.tag === 0x06) {
      const o = decodeOid(b, oid);
      out.keyType = OID_NAMES[o] ?? o;
      out.keyBits = publicKeyBits(b, spki, o);
    }
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
      if (!oid || !value) continue;
      const id = decodeOid(b, oid);
      // The `critical` BOOLEAN is optional and DEFAULT FALSE, so DER omits it
      // when false - which means three parts rather than two, and the middle
      // one is it.
      const critical = parts.length >= 3 && parts[1].tag === 0x01 && b[parts[1].start] !== 0;
      out.extensions.push({ id, name: EXTENSION_NAMES[id] ?? id, critical });
      // Every extension's value is DER inside an OCTET STRING.
      const inner = readTlv(b, value.start, value.end);
      if (!inner) continue;

      if (id === '2.5.29.17') {
        for (const gn of children(b, inner)) {
          const name = decodeGeneralName(b, gn);
          if (!name) continue;
          if (name.kind === 'dns') out.dnsNames.push(name.value);
          else if (name.kind === 'email') out.emailNames.push(name.value);
          else if (name.kind === 'uri') out.uriNames.push(name.value);
          else out.ipNames.push(name.value);
        }
      } else if (id === '2.5.29.19') {
        // basicConstraints. Both members are optional and cA DEFAULTs to
        // FALSE, so an empty SEQUENCE is a perfectly ordinary end-entity
        // certificate saying so - which is why this sets `false` rather than
        // leaving the null that means "no such extension".
        out.isCa = false;
        for (const member of children(b, inner)) {
          if (member.tag === 0x01) out.isCa = b[member.start] !== 0;
          else if (member.tag === 0x02) out.pathLen = smallInt(b, member);
        }
      } else if (id === '2.5.29.15' && inner.tag === 0x03 && inner.end - inner.start >= 2) {
        const unused = b[inner.start];
        const bytes = b.subarray(inner.start + 1, inner.end);
        out.keyUsageHex = Array.from(bytes).map((x) => x.toString(16).padStart(2, '0')).join('');
        const total = bytes.length * 8 - unused;
        for (let bit = 0; bit < Math.min(total, KEY_USAGE_BITS.length); bit++) {
          if (bytes[bit >> 3] & (0x80 >> (bit & 7))) out.keyUsage.push(KEY_USAGE_BITS[bit]);
        }
      } else if (id === '2.5.29.37') {
        for (const purpose of children(b, inner)) {
          if (purpose.tag !== 0x06) continue;
          const o = decodeOid(b, purpose);
          out.extKeyUsage.push(KEY_PURPOSE_NAMES[o] ?? o);
        }
      } else if (id === '1.3.6.1.5.5.7.1.1') {
        for (const description of children(b, inner)) {
          const [method, location] = children(b, description);
          if (!method || method.tag !== 0x06 || !location) continue;
          const o = decodeOid(b, method);
          const where = decodeGeneralName(b, location);
          out.accessDescriptions.push({
            method: ACCESS_METHOD_NAMES[o] ?? o,
            location: where ? where.value : '',
          });
        }
      } else if (id === '2.5.29.31') {
        // A DistributionPoint nests [0] distributionPoint -> [0] fullName ->
        // GeneralNames, and in practice every one of them is a single URI. The
        // walk is written as a search for GeneralNames at any depth rather
        // than as the full CHOICE, because the alternative forms - a relative
        // name, a cRLIssuer - carry nothing a reader would act on.
        const visit = (tlv: Tlv, depth: number): void => {
          if (depth > 4) return;
          for (const child of children(b, tlv)) {
            const name = decodeGeneralName(b, child);
            if (name && name.kind === 'uri') out.crlDistributionPoints.push(name.value);
            else if ((child.tag & 0x20) !== 0) visit(child, depth + 1);
          }
        };
        visit(inner, 0);
      }
    }
  }
  out.selfSigned = out.subject !== '' && out.subject === out.issuer;
  return out;
}
