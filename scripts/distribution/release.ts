/**
 * The release descriptor, and the policy that decides whether to believe it.
 *
 * `release.json` names an installer that a signed PowerShell bootstrap
 * downloads and runs elevated, so it is the same kind of input as the update
 * feed (`electron/updateCenter/manifest.ts`) and is read the same way:
 * strictly, and rejected whole. A defaulted field here could mean "download
 * this URL with no hash", so a missing field invalidates the row and a bad row
 * invalidates the document.
 *
 * ## Why the policy is a separate file
 *
 * The descriptor says where to download from and which hash to expect, so
 * whoever controls it chooses both. What the descriptor cannot choose is
 * `distribution/release-policy.json`: the host allowlist, and the publisher
 * certificate pins the bootstrap checks the installer's signature against.
 * That file travels inside the signed bootstrap, not beside the descriptor.
 *
 * ## Pure on purpose
 *
 * No `node:*` import (`scripts/capture/node-safe.ts` style): this is exactly
 * the logic the PowerShell validator reimplements, and
 * `distribution/fixtures/release-vectors.json` is the shared answer key. Every
 * rule below must stay expressible from a vector alone.
 */
import { MAX_DOWNLOAD_BYTES } from '../../electron/updateCenter/manifest';

export type Product = 'Desktop' | 'EndpointAgent';

export type ReleaseArtifact = {
  product: Product;
  version: string;
  architecture: 'x64';
  url: string;
  sizeBytes: number;
  sha256: string;
};

export type ReleaseDescriptor = { schema: 1; artifacts: ReleaseArtifact[] };

export type ReleasePolicy = {
  descriptorUrl: string;
  allowedHosts: string[];
  publisherCertificateSha256: string[];
  desktopPackageId: string;
  endpointAvailable: boolean;
};

const PRODUCTS: readonly Product[] = ['Desktop', 'EndpointAgent'];

/**
 * Three numeric parts, no leading zeros, at most five digits each. Exactly the
 * shape the bootstrap compares with `-eq`; there is no ordering of versions
 * anywhere in this contract, because a lexicographic comparison puts 1.10.0
 * before 1.9.0 and nobody should be tempted to write one.
 */
const VERSION = /^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/;

const SHA256_ANY_CASE = /^[0-9a-f]{64}$/i;
const SHA256_LOWER = /^[0-9a-f]{64}$/;

/** Lowercase DNS name with at least two labels. No port, path, wildcard or IP-literal brackets. */
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** WinGet's `Publisher.Package` shape. Empty means "not published to WinGet". */
const PACKAGE_ID = /^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9.-]*$/;

export function isReleaseVersion(value: unknown): value is string {
  return typeof value === 'string' && VERSION.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Unknown keys are rejected, not ignored. The manifest tolerates unknown
 * component ids so the feed can evolve; here the consumer is a signed script
 * that ships with its own copy of this schema, so a key it has never heard of
 * means the descriptor was written for something else and must not be half-read.
 */
function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(value, k));
}

/**
 * Whether a download URL is acceptable under a host allowlist.
 *
 * https only (http lets a network attacker rewrite the URL before the hash is
 * read). No credentials, no explicit port, no fragment: each is a way to make a
 * URL that looks like the pinned host to a reader and resolves elsewhere or
 * carries data the server never sees. The host is compared exactly after
 * lowercasing, never by suffix: `endsWith('x.test')` also accepts
 * `evil-x.test`, and `startsWith` accepts `x.test.evil.com`.
 */
function isAllowedUrl(value: unknown, allowedHosts: readonly string[]): boolean {
  if (typeof value !== 'string') return false;
  // The raw text first. WHATWG parsing forgives what .NET's `[Uri]` refuses -
  // surrounding whitespace, a missing or extra `//`, an empty `@`, backslashes,
  // a percent-encoded or fullwidth host - so a URL the generator wrote would
  // fail every bootstrap. Printable ASCII, no backslash, and the authority as
  // written must already be the allowed host.
  if (!/^[\x21-\x5b\x5d-\x7e]+$/.test(value)) return false;
  const authority = /^https:\/\/([^/?#@:]+)(?:[/?#]|$)/i.exec(value);
  if (!authority || !allowedHosts.includes(authority[1].toLowerCase())) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  if (url.username !== '' || url.password !== '') return false;
  if (url.port !== '') return false;
  // `new URL` drops a written-out default port (`:443` reads back as ''), and
  // .NET's `[Uri]`, which the bootstrap uses, reports 443 for the same text.
  // Any colon in the raw authority is refused instead, so the two validators
  // answer the same question from the same characters.
  if (/^https:\/\/[^/?#]*:/i.test(value)) return false;
  if (url.hash !== '') return false;
  return allowedHosts.includes(url.hostname.toLowerCase());
}

/**
 * Parses the policy. `null` means "no usable policy", and a caller must treat
 * it as a stop: there is nothing safe to default a pin or a host to.
 */
export function readPolicy(value: unknown): ReleasePolicy | null {
  if (!isRecord(value)) return null;
  if (!hasExactKeys(value, [
    'schema', 'descriptorUrl', 'allowedHosts', 'publisherCertificateSha256',
    'desktopPackageId', 'endpointAvailable',
  ])) return null;
  if (value.schema !== 1) return null;

  const { allowedHosts, publisherCertificateSha256, descriptorUrl, desktopPackageId, endpointAvailable } = value;

  if (!Array.isArray(allowedHosts) || allowedHosts.length === 0) return null;
  // Lowercase only, so the exact-match comparison above has one spelling to match.
  if (!allowedHosts.every((h) => typeof h === 'string' && HOSTNAME.test(h))) return null;

  // May be empty: that is the honest state before a certificate exists, and
  // `publicBlockers` is what stops a public release in it.
  if (!Array.isArray(publisherCertificateSha256)) return null;
  if (!publisherCertificateSha256.every((p) => typeof p === 'string' && SHA256_LOWER.test(p))) return null;
  if (new Set(publisherCertificateSha256).size !== publisherCertificateSha256.length) return null;

  // The descriptor is fetched from the policy's own hosts, or the allowlist is decorative.
  if (!isAllowedUrl(descriptorUrl, allowedHosts as string[])) return null;

  if (typeof desktopPackageId !== 'string') return null;
  if (desktopPackageId !== '' && !PACKAGE_ID.test(desktopPackageId)) return null;

  if (typeof endpointAvailable !== 'boolean') return null;

  return {
    descriptorUrl: descriptorUrl as string,
    allowedHosts: [...(allowedHosts as string[])],
    publisherCertificateSha256: [...(publisherCertificateSha256 as string[])],
    desktopPackageId,
    endpointAvailable,
  };
}

function readArtifact(raw: unknown, policy: ReleasePolicy): ReleaseArtifact | null {
  if (!isRecord(raw)) return null;
  if (!hasExactKeys(raw, ['product', 'version', 'architecture', 'url', 'sizeBytes', 'sha256'])) return null;

  const { product, version, architecture, url, sizeBytes, sha256 } = raw;

  if (typeof product !== 'string' || !PRODUCTS.includes(product as Product)) return null;
  if (!isReleaseVersion(version)) return null;
  if (architecture !== 'x64') return null;
  if (!isAllowedUrl(url, policy.allowedHosts)) return null;
  if (typeof sha256 !== 'string' || !SHA256_ANY_CASE.test(sha256)) return null;
  if (typeof sizeBytes !== 'number' || !Number.isInteger(sizeBytes)
    || sizeBytes <= 0 || sizeBytes > MAX_DOWNLOAD_BYTES) return null;

  return {
    product: product as Product,
    version,
    architecture: 'x64',
    url: url as string,
    sizeBytes,
    // One spelling downstream, so a comparison never depends on who wrote the file.
    sha256: sha256.toLowerCase(),
  };
}

/**
 * Parses and validates the descriptor against a policy. `null` is "no answer"
 * and a caller stops: it does not fall back to an older descriptor or a
 * default row.
 *
 * One row per product, and a Desktop row is required. Two rows for a product
 * would make "which one is installed" depend on array order, and an endpoint
 * row while the policy says that product does not exist yet is a descriptor
 * from the future (or from someone pretending to be).
 */
export function readRelease(value: unknown, policy: ReleasePolicy): ReleaseDescriptor | null {
  if (!isRecord(value)) return null;
  if (!hasExactKeys(value, ['schema', 'artifacts'])) return null;
  if (value.schema !== 1) return null;
  if (!Array.isArray(value.artifacts) || value.artifacts.length === 0) return null;

  const artifacts: ReleaseArtifact[] = [];
  for (const raw of value.artifacts) {
    const row = readArtifact(raw, policy);
    if (row === null) return null;
    if (artifacts.some((a) => a.product === row.product)) return null;
    if (row.product === 'EndpointAgent' && !policy.endpointAvailable) return null;
    artifacts.push(row);
  }
  if (!artifacts.some((a) => a.product === 'Desktop')) return null;

  return { schema: 1, artifacts };
}

/**
 * The product's row, when no version was asked for or when it is exactly the
 * one asked for. A version is compared as a string for equality only: the
 * descriptor offers one build, and a request for any other is a "not offered",
 * never "close enough".
 */
export function chooseArtifact(
  release: ReleaseDescriptor,
  product: Product,
  version: string | null,
): ReleaseArtifact | null {
  const row = release.artifacts.find((a) => a.product === product);
  if (row === undefined) return null;
  if (version === null || row.version === version) return row;
  return null;
}

/**
 * What stands between this policy and a public release, as sentences for a
 * human. Empty means the bootstrap and the public descriptor are releasable.
 * WinGet has its own blockers, reported elsewhere.
 */
export function publicBlockers(policy: ReleasePolicy): string[] {
  const blockers: string[] = [];
  if (policy.publisherCertificateSha256.length === 0) {
    blockers.push('no publisher signing certificate is pinned (publisherCertificateSha256 is empty), so the bootstrap cannot verify who signed the installer');
  }
  return blockers;
}

/**
 * What stands between this policy and WinGet manifests: everything a public
 * release needs (the manifest names an installer the same way the descriptor
 * does, and a package without the publisher pin would be one nobody can check),
 * plus the package ID, which is empty until the owner has one to submit under.
 */
export function wingetBlockers(policy: ReleasePolicy): string[] {
  const blockers = publicBlockers(policy);
  if (policy.desktopPackageId === '') {
    blockers.push('there is no WinGet package ID (desktopPackageId is empty), so no manifest can name a package');
  }
  return blockers;
}
