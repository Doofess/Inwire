/**
 * The update feed: one JSON document, and the rules for not trusting it.
 *
 * This is the only remote input in the application that can nominate an
 * executable to be **run elevated**, which sets the bar for how it is read. It
 * is validated strictly and rejected whole, and every field a decision depends
 * on - the URL, the hash, the size - must be present and well-formed or the
 * document is treated exactly as if the network were down.
 *
 * ## Reject, do not default
 *
 * That is the opposite of how preferences are read. `interfacePrefs.ts` says
 * every validator "defaults FIELD BY FIELD and clamps rather than rejecting …
 * one bad field must never discard its siblings", and it is right, because a
 * bad preference costs a wrong colour. Here a defaulted field could mean
 * "download this URL with no hash", so a missing `sha256` invalidates the row
 * and a bad row invalidates the document.
 *
 * ## Why the download host is checked and not just the feed host
 *
 * The feed says where to download from, so whoever controls the feed chooses
 * the executable. Pinning the hash does not help: the attacker writes the hash
 * too. The allowlist below is what stops a compromised or spoofed feed from
 * nominating an arbitrary binary - Npcap comes from npcap.com and everything
 * of ours comes from the same host the feed itself was served from.
 *
 * ## Why hand-rolled and not a schema library
 *
 * `zod` is not a dependency, and CLAUDE.md's dependency rule is that a shipped
 * dependency must beat the platform API that replaces it. The document is a
 * fixed shape of six fields; this is the same `isValid*` idiom
 * `services/agentProtocol.ts` already uses on the other untrusted input.
 */
import type { Available, ComponentId, ComponentKind } from './components';
import { isVersion } from './components';

/**
 * Where the feed lives.
 *
 * The domain does not resolve yet, and until it does every check is a quiet
 * no-op - which is a state the pipeline already handles as its ordinary case
 * rather than as an error, so pointing at the real name costs nothing and is
 * one fewer thing to remember on the day it exists.
 *
 * It replaced an RFC 2606 `.invalid` placeholder. The reason to move off that
 * is not tidiness: a name that CANNOT resolve and a name that DOES NOT YET
 * resolve exercise the same path, but only the second one ever starts
 * working, and a build shipped with the first would fail silently and for
 * ever with nothing to notice.
 */
export const DEFAULT_UPDATE_FEED_URL = 'https://updates.inwire.app/manifest.json';

/** The dev override. One variable, read once, never baked into a build. */
export const UPDATE_FEED_ENV = 'INWIRE_UPDATE_FEED';

/**
 * Hosts each component may be downloaded from. `null` means "the host the feed
 * itself came from", which is how our own artifacts are pinned without naming
 * a domain that does not exist yet.
 *
 * Npcap is fetched from npcap.com and nowhere else. We do not mirror it: the
 * free licence forbids redistribution, and a copy we host is a copy we would
 * have to keep honest.
 */
export const DOWNLOAD_HOSTS: Record<ComponentId, readonly string[] | null> = {
  inwire: null,
  agent: null,
  npcap: ['npcap.com', 'www.npcap.com'],
  oui: null,
  geoip: null,
};

const KINDS: readonly ComponentKind[] = ['inwire-installer', 'vendor-installer', 'database'];
const IDS: readonly ComponentId[] = ['inwire', 'agent', 'npcap', 'oui', 'geoip'];

/** 512 MB. Larger than any installer we ship and far larger than any we do not. */
export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;

export interface Manifest {
  schema: number;
  generated: string;
  components: Partial<Record<ComponentId, Available>>;
}

export function resolveFeedUrl(env: Record<string, string | undefined>): string {
  const override = env[UPDATE_FEED_ENV];
  return override !== undefined && override.trim() !== '' ? override.trim() : DEFAULT_UPDATE_FEED_URL;
}

export function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function hostOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    // http would let a network attacker rewrite the URL before the hash is
    // ever read. There is no reason to allow it and one reason not to.
    if (parsed.protocol !== 'https:') return null;
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Whether this component may be downloaded from this URL.
 *
 * Exact host match, never a suffix test: `endsWith('npcap.com')` also accepts
 * `evilnpcap.com`, which is the classic form of this bug.
 */
export function isAllowedDownload(id: ComponentId, url: string, feedUrl: string): boolean {
  const host = hostOf(url);
  if (host === null) return false;
  const allowed = DOWNLOAD_HOSTS[id];
  if (allowed === null) {
    const feedHost = hostOf(feedUrl);
    return feedHost !== null && host === feedHost;
  }
  return allowed.includes(host);
}

function readRow(id: ComponentId, raw: unknown, feedUrl: string): Available | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;

  const { version, url, sha256, size, kind, minAppVersion } = row;

  if (typeof version !== 'string' || !isVersion(version)) return null;
  if (typeof minAppVersion !== 'string' || !isVersion(minAppVersion)) return null;
  if (typeof url !== 'string' || !isAllowedDownload(id, url, feedUrl)) return null;
  if (!isSha256Hex(sha256)) return null;
  if (typeof kind !== 'string' || !KINDS.includes(kind as ComponentKind)) return null;
  if (typeof size !== 'number' || !Number.isInteger(size) || size <= 0 || size > MAX_DOWNLOAD_BYTES) {
    return null;
  }

  return {
    version, url, sha256: sha256.toLowerCase(), size,
    kind: kind as ComponentKind, minAppVersion,
  };
}

/**
 * Parses and validates the feed. `null` means "no answer" and is handled
 * identically to a failed request: nothing is shown, nothing is cleared, and
 * "last checked" does not move.
 *
 * An unknown component id is skipped rather than fatal - a feed serving a
 * newer app may legitimately carry rows this build has never heard of, and
 * refusing the whole document over one would make the feed un-evolvable. A
 * *malformed* row for a known id is fatal, because that is a bug or an attack
 * and neither should be half-applied.
 */
export function parseManifest(text: string, feedUrl: string): Manifest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const document = raw as Record<string, unknown>;

  if (document.schema !== 1) return null;
  if (typeof document.generated !== 'string' || document.generated === '') return null;

  const rawComponents = document.components;
  if (rawComponents === null || typeof rawComponents !== 'object' || Array.isArray(rawComponents)) {
    return null;
  }

  const components: Partial<Record<ComponentId, Available>> = {};
  for (const [key, value] of Object.entries(rawComponents as Record<string, unknown>)) {
    if (!IDS.includes(key as ComponentId)) continue;
    const row = readRow(key as ComponentId, value, feedUrl);
    if (row === null) return null;
    components[key as ComponentId] = row;
  }

  return { schema: 1, generated: document.generated, components };
}
