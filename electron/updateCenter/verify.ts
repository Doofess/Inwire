/**
 * Does the file on disk match the file the feed promised.
 *
 * Two independent checks, and they answer different questions. The **size**
 * bound is a resource guard: it decides when to stop reading, so it has to act
 * while bytes are arriving and cannot wait for a digest. The **digest** is the
 * integrity check, and it is the one that decides whether the file is run.
 *
 * Neither is a substitute for a signature. A pinned hash proves the bytes are
 * the bytes the feed named; it says nothing about whether the feed is honest.
 * That is what `manifest.ts`'s download-host allowlist is for, and what
 * Authenticode verification will be for when there is a certificate to check
 * against. Written down here because a sha256 check looks like more assurance
 * than it is.
 */
import { createHash } from 'node:crypto';

/** Accumulates a digest while the download streams, so nothing is buffered twice. */
export interface Digest {
  update(chunk: Uint8Array): void;
  hex(): string;
}

export function createDigest(): Digest {
  const hash = createHash('sha256');
  return {
    update: (chunk) => { hash.update(chunk); },
    hex: () => hash.digest('hex'),
  };
}

/**
 * Compares two hex digests, case-insensitively.
 *
 * Not constant-time, deliberately: the expected value came from a public feed
 * and is not a secret, so there is nothing here for a timing attack to learn.
 */
export function digestMatches(actual: string, expected: string): boolean {
  if (actual.length !== expected.length) return false;
  return actual.toLowerCase() === expected.toLowerCase();
}

/**
 * Whether to keep reading.
 *
 * The ceiling is the declared size **exactly**, with no slack. Slack would buy
 * nothing: the hash is pinned to one file, so a response even one byte longer
 * than promised is already going to fail verification, and the only thing a
 * tolerance adds is more of a stream we have decided not to trust. What this
 * stops is the unbounded case - a server that answers a 1.3 MB request with an
 * endless body until the disk is full.
 */
export function overSize(received: number, declared: number): boolean {
  return received > declared;
}

/**
 * The verdict once the whole body has arrived. Short is as wrong as long: a
 * truncated download has a valid-looking file at the end of it.
 */
export function verifyDownload(
  received: number, declared: number, actualDigest: string, expectedDigest: string,
): { ok: true } | { ok: false; reason: string } {
  if (received !== declared) {
    return { ok: false, reason: `expected ${declared} bytes, received ${received}` };
  }
  if (!digestMatches(actualDigest, expectedDigest)) {
    return { ok: false, reason: 'the download did not match its published checksum' };
  }
  return { ok: true };
}
