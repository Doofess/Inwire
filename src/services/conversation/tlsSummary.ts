/**
 * TLS phases on a TCP stream, folded from rows (ADR 0055, stage 3).
 *
 * Beside the TCP summary and never inside it: TCP's state machine, outcome and
 * golden hashes are untouched, and a stream with no readable TLS row has no
 * entry here at all. Pure steps over a summary and a row; `StreamDigest` owns
 * the map, the version and the decision to create an entry.
 *
 * Everything is read from fields a TLS row already carries, and the view never
 * claims more than the capture holds: nothing is read from an encrypted record
 * except its content type, so a TLS 1.3 alert without keys is `encrypted alert`,
 * never `close_notify` and never a failure.
 *
 * Only rows of a TCP stream are folded (ruling S3-1). QUIC's TLS is QUIC's
 * phases (`flowSummary.ts`).
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import { ALERT_DESCRIPTION_NAMES } from '../dissectors/tlsTables';
import type { Side, TcpOutcome } from './tcpStates';

export type TlsPhase =
  | 'ClientHello' | 'ServerHello' | 'Certificate' | 'application data'
  | 'close_notify' | 'alert' | 'encrypted alert';

export interface TlsPhaseStep {
  phase: TlsPhase;
  side: Side;
  frameId: number;
  time: number;
  /** For `alert` only: the name from `ALERT_DESCRIPTION_NAMES`. */
  alertName?: string;
}

export interface TlsSummary {
  kind: 'tls';
  /** `tcp.stream`. */
  key: number;
  /** The first of each (phase, side), at most `MAX_TLS_STEPS`. */
  phases: TlsPhaseStep[];
  /** The first readable alert of level 2; a close_notify never sets it. */
  fatalAlert: { side: Side; name: string } | null;
  /** A ServerHello row read as TLS 1.3 (`supported_version` 0x0304). Absent otherwise. */
  tls13?: true;
  /** The digest's version when this summary last changed. */
  version: number;
}

export const MAX_TLS_STEPS = 16;

const CONTENT_ALERT = 21;
const CONTENT_APPLICATION = 23;
const TLS_1_3 = 0x0304;

export function openTls(key: number): TlsSummary {
  return { kind: 'tls', key, phases: [], fatalAlert: null, version: 0 };
}

function num(row: Packet, abbrev: string): number | undefined {
  const v = fieldValue(row, abbrev);
  return typeof v === 'number' ? v : undefined;
}

/**
 * Folds one row of a TCP stream into its TLS summary, from `side`. True when
 * the row was TLS and changed the summary; a row that is not TLS, or shows no
 * phase not already held, changes nothing.
 */
export function foldTls(s: TlsSummary, row: Packet, side: Side): boolean {
  const protocols = row.frameProtocols;
  if (protocols === undefined || !protocols.includes('tcp') || !protocols.includes('tls')) return false;
  // No closure: this runs for every TLS row, and a captured `changed` costs a
  // heap context per call (`scripts/perf/store-boundary.ts`).
  let changed = false;
  const decrypted = fieldValue(row, 'inwire.tls.decrypted') === 1;
  // Most TLS rows are application data and carry no handshake at all; only a
  // row with one (or a decrypted row, whose certificate may come from inside)
  // pays for the three lookups below.
  if (decrypted || fieldValue(row, 'tls.handshake.type') !== undefined) {
    if (!has(s, 'ClientHello', side) && fieldValue(row, 'tls.handshake.ja4') !== undefined) changed = push(s, row, 'ClientHello', side) || changed;
    if (!has(s, 'ServerHello', side) && fieldValue(row, 'tls.handshake.ja3s') !== undefined) {
      changed = push(s, row, 'ServerHello', side) || changed;
      if (s.tls13 !== true && num(row, 'tls.handshake.extensions.supported_version') === TLS_1_3) { s.tls13 = true; changed = true; }
    }
    if (!has(s, 'Certificate', side) && fieldValue(row, 'tls.x509.subject_cn') !== undefined) changed = push(s, row, 'Certificate', side) || changed;
  }

  const contentType = num(row, 'tls.record.content_type');
  // A decrypted record counts by its inner type, so a decrypted handshake (22)
  // is not data; `inwire.tls.app_data` says any record of the frame was 23,
  // where the content type is the first record's alone. A row stored before
  // the flag existed has only the content type.
  if (!has(s, 'application data', side)
    && (fieldValue(row, 'inwire.tls.app_data') === 1 || contentType === CONTENT_APPLICATION)
    && !(s.tls13 === true && !decrypted && side === 'server' && !has(s, 'application data', 'client'))) {
    // TLS 1.3 sends the server's EncryptedExtensions..Finished and the client's
    // Finished as opaque type-23 records too. Without keys the client's first one
    // is its Finished, which ends the handshake, so that is its application data
    // (a 0-RTT record before it is early data and counts as well); the server's
    // waits until it is held, or its handshake flight would read as data.
    changed = push(s, row, 'application data', side) || changed;
  }

  const desc = num(row, 'tls.alert_message.desc');
  if (desc !== undefined) {
    if (desc === 0) changed = push(s, row, 'close_notify', side) || changed;
    else {
      const name = ALERT_DESCRIPTION_NAMES[desc] ?? 'Unknown';
      changed = push(s, row, 'alert', side, name) || changed;
      if (s.fatalAlert === null && num(row, 'tls.alert_message.level') === 2) {
        s.fatalAlert = { side, name };
        changed = true;
      }
    }
  } else if (contentType === CONTENT_ALERT) {
    changed = push(s, row, 'encrypted alert', side) || changed;
  }
  return changed;
}

function has(s: TlsSummary, phase: TlsPhase, side: Side): boolean {
  for (const p of s.phases) if (p.phase === phase && p.side === side) return true;
  return false;
}

/** Adds the step unless that (phase, side) is held or the steps are full; true when it did. */
function push(s: TlsSummary, row: Packet, phase: TlsPhase, side: Side, alertName?: string): boolean {
  if (s.phases.length >= MAX_TLS_STEPS || has(s, phase, side)) return false;
  s.phases.push(alertName === undefined
    ? { phase, side, frameId: row.id, time: row.relativeTime }
    : { phase, side, frameId: row.id, time: row.relativeTime, alertName });
  return true;
}

/**
 * What TLS adds to a TCP outcome (ruling S3-2): ` · TLS alert` for a readable
 * fatal alert from either side, ` · TLS unanswered` for a ClientHello the server
 * never answered in TLS at all once the stream is no longer open, else nothing.
 * Any server step counts as an answer: a ServerHello whose record lost a
 * segment is never read, but the server's later records still show it spoke.
 */
export function tlsNote(tls: TlsSummary | undefined, tcpOutcome: TcpOutcome): string {
  if (tls === undefined) return '';
  if (tls.fatalAlert !== null) return ' · TLS alert';
  if (tcpOutcome === 'open') return '';
  const asked = tls.phases.some((p) => p.phase === 'ClientHello');
  const answered = tls.phases.some((p) => p.side === 'server');
  return asked && !answered ? ' · TLS unanswered' : '';
}
