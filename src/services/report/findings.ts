/**
 * What the analysis means, in sentences.
 *
 * The part of the report a reader reads first and sometimes only: a short list
 * of statements an analyst would write after looking at the numbers, each one
 * carrying a tone so the page can say which of them want attention.
 *
 * ## The rules
 *
 *   - **Only what the data supports.** A finding is emitted when its numbers
 *     say something, and never as a placeholder - "no cleartext protocols were
 *     seen" is not written, because this build recognises a handful of them and
 *     silence is not proof. The exceptions are the ones where "nothing" is
 *     itself the finding: no retransmissions in a TCP capture, no drops.
 *   - **A missing number is not a zero.** A drop counter the agent could not
 *     read is `null`, and it is reported as not available - the one claim a
 *     report must never make on nobody's measurement is "complete".
 *   - **Fixed order, fixed formatting.** The rules run in the order written
 *     here, and every number goes through `format.ts` (en-US, no time zone), so
 *     one capture always produces the same sentences.
 *
 * Tone: `fault` is something wrong with the network or the capture that the
 * reader should act on; `notice` is worth knowing and may be benign; `info` is
 * context.
 */
import type { CaptureMeta } from '../export/captureMeta';
import type { CaptureAnalysis } from './analysis';
import { bitRate, bytes, count, duration, frameRate, offset, percent, plural } from './format';

export type FindingTone = 'fault' | 'notice' | 'info';

const TONE_RANK: Record<FindingTone, number> = { fault: 0, notice: 1, info: 2 };

export interface Finding {
  /** Stable, so a test or a later format can refer to one. */
  id: string;
  tone: FindingTone;
  text: string;
}

/** DNS reply codes by number, as RFC 1035 and 2136 name them. */
export const RCODE_NAMES: Record<number, string> = {
  1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
  6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE',
};

export function rcodeName(rcode: number): string {
  return RCODE_NAMES[rcode] ?? `code ${rcode}`;
}

/** Retransmission rates past which the finding changes tone. */
export const RETRANSMISSION_FAULT = 0.02;
export const RETRANSMISSION_NOTICE = 0.005;

/** A silence shorter than this, or than this share of the capture, is not remarked on. */
export const SILENCE_MIN_SECONDS = 10;
export const SILENCE_MIN_SHARE = 0.05;

/** Broadcast past this share of frames is called out as a notice rather than context. */
export const BROADCAST_NOTICE = 0.2;

/**
 * A filter quoted for a sentence. In single quotes when it has double quotes of
 * its own - `dns.qry.name == "x"` - so the sentence's quotes and the filter's
 * never nest into `""`.
 */
export function quoteFilter(filter: string): string {
  return filter.includes('"') ? `'${filter}'` : `"${filter}"`;
}

/** "a, b and c" */
function list(items: string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

function dropsFinding(meta: CaptureMeta): Finding {
  const { kernel, agent, pipe } = meta.drops;
  const parts: [string, number | null][] = [['driver', kernel], ['agent', agent], ['pipe', pipe]];
  const known = parts.filter((p): p is [string, number] => p[1] !== null);

  if (known.length === 0) {
    return {
      id: 'drops',
      tone: 'notice',
      text: meta.source.kind === 'import'
        ? 'The file does not record whether frames were lost while it was captured: drop counters were not available.'
        : 'Drop counters were not available, so this report cannot say whether the capture is complete.',
    };
  }

  const dropped = known.reduce((sum, [, n]) => sum + n, 0);
  const missing = parts.filter(([, n]) => n === null).map(([where]) => where);
  const unavailable = missing.length === 0 ? ''
    : ` The ${list(missing)} ${missing.length === 1 ? 'counter was' : 'counters were'} not available.`;

  if (dropped > 0) {
    const detail = parts.map(([where, n]) => `${where} ${n === null ? 'not available' : count(n)}`).join(', ');
    return {
      id: 'drops',
      tone: 'fault',
      text: `The capture lost ${plural(dropped, 'frame')} before they reached Inwire (${detail}). `
        + 'Everything below describes what arrived, not everything that was on the wire.',
    };
  }
  return {
    id: 'drops',
    tone: 'info',
    text: `No frames were dropped by the ${list(known.map(([where]) => where))}.${unavailable}`,
  };
}

export function findings(analysis: CaptureAnalysis, meta: CaptureMeta): Finding[] {
  const out: Finding[] = [];
  const a = analysis;
  const s = a.signals;

  if (meta.scope === 'filtered') {
    out.push({
      id: 'scope',
      tone: 'info',
      text: `This report covers only the ${plural(a.frames, 'frame')} matching the display filter ${quoteFilter(meta.filter)}, `
        + `out of ${count(meta.frames.inCapture)} in the capture.`,
    });
  }

  if (a.frames === 0) {
    out.push({ id: 'empty', tone: 'info', text: 'There are no frames to analyse.' });
    out.push(dropsFinding(meta));
    return out;
  }

  out.push({
    id: 'overview',
    tone: 'info',
    text: `${plural(a.frames, 'frame')} (${bytes(a.bytes)}) over ${duration(a.durationSeconds)}, averaging `
      + `${frameRate(a.rates.avgFramesPerSecond)} and ${bitRate(a.rates.avgBitsPerSecond)}. `
      + `The busiest second carried ${plural(a.rates.peakFramesPerSecond, 'frame')} and the heaviest `
      + `${bitRate(a.rates.peakBitsPerSecond)}.`,
  });

  if (meta.frames.unreadable > 0) {
    out.push({
      id: 'unreadable',
      tone: 'fault',
      text: `${plural(meta.frames.unreadable, 'frame')} could not be read back from disk and ${meta.frames.unreadable === 1 ? 'is' : 'are'} missing from this analysis.`,
    });
  }

  out.push(dropsFinding(meta));

  const c = a.expert.counts;
  if (c.CaptureGap > 0) {
    out.push({
      id: 'capture-gap',
      tone: 'notice',
      text: `${plural(c.CaptureGap, 'finding')} show the sniffer missed TCP segments (a previous segment not `
        + 'captured, or an acknowledgement for data never seen). The gap is in the capture, not necessarily on the network.',
    });
  }

  if (a.silence && a.silence.seconds >= SILENCE_MIN_SECONDS && a.silence.seconds >= a.durationSeconds * SILENCE_MIN_SHARE) {
    out.push({
      id: 'silence',
      tone: 'notice',
      // On a filtered report a quiet stretch is a stretch with nothing that
      // matched, which says nothing about whether the link was idle.
      text: `${meta.scope === 'filtered' ? 'No matching frames' : 'No frames at all'} for ${duration(a.silence.seconds)}, from ${offset(a.silence.from)} to `
        + `${offset(a.silence.from + a.silence.seconds)} into the capture.`,
    });
  }

  if (c.Broken > 0) {
    out.push({
      id: 'broken',
      tone: 'fault',
      text: `${plural(c.Broken, 'finding')} mark frames as damaged or impossible to decode.`,
    });
  }

  if (c.Security > 0) {
    const lead = a.expert.groups.find((g) => g.category === 'Security');
    out.push({
      id: 'security',
      tone: 'fault',
      text: `${plural(c.Security, 'security finding')}${lead ? `, led by "${lead.summary}"` : ''}.`,
    });
  }

  if (s.tcp.resets > 0) {
    const conversations = a.conversations.tcp.distinct;
    out.push({
      id: 'resets',
      tone: 'notice',
      text: `${plural(s.tcp.resets, 'TCP reset')} across ${plural(s.tcp.resetConversations, 'conversation')}`
        + (conversations > 0 ? ` (${percent(s.tcp.resetConversations, conversations)} of ${count(conversations)} TCP conversations).` : '.'),
    });
  }

  if (s.tcp.frames > 0) {
    const rate = s.tcp.retransmissions / s.tcp.frames;
    if (s.tcp.retransmissions === 0) {
      out.push({
        id: 'retransmissions',
        tone: 'info',
        text: `No TCP retransmissions in ${plural(s.tcp.frames, 'TCP frame')}.`,
      });
    } else {
      const kinds: string[] = [];
      if (s.tcp.fastRetransmissions > 0) kinds.push(`${count(s.tcp.fastRetransmissions)} fast`);
      if (s.tcp.spuriousRetransmissions > 0) kinds.push(`${count(s.tcp.spuriousRetransmissions)} spurious`);
      out.push({
        id: 'retransmissions',
        tone: rate >= RETRANSMISSION_FAULT ? 'fault' : rate >= RETRANSMISSION_NOTICE ? 'notice' : 'info',
        text: `${plural(s.tcp.retransmissions, 'TCP retransmission')}, ${percent(s.tcp.retransmissions, s.tcp.frames)} `
          + `of TCP frames${kinds.length > 0 ? ` (${list(kinds)})` : ''}.`,
      });
    }
  }

  if (s.dns.responses > 0) {
    if (s.dns.errors > 0) {
      const codes = s.dns.byRcode.map((r) => `${rcodeName(r.rcode)} ${count(r.count)}`);
      out.push({
        id: 'dns-errors',
        tone: 'notice',
        text: `${count(s.dns.errors)} of ${plural(s.dns.responses, 'DNS response')} reported an error (${codes.join(', ')}).`,
      });
    } else {
      out.push({
        id: 'dns-errors',
        tone: 'info',
        text: `All ${plural(s.dns.responses, 'DNS response')} succeeded.`,
      });
    }
  }

  // The busiest host that is not this machine and not a group address. The
  // capturing machine is in nearly every frame of its own capture, so leaving
  // it in would make the finding a statement about the vantage point. Chosen
  // by the analyser, on the real addresses: an anonymised analysis carries
  // pseudonyms, and a pseudonym's range says nothing about the host.
  const remote = a.topRemote;
  if (remote && a.ip.bytes > 0) {
    const name = a.names.find((n) => n.address === remote.address)?.name;
    out.push({
      id: 'top-host',
      tone: 'info',
      text: `The busiest ${a.localAddresses.length > 0 ? 'remote ' : ''}host was ${remote.address}${name ? ` ("${name}")` : ''}, `
        + `in ${percent(remote.bytes, a.ip.bytes)} of IP bytes (${bytes(remote.bytes)}).`,
    });
  }

  // The larger of the two tables' leaders, TCP on a tie - never decided by an
  // address, which an anonymised analysis has replaced.
  const tcpTop = a.conversations.tcp.rows[0];
  const udpTop = a.conversations.udp.rows[0];
  const conv = tcpTop && (!udpTop || tcpTop.bytes > udpTop.bytes || (tcpTop.bytes === udpTop.bytes && tcpTop.packets >= udpTop.packets))
    ? { r: tcpTop, kind: 'TCP' }
    : udpTop ? { r: udpTop, kind: 'UDP' } : undefined;
  if (conv) {
    const { r } = conv;
    out.push({
      id: 'top-conversation',
      tone: 'info',
      text: `The largest conversation, ${conv.kind} ${r.addressA} port ${r.portA} to ${r.addressB} port ${r.portB} (${r.protocol}), `
        + `carried ${percent(r.bytes, a.bytes)} of all bytes (${bytes(r.bytes)}) over ${duration(r.duration)}.`,
    });
  }

  if (s.encrypted.tlsBytes > 0 || s.encrypted.quicBytes > 0) {
    const parts: string[] = [];
    if (s.encrypted.tlsBytes > 0) parts.push(`${percent(s.encrypted.tlsBytes, a.bytes)} TLS over TCP`);
    if (s.encrypted.quicBytes > 0) parts.push(`${percent(s.encrypted.quicBytes, a.bytes)} QUIC`);
    out.push({
      id: 'encryption',
      tone: 'info',
      text: `Of all bytes, ${list(parts)}, each frame counted once. That traffic is encrypted and cannot be read `
        + 'without the session keys.',
    });
  }

  if (s.cleartext.length > 0) {
    out.push({
      id: 'cleartext',
      tone: 'notice',
      text: `Protocols that carry their payload in the clear were seen: ${list(s.cleartext.map((u) => `${u.label} (${plural(u.frames, 'frame')})`))}. `
        + 'Anything they carried, credentials included, is readable by anyone on the path.',
    });
  }

  if (s.dns.port53Frames > 0 || s.encrypted.dotFrames > 0 || s.encrypted.dohResolvers.length > 0) {
    const sentences: string[] = [];
    if (s.dns.port53Frames > 0) {
      sentences.push(`${plural(s.dns.port53Frames, 'frame')} of plain DNS on port 53, so the names this capture looked up are readable on the wire.`);
    }
    const encrypted: string[] = [];
    if (s.encrypted.dotFrames > 0) encrypted.push(`DNS over TLS (${plural(s.encrypted.dotFrames, 'frame')})`);
    if (s.encrypted.dohResolvers.length > 0) {
      encrypted.push(`DNS over HTTPS to ${list(s.encrypted.dohResolvers.map((n) => `"${n}"`))}`);
    }
    if (encrypted.length > 0) sentences.push(`Encrypted DNS was also seen: ${list(encrypted)}.`);
    out.push({ id: 'dns-privacy', tone: 'info', text: sentences.join(' ') });
  }

  if (s.broadcastFrames > 0 || s.multicastFrames > 0) {
    out.push({
      id: 'broadcast',
      tone: s.broadcastFrames / a.frames >= BROADCAST_NOTICE ? 'notice' : 'info',
      text: `Broadcast made up ${percent(s.broadcastFrames, a.frames)} of frames and multicast ${percent(s.multicastFrames, a.frames)}.`,
    });
  }

  if (s.duplicateFrames > 0) {
    out.push({
      id: 'duplicates',
      tone: 'notice',
      text: `${plural(s.duplicateFrames, 'frame')} ${s.duplicateFrames === 1 ? 'was' : 'were'} captured a second time on another interface. `
        + 'The counts in this report include both copies.',
    });
  }

  if (a.interfaces.length > 1) {
    out.push({
      id: 'interfaces',
      tone: 'info',
      text: `Frames came from ${count(a.interfaces.length)} interfaces: `
        + `${list(a.interfaces.map((i) => `"${i.name}" (${plural(i.frames, 'frame')})`))}.`,
    });
  }

  if (a.processes.length > 0) {
    const top = a.processes[0];
    out.push({
      id: 'processes',
      tone: 'info',
      text: `Traffic was attributed to ${plural(a.processes.length, 'process', 'processes')}. The busiest, "${top.name}" `
        + `(pid ${top.pid}), carried ${percent(top.bytes, a.bytes)} of all bytes.`,
    });
  }

  if (c.Unverifiable > 0) {
    out.push({
      id: 'unverifiable',
      tone: 'info',
      text: `${plural(c.Unverifiable, 'finding')} could not be judged from where the capture was taken - usually checksums `
        + 'on frames this machine sent, which its network card fills in after the sniffer has seen them.',
    });
  }

  // The overview and the scope lead, as the frame for everything else; after
  // them faults, then notices, then context. The sort is stable, so within a
  // tone the rules keep the order they are written in.
  const lead = out.filter((f) => f.id === 'scope' || f.id === 'overview');
  const rest = out.filter((f) => f.id !== 'scope' && f.id !== 'overview');
  return [...lead, ...rest.sort((x, y) => TONE_RANK[x.tone] - TONE_RANK[y.tone])];
}
