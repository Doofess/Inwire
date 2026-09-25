/**
 * An analysis with the identifying parts taken out, for an anonymised report.
 *
 * Addresses go through the export's own `Anonymiser`, so a host in the report
 * carries the same pseudonym it has in a pcapng written by the same job - one
 * mapping per export, prefix-preserving, MACs keeping their vendor half.
 *
 * Names are dropped rather than mapped. There is no pseudonym for
 * `payroll.example.com` that is not either the name or a lie, and a resolved
 * name is precisely what anonymising is meant to remove. The same goes for the
 * DNS-over-HTTPS resolvers the capture asked for by name, a process's path and
 * its peers; the process NAME stays, because `chrome.exe` identifies a program
 * rather than a person or a network.
 *
 * Expert summaries are prose that can name an address, so they go through
 * `Anonymiser.text`, which maps every address token it finds the same way.
 */
import { parseIpv4, parseIpv6, type Anonymiser } from '../anonymise';
import type { Conversation, Endpoint, ProcessGroup } from '../statistics';
import type { CaptureMeta } from '../export/captureMeta';
import type { CaptureAnalysis, Ranked } from './analysis';

/** What an imported file is called in an anonymised report. */
export const WITHHELD_FILE_NAME = 'a file (name withheld)';

/**
 * An adapter's label, fit to leave the machine.
 *
 * A friendly name ("Ethernet", "Wi-Fi", "Intel(R) Ethernet Connection I219-V")
 * names hardware rather than a person, and is what makes a multi-adapter
 * report readable, so it stays - with any address inside it mapped. A device
 * path (`\Device\NPF_{GUID}`) or anything else carrying a GUID is an
 * identifier of this one machine's install, and is replaced by its position.
 */
export function adapterLabel(anonymiser: Anonymiser, name: string, index: number): string {
  if (/[{}\\]|[0-9a-f]{8}-[0-9a-f]{4}-/i.test(name)) return `adapter ${index + 1}`;
  return anonymiser.text(name);
}

/**
 * A display filter, fit to leave the machine: every address in it mapped the
 * way the tables map it, and every other quoted value withheld. A filter is
 * often the most specific thing in a report - `http.host contains "payroll"`
 * says what was being looked for - and a quoted string is where that lives.
 */
export function redactFilter(anonymiser: Anonymiser, filter: string): string {
  // Quoted and unquoted runs are rewritten separately, each exactly once: a
  // mapped address is itself an address, and a second pass would map it again.
  const quoted = /"((?:\\.|[^"\\])*)"/g;
  let out = '';
  let at = 0;
  for (const match of filter.matchAll(quoted)) {
    out += anonymiser.text(filter.slice(at, match.index));
    const inner = match[1];
    out += isAddress(inner) ? `"${anonymiser.text(inner)}"` : '"(withheld)"';
    at = match.index + match[0].length;
  }
  return out + anonymiser.text(filter.slice(at));
}

function isAddress(value: string): boolean {
  return /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(value) || parseIpv4(value) !== null
    || (value.includes(':') && parseIpv6(value) !== null);
}

/**
 * The metadata of an anonymised export. Everything in it a reader could tie
 * back to the machine or the traffic - the filter, the file name, adapter
 * labels - is mapped or withheld; counts and times are kept, because they are
 * what the report is for and say nothing about who.
 */
export function redactMeta(meta: CaptureMeta, anonymiser: Anonymiser): CaptureMeta {
  const source: CaptureMeta['source'] = meta.source.kind === 'import'
    ? { kind: 'import', fileName: WITHHELD_FILE_NAME }
    : meta.source.kind === 'live'
      ? { kind: 'live', adapters: meta.source.adapters.map((a, i) => adapterLabel(anonymiser, a, i)) }
      : meta.source;
  return {
    ...meta,
    source,
    filter: redactFilter(anonymiser, meta.filter),
    flags: { ...meta.flags, anonymised: true },
  };
}

/**
 * A table cell that holds an address, the way `Anonymiser.packet` treats a
 * column: an address is mapped, and anything else - a host name a column was
 * showing instead - becomes `host`, because a name is what must not survive.
 */
function address(anonymiser: Anonymiser, value: string): string {
  if (/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(value)) return anonymiser.mac(value);
  if (parseIpv4(value)) return anonymiser.ipv4Address(value);
  if (value.includes(':') && parseIpv6(value)) return anonymiser.ipv6Address(value);
  return 'host';
}

function endpoints(anonymiser: Anonymiser, ranked: Ranked<Endpoint>): Ranked<Endpoint> {
  return {
    distinct: ranked.distinct,
    rows: ranked.rows.map((e) => ({ ...e, address: address(anonymiser, e.address) })),
  };
}

function conversations(anonymiser: Anonymiser, ranked: Ranked<Conversation>): Ranked<Conversation> {
  return {
    distinct: ranked.distinct,
    rows: ranked.rows.map((c) => {
      const a = address(anonymiser, c.addressA);
      const b = address(anonymiser, c.addressB);
      return {
        ...c,
        addressA: a,
        addressB: b,
        key: `${a}|${c.portA ?? ''}|${b}|${c.portB ?? ''}`,
      };
    }),
  };
}

function process(p: ProcessGroup): ProcessGroup {
  return { ...p, exe: '', peers: [] };
}

export function redactAnalysis(analysis: CaptureAnalysis, anonymiser: Anonymiser): CaptureAnalysis {
  return {
    ...analysis,
    endpoints: {
      ipv4: endpoints(anonymiser, analysis.endpoints.ipv4),
      ipv6: endpoints(anonymiser, analysis.endpoints.ipv6),
    },
    conversations: {
      ipv4: conversations(anonymiser, analysis.conversations.ipv4),
      ipv6: conversations(anonymiser, analysis.conversations.ipv6),
      tcp: conversations(anonymiser, analysis.conversations.tcp),
      udp: conversations(anonymiser, analysis.conversations.udp),
    },
    localAddresses: analysis.localAddresses.map((a) => address(anonymiser, a)),
    topRemote: analysis.topRemote && { ...analysis.topRemote, address: address(anonymiser, analysis.topRemote.address) },
    interfaces: analysis.interfaces.map((i, n) => ({ ...i, name: adapterLabel(anonymiser, i.name, n) })),
    expert: {
      ...analysis.expert,
      groups: analysis.expert.groups.map((g) => {
        const summary = anonymiser.text(g.summary);
        return { ...g, summary, key: `${g.category}|${summary}` };
      }),
    },
    names: [],
    processes: analysis.processes.map(process),
    signals: {
      ...analysis.signals,
      encrypted: { ...analysis.signals.encrypted, dohResolvers: [] },
    },
  };
}
