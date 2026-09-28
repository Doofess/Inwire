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
 * DNS-over-HTTPS resolvers the capture asked for by name, every process the
 * capturing machine's socket table attributed traffic to, and the adapters'
 * names, which become `adapter N`.
 *
 * Expert summaries are prose that can name an address, so they go through
 * `Anonymiser.text`, which maps every address token it finds the same way.
 */
import { parseIpv4, parseIpv6, type Anonymiser } from '../anonymise';
import type { Conversation, Endpoint } from '../statistics';
import type { CaptureMeta } from '../export/captureMeta';
import type { CaptureAnalysis, Ranked } from './analysis';

/** What an imported file is called in an anonymised report. */
export const WITHHELD_FILE_NAME = 'a file (name withheld)';

/**
 * An adapter's label, fit to leave the machine: its position, and nothing else.
 *
 * This used to keep a friendly name, on the argument that "Ethernet (Intel(R)
 * Ethernet Controller (3) I225-V)" names hardware rather than a person. It
 * names the one machine that has that controller, as the name in the capture
 * that shipped it did - in the pcapng's comment, in every IDB and on the PDF's
 * cover, while `docs/verification.md` said labels replaced it. A device path
 * (`\Device\NPF_{GUID}`) identifies the install even more precisely. So every
 * adapter is `adapter N`, numbered by its place in the capture's own list of
 * adapters, and a multi-adapter file still tells its adapters apart.
 */
export function adapterLabel(index: number): string {
  return `adapter ${index + 1}`;
}

/**
 * Labels for adapters by their real names: numbered by `known` (the order the
 * metadata lists them in), and after those in the order they are first asked
 * for - so a table, an IDB and the metadata give one adapter one number.
 */
export class AdapterNumbering {
  private readonly order: string[];

  constructor(known: readonly string[] = []) {
    this.order = [...known];
  }

  label(name: string): string {
    let index = this.order.indexOf(name);
    if (index < 0) index = this.order.push(name) - 1;
    return adapterLabel(index);
  }
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
/** What an anonymised export says in place of the capture filter. */
export const WITHHELD_CAPTURE_FILTER = '(withheld)';

export function redactMeta(meta: CaptureMeta, anonymiser: Anonymiser): CaptureMeta {
  const source: CaptureMeta['source'] = meta.source.kind === 'import'
    ? {
      kind: 'import',
      fileName: WITHHELD_FILE_NAME,
      // The file's own account, with what names a machine or a host taken
      // out: its interfaces' names and descriptions, and a filter - withheld
      // as a live one is. Counts, snaplens and link types say nothing of who.
      ...(meta.source.facts === undefined ? {} : {
        facts: {
          application: meta.source.facts.application,
          interfaces: meta.source.facts.interfaces.map((f) => ({
            ...f, name: null, description: null, filter: f.filter === null ? null : WITHHELD_CAPTURE_FILTER,
          })),
        },
      }),
    }
    : meta.source.kind === 'live'
      ? {
        kind: 'live',
        adapters: meta.source.adapters.map((_, i) => adapterLabel(i)),
        // Withheld whole rather than mapped: a capture filter names hosts
        // unquoted - `host example.com` - and address mapping would let every
        // one of them through. That there was a filter is still said.
        filter: typeof meta.source.filter === 'string' ? WITHHELD_CAPTURE_FILTER : meta.source.filter,
        snaplen: meta.source.snaplen,
        // Sizes, durations and counts, naming no host: kept as they are.
        ring: meta.source.ring,
        autostop: meta.source.autostop,
      }
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

/**
 * The analysis of an anonymised report.
 *
 * `adapters` is the capture's adapter list as the metadata gives it, before
 * redaction, so an interface here is numbered the way `redactMeta` numbers it.
 *
 * **Processes are dropped, not trimmed.** A process name and its PID come from
 * the socket table of the machine the capture was taken on - `chrome.exe, pid
 * 8412` is a fact about one person's session, not about the network - and the
 * report is anonymised so that it says nothing about who. The earlier rule
 * kept the name and cleared the path, and the report printed a table of them.
 */
export function redactAnalysis(
  analysis: CaptureAnalysis, anonymiser: Anonymiser, adapters: readonly string[] = [],
): CaptureAnalysis {
  const numbering = new AdapterNumbering(adapters);
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
    interfaces: analysis.interfaces.map((i) => ({ ...i, name: numbering.label(i.name) })),
    expert: {
      ...analysis.expert,
      groups: analysis.expert.groups.map((g) => {
        const summary = anonymiser.text(g.summary);
        return { ...g, summary, key: `${g.category}|${summary}` };
      }),
    },
    names: [],
    processes: [],
    signals: {
      ...analysis.signals,
      encrypted: { ...analysis.signals.encrypted, dohResolvers: [] },
    },
  };
}
