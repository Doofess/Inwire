/**
 * JSON, a page at a time.
 *
 *   {"format":"inwire-export","formatVersion":2,"meta":{...},"packets":[
 *   {...},
 *   {...}
 *   ]}
 *
 * One frame per line inside the array: still one JSON document - which is
 * what the importer and every JSON tool read - and a file a person can scroll
 * or `grep`, which a single 400 MB line is not.
 *
 * ## Version 2
 *
 * Version 1 was a bare array with each frame's protocol tree under `layers`.
 * That tree is dissected on demand and is empty on every frame a whole-capture
 * export reads (`pipeline.worker.ts`), so it is gone; what replaces it is the
 * flat field bag every frame does carry, under `fields`, keyed by Wireshark
 * name - the same values a display filter reads. Frames also gain their
 * protocol stack, analysis flags, direction, stream and colour rule.
 *
 * `meta` is `CaptureMeta` as it is: numbers are numbers, and a count nobody
 * reported is `null`, never 0. Null when the caller had none to give.
 *
 * The importer reads this through its generic path: it accepts an object with
 * a `packets` array, and the standard keys are spellings of its columns.
 * Nothing here is formula-guarded - JSON is not opened by a spreadsheet, and
 * a guarded string would be a different string to every other reader.
 */
import type { ColorRule, Packet } from '../../../types/packet';
import { EXPORT_COLUMNS, type StandardValue } from '../../exportSchema';
import { isoMicros } from '../captureMeta';
import { orderedFieldEntries } from '../fieldColumns';
import { AdapterLabels, RuleSource, splitValues, writesFields, type TabularOptions } from './tabular';
import { utf8, type ExportWriter } from './writer';

export const JSON_MIME = 'application/json;charset=utf-8';

export const JSON_EXPORT_FORMAT = 'inwire-export';
export const JSON_EXPORT_VERSION = 2;

export type JsonOptions = Omit<TabularOptions, 'fields'>;

export class JsonWriter implements ExportWriter {
  private started = false;
  private first = true;
  private readonly rules: RuleSource;
  private readonly labels: AdapterLabels;
  private readonly fields: boolean;

  constructor(private readonly options: JsonOptions) {
    this.rules = new RuleSource(options.colorRules);
    this.labels = new AdapterLabels(options);
    this.fields = writesFields(options);
  }

  write(page: readonly Packet[], rules?: readonly (ColorRule | null)[]): Uint8Array[] {
    const parts: string[] = [];
    if (!this.started) parts.push(this.head());
    for (let i = 0; i < page.length; i++) {
      parts.push(this.first ? '\n' : ',\n');
      this.first = false;
      parts.push(JSON.stringify(this.frame(page[i], this.rules.ruleAt(page, i, rules))));
    }
    return parts.length > 0 ? [utf8(parts.join(''))] : [];
  }

  finish(): Uint8Array[] {
    const head = this.started ? '' : this.head();
    return [utf8(`${head}\n]}\n`)];
  }

  private head(): string {
    this.started = true;
    return `{"format":${JSON.stringify(JSON_EXPORT_FORMAT)},"formatVersion":${JSON_EXPORT_VERSION},`
      + `"meta":${JSON.stringify(this.options.meta ?? null)},"packets":[`;
  }

  private frame(packet: Packet, rule: ColorRule | null): Record<string, unknown> {
    const { includeRawBytes } = this.options;
    const { standard, raw } = splitValues(packet, rule, includeRawBytes, EXPORT_COLUMNS.length, this.labels);
    const v = (key: string): StandardValue => standard[INDEX.get(key)!];
    const out: Record<string, unknown> = {
      no: v('no'),
      time: v('time'),
      epoch: v('epoch'),
      arrival: isoMicros(packet.tsUs),
      source: v('source'),
      destination: v('destination'),
      protocol: v('protocol'),
      length: v('length'),
      info: v('info'),
      status: v('status'),
      expert: v('expert') ?? '',
      interface: v('interface'),
      direction: v('direction'),
      stream: v('stream'),
      protocols: packet.frameProtocols ?? [],
      colourRule: v('colourRule'),
      analysisFlags: packet.analysisFlags ?? [],
    };
    if (this.fields) out.fields = Object.fromEntries(orderedFieldEntries(packet));
    if (includeRawBytes) out.rawBytes = raw ?? '';
    return out;
  }
}

const INDEX = new Map<string, number>(EXPORT_COLUMNS.map((c, i) => [c.key, i]));
