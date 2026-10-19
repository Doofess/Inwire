/**
 * The words of the discard confirmation (ADR 0061), with Electron taken out so a script can assert them.
 *
 * The dialog is main's, opened only after the utility has said what the discard would do (`discard-preview`)
 * and before any file goes. It states what goes, what stays and, for a discard before a date, the cut that
 * actually happens: evidence leaves in whole segments, so the cut is at or before the date asked for.
 *
 * The non-destructive button is first, the default and the cancel, so Enter, Escape and closing the window
 * all leave the data alone. The copy lives here and nowhere else; the sheet shows replies, not this.
 */
import type { DiscardPreviewResult } from '../../src/services/monitoring/control';

export interface DiscardConfirmation {
  type: 'warning';
  title: string;
  message: string;
  detail: string;
  buttons: [string, string];
  defaultId: 0;
  cancelId: 0;
  noLink: true;
}

export interface DiscardConfirmationOptions {
  /** The dataset's folder, as the user would read it. */
  folder: string;
  /** The default location also holds the app's own settings, which a discard never touches. */
  isDefaultLocation: boolean;
  /** The date the user asked to discard before, for a `before` discard; null otherwise. */
  requestedBeforeMs: number | null;
  formatTime: (ms: number) => string;
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

export function discardConfirmation(
  preview: Extract<DiscardPreviewResult, { ok: true }>,
  opts: DiscardConfirmationOptions,
): DiscardConfirmation {
  const at = (ms: number | null): string | null => (ms === null ? null : opts.formatTime(ms));
  const range = (from: number | null, to: number | null): string => {
    const a = at(from);
    const b = at(to);
    if (a !== null && b !== null) return ` from ${a} to ${b}`;
    if (a !== null) return ` from ${a}`;
    if (b !== null) return ` up to ${b}`;
    return '';
  };
  const frame = (): Pick<DiscardConfirmation, 'type' | 'buttons' | 'defaultId' | 'cancelId' | 'noLink'> =>
    ({ type: 'warning', buttons: ['Cancel', 'Discard'], defaultId: 0, cancelId: 0, noLink: true });

  if (preview.scope === 'all') {
    const segments = preview.segments > 0 ? `Every journal segment (${preview.segments})` : 'The journal';
    const goes = `${segments}, the minute archive and the rollup cache${range(preview.fromMs, preview.throughMs)}.`;
    const stays = [
      `The folder itself, ${opts.folder}.`,
      ...(opts.isDefaultLocation ? ['The app\'s settings.'] : []),
      'Any file in that folder that Inwire did not write.',
    ];
    return {
      ...frame(),
      title: 'Discard all monitoring data',
      message: 'Discard the whole monitoring dataset?',
      detail: [
        'What goes:', goes, '',
        'What stays:', ...stays, '',
        'Monitoring starts again from nothing, and this cannot be undone.',
      ].join('\n'),
    };
  }

  const cut = at(preview.cutMs);
  const requested = opts.requestedBeforeMs === null || opts.requestedBeforeMs === preview.cutMs ? null : at(opts.requestedBeforeMs);
  const cutLine = cut === null
    ? 'Evidence goes in whole segments.'
    : requested === null
      ? `Evidence goes in whole segments, so the cut is ${cut}.`
      : `Evidence goes in whole segments, so the cut is ${cut}, the last segment boundary at or before ${requested}.`;
  return {
    ...frame(),
    title: 'Discard evidence before a date',
    message: cut === null ? 'Discard the oldest evidence?' : `Discard evidence up to ${cut}?`,
    detail: [
      'What goes:',
      `${plural(preview.segments, 'segment', 'segments')} of raw datagrams${range(preview.fromMs, preview.cutMs)}.`, '',
      'What stays:',
      'Their minute totals, which the history shows as "Evidence expired".',
      cut === null ? 'Everything after the cut.' : `Everything after ${cut}.`, '',
      cutLine, 'This cannot be undone.',
    ].join('\n'),
  };
}
