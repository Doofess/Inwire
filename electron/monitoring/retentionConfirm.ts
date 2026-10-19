/**
 * The words of the retention confirmation, with Electron taken out so a script can assert them.
 *
 * Saving a retention policy runs the expiry once, at once ("expire evidence before a date is the same
 * mechanism as retention, run once"), so a policy that has something due is confirmed first, in main's
 * dialog and before settings.json is written. The figures come from the utility's `retention-preview`, the
 * same selection the expiry step runs, so the stated cut is the cut. Cancel is first, the default and the
 * cancel.
 */
import type { RetentionPreviewResult } from '../../src/services/monitoring/control';
import type { RetentionPolicy } from '../../src/services/monitoring/retention';

export interface RetentionConfirmation {
  type: 'warning';
  title: string;
  message: string;
  detail: string;
  buttons: [string, string];
  defaultId: 0;
  cancelId: 0;
  noLink: true;
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

export function retentionConfirmation(
  preview: Extract<RetentionPreviewResult, { ok: true }>,
  policy: RetentionPolicy,
  opts: { formatTime: (ms: number) => string },
): RetentionConfirmation {
  const segments = plural(preview.segments, 'segment', 'segments');
  const days = policy.keepRawDays === null ? null : plural(policy.keepRawDays, 'day', 'days');
  const byLimit = preview.cause === 'limit' || days === null;
  const reason = !byLimit
    ? `Keeping raw evidence for ${days}`
    : days === null
      ? 'Expiring the oldest raw evidence at the storage limit'
      : `Keeping raw evidence for ${days} and expiring the oldest at the storage limit`;

  const from = preview.fromMs === null ? null : opts.formatTime(preview.fromMs);
  const before = preview.cutMs === null ? null : opts.formatTime(preview.cutMs + 1);
  const range = from === null ? '' : ` from ${from}`;
  const cutLine = before === null ? '' : `, recorded before ${before}`;

  return {
    type: 'warning',
    title: 'Expire raw evidence now',
    message: `${reason} expires the raw evidence of ${segments} now.`,
    detail: [
      'What goes:',
      `The raw datagrams of ${segments}${range}${cutLine}.`, '',
      'What stays:',
      'Their minute totals, kept in the archive, which the history shows as "Evidence expired".',
      before === null ? 'Everything recorded after them.' : `Everything recorded from ${before}.`, '',
      'Expiry is by whole segments. This cannot be undone.',
    ].join('\n'),
    buttons: ['Cancel', 'Expire evidence'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
  };
}
