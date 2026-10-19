/**
 * The words of the start confirmation, with Electron taken out so a script can assert them.
 *
 * Start against a dataset whose recorded exporter differs from the configured one asks first: the history
 * would then hold two exporters' datagrams, and nothing says so until the user has been told. The dialog is
 * main's, opened only after the utility has refused with `source-differs` and before anything is bound or
 * written. Cancel is first, the default and the cancel, so Enter, Escape and closing the window all leave
 * the history alone.
 */
export interface StartConfirmation {
  type: 'warning';
  title: string;
  message: string;
  detail: string;
  buttons: [string, string];
  defaultId: 0;
  cancelId: 0;
  noLink: true;
}

export function startConfirmation(recordedExporter: string, configuredExporter: string): StartConfirmation {
  return {
    type: 'warning',
    title: 'Start with a different exporter',
    message: 'Record a different exporter into this history?',
    detail: [
      `This history was recorded from ${recordedExporter}.`,
      `Start would record ${configuredExporter} into the same history.`,
      '',
      'A start boundary marks the change, and what is already recorded stays as it is.',
    ].join('\n'),
    buttons: ['Cancel', 'Start recording'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
  };
}
