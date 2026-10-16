/**
 * What the palette's first character means (ADR 0057).
 *
 * VS Code's vocabulary where it has one - `>` for commands, `:` for go to,
 * `?` for help - because those are the keys this audience's hands already
 * know. With no prefix the palette searches commands and the filter field's
 * own suggestions together.
 */

export type PaletteMode = 'search' | 'commands' | 'goto' | 'help';

export const PALETTE_PREFIXES: readonly { prefix: '>' | ':' | '?'; mode: PaletteMode; label: string }[] = [
  { prefix: '>', mode: 'commands', label: 'Commands' },
  { prefix: ':', mode: 'goto', label: 'Go to packet' },
  { prefix: '?', mode: 'help', label: 'Help and shortcuts' },
];

export function parsePaletteQuery(text: string): { mode: PaletteMode; query: string } {
  const prefix = PALETTE_PREFIXES.find((p) => text.startsWith(p.prefix));
  if (!prefix) return { mode: 'search', query: text };
  return { mode: prefix.mode, query: text.slice(1).trimStart() };
}
