import { COMMANDS, availableCommands, formatChord, type CommandContext } from './commands';
import { fuzzyScore } from './fuzzy';
import { PALETTE_PREFIXES, parsePaletteQuery } from './paletteQuery';

/**
 * What the command palette lists for what was typed (ADR 0057).
 *
 * The component draws these rows and decides nothing; every rule about which
 * rows, in which order, under which prefix, is here where
 * `scripts/commands/palette-model.ts` can hold it.
 */

export type PaletteRow =
  | { kind: 'command'; id: string; title: string; group: string; keys?: string; hits: number[] }
  | { kind: 'filter'; expression: string; source: 'recent' | 'preset'; hits: number[] }
  | { kind: 'prefix'; prefix: string; label: string }
  | { kind: 'shortcut'; title: string; keys: string };

/** The filter field's own suggestions, so the palette never offers one it lacks. */
const MAX_FILTER_ROWS = 6;

/**
 * The keys the registry does not hold, because they are not commands: they
 * belong to the packet list, and the list is where they work.
 */
const LIST_KEYS: readonly { title: string; keys: string }[] = [
  { title: 'Start or stop capture (packet list)', keys: 'Space' },
  { title: 'Previous / next packet', keys: '↑ ↓' },
];

/**
 * Commands best first. A title match outranks a keyword match, which is only
 * there so "preferences" finds Settings - so a keyword hit carries no
 * highlight, because the word it matched is not on screen.
 */
function rankCommands(query: string, ctx: CommandContext): PaletteRow[] {
  const ranked: { row: PaletteRow; score: number; at: number }[] = [];
  availableCommands(ctx).forEach((command, at) => {
    const title = fuzzyScore(query, command.title);
    const keyword = (command.keywords ?? [])
      .map((k) => fuzzyScore(query, k))
      .reduce<number | null>((best, m) => (m && (best === null || m.score > best) ? m.score : best), null);
    if (!title && keyword === null) return;
    const score = title ? title.score : (keyword ?? 0) - 1;
    ranked.push({
      at,
      score,
      row: {
        kind: 'command',
        id: command.id,
        title: command.title,
        group: command.group,
        keys: command.keys ? formatChord(command.keys) : undefined,
        hits: title?.hits ?? [],
      },
    });
  });
  ranked.sort((a, b) => b.score - a.score || a.at - b.at);
  return ranked.map((r) => r.row);
}

/** Recent before presets, each ranked on its own, one row per expression. */
function rankFilters(query: string, filters: { recent: string[]; presets: string[] }): PaletteRow[] {
  const seen = new Set<string>();
  const rows: PaletteRow[] = [];
  for (const source of ['recent', 'preset'] as const) {
    const list = source === 'recent' ? filters.recent : filters.presets;
    const ranked: { expression: string; score: number; hits: number[]; at: number }[] = [];
    list.forEach((expression, at) => {
      if (seen.has(expression)) return;
      const match = fuzzyScore(query, expression);
      if (match) ranked.push({ expression, ...match, at });
    });
    ranked.sort((a, b) => b.score - a.score || a.at - b.at);
    for (const r of ranked) {
      if (seen.has(r.expression)) continue;
      seen.add(r.expression);
      rows.push({ kind: 'filter', expression: r.expression, source, hits: r.hits });
    }
  }
  return rows.slice(0, MAX_FILTER_ROWS);
}

/** Every keyed command, whatever applies now; a chord two commands share is one row. */
function shortcutRows(): PaletteRow[] {
  const rows: PaletteRow[] = [];
  const seen = new Set<string>();
  for (const command of COMMANDS) {
    if (!command.keys) continue;
    const keys = formatChord(command.keys);
    if (seen.has(keys)) continue;
    seen.add(keys);
    // Ctrl+E is Start and Stop; the row says both rather than whichever came first.
    const title = command.id === 'capture.start' ? 'Start or stop capture' : command.title;
    rows.push({ kind: 'shortcut', title, keys });
  }
  return [...rows, ...LIST_KEYS.map((k): PaletteRow => ({ kind: 'shortcut', ...k }))];
}

export function paletteRows(
  text: string,
  ctx: CommandContext,
  filters: { recent: string[]; presets: string[] },
): PaletteRow[] {
  const { mode, query } = parsePaletteQuery(text);
  switch (mode) {
    case 'commands': return rankCommands(query, ctx);
    case 'goto': return [];
    case 'help':
      return [
        ...PALETTE_PREFIXES.map((p): PaletteRow => ({ kind: 'prefix', prefix: p.prefix, label: p.label })),
        ...shortcutRows(),
      ];
    case 'search': return [...rankCommands(query, ctx), ...rankFilters(query, filters)];
  }
}
