import React from 'react';

import type { Packet } from '../../types/packet';
import type { CommandContext } from '../../lib/commands';
import { keepActive, paletteRowKey, paletteRows, type PaletteRow } from '../../lib/paletteModel';
import { matchChord } from '../../lib/commands';
import { useEscapeLayer } from '../../hooks/useEscapeLayer';
import { parsePaletteQuery } from '../../lib/paletteQuery';
import { lookupFrame } from '../packet-details/packetDetailModel';

/**
 * Ctrl+K: every command the window has, by name (ADR 0057).
 *
 * It draws `paletteRows` and decides nothing about them - which rows, in what
 * order, under which prefix, is `lib/paletteModel.ts`, where a script holds it.
 * What lives here is what only a component can do: focus, keys, and the `:`
 * prefix, which answers from the buffer through `lookupFrame` exactly as the
 * frame-number box does, so the two give one explanation for a missing frame.
 *
 * **Escape closes the palette and nothing else** - not the presets list or the
 * sheet under it, not the view. It is the newest layer on the window's Escape
 * stack (`lib/escapeStack.ts`), the chain App's bubble-phase Escape listener
 * documents (ADR 0034).
 *
 * **Focus stays in the input**: Tab is held, because the dialog is modal and
 * there is nothing else in it to reach. Keys an IME is composing with are its
 * own, so Enter, Escape and the arrows wait until the composition ends.
 *
 * **Focus goes back where it came from**, except after "Focus display filter",
 * whose whole point is to put it somewhere else.
 */
export interface CommandPaletteProps {
  /** What to open on; a new `n` replaces whatever was typed since. */
  request: { text: string; n: number };
  ctx: CommandContext;
  packets: Packet[];
  recentFilters: string[];
  presetExpressions: string[];
  onRun: (id: string) => void;
  onApplyFilter: (expression: string) => void;
  onGoToFrame: (id: number) => void;
  onClose: () => void;
}

const kbd = 'text-[10px] px-1 rounded border border-border bg-muted text-muted-foreground font-mono shrink-0';

function Highlighted({ text, hits }: { text: string; hits: number[] }): React.ReactElement {
  if (hits.length === 0) return <>{text}</>;
  const on = new Set(hits);
  return (
    <>
      {Array.from(text, (ch, i) => (on.has(i)
        ? <span key={i} className="font-semibold text-foreground">{ch}</span>
        : <React.Fragment key={i}>{ch}</React.Fragment>))}
    </>
  );
}

function Keys({ keys }: { keys: string }): React.ReactElement {
  return <kbd className={kbd}>{keys}</kbd>;
}

/** One line in the list; `null` for a row that does nothing when chosen. */
function rowLabel(row: PaletteRow): React.ReactNode {
  switch (row.kind) {
    case 'command':
      return (
        <>
          <span className="truncate text-foreground/90"><Highlighted text={row.title} hits={row.hits} /></span>
          <span className="text-[11px] text-muted-foreground shrink-0">{row.group}</span>
          <span className="flex-1" />
          {row.keys && <Keys keys={row.keys} />}
        </>
      );
    case 'filter':
      return (
        <>
          <span className="text-muted-foreground shrink-0">Apply filter:</span>
          <code className="truncate font-mono text-[11px] text-primary"><Highlighted text={row.expression} hits={row.hits} /></code>
          <span className="flex-1" />
          <span className="text-[11px] text-muted-foreground shrink-0">{row.source === 'recent' ? 'Recent' : 'Preset'}</span>
        </>
      );
    case 'prefix':
      return (
        <>
          <Keys keys={row.prefix} />
          <span className="text-foreground/90">{row.label}</span>
        </>
      );
    case 'shortcut':
      return (
        <>
          <span className="text-foreground/90 truncate">{row.title}</span>
          <span className="flex-1" />
          <Keys keys={row.keys} />
        </>
      );
  }
}

export function CommandPalette({
  request, ctx, packets, recentFilters, presetExpressions,
  onRun, onApplyFilter, onGoToFrame, onClose,
}: CommandPaletteProps): React.ReactElement {
  const [text, setText] = React.useState(request.text);
  const [active, setActive] = React.useState(0);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const listRef = React.useRef<HTMLDivElement>(null);
  const restoreRef = React.useRef<boolean>(true);
  const listId = React.useId();

  // Ctrl+K pressed again while open hands a new request; take it, even when its
  // text is the one it opened with.
  React.useEffect(() => { setText(request.text); }, [request]);

  React.useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    inputRef.current?.focus();
    return () => { if (restoreRef.current) previous?.focus(); };
  }, []);

  useEscapeLayer(true, onClose);


  const { mode, query } = parsePaletteQuery(text);
  const rows = React.useMemo(
    () => paletteRows(text, ctx, { recent: recentFilters, presets: presetExpressions }),
    [text, ctx, recentFilters, presetExpressions],
  );
  const frame = mode === 'goto' ? lookupFrame(packets, query) : null;

  // A new query starts at the top. The same query over a changed list - the
  // context moves during a capture - keeps the highlight on the same row.
  const shownRef = React.useRef({ text, rows });
  React.useEffect(() => {
    const shown = shownRef.current;
    shownRef.current = { text, rows };
    if (shown.rows === rows) return;
    setActive((a) => (shown.text === text ? keepActive(shown.rows, a, rows) : 0));
  }, [text, rows]);

  React.useEffect(() => {
    listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const choose = (row: PaletteRow): void => {
    switch (row.kind) {
      case 'command':
        // These three only change what the palette shows.
        if (row.id === 'palette.open') { setText(''); return; }
        if (row.id === 'palette.commands') { setText('>'); return; }
        if (row.id === 'packet.goto') { setText(':'); return; }
        if (row.id === 'filter.focus') restoreRef.current = false;
        onRun(row.id);
        return;
      case 'filter':
        onApplyFilter(row.expression);
        return;
      case 'prefix':
        setText(row.prefix === '?' ? '?' : row.prefix);
        inputRef.current?.focus();
        return;
      case 'shortcut':
        return;
    }
  };

  const onInputKey = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (e.nativeEvent.isComposing) return;
    if (e.key === 'Tab') { e.preventDefault(); return; }
    // Ctrl+/ from inside the palette goes where it goes from anywhere else:
    // the window's handler skips it while this input has focus.
    if (matchChord(e.nativeEvent)?.id === 'filter.focus') {
      e.preventDefault();
      e.stopPropagation();
      restoreRef.current = false;
      onRun('filter.focus');
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (rows.length === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      setActive((a) => (a + step + rows.length) % rows.length);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (frame !== null) {
        if (frame.kind === 'found') onGoToFrame(frame.packet.id);
        return;
      }
      const row = rows[active];
      if (row) choose(row);
    }
  };

  const optionId = (i: number): string => `${listId}-opt-${i}`;

  let gotoLine: { text: string; ok: boolean } | null = null;
  if (frame !== null) {
    switch (frame.kind) {
      case 'found': gotoLine = { text: `Frame ${frame.packet.id}`, ok: true }; break;
      case 'invalid': gotoLine = { text: `"${frame.text}" is not a frame number`, ok: false }; break;
      case 'outOfRange':
        gotoLine = {
          text: frame.first === null
            ? 'No frames in the buffer'
            : `Frame ${frame.id} is not in the buffer (${frame.first}–${frame.last})`,
          ok: false,
        };
        break;
      case 'empty':
        gotoLine = {
          text: packets.length === 0
            ? 'No frames in the buffer'
            : `Frame numbers ${packets[0].id}–${packets[packets.length - 1].id}`,
          ok: false,
        };
        break;
    }
  }

  return (
    <div
      className="fixed inset-0 z-[60] bg-black/30"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="absolute left-1/2 top-[12vh] -translate-x-1/2 w-[560px] max-h-[60vh] flex flex-col rounded-lg border shadow-2xl bg-popover border-border text-popover-foreground overflow-hidden"
        style={{ animation: 'palette-in var(--motion-panel, 0ms) var(--ease-out, ease-out)' }}
      >
        <input
          ref={inputRef}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onInputKey}
          placeholder="Type a command, or ? for help"
          spellCheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded={frame === null}
          aria-controls={frame === null ? listId : undefined}
          aria-activedescendant={frame === null && rows.length > 0 ? optionId(active) : undefined}
          className={`h-8 shrink-0 px-3 bg-transparent border-b border-border text-xs text-foreground placeholder:text-muted-foreground outline-none ${
            mode === 'goto' ? 'font-mono' : ''
          }`}
        />
        {gotoLine !== null ? (
          <button
            type="button"
            aria-live="polite"
            tabIndex={-1}
            disabled={!gotoLine.ok}
            onClick={() => { if (frame?.kind === 'found') onGoToFrame(frame.packet.id); }}
            className={`m-1 px-2.5 py-1.5 rounded text-left text-xs ${
              gotoLine.ok ? 'bg-accent text-foreground cursor-pointer' : 'text-muted-foreground'
            }`}
          >
            {gotoLine.text}
          </button>
        ) : (
          <div ref={listRef} id={listId} role="listbox" aria-label="Commands" className="overflow-y-auto custom-scrollbar p-1">
            {rows.length === 0 && (
              <div className="px-2.5 py-3 text-xs text-muted-foreground">
                Nothing matches. Type ? to see the prefixes and shortcuts.
              </div>
            )}
            {rows.map((row, i) => (
              <div
                key={paletteRowKey(row)}
                id={optionId(i)}
                role="option"
                aria-selected={i === active}
                aria-disabled={row.kind === 'shortcut' ? true : undefined}
                onMouseMove={() => { if (i !== active) setActive(i); }}
                // mousedown, not click: keep focus in the input.
                onMouseDown={(e) => { e.preventDefault(); choose(row); }}
                className={`flex items-center gap-2 px-2.5 h-7 rounded text-xs ${
                  row.kind === 'shortcut' ? 'cursor-default' : 'cursor-pointer'
                } ${i === active ? 'bg-accent' : ''}`}
              >
                {rowLabel(row)}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
