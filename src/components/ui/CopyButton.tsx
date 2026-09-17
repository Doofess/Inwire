import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

/**
 * Copy one value to the clipboard, with the tick that says it worked.
 *
 * There was no general one of these: the hex viewer's copy buttons had the only
 * careful implementation and the other half-dozen call sites each wrote
 * `navigator.clipboard.writeText` inline, which quietly does nothing in a
 * sandboxed frame. The Network panel puts a copy control on every value it
 * shows, so this is where a shared one earns its place.
 *
 * Two things carried over from the hex viewer, both of which the inline calls
 * were missing. The **execCommand fallback**, because `navigator.clipboard` is
 * unavailable in some sandboxed frames and a copy button that silently fails
 * is worse than one that is absent. And the **confirmation**, because copying
 * produces no visible change anywhere on screen - without a tick the only way
 * to know it worked is to go and paste it somewhere.
 *
 * **Every copy in the app goes through `copyText` now.** `HexCopyMenu` was
 * first, giving up its own copy of the fallback; the rest followed - the
 * protocol tree and its context menu, the frame field table, the packet list's
 * "copy as hex dump", the Statistics filter menu and the stream dialogue. A
 * grep for `navigator.clipboard.writeText` should find exactly one hit, the
 * line below. If it finds two, the careful implementation has grown a second
 * home again and the new one is missing the fallback.
 *
 * The call sites that show a tick take the boolean: `if (!(await copyText(x)))
 * return;` before setting it, so a copy that did not happen does not claim it
 * did. The fire-and-forget ones are `void copyText(x)`.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Sandboxed frames refuse the async API but still honour the old one.
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.left = '-999999px';
    document.body.appendChild(area);
    area.select();
    try {
      const ok = document.execCommand('copy');
      area.remove();
      return ok;
    } catch {
      area.remove();
      return false;
    }
  }
}

interface CopyButtonProps {
  value: string;
  /** Names the thing in the tooltip: "Copy MAC address". */
  label?: string;
  className?: string;
}

export const CopyButton: React.FC<CopyButtonProps> = ({ value, label, className }) => {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // A component unmounted inside the confirmation window - a panel closed
  // straight after a copy - would otherwise set state on nothing.
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const onClick = useCallback(async (event: React.MouseEvent) => {
    // These sit inside rows that are themselves clickable in some panels.
    event.stopPropagation();
    if (!(await copyText(value))) return;
    setCopied(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1500);
  }, [value]);

  return (
    <button
      type="button"
      onClick={onClick}
      title={copied ? 'Copied' : `Copy${label ? ` ${label}` : ''}`}
      // `aria-label` as well as `title`, because the button has no text: a
      // screen reader would otherwise announce it as an unnamed button.
      aria-label={`Copy${label ? ` ${label}` : ''}`}
      className={`shrink-0 p-1 rounded transition-colors text-muted-foreground
        hover:text-foreground hover:bg-accent cursor-pointer ${className ?? ''}`}
    >
      {copied
        ? <Check className="w-3.5 h-3.5 text-emerald-500" />
        : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
};
