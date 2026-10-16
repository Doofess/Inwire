/**
 * One Escape closes one surface: the one opened last.
 *
 * Each popover used to put its own capture-phase `keydown` listener on
 * `window` and call `stopPropagation`. That stops the event travelling to the
 * next node and does nothing to a sibling listener on the same node, so every
 * open surface heard the key and the oldest - registered first - closed first.
 * Here there is one listener, and a surface pushes a layer while it is up.
 *
 * App's own Escape (closing a view) is a bubble-phase listener and runs only
 * when no layer took the key (ADR 0034).
 */
export interface EscapeKey {
  key: string;
  isComposing?: boolean;
  preventDefault?: () => void;
  stopPropagation?: () => void;
}

export interface EscapeStack {
  /** Adds a layer on top; the returned function removes exactly that layer. */
  push(onEscape: () => void): () => void;
  /** Gives the key to the top layer. True when one took it. */
  handle(e: EscapeKey): boolean;
}

export function createEscapeStack(): EscapeStack {
  const layers: Array<{ onEscape: () => void }> = [];
  return {
    push(onEscape) {
      const layer = { onEscape };
      layers.push(layer);
      return () => {
        const i = layers.indexOf(layer);
        if (i >= 0) layers.splice(i, 1);
      };
    },
    handle(e) {
      // An IME uses Escape to cancel a composition; that key is not ours.
      if (e.key !== 'Escape' || e.isComposing) return false;
      const top = layers[layers.length - 1];
      if (!top) return false;
      e.preventDefault?.();
      e.stopPropagation?.();
      top.onEscape();
      return true;
    },
  };
}

let shared: EscapeStack | null = null;

/** The window's one stack, its listener installed on first use. */
export function windowEscapeStack(): EscapeStack {
  if (shared) return shared;
  const stack = createEscapeStack();
  window.addEventListener('keydown', (e) => { stack.handle(e); }, { capture: true });
  shared = stack;
  return stack;
}
