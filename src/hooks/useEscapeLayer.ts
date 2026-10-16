import React from 'react';

import { windowEscapeStack } from '../lib/escapeStack';

/**
 * Puts a layer on the window's Escape stack while `active` is true
 * (`lib/escapeStack.ts`). The handler is read through a ref, so a new identity
 * each render does not move the layer - which would put an older surface on
 * top of a newer one.
 */
export function useEscapeLayer(active: boolean, onEscape: () => void): void {
  const ref = React.useRef(onEscape);
  ref.current = onEscape;
  React.useEffect(() => {
    if (!active) return undefined;
    return windowEscapeStack().push(() => ref.current());
  }, [active]);
}
