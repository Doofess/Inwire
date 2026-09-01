import { useEffect, useState } from 'react';

/**
 * Whether a CSS media query currently matches.
 *
 * A JS media query rather than Tailwind's responsive variants, for the cases
 * where the two branches must render DIFFERENT TREES rather than the same tree
 * styled two ways. The packet detail window has two of them: the hex dump is
 * rendered once and moved between layouts (rendering it twice and hiding one
 * would mount two virtualized dumps, each with its own scroll and resize
 * listeners), and the meta rail becomes an overlay rather than a column.
 *
 * The initializer reads `matches` synchronously so the first paint is already
 * correct - starting from a default and correcting in the effect shows one
 * frame of the wrong layout.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);

  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = (e: MediaQueryListEvent) => setMatches(e.matches);
    // Re-read on subscribe: the query may have changed, or the viewport may
    // have moved between the initializer running and this effect firing.
    setMatches(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);

  return matches;
}
