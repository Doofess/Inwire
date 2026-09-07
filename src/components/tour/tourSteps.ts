/**
 * What the first-run tour points at, and what it says.
 *
 * The tour covers one path and stops: **get to your own packets on screen.**
 * Everything before that is unguessable - capture needs a driver installed with
 * elevated privileges, an adapter chosen, and capture explicitly started, in
 * that order, and none of those steps announces itself. Everything after it is
 * discoverable by clicking around, which is a thing people are happy to do once
 * the screen has something on it.
 *
 * The list is the same for every user, including one who already has the agent
 * running. It would be easy to skip step one for them, and it would make the
 * tour something different people are shown different versions of - which is
 * how a walkthrough becomes impossible to support, and how the one person who
 * needs to find the driver again never sees where it lives.
 *
 * Steps name an `anchor` rather than holding a ref. The alternative - threading
 * a ref from here down into the header and the panes - would put a tour-shaped
 * prop on four component signatures that have nothing to do with the tour.
 * `scripts/accessibility/tour.ts` is what keeps the two ends in agreement: an
 * anchor with no `data-tour` in the source, or a `data-tour` no step claims,
 * fails the suite. Without that the failure is silent - the tour points at
 * nothing and no error is raised anywhere.
 *
 * No React and no DOM, so the assertion script can import it.
 */

export type TourAnchor = 'menu' | 'interfaces' | 'schedule' | 'start' | 'list' | 'detail';

export interface TourStep {
  anchor: TourAnchor;
  title: string;
  body: string;
  /**
   * Which side of the target the card prefers. Radix flips it when there is no
   * room, so this is a preference and not a promise.
   */
  side: 'top' | 'right' | 'bottom' | 'left';
}

export const TOUR_STEPS: TourStep[] = [
  {
    anchor: 'menu',
    title: 'Install the capture driver',
    body:
      'A browser cannot see raw network traffic, so Inwire reads it through a small '
      + 'local agent instead. Open this menu and choose Download Driver - it installs '
      + 'once, needs admin rights the one time, and runs quietly from then on.',
    side: 'bottom',
  },
  {
    anchor: 'interfaces',
    title: 'Choose what to listen on',
    body:
      'Pick the adapter carrying the traffic you care about - usually your Wi-Fi or '
      + 'Ethernet connection. You can select more than one.',
    side: 'bottom',
  },
  {
    // Between the adapter and Start, which is the order these are used in:
    // both are things you set before pressing it, and this one changes what
    // pressing it means.
    anchor: 'schedule',
    title: 'Set an end, or a start',
    body:
      'Optional. Give the capture a stop time and it ends on its own - useful when '
      + 'you want fifteen minutes of something and not to sit watching it. Leave the '
      + 'start empty and it begins when you press Start; set one and it begins then.',
    side: 'bottom',
  },
  {
    anchor: 'start',
    title: 'Start capturing',
    body:
      'Nothing is recorded until you press this. Press it again to pause; the frames '
      + 'you already have stay on screen.',
    side: 'bottom',
  },
  {
    anchor: 'list',
    title: 'Your traffic, frame by frame',
    body:
      'Each row is one packet, newest at the bottom. Colours come from the rules in '
      + 'Settings, and the filter bar above narrows this to what you are looking for.',
    side: 'top',
  },
  {
    anchor: 'detail',
    title: 'Open one up',
    body:
      'Click any frame and it is dissected here, layer by layer, with the raw bytes '
      + 'beside it. That is the whole loop - everything else is a shortcut around it.',
    side: 'top',
  },
];
