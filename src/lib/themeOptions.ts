import { TbSun, TbMoon, TbDeviceDesktop, TbContrast } from 'react-icons/tb';

// Shared by every surface that offers a theme, so they all list the same
// next-themes values with the same icon/label pairing.
//
// Two of these are dark. "Mono" is not a variant of "Dark" - it is its own
// theme with white where Dark uses cyan - so it sits as a peer rather than
// hiding behind a toggle inside Dark.
export const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: TbSun },
  { value: 'dark', label: 'Dark', icon: TbMoon },
  { value: 'mono', label: 'Mono', icon: TbContrast },
  { value: 'system', label: 'System', icon: TbDeviceDesktop },
] as const;
