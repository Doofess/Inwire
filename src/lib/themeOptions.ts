import { TbSun, TbMoon, TbDeviceDesktop } from 'react-icons/tb';

// Shared between the Header's theme dropdown and the Command Palette's
// Settings group so both list the same three next-themes values with the
// same icon/label pairing.
export const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: TbSun },
  { value: 'dark', label: 'Dark', icon: TbMoon },
  { value: 'system', label: 'System', icon: TbDeviceDesktop },
] as const;
