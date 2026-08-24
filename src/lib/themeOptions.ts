import { Sun, Moon, Monitor } from 'lucide-react';

// Shared between the Header's theme dropdown and the Command Palette's
// Settings group so both list the same three next-themes values with the
// same icon/label pairing.
export const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
] as const;
