import React from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { shortInterfaceLabel } from '../../services/captureInterfaces';

interface CaptureInterfacePickerProps {
  interfaces: { name: string; label: string }[];
  selectedInterface: string | null;
  onSelect: (interfaceName: string) => void;
  children: React.ReactNode;
  align?: 'start' | 'center' | 'end';
  side?: 'top' | 'bottom';
}

/**
 * Wraps a Start Capture control so pressing it asks which adapter to capture
 * from instead of silently reusing whatever was selected last.
 *
 * Capture is single-interface: picking here replaces the selection outright
 * rather than adding to it, which is why this is a radio group and not the
 * checkbox list this UI used to carry. The agent's `set_interfaces` still
 * takes an array - it just always receives exactly one name now.
 *
 * The caller is responsible for NOT wrapping its control in this when the
 * interface list is empty: an agent that has not connected yet has no
 * adapters to offer, and a picker with nothing in it would leave the user
 * with a Start button that cannot start anything.
 */
export const CaptureInterfacePicker: React.FC<CaptureInterfacePickerProps> = ({
  interfaces,
  selectedInterface,
  onSelect,
  children,
  align = 'center',
  side = 'bottom',
}) => {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{children}</DropdownMenuTrigger>
      <DropdownMenuContent align={align} side={side} className="w-72 max-h-80 overflow-y-auto">
        <DropdownMenuLabel className="text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground">
          Capture from
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup
          // A null selection has to become '' rather than staying null:
          // Radix treats the group as uncontrolled when value is undefined,
          // which would let it track its own selection separately from ours.
          value={selectedInterface ?? ''}
          onValueChange={onSelect}
        >
          {interfaces.map((iface) => (
            // Short name in the row, full label in the tooltip: the driver
            // description is what makes these unreadable, and three of this
            // machine's adapters differ only inside their parentheses.
            <DropdownMenuRadioItem key={iface.name} value={iface.name} title={iface.label}>
              <span className="truncate">{shortInterfaceLabel(iface.label)}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
