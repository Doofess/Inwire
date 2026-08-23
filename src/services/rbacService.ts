import { UserRole, UserRolePermissions } from '../types/packet';

export const ROLE_PERMISSIONS: Record<UserRole, UserRolePermissions> = {
  ADMIN: {
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canEditDissectors: true,
    canConfigureAlerts: true,
    canChangeColorRules: true,
    canClearBuffer: true,
  },
  SOC_ANALYST: {
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canEditDissectors: false,
    canConfigureAlerts: true,
    canChangeColorRules: true,
    canClearBuffer: false,
  },
  NETWORK_ENGINEER: {
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canEditDissectors: true,
    canConfigureAlerts: false,
    canChangeColorRules: true,
    canClearBuffer: true,
  },
  AUDITOR_GUEST: {
    canCapture: false,
    canExportPcap: false,
    canViewPayloads: false,
    canEditDissectors: false,
    canConfigureAlerts: false,
    canChangeColorRules: false,
    canClearBuffer: false,
  },
};

export interface RoleInfo {
  role: UserRole;
  label: string;
  badgeColor: string;
  description: string;
  userEmail: string;
}

export const ROLES_LIST: RoleInfo[] = [
  {
    role: 'ADMIN',
    label: 'Lead Security Administrator',
    badgeColor: 'bg-red-500/20 text-red-400 border-red-500/40',
    description: 'Full root access: packet capture, custom dissector compilation, raw payload inspection, and security policy rules.',
    userEmail: 'secops-admin@enterprise.internal',
  },
  {
    role: 'SOC_ANALYST',
    label: 'Senior SOC Incident Analyst',
    badgeColor: 'bg-purple-500/20 text-purple-400 border-purple-500/40',
    description: 'Threat hunting access: deep payload inspection, anomaly alert thresholds, traffic timeline analysis, and PCAP exports.',
    userEmail: 'soc-tier3@enterprise.internal',
  },
  {
    role: 'NETWORK_ENGINEER',
    label: 'Core Network Engineer',
    badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    description: 'Performance & protocol engineering: custom dissector creation, packet rate tuning, QoS and TCP stream analysis.',
    userEmail: 'netops@enterprise.internal',
  },
  {
    role: 'AUDITOR_GUEST',
    label: 'Compliance Auditor / Guest',
    badgeColor: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/40',
    description: 'Read-only access: sanitized metadata summaries, traffic statistics, protocol charts with masked payload data.',
    userEmail: 'auditor@external-review.com',
  },
];
