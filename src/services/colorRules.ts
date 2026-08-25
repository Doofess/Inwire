import { ColorRule, Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';

export const DEFAULT_COLOR_RULES: ColorRule[] = [
  {
    id: 'color-threat-alert',
    name: 'Security Alert / Anomaly',
    filter: 'status == alert || anomaly',
    bgColor: 'rgba(239, 68, 68, 0.18)', // Red
    textColor: '#ef4444',
    enabled: true,
  },
  {
    id: 'color-warning',
    name: 'Warning / TCP RST',
    filter: 'status == warning || info contains "RST"',
    bgColor: 'rgba(245, 158, 11, 0.15)', // Amber
    textColor: '#f59e0b',
    enabled: true,
  },
  {
    id: 'color-http',
    name: 'HTTP Traffic',
    filter: 'proto == http || port == 80',
    bgColor: 'rgba(16, 185, 129, 0.12)', // Emerald
    textColor: '#10b981',
    enabled: true,
  },
  {
    id: 'color-tls',
    name: 'TLS / HTTPS Stream',
    filter: 'proto == tls || proto == https || port == 443',
    bgColor: 'rgba(168, 85, 247, 0.12)', // Purple
    textColor: '#a855f7',
    enabled: true,
  },
  {
    id: 'color-dns',
    name: 'DNS Queries & Replies',
    filter: 'proto == dns || udp.port == 53',
    bgColor: 'rgba(56, 189, 248, 0.12)', // Sky Blue
    textColor: '#38bdf8',
    enabled: true,
  },
  {
    id: 'color-mqtt',
    name: 'MQTT IoT Messages',
    filter: 'proto == mqtt || port == 1883',
    bgColor: 'rgba(20, 184, 166, 0.12)', // Teal
    textColor: '#14b8a6',
    enabled: true,
  },
  {
    id: 'color-icmp',
    name: 'ICMP Echo (Ping)',
    filter: 'proto == icmp',
    bgColor: 'rgba(234, 179, 8, 0.12)', // Yellow
    textColor: '#eab308',
    enabled: true,
  },
  {
    id: 'color-tcp-syn',
    name: 'TCP SYN / Handshake',
    filter: 'info contains "SYN"',
    bgColor: 'rgba(244, 114, 182, 0.12)', // Pink
    textColor: '#f472b6',
    enabled: true,
  },
  {
    id: 'color-custom-proto',
    name: 'Custom Plugins (Proto-IoT / FinFast)',
    filter: 'proto == custom || proto_iot || finfast',
    bgColor: 'rgba(6, 182, 212, 0.15)', // Cyan
    textColor: '#06b6d4',
    enabled: true,
  },
];

interface CompiledRule {
  rule: ColorRule;
  matcher: (p: Packet) => boolean;
}

export class ColorRulesEngine {
  private rules: ColorRule[];
  private compiled: CompiledRule[];

  constructor(initialRules?: ColorRule[]) {
    this.rules = initialRules || [...DEFAULT_COLOR_RULES];
    this.compiled = ColorRulesEngine.compile(this.rules);
  }

  public getRules(): ColorRule[] {
    return this.rules;
  }

  public setRules(rules: ColorRule[]): void {
    this.rules = rules;
    this.compiled = ColorRulesEngine.compile(rules);
  }

  // Compiling each rule's filter once here - instead of re-parsing the
  // filter string from scratch on every getPacketStyle call, as before -
  // is what makes this viable at real capture volume: getPacketStyle runs
  // per row per redraw (including the packet-list minimap's full redraw of
  // every buffered packet), and a Chrome performance trace showed
  // re-parsing every rule's filter on every single call as the dominant
  // cost behind a full tab freeze once the buffer reached a few thousand
  // packets.
  private static compile(rules: ColorRule[]): CompiledRule[] {
    return rules
      .filter(rule => rule.enabled)
      .map(rule => {
        try {
          return { rule, matcher: FilterEngine.compileFilter(rule.filter) };
        } catch {
          return { rule, matcher: () => false };
        }
      });
  }

  public getPacketStyle(packet: Packet, isDark: boolean = true): { background?: string; color?: string; borderColor?: string } {
    for (const { rule, matcher } of this.compiled) {
      try {
        if (matcher(packet)) {
          return {
            background: rule.bgColor,
            color: rule.textColor,
            borderColor: isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
          };
        }
      } catch {
        // Ignore evaluation errors for custom rules
      }
    }

    return {};
  }
}
