export type DetectedOS = 'windows' | 'macos' | 'linux' | 'unknown';

export interface AgentDownload {
  url: string;
  filename: string;
  label: string;
}

export function detectOS(): DetectedOS {
  const uaData = (navigator as any).userAgentData?.platform as string | undefined;
  const signal = `${uaData ?? ''} ${navigator.userAgent} ${navigator.platform}`.toLowerCase();

  if (signal.includes('win')) return 'windows';
  if (signal.includes('mac') || signal.includes('darwin') || signal.includes('iphone') || signal.includes('ipad')) return 'macos';
  if (signal.includes('linux') || signal.includes('x11') || signal.includes('android')) return 'linux';
  return 'unknown';
}

export const AGENT_DOWNLOADS: Record<Exclude<DetectedOS, 'unknown'>, AgentDownload> = {
  windows: {
    url: '/downloads/netview-agent-windows.exe',
    filename: 'netview-agent-windows.exe',
    label: 'Windows',
  },
  macos: {
    url: '/downloads/netview-agent-macos.command',
    filename: 'netview-agent-macos.command',
    label: 'macOS',
  },
  linux: {
    url: '/downloads/netview-agent-linux.sh',
    filename: 'netview-agent-linux.sh',
    label: 'Linux',
  },
};

export function getAgentDownloadForCurrentOS(): AgentDownload {
  const os = detectOS();
  return AGENT_DOWNLOADS[os === 'unknown' ? 'linux' : os];
}
