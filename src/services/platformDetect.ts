export type DetectedOS = 'windows' | 'macos' | 'linux' | 'ios' | 'android' | 'unknown';

export interface AgentDownload {
  url: string;
  filename: string;
  label: string;
  /**
   * What the user has to do after the download. Windows has an installer that
   * does everything; the Unix tarball needs two commands, and saying so on the
   * download button is better than letting them find out afterwards.
   */
  instructions?: string;
}

/**
 * Which system this browser is running on.
 *
 * iOS and Android are their own answers rather than being folded into macOS
 * and Linux. A phone cannot run the agent at all - there is no elevated shell
 * to run it from and no raw socket to open - and offering a download that
 * cannot work is worse than offering none.
 */
export function detectOS(): DetectedOS {
  const uaData = (navigator as { userAgentData?: { platform?: string } }).userAgentData?.platform;
  const signal = `${uaData ?? ''} ${navigator.userAgent} ${navigator.platform}`.toLowerCase();

  // iPadOS reports itself as a Mac and is told apart by having a touch
  // screen - the same test every other library uses, for want of a better one.
  const iPadOS = signal.includes('mac') && typeof document !== 'undefined'
    && navigator.maxTouchPoints > 1;
  if (signal.includes('iphone') || signal.includes('ipad') || iPadOS) return 'ios';
  if (signal.includes('android')) return 'android';
  if (signal.includes('win')) return 'windows';
  if (signal.includes('mac') || signal.includes('darwin')) return 'macos';
  if (signal.includes('linux') || signal.includes('x11')) return 'linux';
  return 'unknown';
}

export const AGENT_DOWNLOADS: Record<'windows' | 'macos' | 'linux', AgentDownload> = {
  windows: {
    // The Inno Setup installer, not the bare exe: the bare exe is a service
    // host that installs nothing when double-clicked (see the agent
    // background-service spec).
    url: '/downloads/Inwire-Agent-Setup.exe',
    filename: 'Inwire-Agent-Setup.exe',
    label: 'Windows',
  },
  // One archive for both, because it is one agent. What shipped before was two
  // shell scripts with a copy of the agent pasted inside each, and the copies
  // had gone stale: they spoke a protocol from before the typed one, so the app
  // parsed nothing and showed the "Update" pill for ever. The tarball is built
  // from the real sources (scripts/agent/package-unix.ts) and carries its own
  // installer.
  macos: {
    url: '/downloads/inwire-agent-unix.tar.gz',
    filename: 'inwire-agent-unix.tar.gz',
    label: 'macOS',
    instructions: 'tar -xzf inwire-agent-unix.tar.gz && sudo ./inwire-agent-*/install.sh',
  },
  linux: {
    url: '/downloads/inwire-agent-unix.tar.gz',
    filename: 'inwire-agent-unix.tar.gz',
    label: 'Linux',
    instructions: 'tar -xzf inwire-agent-unix.tar.gz && sudo ./inwire-agent-*/install.sh',
  },
};

/**
 * The download for this machine, or null where there is nothing worth
 * offering.
 *
 * Null on a phone, and null on an unrecognised platform: the previous version
 * fell back to the Linux script for anything it could not identify, which
 * meant an iPad was handed a shell script and a Windows machine behind an
 * unusual user agent was handed the wrong one.
 */
export function getAgentDownloadForCurrentOS(): AgentDownload | null {
  const os = detectOS();
  if (os === 'ios' || os === 'android' || os === 'unknown') return null;
  return AGENT_DOWNLOADS[os];
}
