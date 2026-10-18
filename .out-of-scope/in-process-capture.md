# Capturing inside the app, or a privileged socket inside the agent

**Rejected:** a native capture addon in Electron's main process or a `utilityProcess`, any capture handle opened by the app, and in the other direction, a listening socket (flow collector, SNMP, speed test) inside the LocalSystem agent.

**Why:** the agent is the only privileged component and is kept deliberately small: it captures, writes pcapng, streams bytes, and dissects nothing. Everything that parses hostile bytes runs unprivileged in the app. Moving capture into the app would give the renderer's parent process a kernel driver handle; moving a listener into the agent would give network input a SYSTEM-level process. The separation is a security and lifetime decision, not browser-era weight.

**Rests on:** ADRs 0010, 0033, 0038 and 0058. The accepted monitoring design puts
the collector's socket in an unprivileged `utilityProcess`, with decoding in a
sandboxed Worker. That collector is not implemented yet; its process boundary
is decided. See `SCOPE.md` for implementation status.
