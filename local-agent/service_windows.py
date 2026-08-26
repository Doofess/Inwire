#!/usr/bin/env python3
"""
Windows service host for the NetView agent, and the PyInstaller entry point.

The same exe serves three roles:

  install / remove / start / stop   the CLI the Inno Setup installer drives.
                                    Silent - the installer checks exit codes,
                                    not output.
  debug                             runs the service body in the foreground
                                    with stderr logging. The only practical
                                    way to iterate on a frozen service.
  (no arguments, launched by SCM)   runs the service.

Built with console=False, so none of these ever show a window. Double-
clicking the exe deliberately does nothing visible.
"""

import asyncio
import logging
import os
import sys

import servicemanager
import win32event
import win32service
import win32serviceutil

# A frozen exe runs from a temp extraction directory; a plain script runs from
# local-agent/. Either way agent.py sits beside this file.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class NetViewAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetViewAgent"
    _svc_display_name_ = "NetView Capture Agent"
    _svc_description_ = (
        "Captures network packets for the NetView web app. Idle until a "
        "NetView page connects, and stops capturing when the last one closes."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.loop = None
        self._stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_requested = True
        logging.getLogger("netview").info("service stop requested - shutting down")
        # A stop can arrive before SvcDoRun has created the loop (the window around
        # `import agent`). The flag above is what makes that case honored; touching
        # the loop is best-effort and must never raise out of SvcStop.
        loop = self.loop
        if loop is not None:
            try:
                # The loop runs on the service's main thread; SvcStop is called on
                # a control thread, so this has to hop threads to touch it.
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                # Already closed - a second stop, or a stop racing shutdown.
                pass
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        import agent

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if self._stop_requested:
            # Stop arrived while `import agent` was still running - honor it
            # instead of entering a server that never returns.
            logging.getLogger("netview").info(
                "stop requested before startup completed - not starting"
            )
            return

        try:
            started_ok = self.loop.run_until_complete(agent.main(to_stderr=False))
            if started_ok is False:
                # agent.main() logs its own reason and returns False rather than
                # raising, so without this the SCM cannot tell a service that never
                # started from one that stopped cleanly.
                logging.getLogger("netview").error(
                    "agent failed to start - see earlier log entries"
                )
                servicemanager.LogErrorMsg(
                    "NetView Capture Agent failed to start. See %ProgramData%\\NetView\\agent.log."
                )
        except RuntimeError as exc:
            if not self._stop_requested:
                # Only a stop we asked for produces asyncio's "Event loop stopped
                # before Future completed". Any other RuntimeError is a real
                # startup failure and must not vanish.
                logging.getLogger("netview").exception(
                    "service terminated with an unhandled RuntimeError"
                )
                servicemanager.LogErrorMsg(f"NetView Capture Agent crashed: {exc}")
                raise
        except Exception as exc:
            # Nothing is attached to stderr under the SCM. If this is not
            # written to the log file before the process dies, a crash at boot
            # is completely invisible.
            logging.getLogger("netview").exception(
                "service terminated with an unhandled exception"
            )
            servicemanager.LogErrorMsg(f"NetView Capture Agent crashed: {exc}")
            raise
        finally:
            loop, self.loop = self.loop, None
            if loop is not None:
                loop.close()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments means the Service Control Manager started us, rather
        # than a person or the installer running a subcommand.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetViewAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NetViewAgentService)
