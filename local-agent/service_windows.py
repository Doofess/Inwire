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

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        import logging

        logging.getLogger("netview").info("service stop requested - shutting down")
        if self.loop is not None:
            # The loop runs on the service's main thread; SvcStop is called on
            # a control thread, so this has to hop threads to touch it.
            self.loop.call_soon_threadsafe(self.loop.stop)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        import logging

        import agent

        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(agent.main(to_stderr=False))
        except RuntimeError:
            # SvcStop called loop.stop() while run_until_complete was waiting
            # on agent.main()'s run-forever future. asyncio signals that as
            # "Event loop stopped before Future completed", which is the
            # normal shutdown path here, not a failure.
            pass
        except Exception:
            # Nothing is attached to stderr under the SCM. If this is not
            # written to the log file before the process dies, a crash at boot
            # is completely invisible.
            logging.getLogger("netview").exception(
                "service terminated with an unhandled exception"
            )
            raise
        finally:
            if self.loop is not None:
                self.loop.close()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments means the Service Control Manager started us, rather
        # than a person or the installer running a subcommand.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetViewAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NetViewAgentService)
