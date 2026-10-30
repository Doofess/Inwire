#!/usr/bin/env python3
"""
Windows service host for the Inwire agent, and the PyInstaller entry point.

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

# Harmless in both cases, not load-bearing in either: when frozen, agent.py/
# config.py/logging_setup.py are embedded in the PYZ archive (declared as
# hiddenimports in inwire_agent.spec) and load via PyInstaller's own
# meta-path importer, never as loose files from sys._MEIPASS - there is
# nothing at this path for them to shadow. Running from source, the
# interpreter already puts the script's own directory on sys.path. Kept for
# defense in depth in case that default ever changes.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set to True only when launched as `... debug` (see __main__ below). Under the
# SCM there is no console, so stderr logging must stay off; `debug` exists
# specifically to run in the foreground with stderr as the point of the
# exercise, so it needs this flipped on before SvcDoRun configures logging.
DEBUG_MODE = False


class InwireAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "InwireAgent"
    _svc_display_name_ = "Inwire Capture Agent"
    # Written into the SCM by pywin32, so this is what an administrator reads
    # in services.msc beside a LocalSystem service - the same audience the
    # onedir build and the VERSIONINFO exist for. It said "for the Inwire web
    # app ... until a Inwire page connects" until the web app had been deleted
    # for two phases.
    _svc_description_ = (
        "Captures network packets for the Inwire desktop app. Idle until "
        "Inwire connects, and stops capturing when it disconnects."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.loop = None
        self._stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_requested = True
        logging.getLogger("inwire").info("service stop requested - shutting down")
        # A stop can arrive before SvcDoRun has created the loop (the window around
        # `import agent`). The flag above is what makes that case honored; touching
        # the loop is best-effort and must never raise out of SvcStop.
        #
        # **`agent.request_shutdown`, not `loop.stop()`.** Stopping the loop
        # stops it wherever it happens to be, which was suspended inside
        # `main()`'s run-forever await - so `main()` never returned, its
        # `finally: pipes.stop()` never ran, and the pipe name was released by
        # the process dying rather than by anything that had decided to release
        # it. Asking through the agent's own event means every exit path,
        # including this one, runs the same shutdown.
        loop = self.loop
        if loop is not None:
            try:
                # Imported here rather than at module scope: this file is also
                # the installer's CLI, and `import agent` pulls in the capture
                # stack. `install` and `remove` must not need it to be working.
                import agent
                agent.request_shutdown("the service control manager asked")
            except Exception:
                # Best-effort by contract. If the agent module is not importable
                # the loop below is what stops the process anyway.
                try:
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
        # Configured before `import agent` so that an exception raised during
        # agent.py's own module-level import (e.g. a broken dependency) still
        # has somewhere to go, instead of escaping with nothing written to
        # agent.log and no LogErrorMsg - an invisible boot-time crash. config
        # and logging_setup import safely: neither pulls in scapy or
        # websockets, the two dependencies most likely to be missing or broken.
        import config
        import logging_setup

        logging_setup.setup_logging(config.config_dir(), to_stderr=DEBUG_MODE, harden=True)

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if self._stop_requested:
            # Stop arrived while startup was still running - honor it instead
            # of entering a server that never returns.
            logging.getLogger("inwire").info(
                "stop requested before startup completed - not starting"
            )
            return

        try:
            # Imported inside the try so a failure here (missing/broken scapy
            # or websockets, or any other module-level error in agent.py) is
            # caught, logged, and reported below like any other startup
            # failure, rather than escaping SvcDoRun unlogged.
            import agent

            # agent.main() calls setup_logging again for this same folder but
            # without harden, since it cannot know it runs as the service.
            # That is safe because hardening is sticky per folder: the second
            # call finds the first one's setup unchanged and returns it.
            started_ok = self.loop.run_until_complete(agent.main(to_stderr=DEBUG_MODE))
            if started_ok is False:
                # agent.main() logs its own reason and returns False rather than
                # raising, so without this the SCM cannot tell a service that never
                # started from one that stopped cleanly.
                logging.getLogger("inwire").error(
                    "agent failed to start - see earlier log entries"
                )
                servicemanager.LogErrorMsg(
                    "Inwire Capture Agent failed to start. See %ProgramData%\\Inwire\\agent.log."
                )
        except RuntimeError as exc:
            if not self._stop_requested:
                # Only a stop we asked for produces asyncio's "Event loop stopped
                # before Future completed". Any other RuntimeError is a real
                # startup failure and must not vanish.
                logging.getLogger("inwire").exception(
                    "service terminated with an unhandled RuntimeError"
                )
                servicemanager.LogErrorMsg(f"Inwire Capture Agent crashed: {exc}")
                raise
        except Exception as exc:
            # Nothing is attached to stderr under the SCM. If this is not
            # written to the log file before the process dies, a crash at boot
            # is completely invisible.
            logging.getLogger("inwire").exception(
                "service terminated with an unhandled exception"
            )
            servicemanager.LogErrorMsg(f"Inwire Capture Agent crashed: {exc}")
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
        servicemanager.PrepareToHostSingle(InwireAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    # There is deliberately no `--init-config` verb here, and it must not come
    # back. It called `config.ensure_config()`, which MINTS A PAIRING TOKEN and
    # writes config.json, then printed the token for the installer's finish page
    # to show. The token is gone from Windows entirely - the pipe's security
    # descriptor is the authentication, and the kernel enforces it
    # (docs/decisions/0029) - so what this verb did was write a secret nothing
    # reads into a file the installer stopped seeding in 3.8.0. Neither
    # installer has invoked it since: grep `init-config` across
    # installer/setup.iss and local-agent/installer/setup.iss and there is
    # nothing, and the legacy one says so outright ("there is no secret to
    # generate, no --init-config").
    #
    # `config.ensure_config` and `config.make_token` are still there and are
    # still right: the macOS/Linux tarball installs over a WebSocket and keeps
    # the token, because a socket file has no interactive-user SID to name.
    # They cannot be reached from this file - it is the Windows SCM host and
    # imports win32service at module scope.
    elif sys.argv[1] == "--version":
        # The installed build's version, for a person at a prompt; the app
        # learns it from hello. The frozen exe has no console, so this is
        # only useful when run from a terminal that captures stdout.
        import agent
        print(agent.AGENT_VERSION)
    else:
        if len(sys.argv) > 1 and sys.argv[1].lower() == "debug":
            DEBUG_MODE = True
        win32serviceutil.HandleCommandLine(InwireAgentService)
