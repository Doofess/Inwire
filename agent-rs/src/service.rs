//! The Windows service host: the SCM's side of the agent's lifetime.
//!
//! ## Why the `windows-service` crate rather than hand-rolled FFI
//!
//! `npcap.rs` and `pipe.rs` both declare their Win32 surface by hand and take no
//! dependency for it, so the consistent-looking choice here is to do the same
//! with `StartServiceCtrlDispatcherW`. ADR 0037 says otherwise, having
//! looked at this before, and it is right - the difference is what a mistake
//! costs.
//!
//! A mistake in the Npcap FFI is a capture that fails loudly on the next frame.
//! A mistake in service status reporting is a service the SCM believes is
//! `START_PENDING` for ever, or one that reports `STOPPED` while its threads are
//! still running, or one whose checkpoint never advances so the SCM kills it
//! mid-start. Those fail **in the SCM's bookkeeping**, where nothing in this
//! process can observe them and the only symptom is a service that behaves
//! strangely on somebody else's machine.
//!
//! `windows-service` is the thin, well-exercised binding over exactly that
//! bookkeeping. It pulls `windows-sys`, which in 0.61 is `windows-link`'s
//! raw-dylib approach rather than the old metadata crate, so the cost is small.
//! CLAUDE.md's dependency rule asks what a dependency buys over the platform
//! API: here it buys the one part of the platform API where a silent wrong
//! answer is the default failure mode.
//!
//! ## The lifetime this implements
//!
//! ADR 0035. The service is demand-start; the app asks the SCM for it at
//! `whenReady()`; the agent stops **itself** when its last client goes away.
//! So there are two ways out of `run()` and they must behave identically: the
//! SCM sending `Stop`, and `runtime`'s own idle watchdog. Both set the same
//! `Shutdown`, and the status reporting below is the same either way.
//!
//! **This is the piece the Python agent got wrong.** `SvcStop` there called
//! `loop.stop()`, which stops the event loop wherever it happens to be - which
//! was suspended inside a run-forever await, so `main()` never returned and its
//! `finally: pipes.stop()` never ran. The pipe name was released by the process
//! dying rather than by anything that had decided to release it. Here the stop
//! is a request that the runtime observes and unwinds through.

#![cfg(windows)]

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::agent_log;
use crate::runtime::{self, Shutdown};

/// The name the SCM knows it by, and the name `sc start InwireAgent` uses.
///
/// It must match `ServiceName` in `installer/setup.iss` and the literal in
/// `electron/agentPipe.ts`; `scripts/agent/version.ts` is not the checker for
/// that, but the app dialling a service by a different name is a link that
/// never connects with nothing to read anywhere.
pub const SERVICE_NAME: &str = "InwireAgent";

/// What an administrator reads beside a LocalSystem service in services.msc.
pub const DISPLAY_NAME: &str = "Inwire Capture Agent";

/// **Own process, not shared.** A shared-process service would run in a host
/// with other services, which is the opposite of what a capture agent holding a
/// driver handle should be doing.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// How long the SCM is told to wait before the next status update.
///
/// Only meaningful on a PENDING status. Generous, because the thing it covers is
/// Npcap's library load and an interface enumeration on a machine that may be
/// doing something else.
const PENDING_HINT: Duration = Duration::from_secs(10);

define_windows_service!(ffi_service_main, service_main);

/// Hands this process to the SCM. Returns only once the service has stopped.
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    // **Before anything that could fail.** Nothing is attached to stderr under
    // the SCM, so until this runs there is nowhere for a start failure to be
    // read - which is the shape this whole module exists to avoid, and which
    // the agent had until the log was ported: every `eprintln!` in the crate
    // went nowhere on exactly the machines they were written for.
    agent_log::init(&agent_log::directory(), false);
    if let Err(error) = serve() {
        crate::log_error!("service failed: {error}");
    }
}

fn serve() -> windows_service::Result<()> {
    let shutdown = Arc::new(Shutdown::new());

    let handler_shutdown = Arc::clone(&shutdown);
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            // The SCM asks with no timeout of its own worth relying on, so the
            // answer is "accepted" immediately and the unwinding happens on the
            // main thread. Doing the work here would block a control thread.
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // service_windows.py:67's line. Written here, on the control
                // thread, because it is the moment the SCM asked - "shutting
                // down: ..." follows from the main thread once it unwinds.
                crate::log_info!("service stop requested - shutting down");
                handler_shutdown.request("the service control manager asked");
                ServiceControlHandlerResult::NoError
            }
            // Required to be answered, and answering it is all it means.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    let report = |state: ServiceState, accept: ServiceControlAccept, checkpoint: u32| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint: PENDING_HINT,
        process_id: None,
    };

    // **`StartPending` before anything slow, and a checkpoint with it.** Npcap's
    // load and the first interface enumeration happen inside `runtime::run`, and
    // a service that goes straight to `Running` and then takes two seconds to
    // become answerable is a service the app connects to and finds nothing on.
    status_handle.set_service_status(report(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
    ))?;

    status_handle.set_service_status(report(
        ServiceState::Running,
        // Stop AND Shutdown: without the second, a machine shutting down kills
        // the process rather than asking, and a capture in progress is torn
        // down mid-write instead of stopped.
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;

    let result = runtime::run(Arc::clone(&shutdown));

    status_handle.set_service_status(report(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        1,
    ))?;

    // **`STOPPED` last, and only once the runtime has actually returned.**
    // Reporting it earlier tells the SCM the process is finished while its
    // threads are still holding a pipe name - and the SCM will happily start a
    // second instance on top of the first, which is a state nobody wants to
    // debug.
    //
    // A runtime failure is reported as a **service-specific** exit code rather
    // than as 0. `sc query` shows it, and a service that failed must not read as
    // one that stopped cleanly.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: match &result {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(_) => ServiceExitCode::ServiceSpecific(1),
        },
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    if let Err(error) = result {
        crate::log_error!("runtime failed: {error}");
    }
    Ok(())
}
