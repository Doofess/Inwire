//! The agent executable: the SCM host, and the CLI the installer drives.
//!
//! One exe, three roles, matching `local-agent/service_windows.py` verb for verb
//! so that `installer/setup.iss` does not have to know which agent it installed:
//!
//! ```text
//!   install / remove / start / stop    what the installer runs. Silent; the
//!                                      installer reads exit codes, not output.
//!   debug                              runs the agent in the foreground, which
//!                                      is the only practical way to iterate.
//!   --version                          prints the version and exits.
//!   (no arguments, launched by SCM)    runs the service.
//! ```
//!
//! **`--startup manual` is accepted and is the default**, because the service is
//! demand-start (ADR 0035). The option is taken rather than assumed so the
//! installer's command line reads the same for both agents.
//!
//! ## The argument order that bit the Python agent
//!
//! pywin32's `HandleCommandLine` parses with `getopt`, which stops at the first
//! non-option token - so `install --startup manual` silently printed a usage
//! screen and exited 1 without registering anything, and options had to precede
//! the verb. This parser has no such rule and accepts either order, but
//! `setup.iss` keeps writing options first, because the installer is shared and
//! the Python agent is still what ships.

#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use inwire_agent::runtime::{self, Shutdown};
use inwire_agent::service::{self, DISPLAY_NAME, SERVICE_NAME};

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// What services.msc shows. It said "for the Inwire web app … until a Inwire
/// page connects" until the web app had been deleted for two phases.
const DESCRIPTION: &str = "Captures network packets for the Inwire desktop app. \
Starts when Inwire asks for it, and stops when Inwire closes.";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    // No arguments means the Service Control Manager started us, rather than a
    // person or the installer running a subcommand.
    if args.is_empty() {
        return match service::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("[inwire-agent] could not start as a service: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let verb = args.iter().find(|a| !a.starts_with("--")).cloned();
    let manual = !args.iter().any(|a| a == "auto");

    match verb.as_deref() {
        Some("install") => report(install(manual)),
        Some("remove") => report(remove()),
        Some("start") => report(start()),
        Some("stop") => report(stop()),
        Some("debug") => report(debug()),
        _ if args.iter().any(|a| a == "--version") => {
            println!("{}", inwire_agent::VERSION);
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "usage: inwire-agent [--startup manual|auto] install|remove|start|stop|debug\n\
                 unrecognised: {}",
                other.unwrap_or("(nothing)")
            );
            ExitCode::FAILURE
        }
    }
}

/// Turns a result into an exit code, and says why on stderr.
///
/// The installer reads the code and never the output, so the message is for a
/// person at a prompt. It must still be written: a silent failure inside an
/// elevated installer is a service that was not registered and an install that
/// reported success.
fn report(result: windows_service::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[inwire-agent] {error}");
            ExitCode::FAILURE
        }
    }
}

fn manager(access: ServiceManagerAccess) -> windows_service::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
}

fn install(manual: bool) -> windows_service::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let service = manager.create_service(
        &ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            // **Manual by default.** Auto meant a LocalSystem capture service
            // running from boot on a machine where Inwire may never be opened.
            // ADR 0035.
            start_type: if manual {
                ServiceStartType::OnDemand
            } else {
                ServiceStartType::AutoStart
            },
            // `Normal` rather than `Critical`: a capture agent that fails to
            // start must not affect the boot, and the app diagnoses it anyway.
            error_control: ServiceErrorControl::Normal,
            executable_path: env::current_exe().map_err(windows_service::Error::Winapi)?,
            launch_arguments: vec![],
            dependencies: vec![],
            // LocalSystem, which is the whole of ADR 0033: it is what lets Npcap
            // be installed admin-only, and what keeps the capture handle out of
            // the process that parses hostile bytes.
            account_name: None,
            account_password: None,
        },
        ServiceAccess::CHANGE_CONFIG,
    )?;
    service.set_description(DESCRIPTION)?;
    Ok(())
}

fn remove() -> windows_service::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)?;
    // Best effort: a service that is already stopped answers with an error that
    // is not a reason to refuse to delete it.
    let _ = service.stop();
    service.delete()
}

fn start() -> windows_service::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start::<&str>(&[])
}

fn stop() -> windows_service::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    let status = service.stop()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    // Asking is asynchronous. Waiting briefly is what makes `stop` usable in a
    // script - an uninstaller that deletes the binary while the service is
    // still exiting leaves a file locked and an entry the SCM cannot clean up.
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
    }
    Ok(())
}

/// Runs the agent in the foreground.
///
/// The only practical way to iterate on it, and it differs from the service
/// path in exactly one respect: nothing reports status to the SCM. The runtime,
/// the pipe, the capture and the idle self-stop are the same code, which is what
/// makes this worth having rather than a second implementation to keep correct.
///
/// **The idle self-stop applies here too**, so a `debug` run with nothing
/// connected exits after the grace period rather than sitting for ever. That is
/// surprising once and then it is the thing being tested.
fn debug() -> windows_service::Result<()> {
    let shutdown = Arc::new(Shutdown::new());
    eprintln!("[inwire-agent] {} - foreground; Ctrl+C to stop", inwire_agent::VERSION);
    runtime::run(shutdown).map_err(windows_service::Error::Winapi)
}
