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
//! the verb. This parser has no such rule and accepts either order. `setup.iss`
//! still writes options first: it is the one order both agents ever accepted,
//! and `switch-agent.ps1 -Python` still registers the Python one.
//!
//! ## `install` over an existing registration updates it
//!
//! This is the binary the installer ships (ADR 0037), and every upgrade runs
//! `--startup manual install` against a machine that already has an
//! `InwireAgent` - registered by the Python agent, by an earlier Rust build, or
//! by the standalone agent product. pywin32 falls through from `install` to
//! `update` on `ERROR_SERVICE_EXISTS`; so does this, rewriting the registration
//! in place rather than failing the one step the installer checks.

#![cfg(windows)]

// **Console subsystem, deliberately, and `windows_subsystem = "windows"` must
// not come back.** It was set on the usual reasoning that a service has no UI
// and should not carry a console. The cost was only found by running the verbs
// at a prompt: a GUI-subsystem process is one a shell does **not wait for**, so
// `$LASTEXITCODE` after `inwire-agent.exe install` is whatever ran *before* it.
// An install that succeeded reports the previous command's code, and one that
// failed reports success just as readily. Its stderr does appear - it inherits
// the parent's console - but after the next prompt has been drawn, which reads
// as output from the wrong command.
//
// What the GUI subsystem was protecting against turns out to be nothing here.
// The SCM runs this in session 0, where a console is invisible whichever
// subsystem it is. `setup.iss` calls it through Inno's `Exec(..., SW_HIDE,
// ewWaitUntilTerminated, ResultCode)`, which hides the console and reads the
// real code either way. And **nothing in the app ever spawns this binary** -
// `electron/agentPipe.ts` asks `sc.exe`, never the exe - so there is no path
// where a window could flash at a user.
//
// That leaves one behaviour change, and it is an improvement: double-clicking
// the exe in Explorer now prints why it cannot run outside the SCM, where
// before it exited silently.

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use inwire_agent::agent_log;
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

    let Parsed { verb, manual } = parse(&args);

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

struct Parsed {
    verb: Option<String>,
    manual: bool,
}

/// Splits the installer's command line into a verb and a start type.
///
/// **`--startup` takes a VALUE, and forgetting that is the bug this shipped
/// with.** The first version took "the first argument that does not begin with
/// `--`" as the verb, which on the installer's own line -
/// `--startup manual install` - is **`manual`**. It printed a usage screen and
/// exited 1 without registering anything.
///
/// Which is, almost exactly, the pywin32 failure this file's header describes:
/// there `getopt` stopped at the first non-option token, so options had to come
/// first; here options came first and the value was mistaken for the verb. Same
/// command line, same outcome, opposite cause. Found by running it rather than
/// by reading it.
fn parse(args: &[String]) -> Parsed {
    let mut verb = None;
    let mut manual = true;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--startup" => {
                // Its value, consumed here so it can never be read as a verb.
                // Anything other than `auto` means on-demand, which is the
                // shipped configuration (ADR 0035).
                if let Some(value) = rest.next() {
                    manual = value != "auto";
                }
            }
            other if other.starts_with("--") => {}
            other if verb.is_none() => verb = Some(other.to_string()),
            _ => {}
        }
    }
    Parsed { verb, manual }
}

#[cfg(test)]
mod parse_tests {
    use super::parse;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The installer's own line. This is the case that shipped broken.
    #[test]
    fn options_before_the_verb() {
        let p = parse(&args(&["--startup", "manual", "install"]));
        assert_eq!(p.verb.as_deref(), Some("install"));
        assert!(p.manual);
    }

    #[test]
    fn auto_is_the_only_thing_that_is_not_manual() {
        assert!(!parse(&args(&["--startup", "auto", "install"])).manual);
        assert!(parse(&args(&["install"])).manual);
    }

    /// Either order, because a parser that only accepts one is the trap again.
    #[test]
    fn options_after_the_verb() {
        let p = parse(&args(&["install", "--startup", "auto"]));
        assert_eq!(p.verb.as_deref(), Some("install"));
        assert!(!p.manual);
    }

    #[test]
    fn a_bare_verb_is_the_verb() {
        assert_eq!(parse(&args(&["debug"])).verb.as_deref(), Some("debug"));
        assert_eq!(parse(&args(&["--version"])).verb, None);
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
            // The SCM's refusals arrive as a fairly opaque "IO error in winapi
            // call". Saying what the code usually means costs a line and is the
            // difference between a person retrying correctly and filing a bug.
            eprintln!("[inwire-agent] {error}");
            eprintln!("[inwire-agent] {}", hint(win32_code(&error)));
            ExitCode::FAILURE
        }
    }
}

/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: i32 = 5;
/// `ERROR_SERVICE_DOES_NOT_EXIST`.
const SERVICE_DOES_NOT_EXIST: i32 = 1060;
/// `ERROR_SERVICE_MARKED_FOR_DELETE`.
const SERVICE_MARKED_FOR_DELETE: i32 = 1072;
/// `ERROR_SERVICE_EXISTS`.
const SERVICE_EXISTS: i32 = 1073;

/// The Win32 error code inside a `windows-service` error, when there is one.
fn win32_code(error: &windows_service::Error) -> Option<i32> {
    match error {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

/// What to tell a person about a failed verb.
///
/// It used to say "need an elevated prompt" whatever the code, which was right
/// for the common case and actively wrong for the other two a person meets:
/// a registration **marked for deletion** fails identically when elevated, and
/// telling somebody to elevate for a service that is not installed sends them
/// round the loop again.
fn hint(code: Option<i32>) -> &'static str {
    match code {
        Some(ACCESS_DENIED) => "install, remove, start and stop need an elevated prompt",
        Some(SERVICE_MARKED_FOR_DELETE) => {
            "the InwireAgent registration is marked for deletion; close services.msc \
             (or anything else holding it open) and try again, or reboot"
        }
        Some(SERVICE_DOES_NOT_EXIST) => "no InwireAgent service is registered; run `install` first",
        _ => "install, remove, start and stop need an elevated prompt",
    }
}

/// Whether a failed `CreateService` means "there is one already", which
/// `install` answers by updating it rather than by failing.
///
/// Only that one code. `MARKED_FOR_DELETE` in particular is **not** an update:
/// `ChangeServiceConfig` fails on such a service exactly as `CreateService`
/// does, and reporting it as what it is beats a second, more confusing error.
fn already_registered(error: &windows_service::Error) -> bool {
    win32_code(error) == Some(SERVICE_EXISTS)
}

fn manager(access: ServiceManagerAccess) -> windows_service::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
}

/// The registration, stated once and used for both a new service and an
/// existing one - so an upgrade cannot leave behind a setting a fresh install
/// would not have.
fn service_info(manual: bool, executable_path: std::path::PathBuf) -> ServiceInfo {
    ServiceInfo {
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
        // `windows-service` quotes it, which is what makes a path under
        // `Program Files` an image path rather than an unquoted-path hijack.
        // The installer's image path is the same string for both agents,
        // `{app}\agent\inwire-agent-windows.exe`, so an upgrade rewrites it to
        // the value it already had.
        executable_path,
        launch_arguments: vec![],
        // **Empty means "leave them alone" on an update**: `windows-service`
        // passes NULL for an empty list, and `ChangeServiceConfig` reads NULL as
        // unchanged. That is what keeps the installer's `depend= npcap` across a
        // re-registration: `install` never sets or clears it, and whatever
        // registers the service owns that decision - the installer and
        // `switch-agent.ps1`'s `Set-InstallerPolicy` both set it with
        // `sc config ... depend= npcap`, and only where Npcap is installed.
        dependencies: vec![],
        // LocalSystem, which is the whole of ADR 0033: it is what lets Npcap
        // be installed admin-only, and what keeps the capture handle out of
        // the process that parses hostile bytes.
        //
        // Named rather than left NULL, because NULL means LocalSystem to
        // `CreateService` and "unchanged" to `ChangeServiceConfig` - so an
        // update over a registration somebody had pointed at another account
        // would have kept that account. The empty password is what both APIs
        // document for LocalSystem.
        account_name: Some(OsString::from("LocalSystem")),
        account_password: Some(OsString::new()),
    }
}

fn install(manual: bool) -> windows_service::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = service_info(
        manual,
        env::current_exe().map_err(windows_service::Error::Winapi)?,
    );
    let service = match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG) {
        Ok(service) => service,
        // pywin32's fall-through from `install` to `update`: the image path,
        // the start type, the account and the display name are rewritten to
        // what a fresh install would have written.
        Err(error) if already_registered(&error) => {
            let service = manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG)?;
            service.change_config(&info)?;
            service
        }
        Err(error) => return Err(error),
    };
    // Rewritten on an update too: the Python agent's said "Idle until Inwire
    // connects", which stopped being true when the service became demand-start.
    service.set_description(DESCRIPTION)?;
    Ok(())
}

#[cfg(test)]
mod install_tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    fn winapi(code: i32) -> windows_service::Error {
        windows_service::Error::Winapi(io::Error::from_raw_os_error(code))
    }

    /// The upgrade case, which failed the installer's one checked step.
    #[test]
    fn an_existing_service_is_updated_rather_than_refused() {
        assert!(already_registered(&winapi(SERVICE_EXISTS)));
    }

    #[test]
    fn nothing_else_is_mistaken_for_an_existing_service() {
        // Marked for deletion is the tempting one: the name is taken, but
        // ChangeServiceConfig fails on it too, so it has to be reported.
        assert!(!already_registered(&winapi(SERVICE_MARKED_FOR_DELETE)));
        assert!(!already_registered(&winapi(ACCESS_DENIED)));
        assert!(!already_registered(&windows_service::Error::LaunchArgumentsNotSupported));
    }

    #[test]
    fn a_fresh_install_and_an_update_write_the_same_registration() {
        let exe = PathBuf::from(r"C:\Program Files\Inwire\agent\inwire-agent-windows.exe");
        let info = service_info(true, exe.clone());
        assert_eq!(info.name, OsString::from("InwireAgent"));
        assert_eq!(info.display_name, OsString::from("Inwire Capture Agent"));
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.start_type, ServiceStartType::OnDemand);
        assert_eq!(info.error_control, ServiceErrorControl::Normal);
        assert_eq!(info.executable_path, exe);
        assert!(info.launch_arguments.is_empty());
        // Empty is "unchanged" to ChangeServiceConfig, which keeps depend= npcap.
        assert!(info.dependencies.is_empty());
        assert_eq!(info.account_name, Some(OsString::from("LocalSystem")));
        assert_eq!(info.account_password, Some(OsString::new()));
    }

    #[test]
    fn auto_is_still_honoured_when_asked_for() {
        let info = service_info(false, PathBuf::from("x.exe"));
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
    }

    #[test]
    fn the_hint_names_the_cause_it_can_name() {
        assert!(hint(Some(ACCESS_DENIED)).contains("elevated"));
        assert!(hint(Some(SERVICE_MARKED_FOR_DELETE)).contains("marked for deletion"));
        assert!(hint(Some(SERVICE_DOES_NOT_EXIST)).contains("install"));
        // Anything unrecognised keeps the old, usually-right advice.
        assert!(hint(None).contains("elevated"));
    }
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
    // `to_stderr` is true here and false under the SCM, which is the whole of
    // `logging_setup.py`'s argument of the same name: run by hand there is a
    // console worth writing to, and under the SCM there is not.
    agent_log::init(&agent_log::directory(), true);
    inwire_agent::log_info!(
        "[inwire-agent] {} - foreground on {}; Ctrl+C to stop",
        inwire_agent::VERSION,
        runtime::pipe_name(),
    );
    runtime::run(shutdown).map_err(windows_service::Error::Winapi)
}
