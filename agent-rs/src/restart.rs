//! Whether `restart_agent` can be honoured, and the one way it is.
//!
//! The port of `local-agent/agent.py`'s restart half (agent.py:343-508).
//! `restart_agent` is implemented by **exiting** and letting the Service
//! Control Manager start a new process, so the guard is the entire feature: in
//! any situation where nothing would start the agent again, exiting is not a
//! restart but a stop the app has no way to undo. Two things have to be true,
//! and both are read back from the SCM at startup rather than assumed:
//!
//! - **this process is the one the SCM runs as `InwireAgent`** - compared by
//!   process id, because `debug` runs the very same code in the foreground and
//!   nothing about the call path tells the two apart;
//! - **a restart-on-failure policy exists** - without one the SCM treats the
//!   exit as a dead service and leaves it stopped.
//!
//! The Rust agent used to answer `restart_agent` with a `state` message, which
//! read to the app as "done" while nothing happened.
//!
//! ## The policy is re-asserted, not just read
//!
//! agent.py:419-466 writes the failure actions at every service start and then
//! reads them back, and only the read decides. The write can legitimately fail
//! and the installer may already have set the policy, so a failed write is not a
//! failed outcome - and never trusting the write is what keeps a silently
//! ignored `ChangeServiceConfig2` from being read as success. The values are
//! the installer's: restart after 5 s, three times, the count reset after a day
//! (`installer/setup.iss`, `sc failure ... restart/5000`).
//!
//! **The write needs `SERVICE_START`, and for as long as it was not asked for,
//! it never happened.** `ChangeServiceConfig2` documents that a policy carrying
//! `SC_ACTION_RESTART` requires the handle to hold `SERVICE_START` as well as
//! `SERVICE_CHANGE_CONFIG`; without it the call fails with access denied. This
//! opened the service for `CHANGE_CONFIG | QUERY_CONFIG` - as `agent.py`
//! does, the same defect - and discarded the result, so the "re-assert" was a
//! read, and a service whose policy had been cleared stayed without one. The
//! installer's own `sc failure` is what actually set it on every machine. The
//! outcome of both halves is logged now, because the failure that hid this was
//! a `let _` and a line at a level the log does not write.
//!
//! `windows-service`'s `update_failure_actions` and `get_failure_actions` are
//! `ChangeServiceConfig2W` and `QueryServiceConfig2W` with
//! `SERVICE_CONFIG_FAILURE_ACTIONS` - the calls `agent.py` makes through
//! pywin32 - so this adds no dependency the crate did not already carry.

#![cfg(windows)]

use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
    ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::control::{Level, RestartSupport};
use crate::service::SERVICE_NAME;

/// Any non-zero code. The SCM treats a service process that ends with one, and
/// without reporting `STOPPED`, as a failure - which is what fires the restart
/// action. A clean exit reads as an intentional stop and nothing comes back.
/// agent.py:349.
pub const RESTART_EXIT_CODE: i32 = 1;

/// How long after `restart_agent` the process exits: long enough for the
/// handler to return and the log line to reach any subscriber, so the pipe
/// closes as a drop rather than mid-message. agent.py:1369.
pub const RESTART_DELAY: Duration = Duration::from_millis(500);

/// agent.py:353-354.
pub const FAILURE_ACTION_DELAY: Duration = Duration::from_millis(5000);
pub const FAILURE_RESET: Duration = Duration::from_secs(86_400);

/// agent.py:481-483.
pub const NOT_THE_SERVICE: &str =
    "Restart is unavailable: this agent is not running as the Inwire service.";
/// agent.py:486-489.
pub const NO_POLICY: &str = "Restart is unavailable: Windows has no restart-on-failure policy \
for the Inwire service, so the agent would not come back. Reinstall the agent to fix this.";

/// `decide_restart_allowed` and `refresh_restart_support`'s texts
/// (agent.py:362-379, 469-495), as a pure function so the reasoning is testable
/// without a service to ask. Answers the support and the log line to write.
pub fn decide(is_service_process: bool, policy_confirmed: bool) -> (RestartSupport, Level, String) {
    if is_service_process && policy_confirmed {
        (
            RestartSupport { allowed: true, reason: String::new() },
            Level::Info,
            "restart is available (service restart-on-failure policy confirmed)".to_string(),
        )
    } else if !is_service_process {
        (
            RestartSupport { allowed: false, reason: NOT_THE_SERVICE.to_string() },
            Level::Info,
            format!("restart is unavailable - not running as the {SERVICE_NAME} service"),
        )
    } else {
        (
            RestartSupport { allowed: false, reason: NO_POLICY.to_string() },
            Level::Warning,
            format!(
                "restart is unavailable - no restart-on-failure policy on {SERVICE_NAME}; refusing to \
                 exit on request because nothing would start the agent again"
            ),
        )
    }
}

/// Works out, once, whether `restart_agent` can be honoured - and on the way,
/// re-asserts the failure policy when this is the service. agent.py:469-495.
///
/// Once rather than per request: it asks the SCM, and a process either is the
/// service or is not for its whole life.
pub fn probe() -> RestartSupport {
    let is_service = running_as_service_process();
    let policy = is_service && ensure_failure_policy();
    let (support, level, line) = decide(is_service, policy);
    crate::agent_log::write(level.as_str(), &line);
    support
}

/// True only when THIS process is the one the SCM runs as `InwireAgent`.
/// agent.py:394-416.
///
/// `query_status` reports a process id only for a `RUNNING` service, which is
/// fine here: `service.rs` reports `Running` before the runtime starts, and a
/// service in any other state is not this process anyway.
///
/// **Read-only**: `SC_MANAGER_CONNECT` and `SERVICE_QUERY_STATUS`, which the
/// interactive user holds. A `debug` run beside the installed service opens it
/// to read its pid and changes nothing.
pub fn running_as_service_process() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false;
    };
    match service.query_status() {
        Ok(status) => status.process_id == Some(std::process::id()),
        Err(_) => false,
    }
}

/// The failure actions `ensure_failure_policy` writes: restart, three times.
pub fn failure_actions() -> ServiceFailureActions {
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: FAILURE_ACTION_DELAY,
    };
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        // `None` leaves both unchanged, which is pywin32's `None` too.
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    }
}

/// Whether any of `actions` restarts the service. agent.py:459-460.
pub fn restarts(actions: &ServiceFailureActions) -> bool {
    actions
        .actions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|a| a.action_type == ServiceActionType::Restart)
}

/// Writes the failure policy, then reads it back; only the read decides.
/// agent.py:419-466.
///
/// **Only ever called from the service process itself** (`probe` checks
/// first), which is LocalSystem and holds every right asked for here. A
/// `debug` run never reaches it, so it cannot touch an installed service's
/// configuration.
fn ensure_failure_policy() -> bool {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(manager) => manager,
        Err(error) => {
            crate::log_warn!("could not read failure actions ({})", describe(&error));
            return false;
        }
    };
    let service = match manager.open_service(SERVICE_NAME, POLICY_ACCESS) {
        Ok(service) => service,
        Err(error) => {
            crate::log_warn!("could not read failure actions ({})", describe(&error));
            return false;
        }
    };
    // Not fatal: the installer may already have set it, which the read below
    // is the judge of. agent.py:454's line, at WARNING rather than its DEBUG:
    // below the file's level, a refused write is the defect nobody sees.
    match service.update_failure_actions(failure_actions()) {
        Ok(()) => crate::log_info!("{}", policy_written_line()),
        Err(error) => crate::log_warn!("could not write failure actions ({})", describe(&error)),
    }
    match service.get_failure_actions() {
        Ok(actions) => restarts(&actions),
        Err(error) => {
            crate::log_warn!("could not read failure actions ({})", describe(&error));
            false
        }
    }
}

/// What the policy write asks the service handle for.
///
/// `SERVICE_START` is not decoration: `ChangeServiceConfig2` refuses a policy
/// with a restart action from a handle without it. See the module note.
const POLICY_ACCESS: ServiceAccess = ServiceAccess::CHANGE_CONFIG
    .union(ServiceAccess::QUERY_CONFIG)
    .union(ServiceAccess::START);

/// The line a successful re-assert writes, with the values it wrote.
fn policy_written_line() -> String {
    format!(
        "restart-on-failure policy written: restart after {} ms, {} times, count reset after {} s",
        FAILURE_ACTION_DELAY.as_millis(),
        failure_actions().actions.map_or(0, |a| a.len()),
        FAILURE_RESET.as_secs()
    )
}

/// `windows-service`'s error with the Windows error inside it - its own
/// `Display` says only "IO error in winapi call", which in a log is no reason.
fn describe(error: &windows_service::Error) -> String {
    match error {
        windows_service::Error::Winapi(inner) => inner.to_string(),
        other => other.to_string(),
    }
}

/// Ends this process so the service manager starts a fresh one.
/// agent.py:498-508.
///
/// `process::exit` rather than an orderly shutdown: the point is for the SCM to
/// see the service process end **without** reporting `STOPPED`, which is what
/// triggers the restart action. The log is written line by line with no buffer
/// held, so the line below is on disk before the exit.
pub fn exit_for_restart() -> ! {
    crate::log_info!("restarting now - exiting so the service manager starts a new process");
    std::process::exit(RESTART_EXIT_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test_protocol.py:1279-1298, the four cases of `decide_restart_allowed`,
    /// with `refresh_restart_support`'s reason and log line for each.
    #[test]
    fn restart_is_allowed_only_as_the_service_with_a_policy() {
        let (yes, level, line) = decide(true, true);
        assert!(yes.allowed);
        assert_eq!(yes.reason, "");
        assert_eq!((level, line.as_str()), (Level::Info, "restart is available (service restart-on-failure policy confirmed)"));

        let (from_source, level, line) = decide(false, true);
        assert!(!from_source.allowed, "a debug run has no service behind it");
        assert_eq!(from_source.reason, NOT_THE_SERVICE);
        assert_eq!((level, line.as_str()), (Level::Info, "restart is unavailable - not running as the InwireAgent service"));

        let (no_policy, level, line) = decide(true, false);
        assert!(!no_policy.allowed, "exiting would stay stopped");
        assert_eq!(no_policy.reason, NO_POLICY);
        assert_eq!(level, Level::Warning);
        assert_eq!(line, "restart is unavailable - no restart-on-failure policy on InwireAgent; refusing to exit on request because nothing would start the agent again");

        assert!(!decide(false, false).0.allowed);
        // test_protocol.py:1312 - a clean exit would read as an intentional stop.
        assert_ne!(RESTART_EXIT_CODE, 0);
    }

    /// The handle the policy is written through carries `SERVICE_START`,
    /// without which `ChangeServiceConfig2` refuses a restart action - the
    /// right both agents left out, which made the write fail every time.
    #[test]
    fn the_policy_is_written_through_a_handle_that_may_start_the_service() {
        assert!(POLICY_ACCESS.contains(ServiceAccess::START), "ChangeServiceConfig2 needs it");
        assert!(POLICY_ACCESS.contains(ServiceAccess::CHANGE_CONFIG));
        assert!(POLICY_ACCESS.contains(ServiceAccess::QUERY_CONFIG), "the read-back decides");
        assert_eq!(
            policy_written_line(),
            "restart-on-failure policy written: restart after 5000 ms, 3 times, count reset after 86400 s"
        );
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        // The Windows error itself, not "IO error in winapi call" - keyed on the
        // code, because the sentence around it is localised.
        assert!(describe(&denied).contains("os error 5"), "{}", describe(&denied));
    }

    /// The policy written is the installer's - restart after 5 s, three times,
    /// reset after a day - and it is one `restarts` recognises.
    #[test]
    fn the_policy_written_is_the_installers_and_reads_back_as_a_restart() {
        let actions = failure_actions();
        assert_eq!(actions.reset_period, ServiceFailureResetPeriod::After(Duration::from_secs(86_400)));
        let list = actions.actions.clone().unwrap();
        assert_eq!(list.len(), 3);
        assert!(list.iter().all(|a| a.action_type == ServiceActionType::Restart
            && a.delay == Duration::from_millis(5000)));
        assert!(restarts(&actions));
        assert!(!restarts(&ServiceFailureActions { actions: None, ..failure_actions() }));
        assert!(!restarts(&ServiceFailureActions {
            actions: Some(vec![ServiceAction { action_type: ServiceActionType::None, delay: Duration::ZERO }]),
            ..failure_actions()
        }));
    }

    /// A test process is not the service, whatever is installed on this
    /// machine - and asking is a read. Nothing here opens the service for
    /// writing: `ensure_failure_policy` is unreachable when this is false.
    #[test]
    fn a_process_that_is_not_the_service_is_told_so() {
        assert!(!running_as_service_process());
    }
}
