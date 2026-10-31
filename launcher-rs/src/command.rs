//! The `inwire` command: what it accepts, where it looks, and what it returns.
//!
//! Everything here is a decision over strings and paths; the Win32 calls live
//! behind [`LauncherPlatform`] in `platform.rs`, so the decisions are tested
//! with a fake that records what was touched.
//!
//! ## Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | success: help or version printed, or Inwire was started (or is already running and was asked to focus) |
//! | 64   | usage: any argument other than none, exactly `--help`, or exactly `--version` |
//! | 65   | the `Inwire.exe` beside the launcher reports a different product version than the launcher (or reports none) |
//! | 66   | payload missing: no `Inwire.exe` at `<app>\Inwire.exe`, or the launcher is not at `<app>\bin\inwire.exe` |
//! | 71   | the launch failed (the OS error is shown), or elevation could not be determined |
//! | 77   | the terminal is elevated: Inwire does not start elevated, so nothing is launched |
//!
//! Elevation that cannot be determined is refused with 71 rather than guessed
//! at in either direction: starting the app elevated by mistake is the worse
//! outcome, and "could not tell" is not "not elevated".

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The launcher's own version, compared with the app's ProductVersion.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 64;
pub const EXIT_VERSION_MISMATCH: i32 = 65;
pub const EXIT_PAYLOAD_MISSING: i32 = 66;
pub const EXIT_LAUNCH_FAILED: i32 = 71;
pub const EXIT_ELEVATED: i32 = 77;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Command {
    Launch,
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage,
    /// The launcher is not at `<app>\bin\inwire.exe` (or its path is not absolute).
    Layout(PathBuf),
    /// `<app>\Inwire.exe` does not exist.
    MissingPayload(PathBuf),
}

pub const USAGE: &str = "usage: inwire [--help | --version]\n\
\n\
  inwire              open Inwire, or bring the running window forward, and return\n\
  inwire --version    print the version\n\
  inwire --help       print this text\n";

/// `args` excludes argv0. Anything but `[]`, exactly `--help` or exactly
/// `--version` is a usage error: no flag is forgiven and no argument is passed on
/// to the app.
pub fn parse_command(args: &[OsString]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Launch),
        [one] => match one.to_str() {
            Some("--help") => Ok(Command::Help),
            Some("--version") => Ok(Command::Version),
            _ => Err(CliError::Usage),
        },
        _ => Err(CliError::Usage),
    }
}

/// `<app>\Inwire.exe` for a launcher at `<app>\bin\inwire.exe`, derived only
/// from the launcher's own path. Pure: nothing on disk is consulted, and neither
/// the current directory nor PATH is ever read.
pub fn desktop_path(launcher: &Path) -> Result<PathBuf, CliError> {
    let layout = || CliError::Layout(launcher.to_path_buf());
    if !launcher.is_absolute() {
        return Err(layout());
    }
    let bin = launcher.parent().ok_or_else(layout)?;
    let is_bin = bin
        .file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |n| n.eq_ignore_ascii_case("bin"));
    if !is_bin {
        return Err(layout());
    }
    let app = bin.parent().ok_or_else(layout)?;
    Ok(app.join("Inwire.exe"))
}

/// `x.y.z` equals ProductVersion, tolerating a trailing `.0` fourth group only.
pub fn versions_match(launcher: &str, product: &str) -> bool {
    let product = product.trim();
    product == launcher || product.strip_suffix(".0") == Some(launcher)
}

pub trait LauncherPlatform {
    fn is_elevated(&self) -> Result<bool, String>;
    fn file_product_version(&self, exe: &Path) -> Result<String, String>;
    fn launch_detached(&self, exe: &Path) -> Result<(), String>;
    fn exists(&self, path: &Path) -> bool;
    fn print_out(&self, text: &str);
    fn print_err(&self, text: &str);
}

/// [`desktop_path`], then a check that the file is there.
pub fn resolve_desktop(
    launcher: &Path,
    platform: &impl LauncherPlatform,
) -> Result<PathBuf, CliError> {
    let desktop = desktop_path(launcher)?;
    if platform.exists(&desktop) {
        Ok(desktop)
    } else {
        Err(CliError::MissingPayload(desktop))
    }
}

pub fn run(command: Command, launcher: &Path, platform: &impl LauncherPlatform) -> i32 {
    match command {
        Command::Help => {
            platform.print_out(USAGE);
            EXIT_OK
        }
        Command::Version => {
            platform.print_out(&format!("inwire {VERSION}\n"));
            EXIT_OK
        }
        Command::Launch => launch(launcher, platform),
    }
}

fn launch(launcher: &Path, platform: &impl LauncherPlatform) -> i32 {
    // Elevation first: it needs nothing from disk, and an elevated terminal is
    // refused whatever state the install is in.
    match platform.is_elevated() {
        Ok(false) => {}
        Ok(true) => {
            platform.print_err(
                "inwire: this terminal is elevated, and Inwire does not start elevated \
                 (the packet dissector must never parse hostile bytes as an administrator).\n\
                 Open a normal (non-elevated) terminal and run `inwire` there.\n",
            );
            return EXIT_ELEVATED;
        }
        Err(e) => {
            platform.print_err(&format!(
                "inwire: could not tell whether this terminal is elevated ({e}); not starting Inwire.\n"
            ));
            return EXIT_LAUNCH_FAILED;
        }
    }

    let desktop = match resolve_desktop(launcher, platform) {
        Ok(p) => p,
        Err(CliError::MissingPayload(p)) => {
            platform.print_err(&format!(
                "inwire: Inwire.exe was not found at {}. Reinstall Inwire.\n",
                p.display()
            ));
            return EXIT_PAYLOAD_MISSING;
        }
        Err(CliError::Layout(p)) => {
            platform.print_err(&format!(
                "inwire: this launcher is at \"{}\", not at <Inwire folder>\\bin\\inwire.exe, \
                 so it cannot find the app. Reinstall Inwire.\n",
                p.display()
            ));
            return EXIT_PAYLOAD_MISSING;
        }
        Err(CliError::Usage) => {
            platform.print_err(USAGE);
            return EXIT_USAGE;
        }
    };

    match platform.file_product_version(&desktop) {
        Ok(v) if versions_match(VERSION, &v) => {}
        Ok(v) => {
            platform.print_err(&format!(
                "inwire: {} is version {v}, but this launcher is {VERSION}. \
                 They are from different installs; reinstall Inwire.\n",
                desktop.display()
            ));
            return EXIT_VERSION_MISMATCH;
        }
        Err(e) => {
            platform.print_err(&format!(
                "inwire: could not read the version of {} ({e}); this launcher is {VERSION}. \
                 Reinstall Inwire.\n",
                desktop.display()
            ));
            return EXIT_VERSION_MISMATCH;
        }
    }

    match platform.launch_detached(&desktop) {
        Ok(()) => EXIT_OK,
        Err(e) => {
            platform.print_err(&format!(
                "inwire: could not start {}: {e}\n",
                desktop.display()
            ));
            EXIT_LAUNCH_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    struct Fake {
        elevated: Result<bool, String>,
        product_version: Result<String, String>,
        launch: Result<(), String>,
        payload_exists: bool,
        calls: RefCell<Vec<String>>,
        out: RefCell<String>,
        err: RefCell<String>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                elevated: Ok(false),
                product_version: Ok(VERSION.to_string()),
                launch: Ok(()),
                payload_exists: true,
                calls: RefCell::new(Vec::new()),
                out: RefCell::new(String::new()),
                err: RefCell::new(String::new()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl LauncherPlatform for Fake {
        fn is_elevated(&self) -> Result<bool, String> {
            self.calls.borrow_mut().push("is_elevated".into());
            self.elevated.clone()
        }
        fn file_product_version(&self, exe: &Path) -> Result<String, String> {
            self.calls
                .borrow_mut()
                .push(format!("file_product_version {}", exe.display()));
            self.product_version.clone()
        }
        fn launch_detached(&self, exe: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("launch {}", exe.display()));
            self.launch.clone()
        }
        fn exists(&self, path: &Path) -> bool {
            self.calls
                .borrow_mut()
                .push(format!("exists {}", path.display()));
            self.payload_exists
        }
        fn print_out(&self, text: &str) {
            self.out.borrow_mut().push_str(text);
        }
        fn print_err(&self, text: &str) {
            self.err.borrow_mut().push_str(text);
        }
    }

    const LAUNCHER: &str = r"C:\Program Files\Inwire\bin\inwire.exe";
    const DESKTOP: &str = r"C:\Program Files\Inwire\Inwire.exe";

    // --- parsing -------------------------------------------------------------

    #[test]
    fn no_arguments_launches() {
        assert_eq!(parse_command(&[]), Ok(Command::Launch));
    }

    #[test]
    fn help_and_version_exactly() {
        assert_eq!(parse_command(&args(&["--help"])), Ok(Command::Help));
        assert_eq!(parse_command(&args(&["--version"])), Ok(Command::Version));
    }

    #[test]
    fn everything_else_is_usage() {
        for bad in [
            vec!["-h"],
            vec!["/?"],
            vec!["-v"],
            vec!["--Help"],
            vec!["--help", "--version"],
            vec!["--version", "x"],
            vec!["--unknown"],
            vec!["x"],
            vec![""],
            vec!["--help="],
            vec!["--"],
        ] {
            assert_eq!(parse_command(&args(&bad)), Err(CliError::Usage), "{bad:?}");
        }
    }

    #[test]
    fn non_utf8_is_usage() {
        use std::os::windows::ffi::OsStringExt;
        let bad = OsString::from_wide(&[0x2d, 0x2d, 0xD800]);
        assert_eq!(parse_command(&[bad]), Err(CliError::Usage));
    }

    // --- path resolution -----------------------------------------------------

    #[test]
    fn resolves_beside_bin() {
        assert_eq!(
            desktop_path(Path::new(LAUNCHER)),
            Ok(PathBuf::from(DESKTOP))
        );
    }

    #[test]
    fn bin_is_case_insensitive() {
        assert_eq!(
            desktop_path(Path::new(r"C:\Inwire\BIN\inwire.exe")),
            Ok(PathBuf::from(r"C:\Inwire\Inwire.exe"))
        );
    }

    #[test]
    fn spaces_unicode_and_metacharacters_resolve_literally() {
        for app in [
            r"C:\Program Files\Inw ïre ✓",
            r"C:\a;b&c",
            r"C:\$(whoami)",
            r"C:\`tick`",
            r"C:\%PATH%",
            r"C:\Inw ïre & co",
            r"C:\one'quote",
        ] {
            let launcher = format!(r"{app}\bin\inwire.exe");
            assert_eq!(
                desktop_path(Path::new(&launcher)),
                Ok(PathBuf::from(format!(r"{app}\Inwire.exe"))),
                "{app}"
            );
        }
    }

    #[test]
    fn launcher_outside_bin_is_a_layout_error() {
        for bad in [
            r"C:\Program Files\Inwire\inwire.exe",
            r"C:\Program Files\Inwire\sbin\inwire.exe",
            r"C:\Program Files\Inwire\bin\x\inwire.exe",
            r"C:\inwire.exe",
            r"inwire.exe",
            r"bin\inwire.exe",
            r"",
        ] {
            assert!(
                matches!(desktop_path(Path::new(bad)), Err(CliError::Layout(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn missing_payload_names_the_path() {
        let mut fake = Fake::new();
        fake.payload_exists = false;
        assert_eq!(
            resolve_desktop(Path::new(LAUNCHER), &fake),
            Err(CliError::MissingPayload(PathBuf::from(DESKTOP)))
        );
        assert_eq!(
            resolve_desktop(Path::new(LAUNCHER), &Fake::new()),
            Ok(PathBuf::from(DESKTOP))
        );
    }

    // --- run: nothing is touched ---------------------------------------------

    #[test]
    fn help_touches_nothing() {
        let fake = Fake::new();
        assert_eq!(run(Command::Help, Path::new(LAUNCHER), &fake), 0);
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        let out = fake.out.borrow().clone();
        assert!(out.contains("--version") && out.contains("--help"), "{out}");
        assert!(fake.err.borrow().is_empty());
    }

    #[test]
    fn version_touches_nothing_and_prints_the_version() {
        let fake = Fake::new();
        assert_eq!(run(Command::Version, Path::new(LAUNCHER), &fake), 0);
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        assert_eq!(fake.out.borrow().as_str(), format!("inwire {VERSION}\n"));
    }

    #[test]
    fn help_and_version_ignore_a_bad_launcher_path() {
        let fake = Fake::new();
        assert_eq!(run(Command::Help, Path::new(""), &fake), 0);
        assert_eq!(run(Command::Version, Path::new(""), &fake), 0);
        assert!(fake.calls().is_empty());
    }

    // --- run: launching ------------------------------------------------------

    #[test]
    fn successful_launch_calls_launch_once_with_the_absolute_path() {
        let fake = Fake::new();
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 0);
        let launches: Vec<_> = fake
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("launch "))
            .collect();
        assert_eq!(launches, vec![format!("launch {DESKTOP}")]);
        assert!(fake.err.borrow().is_empty());
    }

    #[test]
    fn launch_with_hostile_path_is_literal() {
        let fake = Fake::new();
        let launcher = r"C:\Inw ïre ✓ & %PATH%;$(x)`y`\bin\inwire.exe";
        assert_eq!(run(Command::Launch, Path::new(launcher), &fake), 0);
        assert!(fake
            .calls()
            .contains(&r"launch C:\Inw ïre ✓ & %PATH%;$(x)`y`\Inwire.exe".to_string()));
    }

    #[test]
    fn missing_payload_is_66_and_no_launch() {
        let mut fake = Fake::new();
        fake.payload_exists = false;
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 66);
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
        assert!(fake.err.borrow().contains(DESKTOP));
    }

    #[test]
    fn layout_error_is_66_and_no_launch() {
        let fake = Fake::new();
        assert_eq!(
            run(Command::Launch, Path::new(r"C:\Tools\inwire.exe"), &fake),
            66
        );
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
    }

    #[test]
    fn version_mismatch_is_65_and_no_launch() {
        let mut fake = Fake::new();
        fake.product_version = Ok("9.9.9".into());
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 65);
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
        let err = fake.err.borrow().clone();
        assert!(err.contains("9.9.9") && err.contains(VERSION), "{err}");
    }

    #[test]
    fn unreadable_version_is_65_and_no_launch() {
        let mut fake = Fake::new();
        fake.product_version = Err("no version resource".into());
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 65);
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
    }

    #[test]
    fn a_trailing_zero_fourth_group_is_tolerated_and_nothing_else() {
        assert!(versions_match(VERSION, VERSION));
        assert!(versions_match(VERSION, &format!("{VERSION}.0")));
        assert!(!versions_match(VERSION, &format!("{VERSION}.1")));
        assert!(!versions_match(VERSION, &format!("{VERSION}0")));
        assert!(!versions_match(VERSION, &format!("{VERSION}-beta")));
        assert!(!versions_match(VERSION, ""));
        assert!(!versions_match("0.5.0", "0.5"));
        assert!(!versions_match("0.5.0", "0.5.00"));
    }

    #[test]
    fn elevated_is_77_and_no_launch() {
        let mut fake = Fake::new();
        fake.elevated = Ok(true);
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 77);
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
        let err = fake.err.borrow().clone();
        assert!(err.contains("elevated") && err.contains("normal"), "{err}");
    }

    #[test]
    fn elevation_unknown_is_71_and_no_launch() {
        let mut fake = Fake::new();
        fake.elevated = Err("token".into());
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 71);
        assert!(!fake.calls().iter().any(|c| c.starts_with("launch ")));
    }

    #[test]
    fn launch_failure_is_71_and_shows_the_os_error() {
        let mut fake = Fake::new();
        fake.launch = Err("Access is denied. (os error 5)".into());
        assert_eq!(run(Command::Launch, Path::new(LAUNCHER), &fake), 71);
        assert!(fake.err.borrow().contains("Access is denied"));
    }
}
