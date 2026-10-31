//! `inwire`: the narrow console launcher installed at `<app>\bin\inwire.exe`.
//! See `command.rs` for the arguments and exit codes.

mod command;
mod platform;

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let platform = platform::WindowsPlatform;
    let code = match command::parse_command(&args) {
        Err(_) => {
            use command::LauncherPlatform;
            platform.print_err(command::USAGE);
            command::EXIT_USAGE
        }
        Ok(cmd) => {
            // Only a launch needs to know where it is. An unreadable path
            // becomes an empty one, which the layout check turns into exit 66.
            let launcher = std::env::current_exe().unwrap_or_default();
            command::run(cmd, &launcher, &platform)
        }
    };
    std::process::exit(code);
}
