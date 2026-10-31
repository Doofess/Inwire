//! The Win32 side of the launcher: std plus hand-written FFI, no crates.
//!
//! Three questions are put to the OS - is this process elevated, what does that
//! exe's VERSIONINFO say, start that exe detached - and each is a few calls.
//! None of it is exercised by the unit tests (they use a fake); the built
//! exe is driven by `scripts/distribution/launcher-tests.ps1`.

use crate::command::LauncherPlatform;
use std::ffi::c_void;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

type Handle = isize;

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: u32 = 20; // TokenElevation

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

#[repr(C)]
struct TokenElevation {
    token_is_elevated: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetStdHandle(which: u32) -> Handle;
    fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
}

const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

/// Stops this process's own standard handles from being inherited by the app.
///
/// `Stdio::null()` gives the child NUL for its three standard handles, but
/// `CreateProcess` is still called with handle inheritance on, so every
/// inheritable handle this process holds is copied into the child as well - and
/// when the launcher itself was started with a pipe on stdout (`inwire | more`, a
/// script capturing its output, a Node `spawn`), that pipe's write end would then
/// stay open for as long as the app runs and the reader would never see the end of
/// the output. Found by `scripts/distribution/launcher-tests.ps1`, which reads
/// both streams to the end. Handles other than the standard three that a parent
/// leaked into this process are not touched.
fn make_std_handles_private() {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe {
            let handle = GetStdHandle(which);
            if handle != 0 && handle != -1 {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
}

/// Search System32 only: never the application folder or the current directory.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

type SizeFn = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
type InfoFn = unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32;
type QueryFn = unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32;

/// version.dll, loaded from System32 at the moment it is needed. It is loaded
/// rather than linked because the GNU toolchain this repo builds with ships no
/// `libversion.a` import library (and a raw-dylib import needs an assembler it
/// also lacks); loading it by name from System32 only is what an import would
/// do anyway, and a `--help` never pays for it.
struct VersionApi {
    module: Handle,
    size: SizeFn,
    info: InfoFn,
    query: QueryFn,
}

impl VersionApi {
    unsafe fn load() -> Result<VersionApi, String> {
        let name = wide_str("version.dll");
        let module = LoadLibraryExW(name.as_ptr(), 0, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module == 0 {
            return Err(format!("LoadLibraryExW(version.dll): {}", std::io::Error::last_os_error()));
        }
        let get = |symbol: &'static [u8]| -> Result<*mut c_void, String> {
            let p = GetProcAddress(module, symbol.as_ptr());
            if p.is_null() {
                Err(format!(
                    "version.dll has no {}",
                    String::from_utf8_lossy(&symbol[..symbol.len() - 1])
                ))
            } else {
                Ok(p)
            }
        };
        let size = get(b"GetFileVersionInfoSizeW\0");
        let info = get(b"GetFileVersionInfoW\0");
        let query = get(b"VerQueryValueW\0");
        match (size, info, query) {
            (Ok(size), Ok(info), Ok(query)) => Ok(VersionApi {
                module,
                size: std::mem::transmute::<*mut c_void, SizeFn>(size),
                info: std::mem::transmute::<*mut c_void, InfoFn>(info),
                query: std::mem::transmute::<*mut c_void, QueryFn>(query),
            }),
            (a, b, c) => {
                FreeLibrary(module);
                Err(a.err().or(b.err()).or(c.err()).unwrap_or_default())
            }
        }
    }
}

impl Drop for VersionApi {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

pub struct WindowsPlatform;

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl LauncherPlatform for WindowsPlatform {
    fn is_elevated(&self) -> Result<bool, String> {
        unsafe {
            let mut token: Handle = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(format!(
                    "OpenProcessToken: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut elevation = TokenElevation {
                token_is_elevated: 0,
            };
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                &mut elevation as *mut TokenElevation as *mut c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut returned,
            );
            let error = std::io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(format!("GetTokenInformation: {error}"));
            }
            Ok(elevation.token_is_elevated != 0)
        }
    }

    fn file_product_version(&self, exe: &Path) -> Result<String, String> {
        let path = wide(exe.as_os_str());
        unsafe {
            let api = VersionApi::load()?;
            let mut ignored = 0u32;
            let size = (api.size)(path.as_ptr(), &mut ignored);
            if size == 0 {
                return Err(format!(
                    "GetFileVersionInfoSizeW: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut data = vec![0u8; size as usize];
            if (api.info)(path.as_ptr(), 0, size, data.as_mut_ptr() as *mut c_void) == 0 {
                return Err(format!(
                    "GetFileVersionInfoW: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // The language/codepage pairs the file declares, then the string
            // under each; the usual en-US Unicode pair is the fallback for a
            // file that declares none.
            let mut pairs: Vec<(u16, u16)> = Vec::new();
            let mut buf: *mut c_void = std::ptr::null_mut();
            let mut len = 0u32;
            let translation = wide_str("\\VarFileInfo\\Translation");
            if (api.query)(
                data.as_ptr() as *const c_void,
                translation.as_ptr(),
                &mut buf,
                &mut len,
            ) != 0
                && !buf.is_null()
            {
                let words = buf as *const u16;
                for i in 0..(len as usize / 4) {
                    let lang = std::ptr::read_unaligned(words.add(i * 2));
                    let codepage = std::ptr::read_unaligned(words.add(i * 2 + 1));
                    pairs.push((lang, codepage));
                }
            }
            if pairs.is_empty() {
                pairs.push((0x0409, 0x04B0));
            }

            for (lang, codepage) in pairs {
                let query = wide_str(&format!(
                    "\\StringFileInfo\\{lang:04x}{codepage:04x}\\ProductVersion"
                ));
                let mut value: *mut c_void = std::ptr::null_mut();
                let mut chars = 0u32;
                if (api.query)(
                    data.as_ptr() as *const c_void,
                    query.as_ptr(),
                    &mut value,
                    &mut chars,
                ) != 0
                    && !value.is_null()
                    && chars > 0
                {
                    let units = std::slice::from_raw_parts(value as *const u16, chars as usize);
                    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
                    return Ok(String::from_utf16_lossy(&units[..end]));
                }
            }
            Err("no ProductVersion string in its version resource".into())
        }
    }

    fn launch_detached(&self, exe: &Path) -> Result<(), String> {
        // An absolute path with no arguments, from the app's own folder, with
        // no handles shared and no console: the new process is not ours to wait
        // for, and `Child` does not wait when dropped. Focus on a second start
        // is the app's own single-instance handling (electron/main.ts).
        let dir = exe.parent().ok_or("the app path has no folder")?;
        make_std_handles_private();
        Command::new(exe)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map(|_child| ())
            .map_err(|e| e.to_string())
    }

    fn exists(&self, path: &Path) -> bool {
        path.is_file()
    }

    // `write!` and an ignored result, never `println!`: a closed pipe
    // (`inwire --help | head -0`) must not turn into a panic.
    fn print_out(&self, text: &str) {
        let _ = std::io::stdout().write_all(text.as_bytes());
    }

    fn print_err(&self, text: &str) {
        let _ = std::io::stderr().write_all(text.as_bytes());
    }
}
