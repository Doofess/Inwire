//! Inwire's capture agent, in Rust.
//!
//! Replaces `local-agent/` **on Windows only**. macOS and Linux keep the Python
//! tarball and its WebSocket, because those platforms have no desktop app to
//! talk to yet and porting for them would double the surface for no consumer.
//!
//! ## What this is for, and what it is not for
//!
//! It is not for throughput. That was the assumed argument and it is measured
//! and dead: the sniffer thread costs **2.87 us of work per frame** on a real
//! adapter here - a copy and a callback - at a utilisation of 0.003. Python was
//! never the constraint on the capture path, and the frames that were being
//! lost were lost to a sleep in the pump, which is fixed in the Python agent.
//!
//! What it is for:
//!
//! - **One signed executable** instead of a 34 MB `--onedir` tree of unsigned
//!   `.pyd` files. Signing a wrapper does not sign what the wrapper loads.
//! - **Start time**, which became load-bearing when the service moved to
//!   demand-start: the app starts it at launch, so the agent's cold start is on
//!   the critical path of opening Inwire. Measured for the Python agent here:
//!   240 ms of imports before the frozen bootstrap is counted.
//! - **Two defects that are unrepresentable rather than fixed.** The Python
//!   agent crosses live libpcap handles to its event loop with a use-after-free
//!   window at every stop, and carries an undeclared module global whose three
//!   `is not None` guards raise `NameError` instead of returning false.
//!
//! ## The port is byte-compatible first
//!
//! The wire format is open for revision, and it is being opened in a **second**
//! step rather than this one. Porting at byte-compatibility makes the existing
//! hand-written vectors an acceptance gate: `scripts/agent/wire-vectors.json`
//! holds the bytes, and Python, TypeScript and Rust are each checked against
//! that file rather than against their own copy of it. A format change then
//! moves one fixture and three implementations together, with the port already
//! proven underneath it.

/// The agent's version, which is Inwire's version (ADR 0035).
///
/// Sourced from `Cargo.toml`, which `scripts/agent/version.ts` holds to
/// `package.json` alongside `agent_version.py`, `REQUIRED_AGENT_VERSION` and the
/// installer's `MyAppVersion`. It is what `hello` carries and what `--version`
/// prints.
///
/// This crate's `version` was deliberately `0.0.0` while the agent still had a
/// version of its own and six places carried it - adding a seventh stamp to the
/// pile the collapse existed to remove would have been the wrong direction. The
/// collapse has landed, so this is now one more derived copy under one check.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod framing;
pub mod outbound;
pub mod pcapng;
pub mod protocol;
pub mod session;
pub mod wire;

// Windows-only: this is the Npcap surface, and the Python agent remains the
// implementation on macOS and Linux.
#[cfg(windows)]
pub mod adapter_config;
#[cfg(windows)]
pub mod adapters;
#[cfg(windows)]
pub mod agent_log;
// The capture lifecycle's decisions - ownership, start, stop, re-pointing, an
// adapter dying - behind two traits, so they can be tested without Npcap or a
// pipe. `runtime.rs` is the real implementation of both.
#[cfg(windows)]
pub mod capture_file;
#[cfg(windows)]
pub mod control;
// The subscriptions that report on the machine rather than on a capture -
// `interface_stats` and `adapter_config` - and their timers.
#[cfg(windows)]
pub mod host_feeds;
#[cfg(windows)]
pub mod if_table;
#[cfg(windows)]
pub mod npcap;
#[cfg(windows)]
pub mod npcap_access;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod restart;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod sockets;

// Real frames from `test/fixtures/`, for the tests that carry any.
#[cfg(test)]
pub(crate) mod fixture;
