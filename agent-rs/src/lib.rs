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

pub mod framing;
pub mod outbound;
pub mod protocol;
pub mod session;
pub mod wire;

// Windows-only: this is the Npcap surface, and the Python agent remains the
// implementation on macOS and Linux.
#[cfg(windows)]
pub mod npcap;
#[cfg(windows)]
pub mod pipe;
