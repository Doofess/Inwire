//! Serves one connection on a pipe and echoes every frame back.
//!
//!     cargo run --example pipe_serve -- --name \\.\pipe\inwire-probe
//!
//! Exists so the Rust pipe can be driven by the **app's own client** -
//! `scripts/agent/pipe-interop.ts` connects with the same `net.connect` and the
//! same `agentFraming.ts` the renderer uses. Unit tests prove the framing
//! against fixed bytes; this proves the transport against the thing that will
//! actually talk to it, which is where the overlapped-I/O trap lives: a
//! synchronous handle serialises writes behind a blocked read, so the handshake
//! works and the traffic does not.
//!
//! A private pipe name by default. The real one is held by the installed
//! service, and two servers on one name is not a state worth debugging.

#[cfg(not(windows))]
fn main() {
    eprintln!("the pipe is Windows-only; macOS and Linux use the WebSocket agent");
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::sync::Arc;
    use std::thread;

    use inwire_agent::framing::{FRAME_BINARY, FRAME_JSON};
    use inwire_agent::pipe::{self, Connection};

    let args: Vec<String> = std::env::args().collect();
    let name = args
        .windows(2)
        .find(|w| w[0] == "--name")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| r"\\.\pipe\inwire-probe".to_string());
    let expect: usize = args
        .windows(2)
        .find(|w| w[0] == "--frames")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(4);

    let instance = pipe::create_instance(&name, pipe::PIPE_SDDL, pipe::MAX_INSTANCES, true)?;
    println!("listening on {name}");
    println!("descriptor  {}", pipe::PIPE_SDDL);

    pipe::accept(&instance)?;
    println!("client connected");

    let conn = Connection::new();
    let outbound = Arc::clone(&conn.outbound);

    // The writer is its own thread with its own OVERLAPPED and its own event,
    // which is the whole reason this arrangement exists.
    let instance = Arc::new(instance);
    let writer_instance = Arc::clone(&instance);
    let writer = thread::spawn(move || {
        let _ = pipe::write_loop(&writer_instance, &outbound);
    });

    let mut seen = 0usize;
    let result = pipe::read_loop(&instance, |frame| {
        seen += 1;
        let kind = match frame.kind {
            FRAME_JSON => "json",
            FRAME_BINARY => "binary",
            _ => "?",
        };
        println!("recv {seen:3}  {kind:6} {} bytes", frame.payload.len());
        // Echo it straight back, so the client can prove a round trip over the
        // real transport rather than over a description of it.
        conn.send(frame.kind, &frame.payload, 0)
            .map_err(std::io::Error::other)?;
        if seen >= expect {
            // Tell the writer to finish once the last echo is queued behind it.
            conn.outbound.shutdown();
        }
        Ok(())
    });

    conn.outbound.shutdown();
    pipe::cancel_io(&instance);
    let _ = writer.join();
    println!("frames seen {seen}");
    println!("shed        {}", conn.outbound.dropped());
    result
}
