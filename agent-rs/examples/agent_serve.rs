//! The Rust agent, end to end, minus the SCM wrapper.
//!
//!     cargo run --example agent_serve -- --device "\Device\NPF_..." \
//!       [--name \\.\pipe\inwire-probe]
//!
//! Npcap into the bounded queue, the queue into batches, the batches down the
//! pipe - with the control protocol on the same connection. Everything the
//! installed service does except being started by the SCM, which is the one
//! part that needs elevation and therefore the one part this cannot prove.
//!
//! Driven by `scripts/agent/agent-interop.ts`, which speaks the real protocol
//! and decodes the frames with the renderer's own `agentBinary.ts`. That is the
//! test worth having: the unit tests prove each piece against fixed bytes, and
//! this proves the pieces against each other and against the app.

#[cfg(not(windows))]
fn main() {
    eprintln!("the agent is Windows-only here; macOS and Linux keep the Python one");
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use inwire_agent::framing::{FRAME_BINARY, FRAME_JSON};
    use inwire_agent::npcap::{Npcap, Read};
    use inwire_agent::pipe::{self, Connection};
    use inwire_agent::protocol::{self, CaptureState, Command, Interface, InterfaceStats, ParseError};
    use inwire_agent::session::{Drain, FrameQueue, BATCH_INTERVAL_MS};
    use inwire_agent::wire;

    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| args.windows(2).find(|w| w[0] == k).map(|w| w[1].clone());
    let name = arg("--name").unwrap_or_else(|| r"\\.\pipe\inwire-probe".to_string());
    let Some(device) = arg("--device") else {
        eprintln!("pass --device <\\Device\\NPF_...>; `--example probe -- --list` names them");
        return Ok(());
    };

    // **Leaked deliberately.** The DLL stays loaded for the life of the process
    // - a service never unloads it - and this is what lets a `Capture` borrowed
    // from it move into a sniffer thread without an Arc indirection on the hot
    // path. The lifetime is honest rather than erased: the library really does
    // outlive every handle.
    let npcap: &'static Npcap = Box::leak(Box::new(Npcap::load()?));

    let interfaces = vec![Interface {
        id: 0,
        name: device.clone(),
        label: npcap
            .devices()?
            .into_iter()
            .find(|d| d.name == device)
            .and_then(|d| d.description)
            .unwrap_or_else(|| device.clone()),
        // This harness names one device on the command line and never opens it
        // twice. Saying nothing is the honest answer, and the app falls back
        // to Ethernet - which is what this harness has always captured.
        link_type: None,
        ts_precision: None,
    }];

    let instance = Arc::new(pipe::create_instance(&name, pipe::PIPE_SDDL, pipe::MAX_INSTANCES)?);
    eprintln!("listening on {name}");
    pipe::accept(&instance)?;
    eprintln!("client connected");

    let conn = Arc::new(Connection::new());
    let outbound = Arc::clone(&conn.outbound);
    let writer_instance = Arc::clone(&instance);
    let writer = thread::spawn(move || {
        let _ = pipe::write_loop(&writer_instance, &outbound);
    });

    let send_json = |value: &serde_json::Value| {
        let _ = conn.send(FRAME_JSON, value.to_string().as_bytes(), 0);
    };

    send_json(&protocol::hello(
        "0.0.0-dev",
        CaptureState::Idle,
        &interfaces,
        "rs-1",
        None,
        None,
    ));

    let queue = Arc::new(FrameQueue::with_defaults());
    let running = Arc::new(AtomicBool::new(false));
    let seq = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let kernel = Arc::new(Mutex::new(None::<(u32, u32)>));
    let owner: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();

    let read = pipe::read_loop(&instance, |frame| {
        if frame.kind != FRAME_JSON {
            // Binary from the client is not part of the protocol. Logged and
            // ignored rather than treated as a framing failure: the stream
            // position is still known, so there is nothing to resynchronise.
            eprintln!("ignoring a binary frame from the client");
            return Ok(());
        }
        let text = String::from_utf8_lossy(&frame.payload).to_string();
        let command = match protocol::parse_command(&text) {
            Ok(c) => c,
            Err(ParseError::Unknown(what)) => {
                send_json(&protocol::error(
                    "unknown_command",
                    &format!("This agent does not understand '{what}'."),
                ));
                return Ok(());
            }
            Err(ParseError::EmptyInterfaces) => {
                send_json(&protocol::error(
                    "empty_interfaces",
                    "A capture needs at least one adapter.",
                ));
                return Ok(());
            }
            Err(e) => {
                send_json(&protocol::error("bad_message", &format!("{e:?}")));
                return Ok(());
            }
        };

        // The one rule with teeth, and it is the same pure function the unit
        // tests assert: a capture belongs to the client that started it.
        let held = owner.lock().unwrap().clone();
        if !protocol::may_run(&command, "rs-1", held.as_deref()) {
            send_json(&protocol::error(
                "capture_busy",
                "Another client is capturing on this machine.",
            ));
            return Ok(());
        }

        match command {
            Command::StartCapture(_) if !running.load(Ordering::SeqCst) => {
                running.store(true, Ordering::SeqCst);
                *owner.lock().unwrap() = Some("rs-1".into());

                let mut cap = npcap.open(&device, inwire_agent::npcap::OpenOptions { promiscuous: true, snaplen: inwire_agent::protocol::MAX_SNAPLEN })?;
                cap.set_kernel_buffer(
                    inwire_agent::session::kernel_buffer_bytes(
                        inwire_agent::session::available_cores(),
                    ) as i32,
                )?;

                // The sniffer: encode on this thread, so the pump sees finished
                // bytes rather than live driver buffers.
                let (q, run, sq, rx, kn) = (
                    Arc::clone(&queue),
                    Arc::clone(&running),
                    Arc::clone(&seq),
                    Arc::clone(&received),
                    Arc::clone(&kernel),
                );
                workers.push(thread::spawn(move || {
                    while run.load(Ordering::SeqCst) {
                        match cap.next() {
                            Ok(Read::Timeout) => {}
                            Ok(Read::Frame { data, ts_ns, wire_len }) => {
                                let n = sq.fetch_add(1, Ordering::Relaxed);
                                rx.fetch_add(1, Ordering::Relaxed);
                                match wire::encode_record(n as u32, 0, ts_ns, wire_len as usize, data) {
                                    Ok(record) => q.push(record),
                                    // A frame too long for the length field is
                                    // refused rather than masked; losing one is
                                    // better than desynchronising the decoder.
                                    Err(e) => eprintln!("dropping a frame: {e}"),
                                }
                            }
                            Err(e) => {
                                eprintln!("capture failed: {e}");
                                run.store(false, Ordering::SeqCst);
                                return;
                            }
                        }
                        if let Some(s) = cap.stats() {
                            *kn.lock().unwrap() = Some(s);
                        }
                    }
                }));

                // The pump. **It sleeps on `Drained` and on nothing else** -
                // the whole point of `drain` returning why it stopped.
                let (q, run, conn2, kn, rx, sq) = (
                    Arc::clone(&queue),
                    Arc::clone(&running),
                    Arc::clone(&conn),
                    Arc::clone(&kernel),
                    Arc::clone(&received),
                    Arc::clone(&seq),
                );
                workers.push(thread::spawn(move || {
                    let mut last_stats = Instant::now();
                    while run.load(Ordering::SeqCst) {
                        let (batch, state) = q.drain();
                        if !batch.is_empty() {
                            if let Ok(payload) = wire::encode_batch(&batch) {
                                if conn2.send(FRAME_BINARY, &payload, batch.len() as u64).is_err() {
                                    return;
                                }
                            }
                        }
                        if last_stats.elapsed() >= Duration::from_secs(1) {
                            last_stats = Instant::now();
                            let stats = protocol::capture_stats(
                                1000,
                                sq.load(Ordering::Relaxed),
                                q.dropped(),
                                Some(conn2.outbound.dropped()),
                                &[InterfaceStats {
                                    iface: 0,
                                    received: rx.load(Ordering::Relaxed),
                                    kernel: *kn.lock().unwrap(),
                                }],
                            );
                            let _ = conn2.send(FRAME_JSON, stats.to_string().as_bytes(), 0);
                        }
                        if state == Drain::Drained {
                            thread::sleep(Duration::from_millis(BATCH_INTERVAL_MS));
                        }
                    }
                }));

                send_json(&protocol::state(CaptureState::Sniffing, &interfaces, Some("rs-1")));
            }
            Command::StopCapture => {
                running.store(false, Ordering::SeqCst);
                // **A final capture_stats BEFORE the queue is discarded**, and
                // before the state message that tells the app the capture is
                // over. Without it the last figures the app ever sees are up to
                // a second stale, and a burst in that last second is invisible -
                // which is exactly when somebody looks at the number.
                //
                // `queuedAtStop` is what the discard is about to throw away.
                // Those frames were captured and never delivered, and they were
                // not lost to pressure, so counting them as a drop would report
                // a loss the user did not suffer - but leaving them out of the
                // message entirely makes the figures fail to add up, which is
                // how somebody concludes the counters are wrong.
                let (queued, _) = queue.depth();
                let mut final_stats = protocol::capture_stats(
                    1000,
                    seq.load(Ordering::Relaxed),
                    queue.dropped(),
                    Some(conn.outbound.dropped()),
                    &[InterfaceStats {
                        iface: 0,
                        received: received.load(Ordering::Relaxed),
                        kernel: *kernel.lock().unwrap(),
                    }],
                );
                if let Some(obj) = final_stats.as_object_mut() {
                    obj.insert("queuedAtStop".into(), serde_json::json!(queued));
                }
                send_json(&final_stats);

                queue.discard();
                *owner.lock().unwrap() = None;
                send_json(&protocol::state(CaptureState::Idle, &interfaces, None));
            }
            _ => {
                // Subscriptions this example does not serve. Answered rather
                // than ignored: silence is the shape the app cannot diagnose.
                send_json(&protocol::state(
                    if running.load(Ordering::SeqCst) { CaptureState::Sniffing } else { CaptureState::Idle },
                    &interfaces,
                    owner.lock().unwrap().clone().as_deref(),
                ));
            }
        }
        Ok(())
    });

    running.store(false, Ordering::SeqCst);
    conn.outbound.shutdown();
    pipe::cancel_io(&instance);
    for w in workers {
        let _ = w.join();
    }
    let _ = writer.join();
    eprintln!(
        "queue shed {}, pipe shed {}",
        queue.dropped(),
        conn.outbound.dropped()
    );
    read
}
