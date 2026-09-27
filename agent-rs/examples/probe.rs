//! Drives the Rust capture path against a real adapter.
//!
//!     cargo run --example probe -- --list
//!     cargo run --example probe -- --device "\Device\NPF_{...}" --seconds 6
//!
//! Counts and timings only: no payload, address or packet content is printed.
//! It exists to answer the one question the unit tests cannot - whether the FFI
//! layouts are right against the real DLL, where a wrong `pcap_pkthdr` gives
//! plausible frames with nonsense lengths rather than an error.
use std::time::{Duration, Instant};

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe is Windows-only; the Python agent serves macOS and Linux");
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use inwire_agent::npcap::{Npcap, Read};

    let args: Vec<String> = std::env::args().collect();
    let npcap = Npcap::load()?;

    if args.iter().any(|a| a == "--list") {
        for (i, d) in npcap.devices()?.iter().enumerate() {
            println!("{i:2}  {}", d.description.as_deref().unwrap_or("(no description)"));
            println!("    {}", d.name);
        }
        return Ok(());
    }

    let device = args.windows(2).find(|w| w[0] == "--device").map(|w| w[1].clone());
    let Some(device) = device else {
        eprintln!("pass --list, or --device <name> [--seconds n]");
        return Ok(());
    };
    let seconds: f64 = args
        .windows(2)
        .find(|w| w[0] == "--seconds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(6.0);

    let mut cap = npcap.open(&device, inwire_agent::npcap::OpenOptions { promiscuous: true, snaplen: 65535 })?;
    let raised = cap.set_kernel_buffer(
        inwire_agent::session::kernel_buffer_bytes(inwire_agent::session::available_cores()) as i32,
    )?;
    println!("kernel buffer raised to 32 MB: {raised}");

    let deadline = Instant::now() + Duration::from_secs_f64(seconds);
    let (mut frames, mut bytes, mut timeouts) = (0u64, 0u64, 0u64);
    let mut copy_ns = 0u128;
    let mut smallest = usize::MAX;
    let mut largest = 0usize;
    // Kept so the wire format can be exercised on real frames below.
    // Bounded, because this is a diagnostic and not a capture buffer.
    let mut captured: Vec<(Vec<u8>, u64, u32)> = Vec::new();
    const KEEP: usize = 2000;
    let start = Instant::now();
    while Instant::now() < deadline {
        match cap.next()? {
            Read::Timeout => timeouts += 1,
            Read::Frame { data, ts_ns, wire_len } => {
                // The copy is what the agent would do next, and is the half of
                // the per-frame cost that is ours. Timed the same way the Python
                // profile now does, so the two numbers are comparable.
                let t = Instant::now();
                let owned = data.to_vec();
                copy_ns += t.elapsed().as_nanos();
                frames += 1;
                bytes += owned.len() as u64;
                smallest = smallest.min(owned.len());
                largest = largest.max(owned.len());
                // The sanity check the FFI exists to pass: a wire length below
                // what was captured means the header was read at wrong offsets.
                if captured.len() < KEEP {
                    captured.push((owned.clone(), ts_ns, wire_len));
                }
                if (wire_len as usize) < owned.len() {
                    eprintln!(
                        "STRUCT LAYOUT IS WRONG: wire_len {wire_len} < caplen {} (ts {ts_ns})",
                        owned.len()
                    );
                    std::process::exit(2);
                }
            }
        }
    }
    let wall = start.elapsed().as_secs_f64();

    // **The integration the unit tests cannot reach.** The vectors prove the
    // encoder against fixed bytes; this proves it against whatever the driver
    // actually just handed over - jumbo frames, empty ones, an LRO-coalesced
    // segment far above the MTU - and puts them back through the decoder.
    if !captured.is_empty() {
        use inwire_agent::wire;
        let records: Vec<Vec<u8>> = captured
            .iter()
            .enumerate()
            .map(|(i, (data, ts_ns, wire_len))| {
                wire::encode_record(i as u32, 0, *ts_ns, *wire_len as usize, data)
                    .expect("a frame captured at SNAPLEN always fits the length field")
            })
            .collect();
        let batch = wire::encode_batch(&records).expect("a non-empty batch encodes");
        let decoded = wire::decode_batch(&batch).expect("what we encoded decodes");
        assert_eq!(decoded.len(), captured.len());
        for (got, (data, ts_ns, wire_len)) in decoded.iter().zip(&captured) {
            assert_eq!(&got.data, data, "a frame did not survive the round trip");
            assert_eq!(got.ts_ns, *ts_ns, "a timestamp did not survive");
            assert_eq!(got.orig_len, *wire_len, "a wire length did not survive");
        }
        println!(
            "round trip    {} real frames encoded and decoded byte-identical ({} bytes on the wire)",
            decoded.len(),
            batch.len()
        );
    }
    println!("frames        {frames} in {wall:.2}s = {:.0} f/s", frames as f64 / wall);
    println!("bytes         {bytes} ({:.1} MB)", bytes as f64 / 1e6);
    if frames > 0 {
        println!("mean frame    {:.0} bytes (min {smallest}, max {largest})", bytes as f64 / frames as f64);
        println!("copy          {:.2} us/frame", copy_ns as f64 / frames as f64 / 1000.0);
    }
    println!("timeouts      {timeouts}");
    match cap.stats() {
        None => println!("driver stats  unreadable"),
        Some((recv, drop)) => println!("driver        delivered {recv}, DROPPED {drop}"),
    }
    Ok(())
}
