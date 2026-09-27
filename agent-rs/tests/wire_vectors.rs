//! Rust against the golden vectors, which Python and TypeScript also read.
//!
//! The point of the shared file is that no implementation gets to bring its own
//! bytes. Three encoders asserting their own hand-written copies of the same
//! vector report that each agrees with itself, which is what they did before
//! `scripts/agent/wire-vectors.json` existed.
//!
//!     cargo test --manifest-path agent-rs/Cargo.toml

use std::fs;
use std::path::PathBuf;

use inwire_agent::framing::{self, FrameReader, FramingError};
use inwire_agent::wire::{self, WireError};

fn fixture() -> serde_json::Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("agent-rs has a parent")
        .join("scripts")
        .join("agent")
        .join("wire-vectors.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the fixture is valid JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn unb64(s: &str) -> Vec<u8> {
    // Base64 by hand rather than a dependency: this decodes four fixture
    // strings in a test and is not worth a crate in a service's dependency
    // tree, which CLAUDE.md's dependency rule asks about before anything lands.
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = TABLE
            .iter()
            .position(|&t| t == c)
            .unwrap_or_else(|| panic!("not base64: {c}")) as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// A record's timestamp, which the file holds as a decimal STRING: epoch
/// nanoseconds are past 2^53, and TypeScript's `JSON.parse` would round a
/// number there before any decoder was asked about it.
fn ts_ns(record: &serde_json::Value) -> u64 {
    record["tsNs"].as_str().expect("tsNs is a string").parse().expect("tsNs is an integer")
}

#[test]
fn constants_match_the_fixture() {
    let f = fixture();
    let c = &f["constants"];
    assert_eq!(c["recordBytes"].as_u64().unwrap() as usize, wire::RECORD_BYTES);
    assert_eq!(c["headerBytes"].as_u64().unwrap() as usize, wire::HEADER_BYTES);
    assert_eq!(c["magic"].as_str().unwrap().as_bytes(), &wire::MAGIC);
    assert_eq!(c["version"].as_u64().unwrap() as u8, wire::VERSION);
    assert_eq!(c["frameJson"].as_u64().unwrap() as u8, framing::FRAME_JSON);
    assert_eq!(c["frameBinary"].as_u64().unwrap() as u8, framing::FRAME_BINARY);
    assert_eq!(
        c["maxFrameBytes"].as_u64().unwrap() as usize,
        framing::MAX_FRAME_BYTES
    );
}

#[test]
fn each_record_encodes_to_the_golden_bytes() {
    let f = fixture();
    for (i, r) in f["records"].as_array().unwrap().iter().enumerate() {
        let data = unb64(r["dataBase64"].as_str().unwrap());
        let got = wire::encode_record(
            r["seq"].as_u64().unwrap() as u32,
            r["iface"].as_u64().unwrap() as u16,
            ts_ns(r),
            r["origLen"].as_u64().unwrap() as usize,
            &data,
        )
        .expect("the fixture's records all encode");
        assert_eq!(
            got,
            unhex(r["encodedHex"].as_str().unwrap()),
            "record {i} does not match the golden bytes"
        );
    }
}

#[test]
fn the_batch_encodes_to_the_golden_bytes() {
    let f = fixture();
    let records: Vec<Vec<u8>> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let data = unb64(r["dataBase64"].as_str().unwrap());
            wire::encode_record(
                r["seq"].as_u64().unwrap() as u32,
                r["iface"].as_u64().unwrap() as u16,
                ts_ns(r),
                r["origLen"].as_u64().unwrap() as usize,
                &data,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        wire::encode_batch(&records).unwrap(),
        unhex(f["batchHex"].as_str().unwrap())
    );
}

#[test]
fn the_batch_decodes_back_to_what_went_in() {
    let f = fixture();
    let decoded = wire::decode_batch(&unhex(f["batchHex"].as_str().unwrap())).unwrap();
    let expected = f["records"].as_array().unwrap();
    assert_eq!(decoded.len(), expected.len());
    for (got, want) in decoded.iter().zip(expected) {
        assert_eq!(got.seq, want["seq"].as_u64().unwrap() as u32);
        assert_eq!(got.iface, want["iface"].as_u64().unwrap() as u16);
        assert_eq!(got.ts_ns, ts_ns(want));
        // The wire length is RECONSTRUCTED from capLen + extra, which is the
        // half of this format most likely to be got wrong by a new decoder.
        assert_eq!(got.orig_len as u64, want["origLen"].as_u64().unwrap());
        assert_eq!(got.data, unb64(want["dataBase64"].as_str().unwrap()));
    }
}

#[test]
fn each_control_frame_encodes_to_the_golden_bytes() {
    let f = fixture();
    for (i, fr) in f["frames"].as_array().unwrap().iter().enumerate() {
        let got = match fr["kind"].as_str().unwrap() {
            "json" => framing::encode_json(fr["text"].as_str().unwrap()).unwrap(),
            "binary" => framing::encode_frame(
                framing::FRAME_BINARY,
                &unb64(fr["dataBase64"].as_str().unwrap()),
            )
            .unwrap(),
            other => panic!("unknown frame kind in the fixture: {other}"),
        };
        assert_eq!(
            got,
            unhex(fr["encodedHex"].as_str().unwrap()),
            "frame {i} does not match the golden bytes"
        );
    }
}

#[test]
fn a_stream_delivered_one_byte_at_a_time_still_frames() {
    // The property a pipe actually needs: a read returns whatever happened to be
    // in the buffer, so a header can arrive in two pieces and a payload in ten.
    let f = fixture();
    let mut stream = Vec::new();
    for fr in f["frames"].as_array().unwrap() {
        stream.extend_from_slice(&unhex(fr["encodedHex"].as_str().unwrap()));
    }
    let mut reader = FrameReader::new();
    let mut got = Vec::new();
    for b in &stream {
        got.extend(reader.push(&[*b]).unwrap());
    }
    assert_eq!(got.len(), f["frames"].as_array().unwrap().len());
    assert_eq!(reader.pending(), 0, "nothing is left over");

    // And all at once, which must produce exactly the same frames.
    let mut whole = FrameReader::new();
    assert_eq!(whole.push(&stream).unwrap(), got);
}

#[test]
fn a_frame_past_the_ceiling_is_refused_on_its_header_alone() {
    // Five bytes must never be able to ask a privileged service for four
    // gigabytes, so the check is on the declared length before the payload is
    // waited for.
    let mut reader = FrameReader::new();
    let mut header = Vec::new();
    header.extend_from_slice(&((framing::MAX_FRAME_BYTES + 1) as u32).to_le_bytes());
    header.push(framing::FRAME_JSON);
    assert_eq!(
        reader.push(&header),
        Err(FramingError::TooLong(framing::MAX_FRAME_BYTES + 1))
    );
}

#[test]
fn a_zero_length_frame_is_refused() {
    let mut reader = FrameReader::new();
    let mut header = vec![0u8; 4];
    header.push(framing::FRAME_JSON);
    assert_eq!(reader.push(&header), Err(FramingError::Empty));
}

#[test]
fn an_unknown_kind_is_refused_rather_than_guessed() {
    assert_eq!(
        framing::encode_frame(9, b"x"),
        Err(FramingError::UnknownKind(9))
    );
    let mut reader = FrameReader::new();
    let mut frame = Vec::new();
    frame.extend_from_slice(&2u32.to_le_bytes());
    frame.push(9);
    frame.push(b'x');
    assert_eq!(reader.push(&frame), Err(FramingError::UnknownKind(9)));
}

#[test]
fn a_frame_too_long_for_the_length_field_is_refused_not_masked() {
    // The Python side's post-mortem: `cap_len & 0xFFFF` while the payload is
    // appended in full makes the decoder take its next record from inside a
    // frame. `extra` may clamp because nothing seeks by it; this may not.
    let long = vec![0u8; 0x10000];
    assert_eq!(
        wire::encode_record(0, 0, 1, 0x10000, &long),
        Err(WireError::FrameTooLong(0x10000))
    );
    let exact = vec![0u8; 0xFFFF];
    assert!(wire::encode_record(0, 0, 1, 0xFFFF, &exact).is_ok());
}

#[test]
fn an_excess_past_the_u16_ceiling_clamps_instead_of_wrapping() {
    let encoded = wire::encode_record(0, 0, 1, 200_000, &[0u8; 4]).unwrap();
    let batch = wire::encode_batch(&[encoded]).unwrap();
    let decoded = wire::decode_batch(&batch).unwrap();
    assert_eq!(decoded[0].orig_len, 4 + 0xFFFF);
}

#[test]
fn a_malformed_batch_is_refused_rather_than_half_read() {
    let f = fixture();
    let whole = unhex(f["batchHex"].as_str().unwrap());

    let mut not_a_batch = whole.clone();
    not_a_batch[0..4].copy_from_slice(b"NOPE");
    assert_eq!(
        wire::decode_batch(&not_a_batch),
        Err(WireError::NotABatch(*b"NOPE"))
    );

    let mut wrong_version = whole.clone();
    wrong_version[4] = 99;
    assert_eq!(
        wire::decode_batch(&wrong_version),
        Err(WireError::UnsupportedVersion(99))
    );

    assert_eq!(
        wire::decode_batch(&whole[..whole.len() - 1]),
        Err(WireError::TruncatedPayload)
    );

    let mut trailing = whole.clone();
    trailing.push(0);
    assert_eq!(wire::decode_batch(&trailing), Err(WireError::TrailingBytes));

    assert_eq!(wire::decode_batch(&[]), Err(WireError::TruncatedHeader));
    assert_eq!(wire::encode_batch(&[]), Err(WireError::EmptyBatch));
}
