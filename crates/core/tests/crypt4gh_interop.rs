//! Crypt4GH interop tests against the reference Python `crypt4gh`.
//!
//! These are `#[ignore]`d so the default `cargo test` does not require Python. They must pass
//! when run explicitly:
//!
//! ```sh
//! cargo test -p gdi-node-standalone-core crypt4gh -- --ignored
//! ```
//!
//! The Python side is driven through the reference oracle's venv binaries.
//! Override the venv location with `C4GH_VENV` if it moves.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![expect(
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::similar_names,
    reason = "test code; docs reference the Python crypt4gh tool by name; sk/pk naming is conventional"
)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gdi_node_standalone_core::crypt4gh::{
    self, generate_keypair, parse_public_key, parse_secret_key, serialize_public_key,
};

/// The reference-`crypt4gh` venv location. Honours `C4GH_VENV` (CI points it at
/// `$RUNNER_TEMP/c4gh-venv`); otherwise falls back to a neutral, stable per-machine
/// temp path — create it once with
/// `python -m venv "$TMPDIR/gdi-node-standalone-c4gh-venv" && .../pip install crypt4gh==1.8.6`,
/// or set `C4GH_VENV` to point at an existing one.
fn venv_dir() -> PathBuf {
    std::env::var_os("C4GH_VENV").map_or_else(
        || std::env::temp_dir().join("gdi-node-standalone-c4gh-venv"),
        PathBuf::from,
    )
}

fn bin(name: &str) -> PathBuf {
    venv_dir().join("bin").join(name)
}

/// Skip (with a clear message) if the reference venv is not installed, so the
/// ignored test is self-documenting rather than a hard failure on a machine
/// without the oracle.
fn require_venv() -> bool {
    let present = bin("crypt4gh").exists() && bin("crypt4gh-keygen").exists();
    if !present {
        // A skip that passes is invisible from the outside: vacuously-skipped tests are
        // counted as passed, so a caller sees green having verified nothing against the
        // reference implementation. The skip path is still wanted for a developer without
        // the venv, so a caller that needs the check sets C4GH_INTEROP_REQUIRED=1 and a
        // missing venv becomes a hard failure. `corpus.rs` uses the same bound.
        assert!(
            std::env::var_os("C4GH_INTEROP_REQUIRED").is_none(),
            "C4GH_INTEROP_REQUIRED is set but the reference venv is missing at {}: the \
             crypt4gh interop gate would have silently verified nothing (set C4GH_VENV, or \
             run scripts/ci-local.sh crypt4gh which provisions it)",
            venv_dir().display()
        );
        eprintln!(
            "skipping crypt4gh interop: reference venv not found at {} (set C4GH_VENV to override)",
            venv_dir().display()
        );
    }
    present
}

/// Generate an unencrypted Crypt4GH keypair with the reference `crypt4gh-keygen`.
fn python_keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let sk = dir.join("py.sec");
    let pk = dir.join("py.pub");
    let status = Command::new(bin("crypt4gh-keygen"))
        .args(["--sk"])
        .arg(&sk)
        .args(["--pk"])
        .arg(&pk)
        .arg("--nocrypt")
        .arg("-f")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run crypt4gh-keygen");
    assert!(status.success(), "crypt4gh-keygen failed");
    (sk, pk)
}

/// The crypt4gh body segment size (64 KiB of plaintext per encrypted segment).
const SEGMENT_SIZE: usize = 65_536;

/// Plaintext sizes that differentially exercise the segment framing against the
/// reference: empty, one byte below a full segment, exactly one segment, one byte
/// above (a 1-byte second segment), and a multi-segment payload with a partial tail.
fn payload_sizes() -> [usize; 5] {
    [
        0,
        SEGMENT_SIZE - 1,
        SEGMENT_SIZE,
        SEGMENT_SIZE + 1,
        SEGMENT_SIZE * 2 + 4321,
    ]
}

/// A deterministic payload of `size` bytes.
fn payload_of(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// The multi-segment payload used by the single-payload (rewrap) tests.
fn sample_payload() -> Vec<u8> {
    payload_of(SEGMENT_SIZE * 2 + 4321)
}

/// Run a venv `crypt4gh` subcommand, feeding `input` to stdin and returning its stdout.
///
/// The stdin is written on a separate thread, so a large stdout cannot deadlock against a
/// full stdin pipe.
fn run_crypt4gh(args: &[&str], paths: &[&Path], input: Vec<u8>) -> Vec<u8> {
    let mut cmd = Command::new(bin("crypt4gh"));
    cmd.args(args);
    for p in paths {
        cmd.arg(p);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn crypt4gh");

    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        // Ignore broken-pipe on the writer; the child's exit status is checked.
        let _ = stdin.write_all(&input);
        drop(stdin);
    });

    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        out.status.success(),
        "crypt4gh {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Rust encrypts -> Python decrypts.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn rust_to_python() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (py_sk_path, py_pk_path) = python_keygen(tmp.path());

    // Parse the Python-generated public key and encrypt to it in Rust.
    let recipient_pk = parse_public_key(&std::fs::read_to_string(&py_pk_path).unwrap()).unwrap();
    let recipients = [recipient_pk];

    // Exercise every segment-boundary size against the reference.
    for size in payload_sizes() {
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = payload_of(size);
        let mut encrypted = Vec::new();
        crypt4gh::encrypt(&mut &payload[..], &mut encrypted, &recipients, &sender_sk).unwrap();

        // Decrypt with the Python CLI using the recipient secret key.
        let plaintext = run_crypt4gh(&["decrypt", "--sk"], &[&py_sk_path], encrypted);
        assert_eq!(
            plaintext, payload,
            "rust->python plaintext mismatch at size {size}"
        );
    }
}

/// Python encrypts -> Rust decrypts.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn python_to_rust() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();

    // Rust-generated recipient: write the public key out for the Python CLI,
    // keep the secret key in-process for decryption.
    let (recipient_sk, recipient_pk) = generate_keypair();
    let rust_pk_path = tmp.path().join("rust.pub");
    std::fs::write(&rust_pk_path, serialize_public_key(&recipient_pk)).unwrap();
    let secrets = [recipient_sk];

    // Exercise every segment-boundary size against the reference.
    for size in payload_sizes() {
        let payload = payload_of(size);

        // Encrypt with the Python CLI to the Rust recipient public key. Omitting
        // --sk lets the reference generate an ephemeral sender keypair.
        let encrypted = run_crypt4gh(
            &["encrypt", "--recipient_pk"],
            &[&rust_pk_path],
            payload.clone(),
        );

        // Decrypt in Rust with the recipient secret key.
        let mut decrypted = Vec::new();
        crypt4gh::decrypt(&mut &encrypted[..], &mut decrypted, &secrets).unwrap();
        assert_eq!(
            decrypted, payload,
            "python->rust plaintext mismatch at size {size}"
        );
    }
}

/// Rust parses a Python-generated secret key, and both ends agree on a full round trip when
/// the identity comes from Python.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn python_keys_parse_and_round_trip_in_rust() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (py_sk_path, py_pk_path) = python_keygen(tmp.path());

    let recipient_sk = parse_secret_key(&std::fs::read_to_string(&py_sk_path).unwrap()).unwrap();
    let recipient_pk = parse_public_key(&std::fs::read_to_string(&py_pk_path).unwrap()).unwrap();
    // The parsed secret key must derive the parsed public key.
    assert_eq!(
        recipient_sk.public_key().as_bytes(),
        recipient_pk.as_bytes()
    );

    let (sender_sk, _sender_pk) = generate_keypair();
    let payload = b"round trip through python-generated keys".to_vec();
    let mut encrypted = Vec::new();
    crypt4gh::encrypt(
        &mut &payload[..],
        &mut encrypted,
        &[recipient_pk],
        &sender_sk,
    )
    .unwrap();
    let mut decrypted = Vec::new();
    crypt4gh::decrypt(&mut &encrypted[..], &mut decrypted, &[recipient_sk]).unwrap();
    assert_eq!(decrypted, payload);
}

/// The multi-recipient header wraps the body key once per recipient, and each recipient
/// recovers the original independently.
///
/// Rust encrypts one ciphertext to two recipient public keys, and the reference Python
/// `crypt4gh` decrypts it with each recipient secret key in turn.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn rust_multi_recipient_python_decrypt() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (a_sk_path, a_pk_path) = python_keygen_named(tmp.path(), "a");
    let (b_sk_path, b_pk_path) = python_keygen_named(tmp.path(), "b");
    let pk_a = parse_public_key(&std::fs::read_to_string(&a_pk_path).unwrap()).unwrap();
    let pk_b = parse_public_key(&std::fs::read_to_string(&b_pk_path).unwrap()).unwrap();

    let payload = sample_payload();
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut encrypted = Vec::new();
    crypt4gh::encrypt(&mut &payload[..], &mut encrypted, &[pk_a, pk_b], &sender_sk).unwrap();

    // Each recipient secret key decrypts the same ciphertext.
    for sk_path in [&a_sk_path, &b_sk_path] {
        let plaintext = run_crypt4gh(&["decrypt", "--sk"], &[sk_path], encrypted.clone());
        assert_eq!(
            plaintext,
            payload,
            "multi-recipient decrypt mismatch for {}",
            sk_path.display()
        );
    }
}

/// Header rewrite with a Rust producer: Rust encrypts to A and rewraps A to B, the reference
/// Python `crypt4gh` decrypts with B and recovers the original, and A can no longer decrypt.
///
/// The last clause is the rotation property, checked against the reference implementation.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn rust_rewrap_then_python_decrypt() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // A and B are both Python-generated identities, so the Python CLI can decrypt with
    // each, parsed into Rust for the encrypt and the rewrap.
    let (a_sk_path, a_pk_path) = python_keygen_named(tmp.path(), "a");
    let (b_sk_path, b_pk_path) = python_keygen_named(tmp.path(), "b");
    let pk_a = parse_public_key(&std::fs::read_to_string(&a_pk_path).unwrap()).unwrap();
    let sk_a = parse_secret_key(&std::fs::read_to_string(&a_sk_path).unwrap()).unwrap();
    let pk_b = parse_public_key(&std::fs::read_to_string(&b_pk_path).unwrap()).unwrap();

    let payload = sample_payload();

    // Rust encrypts to A.
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut to_a = Vec::new();
    crypt4gh::encrypt(&mut &payload[..], &mut to_a, &[pk_a], &sender_sk).unwrap();

    // Rust rewraps A to B. The new recipient list replaces A.
    let mut to_b = Vec::new();
    crypt4gh::rewrap_header(&mut &to_a[..], &mut to_b, &[sk_a], &[pk_b]).unwrap();

    // Python decrypts with B and recovers the original payload.
    let plaintext = run_crypt4gh(&["decrypt", "--sk"], &[&b_sk_path], to_b.clone());
    assert_eq!(plaintext, payload, "python decrypt with B mismatch");

    // The rotation property: A is no longer a recipient, so a Python decrypt with A fails.
    assert_python_decrypt_fails(&a_sk_path, &to_b);
}

/// Header rewrite with a Python producer: Python encrypts to A, Rust rewraps A to B, the
/// reference Python `crypt4gh` decrypts with B and recovers the original, and A can no
/// longer decrypt.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn python_encrypt_rust_rewrap_python_decrypt() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (a_sk_path, a_pk_path) = python_keygen_named(tmp.path(), "a");
    let (b_sk_path, b_pk_path) = python_keygen_named(tmp.path(), "b");
    let sk_a = parse_secret_key(&std::fs::read_to_string(&a_sk_path).unwrap()).unwrap();
    let pk_b = parse_public_key(&std::fs::read_to_string(b_pk_path).unwrap()).unwrap();

    let payload = sample_payload();

    // Python encrypts to A with an ephemeral sender, the reference's default.
    let to_a = run_crypt4gh(
        &["encrypt", "--recipient_pk"],
        &[&a_pk_path],
        payload.clone(),
    );

    // Rust rewraps A to B.
    let mut to_b = Vec::new();
    crypt4gh::rewrap_header(&mut &to_a[..], &mut to_b, &[sk_a], &[pk_b]).unwrap();

    // Python decrypts with B.
    let plaintext = run_crypt4gh(&["decrypt", "--sk"], &[&b_sk_path], to_b.clone());
    assert_eq!(plaintext, payload, "python decrypt with B mismatch");

    // A can no longer decrypt.
    assert_python_decrypt_fails(&a_sk_path, &to_b);
}

/// Generate an unencrypted Crypt4GH keypair with a name prefix (so a single test
/// can hold several identities side by side).
fn python_keygen_named(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let sk = dir.join(format!("{name}.sec"));
    let pk = dir.join(format!("{name}.pub"));
    let status = Command::new(bin("crypt4gh-keygen"))
        .args(["--sk"])
        .arg(&sk)
        .args(["--pk"])
        .arg(&pk)
        .arg("--nocrypt")
        .arg("-f")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run crypt4gh-keygen");
    assert!(status.success(), "crypt4gh-keygen failed");
    (sk, pk)
}

/// A consumer holding the node crypt4gh identity can read a package's metadata from a ranged
/// GET of its leading bytes, without downloading the parquet payload.
///
/// This is what the package format's fixed `manifest.json -> headers/ -> parquet` member
/// ordering exists for (docs/package-format.md). The test fetches only the front of a
/// multi-segment `.tar.c4gh`, decrypts those segments with the reference Python `crypt4gh`,
/// and recovers the `manifest.json` and `headers/` members but not the parquet tail.
///
/// It composes two properties the other interop tests cover separately: crypt4gh segments
/// decrypt independently from the front, and a Rust-produced package is byte-compatible with
/// the reference reader.
#[test]
#[ignore = "requires the reference Python crypt4gh venv"]
fn python_reads_package_front_from_ranged_prefix() {
    if !require_venv() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (py_sk_path, py_pk_path) = python_keygen(tmp.path());
    let recipient_pk = parse_public_key(&std::fs::read_to_string(&py_pk_path).unwrap()).unwrap();
    let recipients = [recipient_pk];

    // Markers that distinguish the front (metadata) from the tail (bulk payload).
    let manifest_marker = b"GDI-FRONT-TEST-DATASET-ID";
    let header_marker = b"##fileformat=VCFv4.3-FRONT-TEST";
    let payload_tail_marker = b"PARQUET-PAYLOAD-TAIL-END-MARKER";

    // A `.tar` in package order: a small manifest.json, a small headers/ member, then a
    // large parquet payload spanning several crypt4gh segments. Its marker sits at the very
    // end, so reaching it requires decrypting the whole payload.
    let manifest = format!(
        "{{\"metadata\":{{\"datasetId\":\"{}\"}}}}",
        std::str::from_utf8(manifest_marker).unwrap()
    )
    .into_bytes();
    let mut payload = payload_of(SEGMENT_SIZE * 4); // 256 KiB -> many segments
    payload.extend_from_slice(payload_tail_marker);

    let package_tar = {
        let mut builder = tar::Builder::new(Vec::new());
        append_tar_member(&mut builder, "manifest.json", &manifest);
        append_tar_member(&mut builder, "headers/sample.vcf", header_marker);
        append_tar_member(&mut builder, "allele-freq.0.parquet", &payload);
        builder.into_inner().unwrap()
    };

    // Encrypt the whole package to the Python recipient.
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut encrypted = Vec::new();
    crypt4gh::encrypt(
        &mut &package_tar[..],
        &mut encrypted,
        &recipients,
        &sender_sk,
    )
    .unwrap();

    // Sanity: the full package carries the tail marker, so its absence in the front read
    // below means the read stopped early rather than that the marker was never there.
    {
        let recipient_sk =
            parse_secret_key(&std::fs::read_to_string(&py_sk_path).unwrap()).unwrap();
        let mut full = Vec::new();
        crypt4gh::decrypt(&mut &encrypted[..], &mut full, &[recipient_sk]).unwrap();
        assert!(
            bytes_contain(&full, payload_tail_marker),
            "full package must contain the tail marker (sanity)"
        );
    }

    // Derive the on-disk framing by measurement rather than by constant: an empty payload
    // encrypts to the header alone, and one full SEGMENT_SIZE payload adds exactly one
    // on-disk cipher segment. The header length is constant for a given recipient set, so a
    // throwaway sender key measures it correctly.
    let header_len = {
        let (s, _) = generate_keypair();
        let mut h = Vec::new();
        crypt4gh::encrypt(&mut std::io::empty(), &mut h, &recipients, &s).unwrap();
        h.len()
    };
    let cipher_segment_len = {
        let (s, _) = generate_keypair();
        let mut one = Vec::new();
        crypt4gh::encrypt(
            &mut &payload_of(SEGMENT_SIZE)[..],
            &mut one,
            &recipients,
            &s,
        )
        .unwrap();
        one.len() - header_len
    };

    // The ranged GET: the header and the first on-disk segment only, ending exactly on a
    // segment boundary. One 64 KiB plaintext segment more than covers the small manifest and
    // header members at the front of the tar.
    let prefix_len = header_len + cipher_segment_len;
    assert!(
        prefix_len < encrypted.len(),
        "front prefix ({prefix_len}) must be a strict partial of the package ({})",
        encrypted.len()
    );
    let front_prefix = encrypted[..prefix_len].to_vec();

    // The reference Python `crypt4gh` decrypts the front segment with the recipient
    // secret key (the node identity such a system shares).
    let front_plaintext =
        run_crypt4gh_capturing(&["decrypt", "--sk"], &[&py_sk_path], front_prefix);

    // The front read recovers the leading members...
    let members = read_leading_tar_members(&front_plaintext);
    let manifest_member = members
        .get("manifest.json")
        .expect("manifest.json recovered from the package front");
    assert!(
        bytes_contain(manifest_member, manifest_marker),
        "manifest.json content recovered from the front"
    );
    let header_member = members
        .get("headers/sample.vcf")
        .expect("headers/ member recovered from the package front");
    assert!(
        bytes_contain(header_member, header_marker),
        "VCF header content recovered from the front"
    );

    // ...but not the trailing parquet payload, which a front read must never need.
    assert!(
        !bytes_contain(&front_plaintext, payload_tail_marker),
        "a front read must not reach the parquet tail marker"
    );
    let parquet_complete = members
        .get("allele-freq.0.parquet")
        .is_some_and(|p| p.len() >= payload.len());
    assert!(
        !parquet_complete,
        "the parquet payload must not be fully present in a front read"
    );
}

/// Append an in-memory member to a `.tar` with the same normalized header fields the
/// tool's `pack` uses (regular file, 0644, fixed mtime). `append_data` sets the path
/// and recomputes the checksum.
fn append_tar_member(builder: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(data.len()).unwrap());
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_mtime(0);
    builder.append_data(&mut header, name, data).unwrap();
}

/// Whether `haystack` contains the contiguous byte sequence `needle`.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extract the complete leading members of a possibly front-truncated `.tar`, stopping at the
/// first member whose data is cut off by the prefix boundary.
///
/// This mirrors a consumer that reads only the front of a package: it recovers the early
/// metadata members and never needs the truncated bulk payload at the tail.
fn read_leading_tar_members(bytes: &[u8]) -> std::collections::HashMap<String, Vec<u8>> {
    let mut out = std::collections::HashMap::new();
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let Ok(entries) = archive.entries() else {
        return out;
    };
    for entry in entries {
        let Ok(mut e) = entry else { break };
        let name = match e.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => break,
        };
        let mut buf = Vec::new();
        if e.read_to_end(&mut buf).is_err() {
            break;
        }
        out.insert(name, buf);
    }
    out
}

/// Like [`run_crypt4gh`], but returns the child's stdout whatever the exit status.
///
/// Feeding only the leading bytes of a package can make the reference exit non-zero at the
/// truncated tail even after it has written the fully decrypted leading segments to stdout.
/// The caller asserts on the recovered bytes, not on the exit code.
fn run_crypt4gh_capturing(args: &[&str], paths: &[&Path], input: Vec<u8>) -> Vec<u8> {
    let mut cmd = Command::new(bin("crypt4gh"));
    cmd.args(args);
    for p in paths {
        cmd.arg(p);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn crypt4gh");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        drop(stdin);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    out.stdout
}

/// Assert that the reference `crypt4gh decrypt --sk <sk>` fails on `input`, which is how the
/// rotation property is checked: a retired key cannot decrypt.
fn assert_python_decrypt_fails(sk_path: &Path, input: &[u8]) {
    let mut child = Command::new(bin("crypt4gh"))
        .args(["decrypt", "--sk"])
        .arg(sk_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn crypt4gh");
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        drop(stdin);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        !out.status.success(),
        "python decrypt with the retired key A unexpectedly succeeded"
    );
}
