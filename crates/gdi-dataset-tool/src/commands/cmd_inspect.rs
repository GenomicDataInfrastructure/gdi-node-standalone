//! The `inspect` command: inspect a local `.tar.c4gh` package without installing
//! it.
//!
//! Three modes:
//!
//! * **default** — show the package's contents/structure (the member list in
//!   archive order).
//! * `--manifest` — print the `manifest.json` (the first TAR member, the metadata
//!   prefix).
//! * `--files` — list every member with its size, sorted by `--order name|size`,
//!   optionally `-desc`.
//!
//! Packages are encrypted to the node recipient **plus the provider's own
//! recipient**, so `inspect` decrypts with the provider identity. All modes stream the
//! decrypt over an in-process pipe (constant memory; the plaintext TAR is never staged to
//! scratch disk): the member-listing modes (default / `--files`) read every TAR header as
//! the bytes flow through, and `--manifest` stops at the first member, never reading into
//! the bulk parquet payload.
//!
//! `--format json` emits a machine-readable form of each mode (the manifest object,
//! a member array for `--files`, or a `{package, writerKeys, members}` object).
//!
//! The op's logic lives in CLI-independent library functions; the CLI is a thin
//! wrapper. Data output (the manifest JSON, the member listing) goes to stdout;
//! everything else is stderr.

use std::io::{BufReader, Read as _};
use std::path::Path;

use gdi_node_standalone_core::extract::{CappedReader, ExtractBounds};
use gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES;

use crate::cli::{InspectArgs, OrderArg, OutputFormat};
use crate::{ToolError, pkgio};

use crate::MANIFEST_NAME;

/// Total-bytes cap on the decrypt stream (not just the member body) when reading only the
/// manifest. The manifest body is already `.take(MAX_MANIFEST_BYTES)`-bounded, so this only
/// needs to cover it plus the leading tar header blocks; capping the whole reader stops a
/// crafted GNU-longname / PAX extension header before `manifest.json` from buffering an
/// unbounded body into memory, matching `extract_tar_safely`.
///
/// Derived from [`MAX_MANIFEST_BYTES`], never redeclared: the member cap is a package-format
/// fact owned by `core`, this headroom is a property of how `inspect` streams it.
const MANIFEST_STREAM_CAP: u64 = MAX_MANIFEST_BYTES + (1 << 20);

/// One TAR member's name and size (the listing unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// In-package member name (path).
    pub name: String,
    /// Member size in bytes.
    pub size: u64,
    /// Member modification time (Unix seconds; `pack` normalizes it to 0).
    pub mtime: u64,
}

/// The sort key for `--files` (`name` | `size`), with a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Order {
    /// The field to sort on.
    pub key: OrderKey,
    /// `true` for descending (`*-desc`).
    pub desc: bool,
}

/// The field a `--files` listing is sorted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKey {
    /// Sort by member name.
    Name,
    /// Sort by member size.
    Size,
}

impl From<OrderArg> for Order {
    /// Map the validated `--order` [`OrderArg`] to a sort `(key, direction)`. clap
    /// has already rejected any unrecognized value before this runs.
    fn from(arg: OrderArg) -> Self {
        match arg {
            OrderArg::Name => Self {
                key: OrderKey::Name,
                desc: false,
            },
            OrderArg::NameDesc => Self {
                key: OrderKey::Name,
                desc: true,
            },
            OrderArg::Size => Self {
                key: OrderKey::Size,
                desc: false,
            },
            OrderArg::SizeDesc => Self {
                key: OrderKey::Size,
                desc: true,
            },
        }
    }
}

/// Run `inspect`, dispatching on the requested mode.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a decrypt/read failure or an absent
/// `manifest.json` for `--manifest`. (`--order` is validated by clap beforehand.)
pub fn run(args: &InspectArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    if args.manifest {
        crate::output::note(&format!(
            "reading manifest.json from {} (decrypt stops at the first member)",
            args.package.display()
        ));
        let json = read_manifest_json(&args.package, config_path)?;
        crate::output::note(&format!("manifest.json read: {} byte(s)", json.len()));
        // The manifest is data output -> stdout, raw, no trailing reformat. Marked as the
        // run's machine-readable output so `main` does not append an error envelope on top
        // of it; see `output::mark_result_emitted` for why this one path cannot use
        // `emit_json` (doing so would re-serialize the bytes this flag exists to reproduce).
        crate::output::mark_result_emitted();
        print!("{json}");
        if !json.ends_with('\n') {
            println!();
        }
        return Ok(());
    }

    if args.files {
        crate::output::note(&format!("listing members of {}", args.package.display()));
        let order = Order::from(args.order);
        let mut members = list_members(&args.package, config_path)?;
        sort_members(&mut members, order);
        crate::output::note(&format!(
            "{} member(s), {} byte(s) total",
            members.len(),
            members.iter().map(|m| m.size).sum::<u64>()
        ));
        match args.format {
            OutputFormat::Text => {
                for m in &members {
                    println!("{}", member_files_line(m));
                }
            }
            OutputFormat::Json => crate::output::emit_json(&members_json_array(&members)),
        }
        return Ok(());
    }

    // Default: show the structure (member list in archive order) + writer-key
    // provenance: the recovered crypt4gh writer/sender key(s), the only signal of who
    // wrote the package absent a signature. Best-effort: a recovery failure must not
    // fail the structure listing.
    crate::output::note(&format!(
        "inspecting structure of {}",
        args.package.display()
    ));
    let members = list_members(&args.package, config_path)?;
    crate::output::note(&format!("{} member(s) in archive order", members.len()));
    let writer_keys = match pkgio::recover_writer_keys_of(&args.package, config_path) {
        Ok(keys) => Ok(pkgio::writer_key_fingerprints(&keys)),
        Err(e) => Err(e.message),
    };
    match args.format {
        OutputFormat::Text => {
            println!("package: {}", args.package.display());
            match &writer_keys {
                Ok(fps) => {
                    for fp in fps {
                        // Labelled "unauthenticated": the writer key is proof-of-possession
                        // provenance, not a signed identity (see `recover_writer_keys`), so
                        // it is trustworthy only against a known-key allowlist.
                        println!("writer key (unauthenticated): {fp}");
                    }
                }
                Err(msg) => println!("writer key: unavailable ({msg})"),
            }
            for m in &members {
                println!("{}", member_structure_line(m));
            }
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "package": args.package.display().to_string(),
                "writerKeys": writer_keys.as_ref().ok(),
                "members": members.iter().map(member_json).collect::<Vec<_>>(),
            });
            crate::output::emit_json(&json);
        }
    }
    Ok(())
}

/// One member as the `--files` text line: right-aligned size, then the member name.
///
/// The name is TAR-supplied and therefore attacker-controlled, so it is routed through
/// [`crate::output::sanitize_terminal`] like every other human-readable render of
/// untrusted text. Rendering is a function (not an inline `println!`) so the guarantee is
/// pinned by a test rather than by remembering to sanitize at each print site.
fn member_files_line(m: &Member) -> String {
    format!("{:>12}  {}", m.size, crate::output::Untrusted(&m.name))
}

/// One member as the default structure-listing text line.
///
/// Sanitized for the same reason as [`member_files_line`].
fn member_structure_line(m: &Member) -> String {
    format!("  {}", crate::output::Untrusted(&m.name))
}

/// One member as a JSON object (`{name, size, mtime}`).
fn member_json(m: &Member) -> serde_json::Value {
    serde_json::json!({ "name": m.name, "size": m.size, "mtime": m.mtime })
}

/// The `--files` member listing as a JSON array value.
///
/// Returns a `Value` rather than a rendered `String` so the caller emits it through
/// [`crate::output::emit_json`], the one place that records that a machine-readable object
/// reached stdout. Rendering here would keep this path invisible to that bookkeeping.
fn members_json_array(members: &[Member]) -> serde_json::Value {
    serde_json::Value::Array(members.iter().map(member_json).collect())
}

/// Stream a package's crypt4gh decrypt over an in-process pipe and hand the plaintext
/// TAR stream to `read`, surfacing a genuine decrypt failure over a truncated-read
/// symptom.
///
/// The decrypt runs on a worker thread feeding the pipe; `read` reads as far as it needs.
/// Dropping the reader (when `read` returns) releases a decrypter blocked on a full pipe
/// with `BrokenPipe` — which `decrypt_package_to_writer` maps to `Ok` — so an early stop
/// is neither a deadlock nor a spurious error. The whole plaintext TAR is never staged to
/// scratch disk. `read` is responsible for bounding the stream (a [`CappedReader`]); the
/// join surfaces a header-decrypt failure ahead of any early-EOF read symptom.
fn read_decrypted_package<T>(
    package: &Path,
    config_path: Option<&Path>,
    panic_detail: &'static str,
    read: impl FnOnce(std::io::PipeReader) -> Result<T, ToolError>,
) -> Result<T, ToolError> {
    let (reader, mut writer) = std::io::pipe()
        .map_err(|e| ToolError::user(format!("cannot create pipe for decrypt: {e}")))?;
    let package = package.to_path_buf();
    let config_path = config_path.map(Path::to_path_buf);
    let decrypt_thread = std::thread::spawn(move || {
        pkgio::decrypt_package_to_writer(&package, &mut writer, config_path.as_deref())
    });
    let read_result = read(reader);
    decrypt_thread
        .join()
        .unwrap_or_else(|_| Err(ToolError::user(panic_detail)))?;
    read_result
}

/// Return a package's `manifest.json` (the small first TAR member) by streaming the
/// crypt4gh decrypt only as far as that member — never decrypting the parquet payload
/// or staging the whole plaintext TAR to scratch disk.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a decrypt/read failure or if the first
/// member is not `manifest.json`.
pub fn read_manifest_json(package: &Path, config_path: Option<&Path>) -> Result<String, ToolError> {
    // Read only the first member, then stop; the `CappedReader` bounds the stream so a
    // crafted extension header before the manifest cannot buffer an unbounded body ahead
    // of the member-level cap.
    read_decrypted_package(package, config_path, "decrypt thread panicked", |reader| {
        manifest_json_from_reader(BufReader::new(CappedReader::new(
            reader,
            MANIFEST_STREAM_CAP,
        )))
    })
}

/// Extract the `manifest.json` content from an uncompressed TAR stream (the first
/// member must be `manifest.json`).
///
/// Split out from [`read_manifest_json`] so the error paths can be unit-tested
/// without a real encrypted package.
fn manifest_json_from_reader<R: std::io::Read>(reader: R) -> Result<String, ToolError> {
    let mut archive = tar::Archive::new(reader);
    let mut entries = archive
        .entries()
        .map_err(|e| ToolError::user(format!("cannot read tar entries: {e}")))?;

    // The manifest is the first member (metadata prefix); read it and stop, never
    // iterating into the parquet payload.
    let first = entries
        .next()
        .ok_or_else(|| ToolError::user("package is empty (no manifest.json)"))?;
    let entry = first.map_err(|e| ToolError::user(format!("cannot read tar entry: {e}")))?;
    let name = entry
        .path()
        .map_err(|e| ToolError::user(format!("tar member has an unreadable path: {e}")))?
        .to_string_lossy()
        .into_owned();
    if name != MANIFEST_NAME {
        return Err(ToolError::user(format!(
            "first package member is {name:?}, expected {MANIFEST_NAME}"
        )));
    }
    // Cap the manifest read: `inspect` is pointed at untrusted producer packages, so a
    // crafted first member that declares a huge manifest.json must not be read into an
    // unbounded allocation. Reject the header-declared size up front, and `.take` the
    // stream so a lying header cannot exceed the cap either.
    let declared = entry
        .header()
        .size()
        .map_err(|e| ToolError::user(format!("cannot read the manifest.json member size: {e}")))?;
    if declared > MAX_MANIFEST_BYTES {
        return Err(ToolError::user(format!(
            "manifest.json member declares {declared} bytes, exceeding the {MAX_MANIFEST_BYTES}-byte cap"
        )));
    }
    let mut buf = String::new();
    entry
        .take(MAX_MANIFEST_BYTES)
        .read_to_string(&mut buf)
        .map_err(|e| ToolError::user(format!("cannot read manifest.json: {e}")))?;
    Ok(buf)
}

/// Return all of `package`'s members (name + size + mtime) in archive order.
///
/// Streams the crypt4gh decrypt over an in-process pipe and walks the TAR headers as
/// the bytes flow through (reading past each member's payload), so the whole decrypted
/// plaintext TAR is **never** staged to scratch disk. The decrypt runs on a worker thread
/// feeding the pipe; this thread reads every header. The crypt4gh stream is sequential
/// either way, so streaming costs no extra decrypt work and saves a full-size plaintext
/// copy on disk.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a decrypt/read failure.
pub fn list_members(package: &Path, config_path: Option<&Path>) -> Result<Vec<Member>, ToolError> {
    // Read every header to EOF (no early stop), so the decrypter runs to completion. Bound
    // the whole decrypt stream with the same total-bytes cap the ingest extractor uses, so
    // `tar::Archive` cannot be driven to buffer an unbounded extension header.
    let bounds = ExtractBounds::default();
    read_decrypted_package(
        package,
        config_path,
        "decrypt thread panicked while inspecting",
        |reader| {
            members_from_reader(
                BufReader::new(CappedReader::new(reader, bounds.max_total_bytes)),
                bounds.max_members,
            )
        },
    )
}

/// Parse member name/size/mtime from an uncompressed TAR stream.
fn members_from_reader<R: std::io::Read>(
    reader: R,
    max_members: usize,
) -> Result<Vec<Member>, ToolError> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|e| ToolError::user(format!("cannot read tar entries: {e}")))?;
    let mut out = Vec::new();
    for entry in entries {
        // The byte cap above bounds the stream, but an archive of many tiny members stays
        // well under it while growing this `Vec` one heap `Member` per header. Bound the
        // count too, matching `ExtractBounds::max_members`.
        if out.len() >= max_members {
            return Err(ToolError::user(format!(
                "package declares more than the {max_members} members allowed"
            )));
        }
        let entry = entry.map_err(|e| ToolError::user(format!("cannot read tar entry: {e}")))?;
        let header = entry.header();
        let name = entry
            .path()
            .map_err(|e| ToolError::user(format!("tar member has an unreadable path: {e}")))?
            .to_string_lossy()
            .into_owned();
        let size = header
            .size()
            .map_err(|e| ToolError::user(format!("tar member has an invalid size: {e}")))?;
        let mtime = header.mtime().unwrap_or(0);
        out.push(Member { name, size, mtime });
    }
    Ok(out)
}

/// Sort members in place by the requested order (with a `name` tiebreak so the
/// listing is deterministic).
fn sort_members(members: &mut [Member], order: Order) {
    members.sort_by(|a, b| {
        let primary = match order.key {
            OrderKey::Name => a.name.cmp(&b.name),
            OrderKey::Size => a.size.cmp(&b.size).then_with(|| a.name.cmp(&b.name)),
        };
        if order.desc {
            primary.reverse()
        } else {
            primary
        }
    });
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::io::Cursor;

    use super::*;

    fn members() -> Vec<Member> {
        vec![
            Member {
                name: "manifest.json".to_owned(),
                size: 300,
                mtime: 10,
            },
            Member {
                name: "headers/x.vcf".to_owned(),
                size: 50,
                mtime: 30,
            },
            Member {
                name: "allele-freq.chr3.0.parquet".to_owned(),
                size: 9000,
                mtime: 20,
            },
        ]
    }

    /// A TAR member name is attacker-controlled: `inspect` is precisely the verb an
    /// operator runs on a package they do not trust (it never extracts, so the
    /// path-shape gates never see it). A crafted name carrying ANSI escapes can clear
    /// the screen and forge a green "package verified" line.
    fn hostile_member() -> Member {
        Member {
            name: "manifest.json\x1b[2J\x1b[H\x1b[1;32m all members OK\x1b[0m".to_owned(),
            size: 300,
            mtime: 10,
        }
    }

    #[test]
    fn files_line_strips_terminal_control_bytes_from_a_hostile_member_name() {
        let line = member_files_line(&hostile_member());
        assert!(
            !line.chars().any(char::is_control),
            "--files text output must carry no control bytes, got {line:?}"
        );
        assert!(
            line.contains("manifest.json"),
            "the name must still be shown"
        );
    }

    #[test]
    fn structure_line_strips_terminal_control_bytes_from_a_hostile_member_name() {
        let line = member_structure_line(&hostile_member());
        assert!(
            !line.chars().any(char::is_control),
            "structure text output must carry no control bytes, got {line:?}"
        );
        assert!(
            line.contains("manifest.json"),
            "the name must still be shown"
        );
    }

    #[test]
    fn member_json_carries_name_size_and_mtime() {
        // A `Default::default()` (null) stub would not match the {name,size,mtime}
        // object — the `--files`/structure JSON output would silently go empty.
        let ms = members();
        let m = &ms[0];
        assert_eq!(
            member_json(m),
            serde_json::json!({ "name": m.name, "size": m.size, "mtime": m.mtime })
        );
    }

    #[test]
    fn members_json_array_serializes_every_member() {
        // A constant / empty stub would not produce the expected JSON array of members.
        let ms = members();
        let arr = members_json_array(&ms);
        let arr = arr.as_array().expect("a JSON array");
        assert_eq!(arr.len(), ms.len());
        assert_eq!(arr[0]["name"], serde_json::json!(ms[0].name));
    }

    #[test]
    fn order_arg_maps_to_key_and_direction() {
        assert_eq!(
            Order::from(OrderArg::Name),
            Order {
                key: OrderKey::Name,
                desc: false
            }
        );
        assert_eq!(
            Order::from(OrderArg::SizeDesc),
            Order {
                key: OrderKey::Size,
                desc: true
            }
        );
    }

    #[test]
    fn sort_by_size_ascending_and_descending() {
        let mut m = members();
        sort_members(
            &mut m,
            Order {
                key: OrderKey::Size,
                desc: false,
            },
        );
        let sizes: Vec<u64> = m.iter().map(|x| x.size).collect();
        assert_eq!(sizes, vec![50, 300, 9000]);

        sort_members(
            &mut m,
            Order {
                key: OrderKey::Size,
                desc: true,
            },
        );
        let sizes: Vec<u64> = m.iter().map(|x| x.size).collect();
        assert_eq!(sizes, vec![9000, 300, 50]);
    }

    #[test]
    fn sort_by_name() {
        let mut m = members();
        sort_members(
            &mut m,
            Order {
                key: OrderKey::Name,
                desc: false,
            },
        );
        assert_eq!(m[0].name, "allele-freq.chr3.0.parquet");
    }

    #[test]
    fn members_from_tar_reads_names_and_sizes() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let data = b"{}";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "manifest.json", &data[..]).unwrap();
            b.finish().unwrap();
        }
        let members =
            members_from_reader(Cursor::new(&buf), ExtractBounds::default().max_members).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "manifest.json");
        assert_eq!(members[0].size, 2);
    }

    /// A crafted archive of many tiny members stays under the byte cap while growing the
    /// member `Vec` one heap allocation per header. Bound the count too.
    #[test]
    fn members_from_reader_rejects_more_members_than_the_bound() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            for i in 0..10 {
                let data = [0u8; 1];
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, format!("m{i}.bin"), &data[..])
                    .unwrap();
            }
            b.finish().unwrap();
        }
        let err = members_from_reader(Cursor::new(&buf), 4).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("members"),
            "expected a member-count cap error; got: {}",
            err.message
        );
    }

    // manifest_json_from_reader error paths (reading the manifest member out of a tar).

    /// A tar whose first member is `data.parquet` (not `manifest.json`) must
    /// error with "expected manifest.json".
    #[test]
    fn manifest_json_from_reader_wrong_first_member_errors() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let data = b"PAR1";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "data.parquet", &data[..]).unwrap();
            b.finish().unwrap();
        }
        let err = manifest_json_from_reader(Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("expected manifest.json"),
            "msg: {}",
            err.message
        );
    }

    /// An empty tar (no members) must error with "package is empty".
    #[test]
    fn manifest_json_from_reader_empty_tar_errors() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            b.finish().unwrap();
        }
        let err = manifest_json_from_reader(Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("package is empty"),
            "msg: {}",
            err.message
        );
    }

    #[test]
    fn the_manifest_cap_is_cores_cap_not_a_local_copy() {
        // The cap is a package-format fact. `core` owns the one declaration and this crate
        // imports it, so there is no second value to drift against. A local copy that
        // disagreed would make a package the node accepts impossible to inspect. Guard the
        // import, not an agreement between two constants.
        assert_eq!(
            MAX_MANIFEST_BYTES,
            gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES,
            "the tool must enforce exactly the cap the node enforces"
        );
        assert_eq!(
            MANIFEST_STREAM_CAP,
            MAX_MANIFEST_BYTES + (1 << 20),
            "the stream cap is DERIVED from the member cap, never independently declared"
        );
    }
}
