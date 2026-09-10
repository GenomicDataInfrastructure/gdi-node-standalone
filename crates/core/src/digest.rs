//! Per-parquet at-rest content digests: a `parquet-digests.json` sidecar in a dataset
//! directory, written at ingest for plaintext stores only.
//!
//! PME (`PARE`) files already carry per-segment AEAD tamper detection, so a stored
//! plaintext digest is meaningful only for the no-PME profile. There it closes the silent
//! on-disk bit-rot gap: the startup probe parses one footer, so rot in another file or row
//! group is invisible. Verified by the offline `verify` store scrub, never on the query
//! path and never in a boot sweep proportional to stored bytes.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::error::{CoreError, CoreResult};
use crate::util::sha256_hex_reader;

/// Sidecar file name (lives beside the parquet files in a dataset directory).
pub const PARQUET_DIGESTS_FILE: &str = "parquet-digests.json";

/// Outcome of verifying a dataset's stored parquet against its digest sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestVerdict {
    /// No sidecar present, as on a PME store, so the check does not apply. Not a failure.
    Unverified,
    /// All `n` listed files matched their stored digest.
    Verified(usize),
    /// A file's on-disk bytes do not match the stored digest (bit-rot / tamper), or a
    /// listed file is missing. Carries the offending file name.
    Mismatch(String),
}

/// Write the `parquet-digests.json` sidecar into `dir`. No-op if `digests` is empty.
///
/// # Errors
/// Propagates a serialization or I/O error.
#[expect(
    clippy::disallowed_methods,
    reason = "the sidecar lands in the staging directory that `ingest::store_atomically` renames into place as a whole"
)]
pub(crate) fn write_digests_sidecar(
    dir: &Path,
    digests: &BTreeMap<String, String>,
) -> CoreResult<()> {
    if digests.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_vec_pretty(digests).map_err(|e| CoreError::InternalError {
        detail: format!("serializing parquet digests: {e}"),
    })?;
    fs::write(dir.join(PARQUET_DIGESTS_FILE), json)?;
    Ok(())
}

/// Verify a dataset directory's parquet bytes against its `parquet-digests.json`.
///
/// Re-hashes each listed file and compares. Returns [`DigestVerdict::Unverified`] when no
/// sidecar exists. Intended for the offline scrub, not the query path.
///
/// # Errors
/// Propagates an I/O error opening or reading a parquet file, such as a permission denial,
/// an fd-limit refusal or a read fault, or [`CoreError::InvalidManifest`] if the sidecar is
/// corrupt. A listed file that is absent is a [`DigestVerdict::Mismatch`] rather than an
/// error: absence is a finding about the store, while any other open failure says nothing
/// about the data.
pub fn verify_parquet_digests(dir: &Path) -> CoreResult<DigestVerdict> {
    let Ok(raw) = fs::read(dir.join(PARQUET_DIGESTS_FILE)) else {
        return Ok(DigestVerdict::Unverified);
    };
    let expected: BTreeMap<String, String> =
        serde_json::from_slice(&raw).map_err(|e| CoreError::InvalidManifest {
            detail: format!("parquet-digests.json is not valid: {e}"),
        })?;
    let mut checked = 0;
    for (name, want) in &expected {
        let file = match fs::File::open(dir.join(name)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DigestVerdict::Mismatch(format!("{name} (missing)")));
            }
            Err(e) => return Err(e.into()),
        };
        let (got, _size) = sha256_hex_reader(file)?;
        if &got != want {
            return Ok(DigestVerdict::Mismatch(name.clone()));
        }
        checked += 1;
    }
    // The sidecar attests to these files and only these. An `allele-freq.*.parquet` added
    // to the directory after ingest is served by Beacon yet escapes the loop above, so an
    // unlisted on-disk data file is itself a mismatch.
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if crate::s3_layout::is_data_file_name(name) && !expected.contains_key(name) {
            return Ok(DigestVerdict::Mismatch(format!("{name} (not in sidecar)")));
        }
    }
    Ok(DigestVerdict::Verified(checked))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// Hash an explicit list of filenames into a sidecar map. Takes the names rather than
    /// globbing so the data-file predicate stays in one place, `is_data_file_name`; a
    /// helper that re-rolled it would test its own copy instead of the production one.
    fn digests_for(dir: &Path, names: &[&str]) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for name in names {
            let (hex, _size) = sha256_hex_reader(fs::File::open(dir.join(name)).unwrap()).unwrap();
            out.insert((*name).to_owned(), hex);
        }
        out
    }

    fn write_parquet_named(dir: &Path, name: &str, bytes: &[u8]) {
        fs::write(dir.join(name), bytes).unwrap();
    }

    #[test]
    fn round_trip_verify_ok_and_detects_mismatch_and_unverified() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_parquet_named(
            dir,
            "allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet",
            b"PAR1data",
        );
        write_parquet_named(
            dir,
            "allele-freq.chr3.4.br10000000.bbbbbbbbbbbbbbbb.parquet",
            b"PAR1more",
        );

        // No sidecar yet -> Unverified.
        assert_eq!(
            verify_parquet_digests(dir).unwrap(),
            DigestVerdict::Unverified
        );

        // Compute + write, then verify OK.
        let digests = digests_for(
            dir,
            &[
                "allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet",
                "allele-freq.chr3.4.br10000000.bbbbbbbbbbbbbbbb.parquet",
            ],
        );
        assert_eq!(digests.len(), 2);
        write_digests_sidecar(dir, &digests).unwrap();
        assert_eq!(
            verify_parquet_digests(dir).unwrap(),
            DigestVerdict::Verified(2)
        );

        // Corrupt one file -> Mismatch on that file.
        write_parquet_named(
            dir,
            "allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet",
            b"PAR1ROT!",
        );
        std::assert_matches!(
            verify_parquet_digests(dir).unwrap(),
            DigestVerdict::Mismatch(f) if f.contains("aaaaaaaaaaaaaaaa")
        );
    }

    /// A listed file the process cannot open is an I/O error, not `Mismatch("… (missing)")`:
    /// only absence is a finding about the store. Folding `EACCES` or `EMFILE` into
    /// "missing" would let an fd-limit blip quarantine a healthy dataset as tampered.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_listed_file_is_an_io_error_not_a_mismatch() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let name = "allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet";
        write_parquet_named(dir, name, b"PAR1 some bytes PAR1");
        fs::write(
            dir.join(PARQUET_DIGESTS_FILE),
            serde_json::to_vec(&digests_for(dir, &[name])).unwrap(),
        )
        .unwrap();
        let file = dir.join(name);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        if test_util::skip_if_root() {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            return;
        }
        let verdict = verify_parquet_digests(dir);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(
                verdict,
                Err(CoreError::Io(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied
            ),
            "an unreadable listed file must surface as the I/O error it is; got {verdict:?}"
        );
        // And absence is still a mismatch, not an error.
        fs::remove_file(&file).unwrap();
        assert!(matches!(
            verify_parquet_digests(dir),
            Ok(DigestVerdict::Mismatch(ref m)) if m.contains("(missing)")
        ));
    }

    #[test]
    fn verify_detects_an_injected_unlisted_parquet() {
        // An allele-freq.*.parquet added after ingest is absent from the sidecar, so it
        // escapes the per-listed-file check while Beacon still serves it. It must be
        // reported as a mismatch.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_parquet_named(
            dir,
            "allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet",
            b"PAR1one",
        );
        let digests = digests_for(
            dir,
            &["allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet"],
        );
        write_digests_sidecar(dir, &digests).unwrap();
        assert_eq!(
            verify_parquet_digests(dir).unwrap(),
            DigestVerdict::Verified(1)
        );

        // Inject an unlisted parquet. The listed file still matches; the injection must
        // still be caught.
        write_parquet_named(
            dir,
            "allele-freq.chr2.0.br10000000.bbbbbbbbbbbbbbbb.parquet",
            b"PAR1inj",
        );
        std::assert_matches!(
                verify_parquet_digests(dir).unwrap(),
                DigestVerdict::Mismatch(f) if f.contains("bbbbbbbbbbbbbbbb")
            ,
            "an injected unlisted parquet must be a Mismatch"
        );
    }

    #[test]
    fn empty_digests_writes_no_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        write_digests_sidecar(tmp.path(), &BTreeMap::new()).unwrap();
        assert!(!tmp.path().join(PARQUET_DIGESTS_FILE).exists());
    }

    #[test]
    fn verify_requires_both_prefix_and_suffix_for_the_unlisted_scan() {
        // The data-file filter is `starts_with("allele-freq.") && ends_with(".parquet")`,
        // and both halves must hold. Turning that `&&` into `||` would treat a file
        // matching either half as an unlisted data file and report a false mismatch.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let real = "allele-freq.chr3.4.br10000000.aaaaaaaaaaaaaaaa.parquet";
        write_parquet_named(dir, real, b"PAR1data");
        write_digests_sidecar(dir, &digests_for(dir, &[real])).unwrap();

        // Decoys matching only one half of the predicate must be ignored by the scan.
        write_parquet_named(dir, "other.parquet", b"suffix-only");
        write_parquet_named(dir, "allele-freq.x.txt", b"prefix-only");

        assert_eq!(
            verify_parquet_digests(dir).unwrap(),
            DigestVerdict::Verified(1),
            "a suffix-only or prefix-only file is not a data file; neither may be \
             reported as an unlisted parquet"
        );
    }
}
