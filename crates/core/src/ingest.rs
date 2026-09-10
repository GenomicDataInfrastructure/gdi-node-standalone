//! Shared, synchronous ingestion pipeline for a plaintext staging directory.
//!
//! This is the non-TAR, non-crypt4gh path: the inbox drops a prepared staging directory,
//! the output of the tool's `build`, so the decrypt and untar steps are skipped. The same
//! member-safety, file-layout, manifest and parquet validation still run, followed by an
//! atomic store that strips the manifest's non-public `files` and `internal` sections and
//! drops `headers/`.
//!
//! [`ingest_staging_dir`] is synchronous and filesystem-only: the service runs it under
//! `tokio::task::spawn_blocking`, and the tool reuses it. Transient and permanent error
//! classification, and the `.rejected/` lifecycle, live in the service runtime. This
//! function returns a typed [`CoreError`] and leaves the decision to the caller.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use tracing::info_span;

use crate::crypt4gh::{SecretKey, decrypt_authenticated, public_key_fingerprint};
use crate::error::{CoreError, CoreResult, IoResultExt, WriterUnknownKind, invalid_manifest};
use crate::extract::{ExtractBounds, check_staging_dir, extract_tar_safely};
use crate::model::{
    DatasetMode, Internal, Manifest, ManifestConfig, ManifestMetadata, SUPPORTED_MANIFEST_VERSION,
};
use crate::parquet_io::{DatasetEncryptor, store_parquet_file};
use crate::util::rand_suffix;
use crate::validate_parquet::{ParquetCaps, validate_parquet_dir};

/// The outcome of a successful staging-dir ingest: the published id plus the
/// stripped manifest's `metadata` + `config`, ready for the caller to insert into
/// the in-memory cache and the status index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOk {
    /// The published dataset id (from `manifest.metadata.datasetId`).
    pub id: String,
    /// FDP-public metadata (persisted in the stored manifest).
    pub metadata: ManifestMetadata,
    /// Processing config (assembly + `blockRange`; persisted in the stored manifest).
    pub config: ManifestConfig,
    /// What the package header says about who wrote it — see [`WriterProvenance`].
    ///
    /// Proof of possession only: it identifies a key, not an authenticated organisation.
    /// The node gates on it against the channel's `allowed_writer_fingerprints` when
    /// `[ingest].writer_policy` is `warn` or `enforce`, and always surfaces it for the
    /// ingest audit trail and the status index, so a later producer-key mismatch is
    /// answerable.
    pub writer_provenance: WriterProvenance,
}

/// What a package's crypt4gh header says about who wrote it.
///
/// The writer key is proof of possession, not an authenticated identity: anyone who knows
/// the recipient's public key can author a package under a fresh writer key of their own
/// (see [`crate::crypt4gh::recover_writer_keys`]). Gating on it via
/// `[ingest].writer_policy` is therefore opt-in and off by default. When it is on the gate
/// must still be sound, so the ingest path records only the key that authenticated the body
/// (see [`crate::crypt4gh::decrypt_authenticated`]), not every key the header carries.
///
/// A three-state enum rather than a `Vec<String>`, because an empty vector collapses two
/// different facts: an inbox staging directory has no envelope to read, which is the normal
/// case, while a `.tar.c4gh` whose header could not be parsed has an unreadable one, which
/// is anomalous. Flattened, the anomaly is indistinguishable from routine operation and
/// nothing can alert on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterProvenance {
    /// The plaintext staging-dir path: no crypt4gh envelope exists, so no writer key can.
    /// Expected and unremarkable for an inbox drop.
    Plaintext,
    /// The writer-key fingerprint(s) (`sha256:<hex>`) vouching for this package.
    ///
    /// The `.tar.c4gh` ingest path puts exactly one fingerprint here: the writer of the
    /// header packet whose session key decrypted the body. Not every writer key in the
    /// header, because those are unauthenticated with respect to this body, and admitting
    /// on any of them lets a harvested packet spliced into a foreign header pass
    /// `writer_policy = "enforce"`. The type stays a `Vec` because it is persisted in the
    /// status index and older entries may carry several.
    Recovered(Vec<String>),
    /// A crypt4gh package whose writer keys could not be recovered, with the node-local
    /// reason. The ingest still succeeds, because the body decrypted and the package is
    /// readable and valid, but its provenance is unknown and merits an operator's attention.
    Unrecoverable(String),
}

impl WriterProvenance {
    /// The recovered writer-key fingerprints, or an empty slice when none exist.
    #[must_use]
    pub fn fingerprints(&self) -> &[String] {
        match self {
            Self::Recovered(fingerprints) => fingerprints,
            Self::Plaintext | Self::Unrecoverable(_) => &[],
        }
    }
}

/// Whether a package's writer is vouched for by its channel's allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterAdmission {
    /// A recovered writer key on the channel allow-list.
    Admitted,
    /// The writer cannot be vouched for (see [`WriterUnknownKind`]).
    Unknown(WriterUnknownKind),
}

/// Decide whether `provenance` is admitted by `allowlist`. The writer-key gate logic lives
/// only here, shared by the store-time gate (`WriterGate::gate_store`) and the runtime's
/// discovery-mode audit and metric emission, so the two cannot diverge.
#[must_use]
pub fn writer_admission(allowlist: &[String], provenance: &WriterProvenance) -> WriterAdmission {
    match provenance {
        // A plaintext drop carries no key, so it can never be allow-listed. `enforce` gates
        // it too, because it is the one input that would otherwise bypass the control.
        WriterProvenance::Plaintext => WriterAdmission::Unknown(WriterUnknownKind::PlaintextDrop),
        WriterProvenance::Recovered(fingerprints) => {
            if fingerprints.iter().any(|fp| allowlist.contains(fp)) {
                WriterAdmission::Admitted
            } else {
                WriterAdmission::Unknown(WriterUnknownKind::UntrustedKey(fingerprints.clone()))
            }
        }
        WriterProvenance::Unrecoverable(_) => {
            WriterAdmission::Unknown(WriterUnknownKind::UntrustedKey(Vec::new()))
        }
    }
}

/// The store-time writer-key gate. It decides, from the reloadable `[ingest].writer_policy`
/// and the channel's allow-list, whether a package may be renamed into place. The check runs
/// before the rename inside `store_atomically`, so a package rejected under `enforce` is
/// never stored and cannot be re-admitted by a hydrate or reconcile race. A gate running
/// after the rename would leave a compensating erase that a hydrate plus a `visible` sidecar
/// can beat.
pub struct WriterGate<'a> {
    /// The reloadable policy.
    pub policy: crate::config::WriterPolicy,
    /// The owning channel (named in the rejection message).
    pub channel: &'a str,
    /// The channel's allow-listed writer-key fingerprints.
    pub allowlist: &'a [String],
}

impl WriterGate<'static> {
    /// A gate that admits everything: the `off` posture used by the convenience ingest
    /// entry points, the tool and tests, which do no writer gating.
    #[must_use]
    pub fn off() -> Self {
        Self {
            policy: crate::config::WriterPolicy::Off,
            channel: "",
            allowlist: &[],
        }
    }
}

impl WriterGate<'_> {
    /// Reject a package the channel cannot vouch for, before the store rename, and only
    /// under `enforce`. Under `off` and `warn` this is always `Ok`: `warn` publishes an
    /// unknown writer for allow-list discovery, and the runtime emits the discovery metric
    /// and audit event on success.
    ///
    /// # Errors
    /// [`CoreError::WriterRejected`] (carrying the [`WriterUnknownKind`]) under `enforce` when
    /// the writer is not admitted.
    fn gate_store(&self, provenance: &WriterProvenance) -> CoreResult<()> {
        if self.policy != crate::config::WriterPolicy::Enforce {
            return Ok(());
        }
        match writer_admission(self.allowlist, provenance) {
            WriterAdmission::Admitted => Ok(()),
            WriterAdmission::Unknown(kind) => {
                let detail = match &kind {
                    WriterUnknownKind::PlaintextDrop => format!(
                        "plaintext drop on channel {} carries no writer key, so it cannot be \
                         allow-listed; [ingest].writer_policy = \"enforce\" admits only an \
                         encrypted .tar.c4gh from an allow-listed writer",
                        self.channel
                    ),
                    WriterUnknownKind::UntrustedKey(_) => {
                        format!("writer key not allow-listed for channel {}", self.channel)
                    }
                };
                Err(CoreError::WriterRejected { kind, detail })
            }
        }
    }
}

/// Ingest a plaintext staging directory into `data_dir/{id}/` atomically, using the
/// default [`ExtractBounds`].
///
/// Convenience wrapper over [`ingest_staging_dir_with_bounds`]. The service passes
/// operator-configured bounds via the `_with_bounds` form; the tool and tests use
/// this default-bounds entry point.
///
/// # Errors
///
/// See [`ingest_staging_dir_with_bounds`].
pub fn ingest_staging_dir(
    src: &Path,
    data_dir: &Path,
    caps: &ParquetCaps,
    node_catalogs: &BTreeMap<String, String>,
    encryptor: &DatasetEncryptor,
) -> CoreResult<IngestOk> {
    ingest_staging_dir_with_bounds(
        src,
        data_dir,
        caps,
        node_catalogs,
        encryptor,
        &ExtractBounds::default(),
        None,
        &WriterGate::off(),
        &WriterProvenance::Plaintext,
    )
}

/// Ingest a plaintext staging directory into `data_dir/{id}/` atomically, bounding
/// the member count and total size by `bounds`.
///
/// Runs the staging-dir stages of the shared pipeline:
/// member safety -> file-layout -> manifest validation -> parquet validation ->
/// atomic store (manifest `files`/`internal` stripped, `headers/` dropped,
/// read-only + fsync'd, then a single `rename` into place). On any failure the
/// `.incoming` working dir is cleaned up and `data_dir/{id}/` is never created.
///
/// The store assumes it is publishing an id that is not currently served, a fresh create
/// or an error recovery, which the runtime guarantees through the immutability rule. A
/// pre-existing `data_dir/{id}/` is therefore an internal error, not an overwrite.
///
/// # Errors
///
/// Returns the typed [`CoreError`] of the first failing stage:
/// [`CoreError::UnsafeArchive`] (member safety / bounds), [`CoreError::InvalidManifest`]
/// (layout or manifest), [`CoreError::UnknownCatalog`] (catalog not configured),
/// [`CoreError::InvalidParquet`] (parquet), [`CoreError::InternalError`]
/// (pre-existing target / serialization), or [`CoreError::Io`].
#[expect(
    clippy::too_many_arguments,
    reason = "the pipeline inputs plus the writer gate; a params struct only moves the fan-out"
)]
pub fn ingest_staging_dir_with_bounds(
    src: &Path,
    data_dir: &Path,
    caps: &ParquetCaps,
    node_catalogs: &BTreeMap<String, String>,
    encryptor: &DatasetEncryptor,
    bounds: &ExtractBounds,
    expected_id: Option<&str>,
    gate: &WriterGate,
    provenance: &WriterProvenance,
) -> CoreResult<IngestOk> {
    // Steps 3-4: member type, path containment and bounds, then file layout. The
    // `check_layout` span scopes the layout-safety pair. The spans carry no dataset or path
    // field, because the id is unknown until the manifest is parsed.
    //
    // Member safety runs on the original directory, since that is what rejects symlinks,
    // devices and pre-existing hard links. The drop is then snapshotted into node-private
    // scratch, and every later step — layout, manifest, payload, parquet validation and the
    // store — reads the snapshot. The bytes that are approved and the bytes that are stored
    // are then the same inodes, so there is no window to substitute into. See
    // `snapshot_staging_dir`.
    let snapshot = data_dir
        .join(".incoming")
        .join(format!("src.{}", crate::util::rand_suffix()));
    // Armed before the walk, so a partially-linked snapshot is removed on any early return.
    let _snapshot_guard = WorkDirGuard(&snapshot);
    let layout = {
        let _span = info_span!("check_layout").entered();
        check_staging_dir(src, bounds)?;
        snapshot_staging_dir(src, &snapshot)?;
        check_file_layout(&snapshot)?
    };
    // Everything below reads the snapshot, never the caller's directory.
    let src = snapshot.as_path();

    // Step 5: manifest validation of metadata and config, with files and internal opaque.
    // The raw metadata object is retained so the store can preserve additive fields.
    let (manifest, raw_metadata) = {
        let _span = info_span!("validate_manifest").entered();
        parse_and_validate_manifest(src, node_catalogs)?
    };
    let id = manifest.metadata.dataset_id.clone();

    // Step 5b: the package must contain what its manifest says it contains.
    verify_declared_payload(src, &manifest)?;

    // When the caller knows the id this package was published under, from the inbox
    // drop-directory name or the S3 object-key basename, the manifest's own `datasetId`
    // must match it. The ingest runtime keys dedup, in-flight tracking, liveness and
    // quarantine on that name, so a manifest declaring a different id would publish under a
    // name the dedup gate never guarded, and two differently-named drops carrying the same
    // manifest id could both pass. Rejected here, before the store.
    if let Some(expected) = expected_id
        && expected != id
    {
        return Err(invalid_manifest(&format!(
            "manifest metadata.datasetId ({id}) does not match the expected dataset id \
             ({expected}) taken from the drop name / object key"
        )));
    }

    // Every data file's filename `br{N}` blockRange must equal the manifest's
    // `config.blockRange`. The Beacon serve path resolves a file by the
    // `allele-freq.chr{chr}.{block}.br{blockRange}.` prefix it builds from the dataset's
    // configured blockRange, so a file named with a different `br{N}` is unreachable and
    // leaves the dataset Visible yet unqueryable. Rejected here, before the parquet scan
    // and the store. The tool's `build` and `validate` self-check run the same shared
    // check, so the tool rejects what the node would. The scan additionally proves each
    // row's POS falls in the block its name declares, pinning both name and content to the
    // configured blockRange.
    crate::validate_parquet::check_data_file_block_range(src, manifest.config.block_range)?;

    // Step 6: full parquet schema, value and uniqueness validation while plaintext. The
    // scan also recomputes the distinct-variant count, reusing the per-POS uniqueness set,
    // so the manifest's declared `numberOfRecords`, served verbatim in the public FDP and
    // DCAT RDF, is verified against the data. A hand-assembled package that miscounts is
    // rejected here rather than advertising a false record count to harvesters.
    {
        let _span = info_span!("validate_parquet").entered();
        let scan = validate_parquet_dir(src, caps)?;
        // numberOfRecords is mandatory, not conditional: it is served verbatim in the
        // public FDP and DCAT RDF, and this equality is the ingest gate's only cross-check
        // that the parquet matches the advertised count. A manifest that omits it must be
        // rejected, not skipped past the check.
        let counted = scan.distinct_variants;
        let declared = manifest.metadata.number_of_records.ok_or_else(|| {
            invalid_manifest(
                "manifest metadata.numberOfRecords is required (served verbatim in the public \
                 FDP/DCAT RDF and cross-checked against the parquet data) but was not declared",
            )
        })?;
        if declared != counted {
            return Err(invalid_manifest(&format!(
                "manifest metadata.numberOfRecords ({declared}) does not match the {counted} \
                 distinct variants in the parquet data"
            )));
        }
        check_declared_populations(&manifest, &scan.populations)?;
        warn_on_nonconforming_population_labels(&manifest.metadata.dataset_id, &scan.populations);
    }

    // Step 7: atomic store (strip files/internal, drop headers/, rename). The
    // parquet is encrypted here when PME is active (the `encryptor` carries a
    // minter); otherwise it is copied plaintext.
    {
        let _span = info_span!("store").entered();
        store_atomically(
            data_dir,
            &id,
            &layout.parquet_files,
            &manifest,
            &raw_metadata,
            encryptor,
            gate,
            provenance,
        )?;
    }

    Ok(IngestOk {
        id,
        metadata: manifest.metadata,
        config: manifest.config,
        // The caller's recovered provenance: Plaintext for a direct staging-dir drop, the
        // package-header key for the `.tar.c4gh` path. The gate above already consulted it.
        writer_provenance: provenance.clone(),
    })
}

/// Ingest an encrypted `.tar.c4gh` package at `path` into `data_dir/{id}/`.
///
/// Implements the decrypt + extract steps for the encrypted path, then reuses the
/// shared staging-dir pipeline via [`ingest_staging_dir`]:
///
/// 1. create a fresh per-job working dir `data_dir/.incoming/{rand}/`;
/// 2. [`crypt4gh::decrypt`](crate::crypt4gh::decrypt) the file into a temp `.tar`
///    in that working dir, trying each identity in order (the codec wipes session
///    keys via `Zeroizing`; the caller holds the `identities` in a zeroize-backed
///    container);
/// 3. [`extract_tar_safely`] the `.tar` into a `staging/` subdir (uncompressed
///    only; member-type + path-containment + count/size bounds; duplicate-path
///    reject);
/// 4. delegate to [`ingest_staging_dir`] on `staging/`.
///
/// The per-job working dir (decrypted `.tar` plus extracted tree) is removed on every exit,
/// success or failure.
///
/// Error classification:
/// * an empty `identities` list is a caller error: the node cannot decrypt, so this returns
///   [`CoreError::DecryptFailed`] (the caller should skip such files rather than call this;
///   a keyless node disables the encrypted path entirely);
/// * decrypt with available identities where none works, or a corrupt or AEAD-tag failure,
///   is permanent ([`CoreError::DecryptFailed`]);
/// * an unsafe archive is permanent ([`CoreError::UnsafeArchive`]);
/// * an I/O failure surfaces as [`CoreError::Io`]; the caller classifies a
///   resource-exhaustion kind (disk-full, quota, OOM) as transient and retries (see
///   [`CoreError::is_transient`]), while any other I/O error (permission denied, read-only
///   filesystem, ...) is permanent.
///
/// # Errors
///
/// Returns the typed [`CoreError`] of the first failing stage (see above) or any
/// error propagated from [`ingest_staging_dir`].
pub fn ingest_tar_c4gh(
    path: &Path,
    identities: &[SecretKey],
    data_dir: &Path,
    caps: &ParquetCaps,
    node_catalogs: &BTreeMap<String, String>,
    encryptor: &DatasetEncryptor,
) -> CoreResult<IngestOk> {
    ingest_tar_c4gh_with_bounds(
        path,
        identities,
        data_dir,
        caps,
        node_catalogs,
        encryptor,
        &ExtractBounds::default(),
        None,
        &WriterGate::off(),
    )
}

/// Ingest an encrypted `.tar.c4gh` package with explicit member/size `bounds`.
///
/// Identical to [`ingest_tar_c4gh`] but the operator-configured `bounds` govern the
/// whole encrypted path, not just extraction:
///
/// * the decrypt step streams through a counting writer that fails fast once
///   `bounds.max_total_bytes` decrypted bytes have been written, so an oversized package
///   is rejected before extraction. That bounds the bytes landed on the data volume, not
///   only the extracted tree. The over-cap failure is a permanent
///   [`CoreError::UnsafeArchive`] and is never retried;
/// * [`extract_tar_safely`] enforces the same `bounds` on the extracted tree;
/// * the delegated [`ingest_staging_dir_with_bounds`] re-checks the staging tree against
///   the same `bounds`, so loosening the cap above the default takes effect and tightening
///   it is enforced end to end.
///
/// # Errors
///
/// See [`ingest_tar_c4gh`] / [`ingest_staging_dir_with_bounds`]; additionally a
/// decrypted package exceeding `bounds.max_total_bytes` returns
/// [`CoreError::UnsafeArchive`].
#[expect(
    clippy::too_many_arguments,
    reason = "the ingest context plus the expected id; a params struct only moves the fan-out"
)]
pub fn ingest_tar_c4gh_with_bounds(
    path: &Path,
    identities: &[SecretKey],
    data_dir: &Path,
    caps: &ParquetCaps,
    node_catalogs: &BTreeMap<String, String>,
    encryptor: &DatasetEncryptor,
    bounds: &ExtractBounds,
    expected_id: Option<&str>,
    gate: &WriterGate,
) -> CoreResult<IngestOk> {
    // A keyless node cannot decrypt; treat as a permanent decrypt failure so the
    // caller (which normally skips .tar.c4gh when identities are empty) never
    // silently no-ops on a real package.
    if identities.is_empty() {
        return Err(CoreError::DecryptFailed);
    }

    // Step 1: per-job working dir on the data volume, so it shares its encryption.
    // Owner-only, because the decrypted `.tar` and the extracted payload live here and the
    // host's volume may be shared.
    let incoming = data_dir.join(".incoming");
    crate::util::create_private_dir(&incoming).io_ctx("create_dir_all", &incoming)?;
    let work = incoming.join(rand_suffix());
    if work.exists() {
        fs::remove_dir_all(&work).io_ctx("remove_dir_all", &work)?;
    }
    crate::util::create_private_dir(&work).io_ctx("create_dir", &work)?;

    // Everything below is cleaned up on every exit via the guard.
    let _guard = WorkDirGuard(&work);

    // Step 2: decrypt into a temp .tar, streaming in constant memory and bounding the
    // decrypted size, so a package that inflates past the cap is rejected before it can
    // fill the data volume and before extraction.
    let tar_path = work.join("package.tar");
    let authenticated_writer;
    {
        let _span = info_span!("decrypt").entered();
        let mut reader = fs::File::open(path).io_ctx("open", path)?;
        // Owner-only 0o600: this is the full decrypted plaintext tar.
        let file = crate::util::create_private_file(&tar_path).io_ctx("create", &tar_path)?;
        let mut writer = CountingWriter::new(file, bounds.max_total_bytes);
        let decrypt_result = decrypt_authenticated(&mut reader, &mut writer, identities);
        if writer.exceeded {
            // Map the counting-writer trip to a permanent unsafe-archive error, not the
            // transient resource-exhaustion class an `Io` write error would otherwise be
            // read as: the package is over-cap, so retrying it can never succeed.
            return Err(CoreError::UnsafeArchive {
                detail: format!(
                    "decrypted package exceeds max_total_bytes {}",
                    bounds.max_total_bytes
                ),
            });
        }
        // The writer key of the packet that decrypted this body, and the only one that may
        // be gated on. See `decrypt_authenticated`.
        authenticated_writer = decrypt_result?;
        writer.into_inner().sync_all()?;
    }

    // Step 3: safe TAR extraction into a clean staging subdir, 0700 like its parent. It
    // holds a plaintext tree of the provider's data on the node's data path.
    let staging = work.join("staging");
    crate::util::create_private_dir(&staging)?;
    {
        let _span = info_span!("extract").entered();
        // Buffer the tar read: extraction reads 512-byte headers and copies entry
        // bodies in small chunks, so an unbuffered file would issue many tiny reads.
        let tar_file = BufReader::new(fs::File::open(&tar_path).io_ctx("open", &tar_path)?);
        extract_tar_safely(tar_file, &staging, bounds)?;
    }

    // Provenance comes from the body-authenticating packet recorded during the decrypt
    // above, never from a second, independent pass over the header. Recovering it separately
    // would admit the writer of any openable packet, so a packet copied verbatim out of an
    // allow-listed provider's package and prepended to an attacker's own would make
    // `writer_policy = "enforce"` admit that package and attribute it to the harvested
    // writer. There is no re-read here for that reason.
    let writer_provenance = match authenticated_writer {
        Some(pk) => WriterProvenance::Recovered(vec![public_key_fingerprint(&pk)]),
        // No body segments, so nothing authenticated the package. Not admissible under
        // `enforce`, and recorded as unknown rather than guessed from the header.
        None => WriterProvenance::Unrecoverable(
            "package body has no segments, so no writer key authenticated it".to_owned(),
        ),
    };

    // Steps 4-7: reuse the shared staging-dir pipeline with the same bounds, handing it the
    // recovered provenance so the store-time writer gate sees the package's real writer key
    // and `IngestOk.writer_provenance` reflects it.
    ingest_staging_dir_with_bounds(
        &staging,
        data_dir,
        caps,
        node_catalogs,
        encryptor,
        bounds,
        expected_id,
        gate,
        &writer_provenance,
    )
}

/// A [`Write`] adapter that fails fast once `limit` bytes have been written.
///
/// Bounds the crypt4gh-decrypted `.tar` written to disk before extraction. `decrypt`
/// streams the plaintext tar through this writer, and the first write that would carry the
/// running total past `limit` returns an error and latches [`exceeded`](Self::exceeded), so
/// the caller maps the failure to a permanent [`CoreError::UnsafeArchive`] rather than
/// letting an unbounded decrypt fill the data volume.
struct CountingWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
    exceeded: bool,
}

impl<W: Write> CountingWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
            exceeded: false,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(len) > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(
                "decrypted package exceeds the configured byte cap",
            ));
        }
        let n = self.inner.write(buf)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Hard-link `from` to `to`, falling back to a byte copy when linking is not possible.
///
/// A hard link is a second name for the same inode, so it is O(1) regardless of size and a
/// multi-gigabyte dataset snapshots in milliseconds with no extra disk. The fallback exists
/// because the inbox and `data_dir` are often separate mounts (`EXDEV`), which is a
/// supported deployment. Falling back on any link error rather than matching `errno` keeps
/// this portable: if the copy is also impossible, its error is the one that surfaces.
///
/// The fallback is a `create_private_file_new` and `io::copy` pair rather than `fs::copy`,
/// for the two reasons `clippy.toml` bans the latter. `fs::copy` opens the destination
/// `O_WRONLY|O_CREAT|O_TRUNC`, so it writes through a symlink already sitting there, and it
/// carries the source's mode. The source here is the provider-writable inbox drop, so that
/// mode is attacker-chosen and `fs::copy` would reproduce a `0777` or setuid member inside
/// node-private scratch. `O_CREAT|O_EXCL` with a private mode chooses the destination's
/// permissions instead of inheriting them, and refuses rather than following a pre-existing
/// name.
fn link_or_copy(from: &Path, to: &Path) -> CoreResult<()> {
    if fs::hard_link(from, to).is_ok() {
        return Ok(());
    }
    copy_private_file(from, to)
}

/// The `EXDEV` fallback of [`link_or_copy`], split out so a test can exercise it directly:
/// a same-filesystem test never reaches it.
fn copy_private_file(from: &Path, to: &Path) -> CoreResult<()> {
    let mut reader = fs::File::open(from).io_ctx("open", from)?;
    let mut writer = crate::util::create_private_file_new(to).io_ctx("create", to)?;
    std::io::copy(&mut reader, &mut writer).io_ctx("copy", from)?;
    Ok(())
}

/// Snapshot a validated staging dir into node-private scratch.
///
/// Validation and the store must read the same bytes. On the inbox channel the source is the
/// provider-writable drop directory, so validating it and then storing from it leaves a
/// window: whatever is there at store time is what gets stored, under a manifest that
/// approved what was there at validation time.
///
/// The trigger need not be an attacker. `gdi-dataset-tool deploy --replace` is the
/// documented way to correct a dataset, and it is not rename-only: it removes `inbox/{id}`
/// and copies the new drop in. Landing mid-store, that makes the node read some files from
/// the old tree and some from the new one, publishing a mixed dataset under a manifest that
/// validated neither and bypassing the schema, population-cap, POS-in-block,
/// `numberOfRecords` and `populations` coherence checks and the manifest-payload binding.
/// `parquet-digests.json` is computed from the stored files, so `verify --digest` re-reads
/// those same mixed bytes and reports them intact from then on. The `.tar.c4gh` channel
/// extracts into node-private scratch already; this gives the staging-dir channel the same
/// shape.
///
/// A hard link pins the inode, so the provider unlinking or replacing the file leaves this
/// name pointing at the original content. It does not snapshot content: a writer that opens
/// the original and rewrites it in place mutates the same inode. That is a deliberate act
/// by a party who already holds write access to the channel, which is what
/// `[ingest].writer_policy` and the crypt4gh writer provenance address, and a different
/// threat from the accidental interleave closed here.
///
/// Member kinds are re-checked even though `check_staging_dir` just ran, because this walk
/// happens strictly after it and a symlink or device node appearing in between must be
/// caught rather than linked. It is not a second call to `check_staging_dir`: hard links are
/// what that function rejects, so running it over these links would refuse every file.
///
/// Two residual gaps remain, and both trust the single-tenant-inbox invariant. This walk
/// classifies each member with `symlink_metadata` and then hard-links it, a window in which
/// a member swapped for a symlink between the two calls could be linked, and it re-walks the
/// still-provider-writable source tree with no member-count, byte or depth cap. Both are
/// reachable only by a party holding write access to the inbox, which the operating guide
/// documents as single-tenant. An fd-relative (`openat`) traversal with those bounds would
/// close them, and is warranted only if a multi-tenant inbox posture is ever supported.
fn snapshot_staging_dir(src: &Path, dest: &Path) -> CoreResult<()> {
    let mut stack: Vec<(PathBuf, PathBuf)> = vec![(src.to_path_buf(), dest.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        crate::util::create_private_dir(&to).io_ctx("create_dir", &to)?;
        for entry in fs::read_dir(&from).io_ctx("read_dir", &from)? {
            let entry = entry.io_ctx("read_dir entry", &from)?;
            let path = entry.path();
            // Never follow: inspect the link itself, as `check_staging_dir` does.
            let meta = fs::symlink_metadata(&path).io_ctx("symlink_metadata", &path)?;
            let file_type = meta.file_type();
            let target = to.join(entry.file_name());
            if file_type.is_dir() {
                stack.push((path, target));
            } else if file_type.is_file() {
                link_or_copy(&path, &target)?;
            } else {
                return Err(crate::error::CoreError::UnsafeArchive {
                    detail: "staging dir member became a symlink or non-regular file while it \
                             was being ingested"
                        .to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Remove a per-job working dir on drop (success or failure), best-effort.
struct WorkDirGuard<'a>(&'a Path);

impl Drop for WorkDirGuard<'_> {
    fn drop(&mut self) {
        // Best-effort, but not silent. A cleanup that fails leaves the snapshot behind, and
        // its hard links raise the drop's own files to `nlink == 2`. The next retry then
        // fails `check_staging_dir` with a permanent, misleading hardlink verdict, which is
        // undiagnosable without knowing the leftover exists. `Drop` cannot be async or
        // return `Result`, so a warning naming the path is what this can do.
        //
        // `NotFound` is expected and benign: the guard is armed before the directory is
        // created, so an early return that precedes creation drops a guard over a path that
        // never existed. Only a real removal failure is worth a line.
        if let Err(e) = fs::remove_dir_all(self.0)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.0.display(),
                error = %e,
                "failed to remove ingest working directory on drop; a leftover snapshot can \
                 raise its files to nlink==2 and make the next retry fail check_staging_dir with \
                 a false hardlink verdict"
            );
        }
    }
}

/// The recognized members of a valid staging dir.
struct Layout {
    /// The `allele-freq.*.parquet` data files (absolute paths under `src`).
    parquet_files: Vec<PathBuf>,
}

/// Validate the staging dir's root layout.
///
/// Allowed at the root: `manifest.json` (required), `allele-freq.*` parquet data
/// files matching the naming pattern with chromosome in `1-22|X|Y|M`, at least one required,
/// and an optional `headers/` directory. `variants.*` and `samples.parquet`, the unsupported
/// individual-level format, and any other unexpected root entry are rejected. A directory
/// cannot hold two identically named entries, so no two members can resolve to the same
/// in-package path.
fn check_file_layout(src: &Path) -> CoreResult<Layout> {
    let mut has_manifest = false;
    let mut parquet_files: Vec<PathBuf> = Vec::new();

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(invalid_manifest(
                "a staging-dir member has a non-UTF-8 name",
            ));
        };

        if file_type.is_dir() {
            // The only allowed root directory is headers/ (dropped at store time).
            if name == "headers" {
                continue;
            }
            return Err(invalid_manifest(&format!(
                "unexpected directory {name:?} at the package root"
            )));
        }

        // A regular file at the root.
        if name == "manifest.json" {
            has_manifest = true;
            continue;
        }
        // Reject the unsupported individual-level format explicitly.
        if name.starts_with("variants.") || name == "samples.parquet" {
            return Err(invalid_manifest(
                "individual-level data (variants.*/samples.parquet) is not a supported format",
            ));
        }
        if is_allele_freq_name(name) {
            parquet_files.push(path);
            continue;
        }
        return Err(invalid_manifest(&format!(
            "unexpected file {name:?} at the package root"
        )));
    }

    if !has_manifest {
        return Err(invalid_manifest("manifest.json is required but missing"));
    }
    if parquet_files.is_empty() {
        return Err(invalid_manifest(
            "at least one allele-freq.*.parquet data file is required",
        ));
    }
    Ok(Layout { parquet_files })
}

/// Whether `name` is a well-formed `allele-freq.chr{CHR}.{block}.br{range}.{vcfid}.parquet`
/// data-file name with a recognized chromosome.
///
/// Layout: `allele-freq` . `chr{CHR}` . `{block}` . `br{range}` . `{vcfid}` . `parquet`
/// (six dot-separated components). `{CHR}` is `1`-`22`, `X`, `Y`, or `M`.
fn is_allele_freq_name(name: &str) -> bool {
    // The slice pattern pins the component count and the two fixed literals in one go,
    // and names the rest so the checks below read as fields rather than indices.
    let parts: Vec<&str> = name.split('.').collect();
    let ["allele-freq", chr, block, range, vcf_id, "parquet"] = parts[..] else {
        return false;
    };
    let (Some(chr), Some(range)) = (chr.strip_prefix("chr"), range.strip_prefix("br")) else {
        return false;
    };
    // {block} and {range} must be canonical decimal, by the same rule `is_valid_chr` applies
    // to {chr}. A looser parse is not enough, because the two consumers disagree on what a
    // name means: `validate_parquet` builds its uniqueness group by string-splitting the
    // filename, while `parse_block_and_range`, and therefore serve-time file selection,
    // parses a `u64`. So `…chr3.0.br10000000…` and `…chr3.00.br10000000…` are different
    // uniqueness groups but the same served block. Two files carrying identical rows are
    // then never compared by the k-way merge and are merged at serve time into one variant
    // group, so the beacon emits the same population twice in `frequencyInPopulations` and
    // the DCAT record's `numberOfRecords` is inflated. `u64::from_str` also accepts a
    // leading `+` and arbitrary leading zeros, so the collision set is unbounded.
    //
    // Enforcing it costs nothing: `convert` only ever emits the canonical unpadded form.
    is_valid_chr(chr) && is_canonical_u64(block) && is_canonical_u64(range) && !vcf_id.is_empty()
}

/// Whether `s` is the canonical decimal rendering of a `u64` — no leading `+`, no leading
/// zeros, no whitespace. `"0"` is canonical; `"00"` and `"+0"` are not.
fn is_canonical_u64(s: &str) -> bool {
    s.parse::<u64>().is_ok_and(|n| s == n.to_string())
}

/// Whether `chr` is in the canonical served set `1`-`22`, `X`, `Y`, `M`.
fn is_valid_chr(chr: &str) -> bool {
    match chr {
        "X" | "Y" | "M" => true,
        _ => chr
            .parse::<u8>()
            .is_ok_and(|n| (1..=22).contains(&n) && chr == n.to_string()),
    }
}

/// Minimal envelope for reading `config.manifestVersion` before the full strict
/// [`Manifest`] parse, so an unsupported future version yields a clean
/// version-mismatch message rather than an opaque field-level serde error (see
/// [`parse_and_validate_manifest`]).
#[derive(serde::Deserialize)]
struct ManifestVersionProbe {
    config: ManifestVersionProbeConfig,
}

/// The `config` sub-object of [`ManifestVersionProbe`] — carries only `manifestVersion`.
#[derive(serde::Deserialize)]
struct ManifestVersionProbeConfig {
    #[serde(rename = "manifestVersion")]
    manifest_version: u32,
}

/// Maximum accepted `manifest.json` size, in bytes. It is a property of the package format
/// rather than of one program, so every reader of a `manifest.json` shares this value.
///
/// The manifest is read whole and, after the typed parse, materialized again as a full
/// `serde_json` DOM to preserve additive metadata fields, which multiplies the memory. With
/// no dedicated cap it would be bounded only by the coarse extraction `max_total_bytes`,
/// which is routinely above node RAM, so a hostile package shipping a multi-gigabyte
/// manifest could abort the process.
///
/// 8 MiB is three orders of magnitude above the largest real manifest, which holds metadata,
/// config and source-file provenance but never file bodies, while bounding the read and the
/// DOM to a survivable size. Both the node's ingest path and the tool's `inspect` path
/// enforce it, because a value the node accepts but the tool refuses to read would make a
/// valid package un-inspectable.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// The manifest's filename inside a built dataset dir or an extracted package.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Read `<dir>/manifest.json`, bounded by [`MAX_MANIFEST_BYTES`].
///
/// The cap is not a parameter. Every reader of a `manifest.json` goes through this
/// function, so there is no argument to omit and no filename to misspell. Spelling the
/// capped read out per call site makes "every reader enforces the cap" an invariant held in
/// as many copies as there are readers, and lets a new reader ship without it or with a
/// different value.
///
/// # Errors
///
/// Propagates [`std::io::Error`] — including [`std::io::ErrorKind::InvalidData`] with a
/// `"<path> exceeds the <cap>-byte cap"` message when the file is over the ceiling, which
/// callers may discriminate on to report the size rather than a generic read failure.
pub fn read_manifest_bytes(dir: &std::path::Path) -> std::io::Result<Vec<u8>> {
    crate::util::read_capped(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)
}

/// Reject a `manifest.json` larger than [`MAX_MANIFEST_BYTES`] before it is read into
/// memory.
fn check_manifest_size(len: u64) -> CoreResult<()> {
    if len > MAX_MANIFEST_BYTES {
        return Err(invalid_manifest(&format!(
            "manifest.json is {len} bytes, exceeding the {MAX_MANIFEST_BYTES}-byte limit"
        )));
    }
    Ok(())
}

/// Parse `manifest.json` into a [`Manifest`] and validate its `metadata`/`config`.
///
/// The `files` and `internal` sections are treated as opaque (parsed only so the
/// document deserializes; never validated). Checks: catalog membership in
/// `node_catalogs`, a valid dataset id, a supported `manifestVersion`, and the
/// aggregated-only mode.
///
/// Returns the typed [`Manifest`] alongside the raw `metadata` JSON object, as a
/// [`serde_json::Value`] or `Null` if absent. The store step re-attaches any additive
/// metadata fields the typed struct does not model from this raw value, so the stored
/// manifest stays a faithful superset.
fn parse_and_validate_manifest(
    src: &Path,
    node_catalogs: &BTreeMap<String, String>,
) -> CoreResult<(Manifest, serde_json::Value)> {
    let path = src.join("manifest.json");
    // Bound the manifest size before reading it whole, and before the DOM parse below, so a
    // hostile multi-gigabyte manifest cannot exhaust node memory (see `MAX_MANIFEST_BYTES`).
    //
    // Cap the read itself, not a preceding stat. A stat is a snapshot and the staging dir is
    // provider-writable, so the file can grow between the two calls; capping the read is
    // what closes that window. Reading one byte past the cap is enough for
    // `check_manifest_size` to classify it, keeping the `InvalidManifest` class and message.
    let raw = crate::util::read_capped(&path, MAX_MANIFEST_BYTES.saturating_add(1)).map_err(
        |e| match e.kind() {
            // Larger than the cap: memory is already bounded, which is the security
            // property. Classify it as the manifest fault it is, not as an I/O error.
            std::io::ErrorKind::InvalidData => invalid_manifest(&format!(
                "manifest.json exceeds the {MAX_MANIFEST_BYTES}-byte limit"
            )),
            _ => CoreError::Io(e),
        },
    )?;
    check_manifest_size(u64::try_from(raw.len()).unwrap_or(u64::MAX))?;
    // Read the version discriminator from a minimal envelope before the strict typed parse,
    // so a future breaking `manifestVersion` is rejected with an explicit version-mismatch
    // message instead of an opaque field-level serde error from the full deserialize. A
    // manifest too malformed to yield even the version falls through to the parse error.
    if let Ok(probe) = serde_json::from_slice::<ManifestVersionProbe>(&raw)
        && probe.config.manifest_version != SUPPORTED_MANIFEST_VERSION
    {
        return Err(invalid_manifest(&format!(
            "manifest config.manifestVersion {} is not supported (expected {SUPPORTED_MANIFEST_VERSION})",
            probe.config.manifest_version
        )));
    }
    // `{e:?}`, not `{e}`: serde_json's `Display` embeds the offending input bytes, which are
    // provider-controlled. In text log format that string reaches an operator's terminal
    // unescaped, so a manifest carrying newlines, which forge a second log line, or ANSI
    // escapes, which rewrite the terminal, would be rendered verbatim. `Debug` applies
    // `escape_debug`, so the bytes stay inert. The JSON formatter escapes on its own.
    let manifest: Manifest = serde_json::from_slice(&raw)
        .map_err(|e| invalid_manifest(&format!("manifest.json is not a valid manifest: {e:?}")))?;

    let meta = &manifest.metadata;
    if !crate::id::is_valid_dataset_id(&meta.dataset_id) {
        return Err(invalid_manifest(
            "manifest metadata.datasetId is not a valid dataset ID",
        ));
    }
    if meta.catalog.is_empty() {
        return Err(invalid_manifest("manifest metadata.catalog is empty"));
    }
    if !node_catalogs.contains_key(&meta.catalog) {
        return Err(CoreError::UnknownCatalog {
            name: meta.catalog.clone(),
        });
    }
    // The node ingest gate is the authoritative trust boundary for the public RDF plane. A
    // hand-assembled `.tar.c4gh`, one not produced by `gdi-dataset-tool build`, must satisfy
    // the same mandatory-field, enum, IRI-safety and contact-point constraints as a
    // tool-built one, so the FDP emitter can never serve a record that fails the SHACL
    // shapes. This is the same shared validator the tool applies: description present;
    // accessRights, type, healthCategory and conformsTo enums; applicableLegislation and
    // healthCategory non-empty; contactPoint completeness; IRI well-formedness and
    // IRIREF-character safety. Catalog membership is checked above, and `files`, `internal`
    // and `config` are out of scope here.
    //
    // Its non-fatal advisories are logged rather than dropped: on a package this tool did
    // not build, the node's log is the only place an advisory can reach the operator.
    // The strings are validator-authored constants, never provider text.
    //
    // The two classes keep their levels. A warning is something to fix, such as an absent
    // EHDS ELI or an omitted recommended field. A note describes a valid configuration,
    // such as a contactPoint without its recommended `hasURL`, and is nobody's action item;
    // logging those at `warn` would put a few lines of noise per dataset per ingest in
    // front of an operator who has done nothing wrong.
    let advisories = crate::validate_pkg::validate_overlay_result(meta)?;
    for warning in &advisories.warnings {
        tracing::warn!(
            dataset = %meta.dataset_id,
            warning = %warning,
            "package metadata advisory at ingest"
        );
    }
    for note in &advisories.notes {
        tracing::info!(
            dataset = %meta.dataset_id,
            note = %note,
            "package metadata note at ingest"
        );
    }

    let config = &manifest.config;
    if config.manifest_version != SUPPORTED_MANIFEST_VERSION {
        return Err(invalid_manifest(&format!(
            "manifest config.manifestVersion {} is not supported (expected {SUPPORTED_MANIFEST_VERSION})",
            config.manifest_version
        )));
    }
    if config.mode != DatasetMode::Aggregated {
        return Err(invalid_manifest(
            "config.mode=individual (individual-level genotypes) is not yet supported",
        ));
    }
    if config.assembly.reference.is_empty() {
        return Err(invalid_manifest("manifest config.assembly is empty"));
    }
    // Canonicalize by rejection. The Beacon query path selects a dataset by comparing the
    // request's normalized assembly, with synonyms folded to GRCh37 or GRCh38, against this
    // stored value case-insensitively, while `accession_for` matches it case-sensitively. A
    // non-canonical synonym such as `hg38`, or a mis-cased label such as `GRCH38`, would
    // leave the dataset Visible yet unqueryable on `g_variants`. Enforcing the same strict
    // canonical set the tool does keeps the stored assembly at GRCh37 or GRCh38.
    if !crate::chrom::is_known_assembly(&config.assembly.reference) {
        return Err(invalid_manifest(&format!(
            "manifest config.assembly.reference {:?} is not supported (expected GRCh37 or GRCh38)",
            config.assembly.reference
        )));
    }
    // config.afSourceReference is served verbatim to Beacon clients as a URL in
    // `frequencyInPopulations[].sourceReference`. A hand-assembled manifest must satisfy the
    // same scheme allow-list and IRIREF safety the tool's build path enforces, so a
    // `javascript:` or `data:` value, or one carrying control characters, can never reach a
    // client that renders it as a link.
    if let Some(asr) = &config.af_source_reference {
        crate::validate_pkg::validate_url("config.afSourceReference", asr)?;
    }
    // config.afSource is the sibling of the field above and lands in the same served object,
    // `frequencyInPopulations[].source`, so it needs a validator for the same reasons.
    //
    // The length cap is the part that matters most: `assemble_dataset` clones this string
    // into every result entry, and `max_page_limit` is applied per dataset, so a value
    // filling most of an 8 MiB manifest yields gigabytes per anonymous request, per matching
    // dataset. The bound matches its sibling's IRIREF cap rather than introducing a second
    // number, because the two fields are rendered side by side.
    if let Some(af_source) = &config.af_source {
        crate::validate_pkg::validate_bounded_text("config.afSource", af_source)?;
    }

    // Capture the raw `metadata` object with a second, cheap parse of the already-validated
    // bytes, so the store step can re-attach additive metadata fields the typed struct
    // dropped. The typed parse above already proved the document is valid.
    let raw_metadata = serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()
        .and_then(|mut v| v.get_mut("metadata").map(serde_json::Value::take))
        .unwrap_or(serde_json::Value::Null);

    Ok((manifest, raw_metadata))
}

/// Verify the extracted staging tree against the manifest's `payload` section.
///
/// Answers whether this node received what the producer said they packed. The
/// `parquet-digests.json` sidecar is computed from the received bytes after storage, so it
/// records whatever arrived: if a package's contents disagree with its own manifest, that
/// sidecar enshrines the disagreement and `verify --digest` reports `ok` from then on. The
/// tool refuses to build such a package, but a node ingests packages built by other
/// producers and by older tool versions.
///
/// A no-op when the manifest declares no `payload`, as every package built before the
/// section existed does: absence is unknown, not verified empty.
///
/// An `algorithm` this build cannot compute is a hard rejection rather than a no-op.
/// Absence means the producer made no claim; an unknown algorithm means the producer made
/// one this node cannot check, and ingesting it would record a `payload` the node then
/// presents as verified.
///
/// Runs before storage and before `files` and `internal` are stripped, so a package that
/// fails leaves nothing behind in the data dir. It costs one extra read of the payload,
/// which is cheap next to the decrypt, the extract and the parquet validation scan.
///
/// Checks the declared side only: every member the manifest names must be present and
/// match. An extra file on disk that the manifest does not declare is not caught here; the
/// tool checks that direction, and `check_staging_dir` bounds what may exist.
///
/// # Errors
///
/// Returns an invalid-manifest [`CoreError`] if the declared `algorithm` is one this
/// build cannot compute, or a declared member is missing, has different bytes or size,
/// or is named unsafely.
fn verify_declared_payload(src: &Path, manifest: &Manifest) -> CoreResult<()> {
    let Some(payload) = manifest.payload.as_ref() else {
        return Ok(());
    };
    if !payload.algorithm_supported() {
        return Err(invalid_manifest(&format!(
            "manifest payload declares algorithm {:?}, which this build cannot compute; \
             refusing to ingest a payload it cannot verify",
            payload.algorithm
        )));
    }

    for (name, want) in &payload.members {
        // The key comes from an untrusted manifest and is about to be joined onto the
        // staging path. `check_staging_dir` bounds what the TAR could write, but says
        // nothing about what the manifest may name. Without this check a crafted key such
        // as `../../etc/shadow` would make the node hash an arbitrary readable file and
        // report whether it matches a chosen digest: a file-existence and content oracle.
        if name.is_empty()
            || name.starts_with('/')
            || name.contains('\\')
            || name
                .split('/')
                .any(|seg| seg == ".." || seg == "." || seg.is_empty())
        {
            return Err(invalid_manifest(&format!(
                "manifest payload names an unsafe member path: {name:?}"
            )));
        }
        let path = src.join(name);
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(invalid_manifest(&format!(
                    "manifest payload declares {name:?}, but the package does not contain it"
                )));
            }
            Err(e) => return Err(CoreError::from(e)),
        };
        let (got, size) = crate::util::sha256_hex_reader(std::io::BufReader::new(file))?;
        // Size is compared, not merely reported: the hasher already returns it, so the
        // check is free, and the message below interpolates it. An unverified field matters
        // here because `stored_manifest_json` retains `payload` as the node's at-rest record
        // of what the package was supposed to contain.
        if got != want.sha256 || size != want.size {
            return Err(invalid_manifest(&format!(
                "manifest payload mismatch for {name:?}: declared sha256 {} / {} bytes, \
                 found {got} / {size}: the package does not contain what its own manifest \
                 says it does",
                want.sha256, want.size
            )));
        }
    }
    Ok(())
}

/// Serialize the stored `manifest.json` bytes: the typed manifest with `files` and
/// `internal` stripped, so only `metadata` and `config` persist, and with additive
/// raw-metadata keys merged back. `metadata` may grow additive fields without a version
/// bump, and re-serializing the typed struct alone would drop fields this build does not
/// model.
///
/// Deterministic for a given (`manifest`, `raw_metadata`): two stores of the same
/// dataset produce byte-identical output, which [`store_atomically`] relies on to
/// recognise an already-completed store on a crash-recovery re-ingest.
///
/// # Errors
/// Returns [`CoreError::InternalError`] if the manifest cannot be serialized.
fn stored_manifest_json(
    manifest: &Manifest,
    raw_metadata: &serde_json::Value,
) -> CoreResult<Vec<u8>> {
    let serialize_failed = |e: serde_json::Error| CoreError::InternalError {
        detail: format!("serializing stored manifest: {e}"),
    };

    let stored = Manifest {
        metadata: manifest.metadata.clone(),
        files: Vec::new(),
        internal: Internal::default(),
        // Retained, unlike `files` and `internal`. Those two are stripped because they are
        // the provider's non-public source inventory and bookkeeping. `payload` is the
        // digest of the parquet this node now serves, carries no upstream provenance, and is
        // the only at-rest record of what the package was supposed to contain; stripping it
        // would leave the node holding data it cannot re-verify.
        //
        // It is the package's inventory, not this directory's. `headers/` members are
        // digested here and dropped at store time for data minimisation, so a reader that
        // treats this map as a listing of `<data_dir>/{id}/` finds every `headers/*` entry
        // missing on a healthy dataset. Re-verify the `allele-freq.*.parquet` entries
        // against the directory and use the rest only as a record of what arrived.
        //
        // `Payload::members` is a `BTreeMap`, so it serializes in key order:
        // `store_atomically` relies on byte-identical output across re-ingests.
        payload: manifest.payload.clone(),
        config: manifest.config.clone(),
    };
    let mut stored_value = serde_json::to_value(&stored).map_err(serialize_failed)?;
    if let (Some(dst), Some(src)) = (
        stored_value
            .get_mut("metadata")
            .and_then(serde_json::Value::as_object_mut),
        raw_metadata.as_object(),
    ) {
        // Only genuinely-additive keys are added (`or_insert` keeps the typed value for
        // every known field); a `null` carries no information, so skip it rather than
        // re-emit fields the typed form intentionally omitted.
        for (key, value) in src {
            if !value.is_null() {
                dst.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
    serde_json::to_vec_pretty(&stored_value).map_err(serialize_failed)
}

/// Whether an existing store `target` already holds this dataset, a crash-recovery
/// re-ingest that is safe to treat as an idempotent success, or a different one, which is
/// an immutability conflict. Decided by comparing the stored `manifest.json` against the
/// bytes this store would write. A missing or unreadable manifest is treated as a conflict,
/// so an unrecognisable existing target is never accepted.
enum ExistingTarget {
    AlreadyStored,
    Conflict,
}

fn classify_existing_target(target: &Path, want_manifest_json: &[u8]) -> ExistingTarget {
    match fs::read(target.join("manifest.json")) {
        Ok(bytes) if bytes == want_manifest_json => ExistingTarget::AlreadyStored,
        _ => ExistingTarget::Conflict,
    }
}

/// Store the validated dataset atomically.
///
/// Stores each parquet file into a fresh `data_dir/.incoming/{id}.{rand}/`, copied plaintext
/// or, when `encryptor` carries a minter, PME-encrypted with a freshly minted per-file DEK
/// as a `PARE` file. It writes the manifest there with `files` and `internal` stripped and
/// `headers/` omitted, sets the files read-only, fsyncs the files and the directory, then
/// renames the working dir into `data_dir/{id}/`. On any failure the working dir is removed.
#[expect(
    clippy::too_many_arguments,
    reason = "the store inputs plus the writer gate; a params struct only moves the fan-out"
)]
fn store_atomically(
    data_dir: &Path,
    id: &str,
    parquet_files: &[PathBuf],
    manifest: &Manifest,
    raw_metadata: &serde_json::Value,
    encryptor: &DatasetEncryptor,
    gate: &WriterGate,
    provenance: &WriterProvenance,
) -> CoreResult<()> {
    let target = data_dir.join(id);
    if target.exists() {
        // A present target is always a complete store: a dataset dir becomes visible only
        // through the atomic rename of a finished working dir at the end of this function.
        // Reaching this path for an id whose target exists is the crash-recovery case, where
        // a prior attempt renamed the dir into place but crashed before the caller recorded
        // the status, so the runtime still sees the id as absent or errored and retries it.
        // If the stored manifest is byte-identical to what this run would write, the store
        // already succeeded: return `Ok` so the caller completes the interrupted transaction
        // by recording the status and consuming the source. Failing unconditionally instead
        // would wedge that retry into a permanent error loop, with the completed dataset
        // never served. A differing manifest is an attempt to mutate an immutable id and
        // stays a hard error.
        let want = stored_manifest_json(manifest, raw_metadata)?;
        return match classify_existing_target(&target, &want) {
            ExistingTarget::AlreadyStored => {
                // Clear the pending erase intent here too. A complete, byte-identical
                // target is a publish by the same proof as the successful store at the end
                // of this function, and this arm returns before reaching that clear. A
                // `.deleting/{id}` marker that survived an erase whose removal failed
                // without unlinking would otherwise be replayed at the next boot, erasing a
                // live, served, re-added dataset. Not hoisted above the `target.exists()`
                // branch: clearing on a path that can still fail would discard a genuine
                // erase intent. Best-effort, and must not fail an otherwise complete ingest.
                let _ = crate::util::clear_deleting_marker(data_dir, id, Ok(()));
                Ok(())
            }
            ExistingTarget::Conflict => Err(CoreError::InternalError {
                detail: "store target already exists for an immutable id".to_owned(),
            }),
        };
    }

    // The writer-key gate runs before the rename, so a package rejected under `enforce` is
    // never renamed into place and cannot be re-admitted by a hydrate or reconcile race. It
    // sits after the `target.exists()` short-circuit above so that an already-stored
    // dataset, from a crash-recovery re-run or a re-presentation, is never re-gated: a node
    // restart after an allow-list edit that dropped a key would otherwise reject a dataset
    // that is already published and served.
    gate.gate_store(provenance)?;

    let incoming = data_dir.join(".incoming");
    crate::util::create_private_dir(&incoming).io_ctx("create_dir_all", &incoming)?;
    let work = incoming.join(format!("{id}.{}", rand_suffix()));
    // A leftover from a crashed prior run with the same suffix is vanishingly unlikely, but
    // clearing it keeps the copy below clean.
    if work.exists() {
        fs::remove_dir_all(&work)?;
    }
    crate::util::create_private_dir(&work)?;

    // Everything from here is cleaned up on error.
    let result = (|| -> CoreResult<()> {
        stage_parquet_files(&work, parquet_files, encryptor)?;
        stage_manifest(&work, manifest, raw_metadata)?;
        // Test-only fault point, a no-op unless the `fault-injection` feature is built. An
        // injected ENOSPC models the scratch disk filling mid-store, a transient error, so
        // the working dir is cleaned up below and the job is retried. An injected panic
        // models a crash mid-publish, which unwinds out of this function leaving the working
        // dir under `.incoming/` for the next boot's reap. Keyed by `id`, so a concurrent
        // test's ingest is unaffected.
        crate::faults::guard(crate::faults::FaultPoint::IngestStore, id)?;
        // fsync the working dir so the renamed dir's contents are durable.
        fsync_dir_strict(&work)?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_dir_all(&work);
        return Err(e);
    }

    // Atomic publish: rename the complete working dir into place. A query never
    // observes a half-written dataset because only a complete dir is renamed.
    if let Err(e) = fs::rename(&work, &target) {
        let _ = fs::remove_dir_all(&work);
        // Name both ends of the failed atomic publish (source working dir → target)
        // in the message, preserving the io kind for classification.
        return Err(CoreError::Io(std::io::Error::new(
            e.kind(),
            format!("rename {} -> {}: {e}", work.display(), target.display()),
        )));
    }
    // Test-only fault point, a no-op unless the `fault-injection` feature is built. Arming a
    // panic here models a crash in the torn cross-store window: the dataset dir is committed
    // on disk, but the caller has not yet recorded the status entry. A restart must recover
    // through the idempotent-store path above rather than wedge on a permanent error. Keyed
    // by `id`.
    crate::faults::guard(crate::faults::FaultPoint::PostRename, id)?;
    // Best-effort durability of the rename itself.
    let _ = fsync_dir_strict(data_dir);
    // A successful publish proves any pending erase intent for this id is obsolete: the
    // dataset was re-added after the take-down the marker records. Clearing it here, rather
    // than only where the erasure ran, makes "publishing an id invalidates its deletion
    // marker" true at the one chokepoint every ingest passes through. Without it, a marker
    // that survived an unlink lost to a crash is replayed at the next boot, removing
    // whatever is at `data_dir/{id}` and erasing the dataset that was just re-added.
    // Best-effort: a failure here must not fail an otherwise complete ingest.
    let _ = crate::util::clear_deleting_marker(data_dir, id, Ok(()));
    Ok(())
}

/// Stage every validated parquet into the store's working dir `work`, read-only and
/// fsync'd.
///
/// Each file is PME-encrypted (when `encryptor` carries a minter) or copied plaintext;
/// the file is self-describing (`PARE` vs `PAR1`), so a mixed store reads back fine. For
/// plaintext stores only, a sha256 of each stored file is collected into the
/// `parquet-digests.json` sidecar, which closes the on-disk bit-rot gap. PME files already
/// carry AEAD, so they get no digest (see [`crate::digest`]).
fn stage_parquet_files(
    work: &Path,
    parquet_files: &[PathBuf],
    encryptor: &DatasetEncryptor,
) -> CoreResult<()> {
    let want_digests = encryptor.writes_plaintext();
    let mut digests = BTreeMap::new();
    for parquet in parquet_files {
        let name = parquet
            .file_name()
            .ok_or_else(|| CoreError::InternalError {
                detail: "parquet path has no file name".to_owned(),
            })?;
        let dest = work.join(name);
        store_parquet_file(parquet, &dest, encryptor)?;
        set_read_only(&dest)?;
        fsync_file(&dest)?;
        if want_digests {
            let (hex, _size) =
                crate::util::sha256_hex_reader(fs::File::open(&dest).io_ctx("open", &dest)?)?;
            digests.insert(name.to_string_lossy().into_owned(), hex);
        }
    }
    if !want_digests {
        return Ok(());
    }
    crate::digest::write_digests_sidecar(work, &digests)?;
    let sidecar = work.join(crate::digest::PARQUET_DIGESTS_FILE);
    if sidecar.exists() {
        set_read_only(&sidecar)?;
        fsync_file(&sidecar)?;
    }
    Ok(())
}

/// Write the stored `manifest.json` into the store's working dir `work`, read-only and
/// fsync'd.
///
/// The bytes come from [`stored_manifest_json`] (files/internal stripped, additive
/// metadata merged back) — the same call the idempotency check at the top of
/// [`store_atomically`] compares against, so the bytes compared there are exactly the
/// bytes written here.
#[expect(
    clippy::disallowed_methods,
    reason = "writes into the staging directory that store_atomically renames into place"
)]
fn stage_manifest(
    work: &Path,
    manifest: &Manifest,
    raw_metadata: &serde_json::Value,
) -> CoreResult<()> {
    let json = stored_manifest_json(manifest, raw_metadata)?;
    let manifest_path = work.join("manifest.json");
    fs::write(&manifest_path, &json).io_ctx("write", &manifest_path)?;
    set_read_only(&manifest_path)?;
    fsync_file(&manifest_path)
}

/// Set a stored data-dir file immutable and owner-only.
///
/// On Unix this is `0o400`. `set_readonly(true)` alone clears only the write bits and leaves
/// a world-readable `0o444`, so on a shared-volume host a co-located uid could read the
/// stored dataset, including a hidden or taken-down one. Every stored-file site — parquet,
/// digest sidecar, manifest — routes through here, so the mode is set in one place.
fn set_read_only(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    }
    #[cfg(not(unix))]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// fsync a file's contents to disk.
fn fsync_file(path: &Path) -> CoreResult<()> {
    let file = fs::File::open(path)?;
    file.sync_all()?;
    Ok(())
}

/// Whether a directory `sync_all` error reflects a platform limitation to tolerate, rather
/// than a durability failure that must propagate. Some filesystems cannot fsync a directory
/// file descriptor and return `Unsupported` or `EINVAL`.
fn dir_sync_unsupported(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
    )
}

/// fsync a directory so its entries are durable.
///
/// A genuine `sync_all` I/O error is propagated, so the pre-rename durability barrier fails
/// rather than publishing a non-durable directory. Only a platform limitation where a
/// directory file descriptor cannot be fsync'd (see [`dir_sync_unsupported`]) is tolerated.
/// [`fsync_file`] propagates its `sync_all` error the same way.
fn fsync_dir_strict(path: &Path) -> CoreResult<()> {
    let dir = fs::File::open(path).map_err(CoreError::Io)?;
    match dir.sync_all() {
        Ok(()) => Ok(()),
        Err(e) if dir_sync_unsupported(&e) => Ok(()),
        Err(e) => Err(CoreError::Io(e)),
    }
}

/// Verify a manifest's declared `metadata.populations` against the labels actually present
/// in the parquet.
///
/// The beacon advertises this set on `/datasets` so a client can tell a suppressed
/// population from an absent one. An unverified claim would let a node assert a population
/// the data does not hold, reintroducing the ambiguity the disclosure removes. Checked the
/// same way `numberOfRecords` is.
///
/// Absent is tolerated, not rejected: a package built before the field existed advertises
/// no set, and the beacon then omits `populations` rather than claiming an empty one.
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] when a declared set differs from the observed
/// one, naming the declared-but-absent and present-but-undeclared labels.
fn check_declared_populations(manifest: &Manifest, observed: &BTreeSet<String>) -> CoreResult<()> {
    let Some(declared) = manifest.metadata.populations.as_ref() else {
        return Ok(());
    };
    let declared: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
    let observed: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    if declared == observed {
        return Ok(());
    }
    let phantom: Vec<&str> = declared.difference(&observed).copied().collect();
    let missing: Vec<&str> = observed.difference(&declared).copied().collect();
    Err(invalid_manifest(&format!(
        "manifest metadata.populations does not match the parquet data: \
         declared-but-absent [{}], present-but-undeclared [{}]",
        phantom.join(", "),
        missing.join(", ")
    )))
}

/// Warn, never reject, for each population label in the parquet that
/// [`crate::popfield::is_conforming_population_label`] would not emit. The sex-chromosome
/// strata `XX` and `XY` are the known shape.
///
/// `build` deny-lists such labels at conversion, but a dataset converted by an older tool
/// still publishes them, and `populations` rides every beacon `datasets` entry and every
/// `g_variants` resultSet, where a federation aggregator sees `XX` beside a real node's `EE`
/// with nothing to tell them apart. The node cannot know whether the provider meant it, so
/// it names the dataset and the label and leaves the decision to the operator: hide the
/// dataset, or rebuild it with a current tool. The label is provider text bounded only by
/// `max_population_len`, so it is escaped before it reaches the log stream.
fn warn_on_nonconforming_population_labels(dataset_id: &str, observed: &BTreeSet<String>) {
    for label in observed
        .iter()
        .filter(|label| !crate::popfield::is_conforming_population_label(label))
    {
        tracing::warn!(
            dataset = dataset_id,
            population = %label.escape_default(),
            "population label is not one the dataset tool emits (a reserved sex-chromosome \
             token, or not a country code); it is published as-is in `populations` on \
             /datasets and every g_variants resultSet. Rebuild with a current tool, or \
             `dataset hide` it"
        );
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    #![expect(
        clippy::similar_names,
        reason = "sender/recipient and node/stale sk/pk are the standard, clearest crypto naming"
    )]
    use super::*;
    use std::sync::Arc;

    use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
    use parquet::arrow::arrow_writer::ArrowWriter;

    #[test]
    fn writer_admission_decides_by_provenance_and_allowlist() {
        let allow = vec!["sha256:aa".to_owned(), "sha256:bb".to_owned()];
        // A plaintext drop carries no key, so it can never be allow-listed.
        assert_eq!(
            writer_admission(&allow, &WriterProvenance::Plaintext),
            WriterAdmission::Unknown(WriterUnknownKind::PlaintextDrop)
        );
        // A recovered key in the list is admitted; one not in the list is untrusted.
        assert_eq!(
            writer_admission(
                &allow,
                &WriterProvenance::Recovered(vec!["sha256:aa".to_owned()])
            ),
            WriterAdmission::Admitted
        );
        assert_eq!(
            writer_admission(
                &allow,
                &WriterProvenance::Recovered(vec!["sha256:zz".to_owned()])
            ),
            WriterAdmission::Unknown(WriterUnknownKind::UntrustedKey(vec![
                "sha256:zz".to_owned()
            ]))
        );
        // Any one allow-listed key among several is enough.
        assert_eq!(
            writer_admission(
                &allow,
                &WriterProvenance::Recovered(vec!["sha256:zz".to_owned(), "sha256:bb".to_owned()])
            ),
            WriterAdmission::Admitted
        );
        // An unreadable header is never admitted; an empty allow-list admits no recovered key.
        std::assert_matches!(
            writer_admission(&allow, &WriterProvenance::Unrecoverable("bad".to_owned())),
            WriterAdmission::Unknown(WriterUnknownKind::UntrustedKey(_))
        );
        std::assert_matches!(
            writer_admission(
                &[],
                &WriterProvenance::Recovered(vec!["sha256:aa".to_owned()])
            ),
            WriterAdmission::Unknown(_)
        );
    }

    #[test]
    fn writer_gate_off_and_warn_never_reject_but_enforce_does() {
        let allow = vec!["sha256:aa".to_owned()];
        let unknown = WriterProvenance::Plaintext;
        // off and warn admit everything at the store gate; warn publishes for discovery.
        for policy in [
            crate::config::WriterPolicy::Off,
            crate::config::WriterPolicy::Warn,
        ] {
            let gate = WriterGate {
                policy,
                channel: "c",
                allowlist: &allow,
            };
            assert!(
                gate.gate_store(&unknown).is_ok(),
                "{policy:?} must not reject at the store"
            );
        }
        // enforce rejects an unadmitted writer with WriterRejected(PlaintextDrop).
        let gate = WriterGate {
            policy: crate::config::WriterPolicy::Enforce,
            channel: "c",
            allowlist: &allow,
        };
        std::assert_matches!(
            gate.gate_store(&unknown),
            Err(CoreError::WriterRejected {
                kind: WriterUnknownKind::PlaintextDrop,
                ..
            })
        );
        // enforce admits an allow-listed key.
        assert!(
            gate.gate_store(&WriterProvenance::Recovered(vec!["sha256:aa".to_owned()]))
                .is_ok()
        );
    }

    use crate::crypt4gh::{encrypt, generate_keypair};
    use crate::error::ErrorClass;
    use crate::model::{
        Agent, Assembly, DatasetMode, FileEntry, FileGroup, LocalizedText, ManifestConfig,
        ManifestMetadata,
    };
    use crate::parquet_io::allele_freq_schema;

    /// The node catalog allow-list used in tests.
    fn node_catalogs() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "gdi-aggregated".to_owned(),
            "Genome of Europe Aggregated Data".to_owned(),
        );
        m
    }

    /// A representative valid manifest (carries non-empty `files`/`internal` so we
    /// can assert they are stripped).
    fn sample_manifest(id: &str) -> Manifest {
        Manifest {
            payload: None,
            metadata: ManifestMetadata {
                dataset_id: id.to_owned(),
                catalog: "gdi-aggregated".to_owned(),
                title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
                description: Some(LocalizedText::Plain(
                    "Aggregated allele frequencies for COVID monogenic variants.".to_owned(),
                )),
                access_rights:
                    "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                        .to_owned(),
                applicable_legislation: vec![
                    "http://data.europa.eu/eli/reg/2018/1725/oj".to_owned(),
                ],
                license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
                creator: vec![Agent {
                    name: "University of Tartu".to_owned(),
                }],
                health_category: vec![
                    "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
                ],
                keywords: None,
                number_of_unique_individuals: None,
                conforms_to: None,
                type_: None,
                legal_basis: None,
                is_referenced_by: None,
                other_identifier: None,
                contact_point: None,
                number_of_records: Some(1),
                populations: None,
            },
            // Non-empty so the store-strip is observable.
            files: vec![FileGroup {
                category: "VCF".to_owned(),
                reference: Some("GRCh38".to_owned()),
                precise_reference: None,
                files: vec![FileEntry {
                    path: "covid.vcf".to_owned(),
                    sha256: Some("a".repeat(64)),
                    size: Some(123),
                    // Conversion provenance is a non-public provider claim carried inside
                    // the stripped `files` section. The sentinel proves it is not persisted,
                    // rather than merely absent from the typed struct.
                    conversion: Some(crate::model::ConversionStats {
                        input: crate::model::ConversionInput {
                            records: 1,
                            non_pass_records: 0,
                            gvcf_reference_blocks: 0,
                            populations_recognized: vec!["Total".to_owned()],
                        },
                        discarded: crate::model::ConversionDiscarded {
                            records_unsupported_contig: 0,
                            records_no_supported_alt: 0,
                            records_all_rows_withheld: 0,
                            records_no_af: 0,
                            alleles: 0,
                            ignored_info_fields: vec!["SECRET_SENTINEL_AF".to_owned()],
                            populations_without_af: Vec::new(),
                        },
                        suppressed: crate::model::ConversionSuppressed {
                            rows_below_floor: 0,
                            rows_collapsed_to_total: 0,
                            variants_collapsed_to_total: 0,
                        },
                        output: crate::model::ConversionOutput {
                            records: 1,
                            records_emitted: 1,
                            rows: 1,
                            populations: vec!["Total".to_owned()],
                        },
                    }),
                }],
            }],
            internal: Internal {
                internal_id: Some("secret-internal-id".to_owned()),
                ..Internal::default()
            },
            config: ManifestConfig {
                mode: DatasetMode::Aggregated,
                block_range: 10_000_000,
                af_source: None,
                af_source_reference: None,
                min_allele_count: 0,
                hide_lower_counts: None,
                assembly: Assembly {
                    reference: "GRCh38".to_owned(),
                },
                manifest_version: 1,
                generated_by: "test".to_owned(),
            },
        }
    }

    /// A label the dataset tool would not emit is warned about at ingest, naming the dataset
    /// and the label, and never rejected. Conforming labels produce no line.
    #[test]
    fn a_nonconforming_population_label_is_warned_about_by_id() {
        let observed: BTreeSet<String> = ["Total", "EE", "EE_F", "M", "XX"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let ((), logs) = test_util::capture_json_logs(|| {
            warn_on_nonconforming_population_labels("GDI-EE-UTARTU-20260409143052837", &observed);
        });
        let warns: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("population label is not one the dataset tool emits"))
            .collect();
        assert_eq!(
            warns.len(),
            1,
            "exactly the XX stratum is non-conforming: {logs}"
        );
        assert!(
            warns[0].contains("\"population\":\"XX\"")
                && warns[0].contains("GDI-EE-UTARTU-20260409143052837")
                && warns[0].contains("\"level\":\"WARN\""),
            "the line must name the dataset and the label at WARN: {}",
            warns[0]
        );

        let conforming: BTreeSet<String> = ["Total", "EE", "EE_F", "M"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let ((), logs) = test_util::capture_json_logs(|| {
            warn_on_nonconforming_population_labels("GDI-EE-UTARTU-20260409143052837", &conforming);
        });
        assert!(
            !logs.contains("population label"),
            "a conforming set must not warn: {logs}"
        );
    }

    /// Write one canonical-schema parquet with a single valid row.
    fn write_parquet(path: &Path) {
        write_parquet_with_population(path, "Total");
    }

    /// As [`write_parquet`], with the row's POPULATION label chosen by the caller.
    fn write_parquet_with_population(path: &Path, label: &str) {
        let schema = allele_freq_schema();
        // POS 40_000_000 (0-based) over blockRange 10_000_000 is block 4, matching the
        // `allele-freq.chr3.4.br10000000.*` fixture name.
        let pos = Int32Array::from(vec![40_000_000]);
        let ref_ = StringArray::from(vec!["T"]);
        let alt = StringArray::from(vec!["C"]);
        let vt = StringArray::from(vec!["SNP"]);
        let population = StringArray::from(vec![label]);
        let af = Float32Array::from(vec![0.1_f32]);
        let ac = Int32Array::from(vec![Some(1)]);
        // The genotype sub-counts count alleles and partition AC, so the single alternate
        // allele must sit in exactly one class. One heterozygote: AC_HOM 0 + AC_HET 1 +
        // AC_HEMI 0 == AC 1. All-zero sub-counts under AC = 1 would place an allele in no
        // class at all, which the ingest gate rejects.
        let ac_hom = Int32Array::from(vec![Some(0)]);
        let ac_het = Int32Array::from(vec![Some(1)]);
        let ac_hemi = Int32Array::from(vec![Some(0)]);
        let an = Int32Array::from(vec![Some(10)]);
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(pos),
                Arc::new(ref_),
                Arc::new(alt),
                Arc::new(vt),
                Arc::new(population),
                Arc::new(af),
                Arc::new(ac),
                Arc::new(ac_hom),
                Arc::new(ac_het),
                Arc::new(ac_hemi),
                Arc::new(an),
            ],
        )
        .unwrap();
        let file = fs::File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    /// Build a valid staging dir under `dir` for `id`, with a `headers/` dir and a
    /// full (files/internal-bearing) manifest. Returns the staging path.
    fn build_staging(dir: &Path, id: &str) -> PathBuf {
        let staging = dir.join("build").join(id);
        fs::create_dir_all(&staging).unwrap();
        // One data file (chr3, block 4).
        write_parquet(&staging.join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet"));
        // headers/ (must be dropped at store).
        let headers = staging.join("headers");
        fs::create_dir(&headers).unwrap();
        fs::write(
            headers.join("0123456789abcdef.vcf"),
            b"##fileformat=VCFv4.2\n",
        )
        .unwrap();
        // manifest.json.
        let manifest = sample_manifest(id);
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        staging
    }

    /// Rewrite the staged manifest with a patched `metadata.populations`.
    fn set_populations(staging: &Path, populations: Option<Vec<String>>) {
        let path = staging.join("manifest.json");
        let mut m: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        m.metadata.populations = populations;
        fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    }

    /// Rewrite the staged manifest with `edit` applied to its metadata section.
    fn edit_staged_metadata(staging: &Path, edit: impl FnOnce(&mut ManifestMetadata)) {
        let path = staging.join("manifest.json");
        let mut m: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut m.metadata);
        fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    }

    /// Ingest `staging` under a captured JSON subscriber, returning the log text.
    fn ingest_capturing_logs(tmp: &Path, staging: &Path) -> String {
        let (result, logs) = test_util::capture_json_logs(|| {
            ingest_staging_dir(
                staging,
                &tmp.join("data"),
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
        });
        result.unwrap_or_else(|e| panic!("ingest must succeed: {e}\n{logs}"));
        logs
    }

    /// A manifest whose `applicableLegislation` omits the EHDS ELI is ingested, and says so
    /// at `warn`, naming the dataset. A hand-assembled package never saw the tool's `build`,
    /// so the node's log is the only place the advisory can reach its operator.
    #[test]
    fn an_absent_ehds_eli_is_warned_about_at_ingest() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052861";
        // `sample_manifest` cites the 2018/1725 ELI, not the EHDS one.
        let staging = build_staging(tmp.path(), id);
        let logs = ingest_capturing_logs(tmp.path(), &staging);
        let warn = logs
            .lines()
            .find(|line| line.contains("EHDS ELI absent"))
            .unwrap_or_else(|| {
                panic!("the ingest gate must WARN about the absent EHDS ELI: {logs}")
            });
        assert!(
            warn.contains(id) && warn.contains("\"level\":\"WARN\""),
            "the advisory must name the dataset and arrive at WARN: {warn}"
        );
    }

    /// The other outcome: citing the EHDS ELI ingests silently on that count.
    #[test]
    fn citing_the_ehds_eli_produces_no_such_warning_at_ingest() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052862";
        let staging = build_staging(tmp.path(), id);
        edit_staged_metadata(&staging, |m| {
            m.applicable_legislation = vec![crate::validate_pkg::EHDS_ELI.to_owned()];
        });
        let logs = ingest_capturing_logs(tmp.path(), &staging);
        assert!(
            !logs.contains("EHDS ELI absent"),
            "a package citing the EHDS ELI must not warn about it: {logs}"
        );
    }

    /// A note-class advisory, a present optional parent missing a recommended sub-field, is
    /// logged at info rather than warn. It describes a valid configuration, and the operator
    /// would otherwise get warn lines per dataset per ingest for doing nothing wrong.
    #[test]
    fn a_metadata_note_is_logged_at_info_not_warn() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052863";
        let staging = build_staging(tmp.path(), id);
        edit_staged_metadata(&staging, |m| {
            m.contact_point = Some(crate::model::ContactPoint {
                fn_: Some("Data team".to_owned()),
                has_email: Some("mailto:data@example.org".to_owned()),
                has_url: None,
            });
        });
        let logs = ingest_capturing_logs(tmp.path(), &staging);
        let note = logs
            .lines()
            .find(|line| line.contains("hasURL"))
            .unwrap_or_else(|| panic!("the sub-field advisory must be logged: {logs}"));
        assert!(
            note.contains("\"level\":\"INFO\"") && note.contains(id),
            "a note must arrive at INFO, naming the dataset: {note}"
        );
        assert!(
            !logs
                .lines()
                .any(|line| line.contains("hasURL") && line.contains("\"level\":\"WARN\"")),
            "no note may arrive at WARN: {logs}"
        );
    }

    #[test]
    fn dir_sync_error_propagates_except_platform_unsupported() {
        use std::io::{Error, ErrorKind};
        // A platform that cannot fsync a directory fd (Unsupported / EINVAL) is a
        // tolerated limitation, so the ingest durability barrier still works there.
        assert!(dir_sync_unsupported(&Error::from(ErrorKind::Unsupported)));
        assert!(dir_sync_unsupported(&Error::from(ErrorKind::InvalidInput)));
        // A real durability failure must not be tolerated: it propagates, so the pre-rename
        // barrier fails rather than publishing a directory whose metadata was never durably
        // flushed. Discarding the `sync_all` result would swallow exactly this error.
        assert!(!dir_sync_unsupported(&Error::from(ErrorKind::Other)));
        assert!(!dir_sync_unsupported(&Error::other("EIO")));
    }

    #[test]
    fn a_declared_population_set_is_verified_against_the_parquet() {
        // The beacon advertises `metadata.populations` as the dataset's served set, so an
        // unverified claim would let a node tell users a population exists when the data
        // holds none, which is the ambiguity the disclosure fixes. `numberOfRecords` is
        // cross-checked the same way.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = build_staging(tmp.path(), id);
        set_populations(&staging, Some(vec!["EE".to_owned(), "Total".to_owned()]));

        let err = ingest_staging_dir(
            &staging,
            &tmp.path().join("data"),
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect_err("a false population claim must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("metadata.populations") && msg.contains("EE"),
            "the error must name the field and the phantom population: {msg}"
        );
    }

    /// The warning is wired into the ingest gate: a dataset whose parquet carries a label
    /// the tool would never emit is accepted, since an older tool's output is still a valid
    /// dataset, and the log names the dataset and the label so the operator can decide.
    #[test]
    fn an_ingested_dataset_with_a_nonconforming_label_is_accepted_and_warned_about() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = build_staging(tmp.path(), id);
        write_parquet_with_population(
            &staging.join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet"),
            "XX",
        );
        set_populations(&staging, Some(vec!["XX".to_owned()]));

        let (result, logs) = test_util::capture_json_logs(|| {
            ingest_staging_dir(
                &staging,
                &tmp.path().join("data"),
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
        });
        result.expect("a non-conforming label is warned about, never rejected");
        let warn = logs
            .lines()
            .find(|line| line.contains("population label is not one the dataset tool emits"))
            .unwrap_or_else(|| panic!("the ingest gate must WARN about XX: {logs}"));
        assert!(
            warn.contains("\"population\":\"XX\"") && warn.contains(id),
            "the WARN must name the label and the dataset: {warn}"
        );
    }

    #[test]
    fn a_truthful_population_set_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = build_staging(tmp.path(), id);
        set_populations(&staging, Some(vec!["Total".to_owned()]));
        ingest_staging_dir(
            &staging,
            &tmp.path().join("data"),
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("the parquet holds exactly Total");
    }

    #[test]
    fn a_manifest_without_populations_still_ingests() {
        // A package built before the field existed advertises no set rather than being
        // rejected. The beacon then omits `populations` entirely.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = build_staging(tmp.path(), id);
        set_populations(&staging, None);
        ingest_staging_dir(
            &staging,
            &tmp.path().join("data"),
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("an absent claim is not a false claim");
    }

    #[test]
    fn unsupported_manifest_version_gives_clean_message_before_full_parse() {
        // A future breaking `manifestVersion` is caught by the minimal version probe and
        // reported with an explicit version-mismatch message, not the opaque field-level
        // serde error the full parse would emit. This manifest is otherwise incomplete, with
        // no `metadata`, which the full parse would reject first, so the message proves the
        // probe runs before it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("manifest.json"),
            br#"{"config":{"manifestVersion":2}}"#,
        )
        .unwrap();
        let err = parse_and_validate_manifest(dir.path(), &BTreeMap::new()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("manifestVersion 2 is not supported"),
            "expected a version-mismatch message, got: {msg}"
        );
    }

    #[test]
    fn oversized_manifest_is_rejected_by_size_gate() {
        // A hostile package can ship a multi-gigabyte manifest.json, bounded otherwise only
        // by the coarse extraction cap, which the read plus the full DOM parse would
        // materialize and exhaust node memory. The size gate rejects it up front, before any
        // read. Exercised on the byte length directly, so the test need not write the file.
        let err = check_manifest_size(MAX_MANIFEST_BYTES + 1).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("exceed"),
            "expected a size-limit message, got: {err}"
        );
        // A manifest exactly at the cap is still accepted.
        assert!(check_manifest_size(MAX_MANIFEST_BYTES).is_ok());
    }

    #[test]
    fn writer_provenance_reports_no_fingerprints_for_the_non_recovered_variants() {
        assert!(WriterProvenance::Plaintext.fingerprints().is_empty());
        assert!(
            WriterProvenance::Unrecoverable("boom".to_owned())
                .fingerprints()
                .is_empty()
        );
        assert_eq!(
            WriterProvenance::Recovered(vec!["sha256:aa".to_owned()]).fingerprints(),
            ["sha256:aa"]
        );
    }

    #[test]
    fn manifest_cap_value_is_pinned() {
        // The boundary test above passes for any value of `MAX_MANIFEST_BYTES`: it
        // exercises the comparison, not the invariant. This pins the value itself, so a
        // widening cannot land unremarked. The tool imports this same constant, so there is
        // no second declaration to drift against.
        assert_eq!(MAX_MANIFEST_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn ingest_rejects_a_malformed_metadata_iri() {
        // The ingest gate validates IRI-valued metadata, so a hand-assembled staging dir
        // with a malformed `accessRights` IRI is rejected. It would otherwise reach the FDP
        // plane's unchecked node constructor as broken RDF.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052853";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let mut manifest = sample_manifest(id);
        manifest.metadata.access_rights = "not a uri".to_owned();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("accessRights"),
            "error should name the bad IRI field: {err}"
        );
    }

    #[test]
    fn ingest_rejects_disallowed_af_source_reference_scheme() {
        // The tool's build path validates config.afSourceReference against a scheme
        // allow-list and for IRIREF safety, and the ingest gate must do the same, or a
        // hand-assembled manifest can serve a `javascript:` URL to Beacon clients through
        // frequencyInPopulations[].sourceReference.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052853";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let mut manifest = sample_manifest(id);
        manifest.config.af_source_reference = Some("javascript:alert(document.cookie)".to_owned());
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("afSourceReference"),
            "error should name the offending field: {err}"
        );
    }

    #[test]
    fn ingest_rejects_data_file_blockrange_mismatch() {
        // A data file whose filename `br{N}` disagrees with the manifest's
        // `config.blockRange` is unreachable on the serve path, which globs stored files by
        // the configured blockRange, so ingest must reject it before the store rather than
        // publish a Visible but unqueryable dataset.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052853";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // Rename the canonical br10000000 file to a br that disagrees with the manifest's
        // blockRange, which stays 10_000_000. Keep block 4 so the failure is the blockRange
        // mismatch alone, not the per-row block scan.
        let orig = staging.join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet");
        let mismatched = staging.join("allele-freq.chr3.4.br5000000.0123456789abcdef.parquet");
        fs::rename(&orig, &mismatched).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("config.blockRange"),
            "error should name the blockRange mismatch: {err}"
        );
    }

    #[test]
    fn ingest_preserves_additive_metadata_fields_in_stored_manifest() {
        // The manifest contract lets `metadata` grow additive fields without a version
        // bump, so the node must preserve such a field when it re-serializes the stripped
        // stored manifest: a newer producer's additive metadata must survive for any
        // integrating system that reads it.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052853";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // Rewrite the manifest with an additive metadata field this build does not model. A
        // lenient `metadata` accepts it; `config` is deny_unknown, so it is left alone.
        let mut manifest_value = serde_json::to_value(sample_manifest(id)).unwrap();
        manifest_value["metadata"]["futureAdditiveField"] = serde_json::json!("preserve-me");
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest_value).unwrap(),
        )
        .unwrap();

        let ok = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap();

        assert_eq!(
            ok.writer_provenance,
            WriterProvenance::Plaintext,
            "a staging dir has no crypt4gh envelope, so its provenance is `Plaintext` — \
             NOT an empty `Recovered`, which would be indistinguishable from a failed \
             header read"
        );

        let raw = fs::read(data_dir.join(&ok.id).join("manifest.json")).unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            stored["metadata"]["futureAdditiveField"],
            serde_json::json!("preserve-me"),
            "the additive metadata field must be preserved in the stored manifest"
        );
        // files and internal are still stripped, alongside the additive-field preservation.
        let typed: Manifest = serde_json::from_slice(&raw).unwrap();
        assert!(typed.files.is_empty());
        assert_eq!(typed.internal, Internal::default());
    }

    #[test]
    fn ingest_rejects_a_manifest_missing_mandatory_description() {
        // The ingest gate enforces the mandatory `description` just as the tool's
        // `validate_package` does, so the FDP plane cannot serve a description-less Dataset
        // record that fails the SHACL shapes for a hand-assembled package.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052854";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let mut manifest = sample_manifest(id);
        manifest.metadata.description = None;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("description"),
            "error should name the missing mandatory field: {err}"
        );
    }

    #[test]
    fn ingest_rejects_a_manifest_omitting_number_of_records() {
        // A hand-assembled manifest that omits numberOfRecords must be rejected. The field
        // is served verbatim in the public FDP and DCAT RDF, and is the ingest gate's only
        // cross-check that the parquet data matches the advertised record count. Treating it
        // as optional would let a forged package skip that check.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052860";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // `number_of_records` is `skip_serializing_if = None`, so `None` omits the key.
        let mut manifest = sample_manifest(id);
        manifest.metadata.number_of_records = None;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("numberOfRecords"),
            "error should name the missing field: {err}"
        );
    }

    #[test]
    fn ingest_rejects_a_manifest_with_wrong_number_of_records() {
        // A manifest whose numberOfRecords does not equal the distinct-variant count in the
        // parquet is rejected, so a package cannot advertise a false record count to FDP and
        // DCAT harvesters. `build_staging` writes one variant, so any other value mismatches.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052861";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let mut manifest = sample_manifest(id);
        manifest.metadata.number_of_records = Some(999);
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        let msg = format!("{err}");
        assert!(
            msg.contains("999") && msg.contains("does not match"),
            "error should report the declared vs counted mismatch: {msg}"
        );
    }

    #[test]
    fn ingest_rejects_a_non_canonical_assembly() {
        // A non-canonical assembly synonym such as `hg38`, or a mis-cased label, would
        // leave a dataset Visible yet unqueryable on g_variants, because the query path
        // matches the request's normalized assembly against the stored raw value. The gate
        // enforces the strict GRCh37 and GRCh38 set, so the stored value is canonical.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052855";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let mut manifest = sample_manifest(id);
        manifest.config.assembly.reference = "hg38".to_owned();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("GRCh37 or GRCh38"),
            "error should name the supported assemblies: {err}"
        );
    }

    #[test]
    fn expected_id_mismatch_is_rejected() {
        // The drop name or key basename (`expected_id`) is the published id by contract. A
        // manifest declaring a different `datasetId` under a mismatched name must be
        // rejected before the store, so an inconsistent manifest cannot defeat the dedup the
        // runtime keys on that name.
        let tmp = tempfile::tempdir().unwrap();
        let manifest_id = "GDI-EE-UTARTU-20260409143052901";
        let staging = build_staging(tmp.path(), manifest_id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir_with_bounds(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
            &ExtractBounds::default(),
            Some("GDI-EE-UTARTU-99999999999999999"),
            &WriterGate::off(),
            &WriterProvenance::Plaintext,
        )
        .expect_err("a manifest datasetId that differs from the drop id must be rejected");
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            !data_dir.join(manifest_id).exists(),
            "a mismatched package must NOT be published under its manifest id"
        );

        // The same staging dir ingests cleanly when the expected id matches, or is None.
        ingest_staging_dir_with_bounds(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
            &ExtractBounds::default(),
            Some(manifest_id),
            &WriterGate::off(),
            &WriterProvenance::Plaintext,
        )
        .expect("a matching expected_id ingests");
    }

    #[test]
    fn ingests_a_staging_dir_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let ok = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("a valid staging dir ingests");
        assert_eq!(ok.id, id);
        assert_eq!(ok.config.assembly.reference, "GRCh38");

        let published = data_dir.join(id);
        assert!(published.is_dir(), "datasets/{{id}}/ must exist");
        // The parquet was published.
        assert!(
            published
                .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet")
                .is_file()
        );
        // headers/ was not persisted: data minimization.
        assert!(
            !published.join("headers").exists(),
            "headers/ must be dropped"
        );
        // A plaintext store writes a per-parquet digest sidecar, and it verifies.
        assert!(
            published
                .join(crate::digest::PARQUET_DIGESTS_FILE)
                .is_file(),
            "plaintext ingest must write the digest sidecar"
        );
        assert_eq!(
            crate::digest::verify_parquet_digests(&published).unwrap(),
            crate::digest::DigestVerdict::Verified(1),
            "the stored parquet must match its digest"
        );
        // No .incoming working dir lingers.
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must be empty after a successful publish"
        );

        // The stored manifest has files/internal stripped.
        let raw = fs::read(published.join("manifest.json")).unwrap();
        let stored: Manifest = serde_json::from_slice(&raw).unwrap();
        assert!(stored.files.is_empty(), "files must be stripped");
        assert_eq!(stored.internal, Internal::default(), "internal stripped");
        // metadata + config are retained.
        assert_eq!(stored.metadata.dataset_id, id);
        assert_eq!(stored.config.assembly.reference, "GRCh38");

        // The raw JSON contains neither the secret internal id nor the conversion
        // provenance carried in `files`: a provider's private record of what its pipeline
        // discarded must never reach a node-served artifact.
        let text = String::from_utf8(raw).unwrap();
        assert!(
            !text.contains("secret-internal-id"),
            "internal data must not be persisted"
        );
        assert!(
            !text.contains("conversion") && !text.contains("SECRET_SENTINEL_AF"),
            "conversion provenance must not be persisted: {text}"
        );
    }

    #[test]
    fn unknown_catalog_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052838";
        let staging = build_staging(tmp.path(), id);
        // Rewrite the manifest with a catalog not in the node allow-list.
        let mut manifest = sample_manifest(id);
        manifest.metadata.catalog = "not-a-catalog".to_owned();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnknownCatalog);
        // Nothing published.
        assert!(!data_dir.join(id).exists());
    }

    // ---- parse_and_validate_manifest gate tests ----

    #[test]
    fn manifest_version_not_one_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052843";
        let staging = build_staging(tmp.path(), id);
        let mut manifest = sample_manifest(id);
        manifest.config.manifest_version = 2;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("manifestVersion"),
            "error should name manifestVersion: {err}"
        );
        assert!(!data_dir.join(id).exists());
    }

    #[test]
    fn individual_mode_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052844";
        let staging = build_staging(tmp.path(), id);
        let mut manifest = sample_manifest(id);
        manifest.config.mode = DatasetMode::Individual;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("mode"),
            "error should name config.mode: {err}"
        );
        assert!(!data_dir.join(id).exists());
    }

    /// Each required aggregated metadata field, blanked, must be rejected by ingest.
    ///
    /// The per-field logic lives in `validate_pkg::validate_overlay_result` and is
    /// unit-tested there. These cases prove `parse_and_validate_manifest` calls it and fails
    /// closed: `InvalidManifest`, the field named, and no dataset directory.
    #[test]
    fn empty_required_metadata_fields_are_rejected() {
        // (index -> which field to blank, substring the error must name).
        let cases: [&str; 3] = ["accessRights", "license", "creator"];
        for (i, needle) in cases.into_iter().enumerate() {
            let tmp = tempfile::tempdir().unwrap();
            let id = format!("GDI-EE-UTARTU-2026040914305284{}", 5 + i);
            let staging = build_staging(tmp.path(), &id);
            let mut manifest = sample_manifest(&id);
            match i {
                0 => manifest.metadata.access_rights = String::new(),
                1 => manifest.metadata.license = String::new(),
                _ => manifest.metadata.creator.clear(),
            }
            fs::write(
                staging.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
            let data_dir = tmp.path().join("data");
            fs::create_dir(&data_dir).unwrap();

            let err = ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
            .unwrap_err();
            assert_eq!(err.class(), ErrorClass::InvalidManifest);
            assert!(
                format!("{err}").contains(needle),
                "error should name {needle}: {err}"
            );
            assert!(!data_dir.join(&id).exists(), "no dataset dir on rejection");
        }
    }

    #[test]
    fn invalid_dataset_id_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // Use a valid id to build the staging dir, then rewrite the manifest with a bad one.
        let real_id = "GDI-EE-UTARTU-20260409143052848";
        let staging = build_staging(tmp.path(), real_id);
        let mut manifest = sample_manifest(real_id);
        manifest.metadata.dataset_id = "not-a-valid-id".to_owned();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("datasetId"),
            "error should name datasetId: {err}"
        );
        // Nothing published under either the real or the bad id.
        assert!(!data_dir.join("not-a-valid-id").exists());
        assert!(!data_dir.join(real_id).exists());
    }

    #[test]
    fn empty_assembly_reference_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052849";
        let staging = build_staging(tmp.path(), id);
        let mut manifest = sample_manifest(id);
        manifest.config.assembly.reference = String::new();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("assembly"),
            "error should name assembly: {err}"
        );
        assert!(!data_dir.join(id).exists());
    }

    #[test]
    fn individual_level_format_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052839";
        let staging = build_staging(tmp.path(), id);
        // Drop in an unsupported individual-level file.
        fs::write(staging.join("variants.parquet"), b"PAR1").unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(format!("{err}").contains("individual-level"));
        assert!(!data_dir.join(id).exists());
    }

    #[test]
    fn missing_manifest_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052840";
        let staging = build_staging(tmp.path(), id);
        fs::remove_file(staging.join("manifest.json")).unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(format!("{err}").contains("manifest.json"));
    }

    #[test]
    fn unexpected_root_file_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052841";
        let staging = build_staging(tmp.path(), id);
        fs::write(staging.join("README.txt"), b"hello").unwrap();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(format!("{err}").contains("unexpected file"));
    }

    #[test]
    fn pre_existing_target_is_an_internal_error() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052842";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        // A live id already exists.
        fs::create_dir(data_dir.join(id)).unwrap();

        let err = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::InternalError);
    }

    #[test]
    fn reingest_of_a_completed_store_is_idempotent() {
        // A crash after the atomic publish rename but before the status write leaves the
        // completed dataset dir on disk while the runtime still sees the id as absent or
        // errored and retries it. Re-ingesting the same package must recognise the completed
        // store and succeed, so the caller records the status and consumes the source,
        // rather than wedging on a permanent internal error.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052843";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // First ingest publishes the dataset dir + manifest.json.
        ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("first ingest should publish the dataset");
        assert!(data_dir.join(id).join("manifest.json").exists());

        // Second ingest of the identical package: the stored manifest matches byte for byte,
        // so this is the crash-recovery case and must succeed idempotently.
        ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect(
            "re-ingest of a byte-identical completed store must be idempotent, not InternalError",
        );
    }

    #[test]
    fn an_already_stored_dataset_is_not_re_gated_after_an_allowlist_edit() {
        // The store-time writer gate sits after the `target.exists()` short-circuit, so a
        // dataset already stored and served is never re-gated. Otherwise a restart or rescan
        // after an allow-list edit that dropped a writer's key would reject an
        // already-published dataset. First store it with the gate off, then re-ingest the
        // identical package under an enforce gate that would reject a plaintext drop: it
        // must still succeed idempotently, because the target already exists.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052846";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // This is the module's only unit test that drives a full ingest through to the store
        // stage. Under the default no-op dispatch it would register the per-stage span
        // callsites with interest `never` in the process-global callsite cache. Interest is
        // cached per callsite rather than per subscriber, so that poisons
        // `staging_ingest_emits_per_stage_spans`, which then intermittently fails to observe
        // the `store` span; see the `SpanNameRecorder` note on why `sometimes()` alone does
        // not save it. Running the ingests under a throwaway recording subscriber registers
        // those callsites as `sometimes()` instead. The recorder is discarded; this test
        // asserts only the gate and idempotency behaviour below.
        tracing::subscriber::with_default(SpanNameRecorder::default(), || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
            .expect("first ingest publishes the dataset");
            assert!(data_dir.join(id).exists());

            // An enforce gate with an empty allow-list would reject this plaintext staging
            // drop as a fresh store, but the target already exists, so the gate is skipped.
            let rejecting = WriterGate {
                policy: crate::config::WriterPolicy::Enforce,
                channel: "inbox",
                allowlist: &[],
            };
            ingest_staging_dir_with_bounds(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
                &ExtractBounds::default(),
                None,
                &rejecting,
                &WriterProvenance::Plaintext,
            )
            .expect(
                "an already-stored dataset must NOT be re-rejected by a now-stricter enforce \
                 gate (the restart-after-allowlist-edit footgun)",
            );
        });
    }

    #[test]
    fn store_over_a_target_with_a_different_manifest_is_a_conflict() {
        // The immutability guard must still reject a different payload under a live id, an
        // attempt to mutate an immutable dataset, so idempotency cannot be a blanket
        // "target exists means Ok". Driven at the `store_atomically` layer so a hand-crafted
        // differing manifest reaches the store check without the upstream
        // manifest-validation gate rejecting it first.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052844";
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        // A live target dir whose stored manifest differs from what this store writes.
        let target = data_dir.join(id);
        fs::create_dir(&target).unwrap();
        fs::write(target.join("manifest.json"), b"{\"not\":\"a match\"}").unwrap();

        let manifest = sample_manifest(id);
        let err = store_atomically(
            &data_dir,
            id,
            &[],
            &manifest,
            &serde_json::json!({}),
            &DatasetEncryptor::plaintext(),
            &WriterGate::off(),
            &WriterProvenance::Plaintext,
        )
        .expect_err(
            "a differing stored manifest under a live id must stay an InternalError conflict",
        );
        assert_eq!(err.class(), ErrorClass::InternalError);
    }

    #[test]
    fn allele_freq_name_recognition() {
        assert!(is_allele_freq_name(
            "allele-freq.chr3.4.br10000000.0123456789abcdef.parquet"
        ));
        assert!(is_allele_freq_name(
            "allele-freq.chrX.0.br0.deadbeefdeadbeef.parquet"
        ));
        assert!(is_allele_freq_name(
            "allele-freq.chrM.0.br0.deadbeefdeadbeef.parquet"
        ));
        // Bad chromosome.
        assert!(!is_allele_freq_name(
            "allele-freq.chr23.0.br0.deadbeef.parquet"
        ));
        assert!(!is_allele_freq_name(
            "allele-freq.chrZ.0.br0.deadbeef.parquet"
        ));
        // Wrong component count / extension.
        assert!(!is_allele_freq_name("allele-freq.chr3.4.br10.id.txt"));
        assert!(!is_allele_freq_name("variants.parquet"));
    }

    // ---- ingest_tar_c4gh ----

    /// Build an uncompressed TAR of a staging dir (`manifest.json` + the parquet)
    /// into `tar_path`, in the spec member order.
    fn write_staging_tar(staging: &Path, tar_path: &Path) {
        let file = fs::File::create(tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        // manifest.json first.
        builder
            .append_path_with_name(staging.join("manifest.json"), "manifest.json")
            .unwrap();
        // every allele-freq.*.parquet at the root.
        for entry in fs::read_dir(staging).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("allele-freq.") && name.ends_with(".parquet") {
                builder.append_path_with_name(&p, &name).unwrap();
            }
        }
        builder.into_inner().unwrap().sync_all().unwrap();
    }

    /// Build a `{id}.tar.c4gh` encrypted to `recipient` from a freshly-built
    /// staging dir, returning the package path.
    fn build_tar_c4gh(tmp: &Path, id: &str, recipient: &crate::crypt4gh::PublicKey) -> PathBuf {
        let staging = build_staging(tmp, id);
        let tar_path = tmp.join(format!("{id}.tar"));
        write_staging_tar(&staging, &tar_path);
        // Drop the plaintext staging dir so it cannot be mistaken for the result.
        fs::remove_dir_all(&staging).unwrap();

        let pkg = tmp.join(format!("{id}.tar.c4gh"));
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut reader = fs::File::open(&tar_path).unwrap();
        let mut writer = fs::File::create(&pkg).unwrap();
        encrypt(
            &mut reader,
            &mut writer,
            std::slice::from_ref(recipient),
            &sender_sk,
        )
        .unwrap();
        writer.sync_all().unwrap();
        pkg
    }

    #[test]
    fn ingests_an_encrypted_tar_c4gh() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052900";
        let (node_sk, node_pk) = generate_keypair();
        let pkg = build_tar_c4gh(tmp.path(), id, &node_pk);

        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let ok = ingest_tar_c4gh(
            &pkg,
            &[node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("a valid .tar.c4gh ingests");
        assert_eq!(ok.id, id);
        assert_eq!(ok.config.assembly.reference, "GRCh38");

        // Published, with files/internal stripped.
        let published = data_dir.join(id);
        assert!(published.join("manifest.json").is_file());
        assert!(
            published
                .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet")
                .is_file()
        );
        let raw = fs::read(published.join("manifest.json")).unwrap();
        let stored: Manifest = serde_json::from_slice(&raw).unwrap();
        assert!(stored.files.is_empty());
        assert_eq!(stored.internal, Internal::default());

        // The working dir was cleaned up.
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must be empty after a successful ingest"
        );
    }

    #[test]
    fn tar_c4gh_ingest_recovers_writer_provenance() {
        // The crypt4gh writer key is recovered from the package header and surfaced on
        // IngestOk for the audit trail. Build a package with a known sender key and assert
        // its fingerprint round-trips.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052900";
        let (node_sk, node_pk) = generate_keypair();
        let (sender_sk, sender_pk) = generate_keypair();

        let staging = build_staging(tmp.path(), id);
        let tar_path = tmp.path().join(format!("{id}.tar"));
        write_staging_tar(&staging, &tar_path);
        fs::remove_dir_all(&staging).unwrap();
        let pkg = tmp.path().join(format!("{id}.tar.c4gh"));
        {
            let mut reader = fs::File::open(&tar_path).unwrap();
            let mut writer = fs::File::create(&pkg).unwrap();
            encrypt(
                &mut reader,
                &mut writer,
                std::slice::from_ref(&node_pk),
                &sender_sk,
            )
            .unwrap();
            writer.sync_all().unwrap();
        }

        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        let ok = ingest_tar_c4gh(
            &pkg,
            &[node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("a valid .tar.c4gh ingests");

        assert_eq!(
            ok.writer_provenance,
            WriterProvenance::Recovered(vec![crate::crypt4gh::public_key_fingerprint(&sender_pk)]),
            "the package writer key fingerprint is recovered for provenance"
        );
    }

    #[test]
    fn oversized_decrypted_package_is_permanent_unsafe_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052900";
        let (node_sk, node_pk) = generate_keypair();
        let pkg = build_tar_c4gh(tmp.path(), id, &node_pk);

        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // A byte cap far below the real decrypted-tar size: the counting writer must trip
        // during decrypt, before any extraction happens.
        let bounds = ExtractBounds {
            max_members: 100_000,
            max_total_bytes: 16,
        };
        let err = ingest_tar_c4gh_with_bounds(
            &pkg,
            &[node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
            &bounds,
            None,
            &WriterGate::off(),
        )
        .expect_err("an over-cap decrypted package must be rejected");

        // Permanent unsafe-archive, not a transient resource error: retrying an over-cap
        // package can never succeed, so it must not re-enqueue forever.
        std::assert_matches!(
            err,
            CoreError::UnsafeArchive { .. },
            "expected UnsafeArchive, got {err:?}"
        );
        assert!(!err.is_transient(), "over-cap must be permanent");
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);

        // Nothing published; the per-job working dir (incl. the partial .tar) is gone.
        assert!(!data_dir.join(id).exists());
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must be empty after an over-cap rejection"
        );
    }

    #[test]
    fn counting_writer_trips_past_limit_and_latches() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = CountingWriter::new(&mut buf, 4);
            assert_eq!(
                w.write(b"abc").unwrap(),
                3,
                "a write within the limit passes"
            );
            let err = w
                .write(b"xy")
                .expect_err("the write that crosses the limit fails");
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert!(w.exceeded, "the over-limit write latches `exceeded`");
        }
        // Only the first, allowed write reached the inner buffer; the over-limit bytes were
        // never written.
        assert_eq!(buf, b"abc");
    }

    /// Build an uncompressed TAR that, unlike [`write_staging_tar`], includes the staging
    /// dir's `headers/{vcfid}.vcf` entry, so a test can assert the encrypted path's
    /// headers-drop invariant: a package that carries headers must not leave them on disk.
    fn write_staging_tar_with_headers(staging: &Path, tar_path: &Path) {
        let file = fs::File::create(tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder
            .append_path_with_name(staging.join("manifest.json"), "manifest.json")
            .unwrap();
        // The headers/ dir + its member (build_staging plants headers/{vcfid}.vcf).
        builder
            .append_path_with_name(
                staging.join("headers").join("0123456789abcdef.vcf"),
                "headers/0123456789abcdef.vcf",
            )
            .unwrap();
        for entry in fs::read_dir(staging).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("allele-freq.") && name.ends_with(".parquet") {
                builder.append_path_with_name(&p, &name).unwrap();
            }
        }
        builder.into_inner().unwrap().sync_all().unwrap();
    }

    /// A package whose TAR carries a `headers/` directory must not persist it. The encrypted
    /// `.tar.c4gh` path applies the same data-minimization drop as the plaintext staging
    /// path: headers are extracted into the per-job working dir, never into `datasets/{id}/`.
    #[test]
    fn encrypted_tar_c4gh_drops_headers_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052910";
        let (node_sk, node_pk) = generate_keypair();

        // Build a staging dir, which plants headers/, tar it including headers/, then
        // encrypt to the node recipient.
        let staging = build_staging(tmp.path(), id);
        let tar_path = tmp.path().join(format!("{id}.tar"));
        write_staging_tar_with_headers(&staging, &tar_path);
        fs::remove_dir_all(&staging).unwrap();
        let pkg = tmp.path().join(format!("{id}.tar.c4gh"));
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut reader = fs::File::open(&tar_path).unwrap();
        let mut writer = fs::File::create(&pkg).unwrap();
        encrypt(
            &mut reader,
            &mut writer,
            std::slice::from_ref(&node_pk),
            &sender_sk,
        )
        .unwrap();
        writer.sync_all().unwrap();

        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let ok = ingest_tar_c4gh(
            &pkg,
            &[node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("a valid headers-bearing .tar.c4gh ingests");
        assert_eq!(ok.id, id);

        let published = data_dir.join(id);
        assert!(published.join("manifest.json").is_file());
        // The data-minimization invariant on the encrypted path: headers/ dropped.
        assert!(
            !published.join("headers").exists(),
            "headers/ must be dropped on the .tar.c4gh path"
        );
        // No working dir lingers: the headers were materialised, then discarded.
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must be empty after headers-bearing ingest"
        );
    }

    #[test]
    fn wrong_recipient_is_a_permanent_decrypt_error() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052901";
        // Encrypt to a recipient the node does not hold.
        let (_other_sk, other_pk) = generate_keypair();
        let pkg = build_tar_c4gh(tmp.path(), id, &other_pk);

        let (node_sk, _node_pk) = generate_keypair();
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_tar_c4gh(
            &pkg,
            &[node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::DecryptFailed);
        assert!(!data_dir.join(id).exists());
        // No working dir lingers.
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must be empty after a wrong-recipient decrypt failure"
        );
    }

    #[test]
    fn empty_identities_cannot_decrypt() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052902";
        let (_node_sk, node_pk) = generate_keypair();
        let pkg = build_tar_c4gh(tmp.path(), id, &node_pk);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let err = ingest_tar_c4gh(
            &pkg,
            &[],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .unwrap_err();
        assert_eq!(err.class(), ErrorClass::DecryptFailed);
    }

    #[test]
    fn tries_multiple_identities_until_one_works() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052903";
        let (node_sk, node_pk) = generate_keypair();
        let pkg = build_tar_c4gh(tmp.path(), id, &node_pk);

        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // A stale identity first, the working identity second.
        let (stale_sk, _stale_pk) = generate_keypair();
        let ok = ingest_tar_c4gh(
            &pkg,
            &[stale_sk, node_sk],
            &data_dir,
            &ParquetCaps::default(),
            &node_catalogs(),
            &DatasetEncryptor::plaintext(),
        )
        .expect("decrypts with the second identity");
        assert_eq!(ok.id, id);
    }

    /// A `tracing::Subscriber` that records the name of every span created on the calling
    /// thread, so a test can assert which per-stage ingest spans fired without a
    /// `tracing-subscriber` dev-dependency.
    #[derive(Clone, Default)]
    struct SpanNameRecorder(Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for SpanNameRecorder {
        // Force per-call `enabled()` evaluation instead of a cached fixed answer. The
        // span-callsite interest cache is process-global, so a sibling test that emits these
        // same ingest spans with no recording subscriber would otherwise poison the cache,
        // suppress `new_span` here and drop a stage name under parallel scheduling.
        // `sometimes()` opts these callsites out of caching, so this recorder sees them
        // while it is the thread default.
        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            self.0
                .lock()
                .unwrap()
                .push(attrs.metadata().name().to_owned());
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn staging_ingest_emits_per_stage_spans() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052851";
        let staging = build_staging(tmp.path(), id);
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        let recorder = SpanNameRecorder::default();
        let names = Arc::clone(&recorder.0);
        tracing::subscriber::with_default(recorder, || {
            ingest_staging_dir(
                &staging,
                &data_dir,
                &ParquetCaps::default(),
                &node_catalogs(),
                &DatasetEncryptor::plaintext(),
            )
            .expect("a valid staging dir ingests");
        });

        let seen = names.lock().unwrap();
        for stage in [
            "check_layout",
            "validate_manifest",
            "validate_parquet",
            "store",
        ] {
            assert!(
                seen.iter().any(|n| n == stage),
                "ingest must emit the {stage:?} span; saw {seen:?}"
            );
        }
    }

    #[test]
    fn store_atomically_missing_source_leaves_no_partial_dir() {
        // Drive `store_atomically` to error inside its closure, because the staged parquet
        // does not exist, and assert the atomicity guarantee: the published target dir is
        // never created and no partial work dir is left in `.incoming`.
        let tmp = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052852";
        let data_dir = tmp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        // A path with a valid file_name() that does not exist reaches the realistic copy
        // NotFound branch, not the "no file name" internal-error branch.
        let missing = tmp
            .path()
            .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet");
        let parquet_files = vec![missing];
        let manifest = sample_manifest(id);

        let err = store_atomically(
            &data_dir,
            id,
            &parquet_files,
            &manifest,
            &serde_json::json!({}),
            &DatasetEncryptor::plaintext(),
            &WriterGate::off(),
            &WriterProvenance::Plaintext,
        )
        .expect_err("a missing staged parquet must fail the store");
        std::assert_matches!(
            err,
            CoreError::Io(_),
            "missing source surfaces as Io, got {err:?}"
        );
        assert!(
            !data_dir.join(id).exists(),
            "the target dataset dir must never be created on a store error"
        );
        let incoming = data_dir.join(".incoming");
        assert!(
            !incoming.exists() || fs::read_dir(&incoming).unwrap().next().is_none(),
            ".incoming must hold no partial work dir after a store error"
        );
    }
    /// Build a manifest carrying a `payload` that declares `entries`.
    fn manifest_declaring(entries: &[(&str, &str, u64)]) -> Manifest {
        let mut files = std::collections::BTreeMap::new();
        for (name, sha, size) in entries {
            files.insert(
                (*name).to_owned(),
                crate::model::PayloadEntry {
                    sha256: (*sha).to_owned(),
                    size: *size,
                },
            );
        }
        let mut m = sample_manifest("GDI-EE-UTARTU-20260409143052837");
        m.payload = Some(crate::model::Payload {
            algorithm: "sha256".to_owned(),
            members: files,
        });
        m
    }

    /// A manifest key is untrusted input joined onto the staging path. `check_staging_dir`
    /// bounds what the TAR may write, but says nothing about what the manifest may name.
    /// Without a name check, `../../etc/shadow` would make the node hash an arbitrary
    /// readable file and report whether it matched: a content and file-existence oracle
    /// against the host, reachable by anyone who can get a package ingested.
    #[test]
    fn a_payload_naming_a_path_outside_the_package_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for evil in [
            "../../etc/shadow",
            "/etc/shadow",
            "headers/../../../etc/shadow",
            "./secret",
            "",
        ] {
            let m = manifest_declaring(&[(evil, &"0".repeat(64), 1)]);
            let err = verify_declared_payload(tmp.path(), &m)
                .expect_err("an unsafe member path must be refused");
            assert!(
                format!("{err}").contains("unsafe member path"),
                "{evil:?} must be refused as an unsafe path, got: {err}"
            );
        }
    }

    /// A package whose bytes disagree with its own manifest.
    #[test]
    fn a_payload_whose_bytes_disagree_with_the_manifest_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let name = "allele-freq.chr1.0.br0-1000.in.parquet";
        fs::write(tmp.path().join(name), b"actual-bytes").expect("write member");

        // The declared digest is of different content.
        let m = manifest_declaring(&[(name, &"a".repeat(64), 12)]);
        let err = verify_declared_payload(tmp.path(), &m).expect_err("mismatch must be refused");
        assert!(
            format!("{err}").contains("does not contain what its own manifest says"),
            "the refusal must name the disagreement; got: {err}"
        );

        // The same member with its true digest passes, so the failure above came from the
        // content and not from the check rejecting everything.
        let (real, size) =
            crate::util::sha256_hex_reader(&b"actual-bytes"[..]).expect("hash the fixture");
        let ok = manifest_declaring(&[(name, &real, size)]);
        verify_declared_payload(tmp.path(), &ok).expect("matching bytes must verify");

        // Correct digest, wrong declared size. Without the size comparison this would pass,
        // and the node would persist a `payload` whose size field it never checked while
        // presenting the section as verified.
        let wrong_size = manifest_declaring(&[(name, &real, size + 1)]);
        let err = verify_declared_payload(tmp.path(), &wrong_size)
            .expect_err("a wrong declared size must be refused even when the digest matches");
        assert!(
            format!("{err}").contains("does not contain what its own manifest"),
            "got: {err}"
        );
    }

    /// A declared member that is not in the package at all.
    #[test]
    fn a_declared_member_missing_from_the_package_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let m =
            manifest_declaring(&[("allele-freq.chr1.0.br0-1000.in.parquet", &"a".repeat(64), 1)]);
        let err = verify_declared_payload(tmp.path(), &m).expect_err("missing must be refused");
        assert!(
            format!("{err}").contains("does not contain it"),
            "got: {err}"
        );
    }

    /// No `payload` means unknown, not verified empty. Every package built before the
    /// section existed has none, and refusing them would be a compatibility break.
    #[test]
    fn a_manifest_without_a_payload_section_still_ingests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut m = sample_manifest("GDI-EE-UTARTU-20260409143052837");
        m.payload = None;
        verify_declared_payload(tmp.path(), &m).expect("absence must not fail the check");
    }
}

#[cfg(test)]
mod manifest_reader_guard {
    /// No reader may re-derive the manifest cap by hand.
    ///
    /// Spelling the capped read out per call site makes "every reader enforces
    /// `MAX_MANIFEST_BYTES`" an invariant held in as many copies as there are readers, so a
    /// new reader can ship without it, or with a different value, and no test fails.
    /// `read_manifest_bytes` removes the parameter, and this guard keeps it that way by
    /// rejecting the hand-written pairing anywhere in the workspace. It is scoped to that
    /// shape, not to capped reads in general: reading some other file under a cap is fine.
    #[test]
    fn no_call_site_pairs_read_capped_with_the_manifest_by_hand() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![std::path::PathBuf::from(root).join("crates")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n == "target") {
                        continue;
                    }
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let Ok(text) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    scanned += 1;
                    // Comments are stripped first, then the file is joined into one line so
                    // a rustfmt-wrapped call still matches. The strip is required: an
                    // assertion about what the code does must read only what it runs, and
                    // the doc comment above quotes the pattern it forbids.
                    let flat: String = text
                        .lines()
                        .map(str::trim_start)
                        .filter(|l| !l.starts_with("//"))
                        .flat_map(str::split_whitespace)
                        .collect::<Vec<_>>()
                        .join(" ");
                    // The needles are built, never written as literals: spelling them out
                    // here would make this file match itself.
                    let call = ["read", "_capped("].concat();
                    let name = ["\"manifest", ".json\""].concat();
                    if flat.split(&call).skip(1).any(|rest| {
                        rest.trim_start()
                            .starts_with(&["&dir.join(", &name].concat())
                            || rest
                                .trim_start()
                                .starts_with(&["&staging.join(", &name].concat())
                    }) {
                        offenders.push(path.display().to_string());
                    }
                }
            }
        }
        // Anti-vacuity: a wrong root would scan nothing and pass having checked nothing.
        assert!(
            scanned > 50,
            "only {scanned} .rs files scanned from {root} — this guard would pass vacuously"
        );
        assert!(
            offenders.is_empty(),
            "these call sites pair `read_capped` with `manifest.json` by hand instead of \
             calling `ingest::read_manifest_bytes`, which is what keeps the cap \
             unforgettable: {offenders:?}"
        );
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// The property that makes validate-then-store safe: replacing the source does not
    /// change the snapshot.
    ///
    /// `gdi-dataset-tool deploy --replace` is not rename-only: it removes `inbox/{id}` and
    /// copies the new drop in. Landing mid-ingest, that would make the node read some files
    /// from the old tree and some from the new one, publishing a mixed dataset under a
    /// manifest that validated neither, with the digest sidecar computed from the mixed
    /// bytes so `verify --digest` could never see it. A snapshot pins the inode, so the
    /// unlink leaves this name pointing at the original content.
    #[test]
    fn a_snapshot_survives_the_source_being_replaced() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("inbox-drop");
        std::fs::create_dir_all(src.join("nested")).expect("create src");
        std::fs::write(src.join("a.parquet"), b"original-a").expect("write a");
        std::fs::write(src.join("nested/b.parquet"), b"original-b").expect("write b");

        let snap = tmp.path().join("snapshot");
        snapshot_staging_dir(&src, &snap).expect("snapshot the drop");
        assert_eq!(
            std::fs::read(snap.join("a.parquet")).expect("read a"),
            b"original-a"
        );

        // The replace shape: remove the whole drop, then write a different one back.
        std::fs::remove_dir_all(&src).expect("remove src");
        std::fs::create_dir_all(src.join("nested")).expect("recreate src");
        std::fs::write(src.join("a.parquet"), b"REPLACED-a").expect("rewrite a");
        std::fs::write(src.join("nested/b.parquet"), b"REPLACED-b").expect("rewrite b");

        assert_eq!(
            std::fs::read(snap.join("a.parquet")).expect("read a"),
            b"original-a",
            "the snapshot must keep the bytes that were VALIDATED, not the ones that replaced them"
        );
        assert_eq!(
            std::fs::read(snap.join("nested/b.parquet")).expect("read b"),
            b"original-b",
            "nested members too"
        );
    }

    /// A member that turns into a symlink after `check_staging_dir` has run must be refused
    /// by the snapshot walk rather than linked.
    ///
    /// `check_staging_dir` rejects symlinks, but it runs strictly before this walk, so the
    /// walk re-checks member kinds rather than trusting a check that has already finished.
    /// The two run in that order, so only the second can see a change made in between.
    #[cfg(unix)]
    #[test]
    fn a_snapshot_refuses_a_member_that_became_a_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secret = tmp.path().join("secret.txt");
        std::fs::write(&secret, b"not yours").expect("write secret");
        let src = tmp.path().join("inbox-drop");
        std::fs::create_dir_all(&src).expect("create src");
        std::os::unix::fs::symlink(&secret, src.join("sneaky.parquet")).expect("symlink");

        let err = snapshot_staging_dir(&src, &tmp.path().join("snapshot"))
            .expect_err("a symlink member must be refused, never followed");
        std::assert_matches!(
            err,
            crate::error::CoreError::UnsafeArchive { .. },
            "expected UnsafeArchive, got {err:?}"
        );
    }

    /// The `EXDEV` fallback must not inherit the source's mode.
    ///
    /// `fs::copy`, which `clippy.toml` bans, reproduces the source's permission bits. The
    /// source here is the provider-writable inbox drop, so those bits are attacker-chosen and
    /// a `0777` member would land `0777` inside node-private scratch.
    /// `create_private_file_new` chooses the destination's mode instead of inheriting it.
    #[cfg(unix)]
    #[test]
    fn the_copy_fallback_chooses_the_destination_mode_rather_than_inheriting_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let from = tmp.path().join("provider-written.parquet");
        std::fs::write(&from, b"payload").expect("write source");
        std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o777))
            .expect("make the source world-writable, as a hostile drop would");

        let to = tmp.path().join("snapshot-copy.parquet");
        copy_private_file(&from, &to).expect("the fallback copy must succeed");

        assert_eq!(
            std::fs::read(&to).expect("read the copy"),
            b"payload",
            "the fallback must still copy the bytes"
        );
        let mode = std::fs::metadata(&to).expect("stat").permissions().mode() & 0o777;
        assert_ne!(mode, 0o777, "the source's mode must NOT be inherited");
        assert_eq!(mode & 0o077, 0, "group/other must have no access: {mode:o}");
    }

    /// The fallback refuses a destination that already exists rather than truncating it.
    #[test]
    fn the_copy_fallback_refuses_an_existing_destination() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let from = tmp.path().join("a.parquet");
        std::fs::write(&from, b"new").expect("write source");
        let to = tmp.path().join("occupied.parquet");
        std::fs::write(&to, b"pre-existing").expect("write destination");

        copy_private_file(&from, &to)
            .expect_err("O_CREAT|O_EXCL must refuse an existing destination");
        assert_eq!(
            std::fs::read(&to).expect("read destination"),
            b"pre-existing",
            "the existing file must not be truncated"
        );
    }
}
