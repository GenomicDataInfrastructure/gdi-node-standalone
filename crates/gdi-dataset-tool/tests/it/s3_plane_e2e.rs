//! The S3-plane commands `upload`, `list` and `download`.
//!
//! Two layers are covered. First, the guards that run before a single byte reaches S3:
//! dataset-id validation and the uniform "this profile has no `[profiles.<name>.s3]` block"
//! refusal. Those are the paths a misconfigured operator hits. Second, the commands' own
//! reporting layer, driven against `object_store::InMemory` through the `run_with_store`
//! seam, which splits profile resolution from the operation.
//!
//! The reporting tests at the bottom of this file exist because a unit test one layer down
//! in `s3.rs` cannot observe a command that contradicts it: `cmd_upload` can report a flat
//! `hidden` while the rule below says otherwise.
//!
//! The real backend stays covered by `s3_reconcile::real_endpoint`'s `#[ignore]`d smoke,
//! which `scripts/e2e/run-full.sh` runs against Garage.

use std::fs;

use gdi_dataset_tool::cli::{DownloadArgs, ListArgs, UploadArgs};
use gdi_dataset_tool::commands::{cmd_download, cmd_list, cmd_upload};

/// A well-formed GDI dataset id (the shape `is_valid_dataset_id` accepts).
const ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// A tool.toml whose only profile is inbox-only: no `[profiles.default.s3]`, so every
/// S3-plane command must refuse rather than half-run.
fn write_inbox_only_config(dir: &std::path::Path) -> std::path::PathBuf {
    let cfg = dir.join("tool.toml");
    fs::write(
        &cfg,
        "[profiles.default]\ninbox = \"/var/lib/gdi-node-standalone/inbox\"\n",
    )
    .expect("write tool.toml");
    cfg
}

#[test]
fn download_rejects_a_malformed_dataset_id_before_touching_the_profile() {
    // The id is validated first, so a malformed one fails clearly instead of deriving an
    // output path from unvalidated input and surfacing a confusing store error. There is
    // no config file here at all, so reaching `load_active` would itself be the failure.
    let args = DownloadArgs {
        id: "../../etc/passwd".to_owned(),
        output: None,
        force: false,
        max_size: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_download::run(&args, None, None).expect_err("a malformed id must be refused");
    assert_eq!(err.exit_code, gdi_dataset_tool::EXIT_USER);
    assert!(
        err.message.contains("invalid dataset id"),
        "the refusal names the problem: {}",
        err.message
    );
    assert!(
        err.message.contains("../../etc/passwd"),
        "the refusal echoes the offending id: {}",
        err.message
    );
}

#[test]
fn upload_refuses_an_inbox_only_profile_and_names_the_verb() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = write_inbox_only_config(tmp.path());
    // The package path is never read: the profile refusal comes first.
    let args = UploadArgs {
        package: tmp.path().join("nonexistent.tar.c4gh"),
        replace: false,
        wait: false,
        wait_timeout: 300,
        management_url: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_upload::run(&args, None, Some(&cfg))
        .expect_err("upload must refuse a profile with no S3 bucket");
    assert_eq!(err.exit_code, gdi_dataset_tool::EXIT_USER);
    assert!(
        err.message.contains("no [profiles.<name>.s3] block"),
        "the refusal explains what is missing: {}",
        err.message
    );
    // The verb is interpolated per call site; asserting it keeps the four commands'
    // messages from collapsing into one indistinguishable string.
    assert!(
        err.message.contains("upload"),
        "the refusal names the verb that needed the bucket: {}",
        err.message
    );
}

#[test]
fn list_refuses_an_inbox_only_profile_and_names_the_verb() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = write_inbox_only_config(tmp.path());
    let args = ListArgs {
        visible: false,
        hidden: false,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err =
        cmd_list::run(&args, None, Some(&cfg)).expect_err("list must refuse a profile with no S3");
    assert_eq!(err.exit_code, gdi_dataset_tool::EXIT_USER);
    assert!(
        err.message.contains("no [profiles.<name>.s3] block") && err.message.contains("list"),
        "list's refusal names itself: {}",
        err.message
    );
}

#[test]
fn download_refuses_an_inbox_only_profile_after_the_id_passes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = write_inbox_only_config(tmp.path());
    let args = DownloadArgs {
        id: ID.to_owned(),
        output: Some(tmp.path().join("out.tar.c4gh")),
        force: false,
        max_size: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_download::run(&args, None, Some(&cfg))
        .expect_err("download must refuse a profile with no S3");
    assert_eq!(err.exit_code, gdi_dataset_tool::EXIT_USER);
    assert!(
        err.message.contains("no [profiles.<name>.s3] block") && err.message.contains("download"),
        "download's refusal names itself: {}",
        err.message
    );
    assert!(
        !tmp.path().join("out.tar.c4gh").exists(),
        "a refused download must not create its output file"
    );
}

// ---------------------------------------------------------------------------------------
// The reporting layer, driven against an in-memory store via the `run_with_store` seam.
// ---------------------------------------------------------------------------------------

/// Build an in-memory store pair and a package file on disk, returning both plus the tempdir.
fn in_memory_upload_fixture(
    tmp: &std::path::Path,
) -> (
    gdi_dataset_tool::s3::Store,
    gdi_dataset_tool::s3::PackageStore,
    std::path::PathBuf,
) {
    use std::sync::Arc;
    let store: gdi_dataset_tool::s3::Store = Arc::new(object_store::memory::InMemory::new());
    let package_store = gdi_dataset_tool::s3::PackageStore::new(Arc::clone(&store));
    let package = tmp.join(format!("{ID}.tar.c4gh"));
    fs::write(&package, b"crypt4gh-ish-bytes").expect("write package");
    (store, package_store, package)
}

fn upload_args(package: &std::path::Path, replace: bool) -> UploadArgs {
    UploadArgs {
        package: package.to_path_buf(),
        replace,
        wait: false,
        wait_timeout: 300,
        management_url: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    }
}

/// A fresh upload reports `hidden` — and reports it because that is what was written.
#[test]
fn a_fresh_upload_reports_the_hidden_it_wrote() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, package_store, package) = in_memory_upload_fixture(tmp.path());

    let reported = cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("a fresh upload succeeds");

    assert_eq!(reported, gdi_dataset_tool::s3::Visibility::Hidden);
    assert_eq!(
        read_visibility(&store),
        gdi_dataset_tool::s3::Visibility::Hidden,
        "the reported value must equal the sidecar actually written"
    );
}

/// The visibility the bucket actually records for [`ID`].
fn read_visibility(store: &gdi_dataset_tool::s3::Store) -> gdi_dataset_tool::s3::Visibility {
    gdi_dataset_tool::runtime::block_on(gdi_dataset_tool::s3::fetch_visibility(store, ID))
        .expect("sidecar readable")
}

/// Write the visibility sidecar directly, as an operator's `publish` would.
fn set_visibility(store: &gdi_dataset_tool::s3::Store, state: &str) {
    use object_store::{ObjectStoreExt as _, PutPayload, path::Path as ObjPath};
    let key = ObjPath::from(format!(
        "{ID}{}",
        gdi_node_standalone_core::s3_layout::STATE_SUFFIX
    ));
    let body = gdi_dataset_tool::s3::state_sidecar_body(state, false);
    gdi_dataset_tool::runtime::block_on(async {
        store
            .put(&key, PutPayload::from(body.into_bytes()))
            .await
            .map(|_| ())
            .map_err(|e| gdi_dataset_tool::ToolError::user(e.to_string()))
    })
    .expect("write the state sidecar");
}

/// The rule this seam exists for: `--replace` over a visible dataset must report `visible`,
/// not `hidden`.
///
/// `s3.rs` asserts that the sidecar is preserved, but that is one layer below what the
/// command tells the operator. A command reporting `hidden` would follow it with a stderr
/// epilogue telling the operator to run `publish`, which on a dataset hidden for a consent
/// withdrawal or a legal hold discloses it. A test at the `s3::` layer alone cannot catch
/// that, because the substitution happens above it.
#[test]
fn replace_over_a_visible_dataset_reports_visible_not_hidden() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, package_store, package) = in_memory_upload_fixture(tmp.path());

    cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("initial upload succeeds");

    // Operator publishes it: the sidecar now says visible.
    set_visibility(&store, "visible");
    assert_eq!(
        read_visibility(&store),
        gdi_dataset_tool::s3::Visibility::Visible,
        "precondition: the dataset is live and visible"
    );

    let reported = cmd_upload::run_with_store(
        &upload_args(&package, true),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("replace succeeds");

    assert_eq!(
        reported,
        gdi_dataset_tool::s3::Visibility::Visible,
        "replace must report the preserved visibility; reporting `hidden` here would tell \
         an operator to re-publish a dataset that was hidden on purpose"
    );
    assert_eq!(
        read_visibility(&store),
        gdi_dataset_tool::s3::Visibility::Visible,
        "and the sidecar itself must be untouched"
    );
}

/// The pre-network duplicate guard still fires through the seam (no `--replace`, id present).
#[test]
fn a_second_upload_without_replace_is_refused_through_the_seam() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, package_store, package) = in_memory_upload_fixture(tmp.path());
    cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("first upload succeeds");

    let err = cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect_err("a duplicate id without --replace must be refused");
    assert!(
        err.message.contains("already present"),
        "the refusal names the cause: {}",
        err.message
    );
}

/// `download` round-trips the package bytes through the seam, and `--max-size` refuses an
/// object larger than the cap before writing anything.
///
/// The cap is a guard against an oversized or hostile package filling the disk, so the
/// assertion that matters is not merely that it errors — it is that no output file is left
/// behind when it does.
#[test]
fn download_round_trips_bytes_and_honours_max_size_through_the_seam() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, package_store, package) = in_memory_upload_fixture(tmp.path());
    let original = fs::read(&package).expect("read the source package");
    cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("upload succeeds");

    let out = tmp.path().join("downloaded.tar.c4gh");
    let args = DownloadArgs {
        id: ID.to_owned(),
        output: Some(out.clone()),
        force: false,
        max_size: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    cmd_download::run_with_store(&args, &package_store, Some("test-bucket"))
        .expect("download succeeds");
    assert_eq!(
        fs::read(&out).expect("read the downloaded file"),
        original,
        "the downloaded bytes must be the uploaded bytes"
    );

    // A cap below the object's size refuses, and leaves nothing on disk.
    let capped_out = tmp.path().join("capped.tar.c4gh");
    let capped = DownloadArgs {
        id: ID.to_owned(),
        output: Some(capped_out.clone()),
        force: false,
        max_size: Some((original.len() as u64) - 1),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_download::run_with_store(&capped, &package_store, Some("test-bucket"))
        .expect_err("an object over --max-size must be refused");
    assert!(
        !capped_out.exists(),
        "a refused download must leave no output file behind: {}",
        err.message
    );
}

/// `list` reports what the bucket holds, including the visibility filter, through the seam.
#[test]
fn list_reports_uploaded_datasets_through_the_seam() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, package_store, package) = in_memory_upload_fixture(tmp.path());
    cmd_upload::run_with_store(
        &upload_args(&package, false),
        &store,
        &package_store,
        "test-bucket",
    )
    .expect("upload succeeds");

    // All three filter shapes, against a real store — and the count each reports, which
    // `run_with_store` documents as the datasets the bucket held, before the filter. An
    // empty listing is `Ok(0)`, not an error, so discarding the count let a listing that
    // found nothing (a regressed prefix, say) stay green under every shape.
    for (visible, hidden) in [(false, false), (false, true), (true, false)] {
        let args = ListArgs {
            visible,
            hidden,
            format: gdi_dataset_tool::cli::OutputFormat::Json,
        };
        let listed = cmd_list::run_with_store(&args, &store, Some("test-bucket"))
            .expect("list must succeed against a populated store");
        assert_eq!(
            listed, 1,
            "list --visible={visible} --hidden={hidden} must see the one uploaded dataset"
        );
    }
}
