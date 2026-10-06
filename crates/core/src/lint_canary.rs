//! Canary for the workspace `clippy.toml` `disallowed-methods` and `disallowed-types` lists.
//!
//! Clippy silently ignores a path it cannot resolve: no warning, no error, the entry simply
//! never fires. A typo or an upstream rename therefore disables a ban while the build stays
//! green.
//!
//! Each function below calls one banned method, or names one banned type, under the matching
//! `#[expect]`. `unfulfilled_lint_expectations` is a hard error under `-D warnings`, so a path
//! that stops resolving leaves its expectation unfulfilled and fails the build here, naming
//! the entry.
//!
//! The functions are never called; they exist only to be linted.

use std::path::Path;

/// Canary for `std::fs::write`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::write` still resolves in clippy.toml"
)]
fn canary_fs_write(path: &Path) {
    let _ = std::fs::write(path, b"");
}

/// Canary for `ArrowReaderBuilder::try_new`.
///
/// Spelled through `ArrowReaderBuilder` rather than the `ParquetRecordBatchReaderBuilder`
/// alias, for two reasons: clippy resolves `disallowed-methods` to the underlying item and
/// the alias path does not resolve, and `every_disallowed_path_has_a_canary` matches the
/// path textually as `clippy.toml` writes it.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `ArrowReaderBuilder::try_new` still resolves in clippy.toml"
)]
fn canary_parquet_reader_try_new(file: std::fs::File) {
    let _ = parquet::arrow::arrow_reader::ArrowReaderBuilder::try_new(file);
}

/// Canary for `ArrowReaderBuilder::try_new_with_options`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `ArrowReaderBuilder::try_new_with_options` still resolves in clippy.toml"
)]
fn canary_parquet_reader_try_new_with_options(file: std::fs::File) {
    let _ = parquet::arrow::arrow_reader::ArrowReaderBuilder::try_new_with_options(
        file,
        parquet::arrow::arrow_reader::ArrowReaderOptions::new(),
    );
}

/// Canary for `ArrowReaderMetadata::load`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `ArrowReaderMetadata::load` still resolves in clippy.toml"
)]
fn canary_parquet_metadata_load(file: &std::fs::File) {
    let _ = parquet::arrow::arrow_reader::ArrowReaderMetadata::load(
        file,
        parquet::arrow::arrow_reader::ArrowReaderOptions::new(),
    );
}

/// Canary for `ParquetRecordBatchReader::try_new`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `ParquetRecordBatchReader::try_new` still resolves in clippy.toml"
)]
fn canary_parquet_record_batch_reader_try_new(file: std::fs::File) {
    let _ = parquet::arrow::arrow_reader::ParquetRecordBatchReader::try_new(file, 1024);
}

/// Canary for `index_reader::decode_offset_index`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `decode_offset_index` still resolves in clippy.toml"
)]
fn canary_parquet_decode_offset_index(data: &[u8]) {
    let _ = parquet::file::page_index::index_reader::decode_offset_index(data);
}

/// Canary for `index_reader::decode_column_index`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `decode_column_index` still resolves in clippy.toml"
)]
fn canary_parquet_decode_column_index(data: &[u8]) {
    let _ = parquet::file::page_index::index_reader::decode_column_index(
        data,
        parquet::basic::Type::INT32,
    );
}

/// Canary for the `SerializedFileReader` type ban.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_types,
    reason = "canary: proves `SerializedFileReader` still resolves in clippy.toml"
)]
fn canary_parquet_serialized_file_reader() {
    let _ = None::<parquet::file::serialized_reader::SerializedFileReader<std::fs::File>>;
}

/// Canary for the `ParquetMetaDataReader` type ban.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_types,
    reason = "canary: proves `ParquetMetaDataReader` still resolves in clippy.toml"
)]
fn canary_parquet_metadata_reader() {
    let _ = None::<parquet::file::metadata::ParquetMetaDataReader>;
}

/// Canary for the `ParquetMetaDataPushDecoder` type ban.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_types,
    reason = "canary: proves `ParquetMetaDataPushDecoder` still resolves in clippy.toml"
)]
fn canary_parquet_metadata_push_decoder() {
    let _ = None::<parquet::file::metadata::ParquetMetaDataPushDecoder>;
}

/// Canary for `std::fs::copy`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::copy` still resolves in clippy.toml"
)]
fn canary_fs_copy(from: &Path, to: &Path) {
    let _ = std::fs::copy(from, to);
}

/// Canary for `std::fs::File::create`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::File::create` still resolves in clippy.toml"
)]
fn canary_file_create(path: &Path) {
    let _ = std::fs::File::create(path);
}

/// Canary for `gdi_node_standalone_core::util::write_durable_atomic`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `util::write_durable_atomic` still resolves in clippy.toml"
)]
fn canary_write_durable_atomic(path: &Path) {
    let _ = crate::util::write_durable_atomic(path, b"");
}

/// Canary for `tokio::fs::write`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `tokio::fs::write` still resolves in clippy.toml"
)]
async fn canary_tokio_fs_write(path: &Path) {
    let _ = tokio::fs::write(path, b"").await;
}

/// Canary for `gdi_node_standalone_core::config::config_dir`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `config::config_dir` still resolves in clippy.toml"
)]
fn canary_config_dir() {
    let _ = crate::config::config_dir();
}

/// Canary for `tokio::fs::File::create`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `tokio::fs::File::create` still resolves in clippy.toml"
)]
async fn canary_tokio_file_create(path: &Path) {
    let _ = tokio::fs::File::create(path).await;
}

/// Canary for `std::fs::create_dir_all`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::create_dir_all` still resolves in clippy.toml"
)]
fn canary_fs_create_dir_all(path: &Path) {
    let _ = std::fs::create_dir_all(path);
}

/// Canary for `tokio::fs::create_dir_all`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `tokio::fs::create_dir_all` still resolves in clippy.toml"
)]
async fn canary_tokio_fs_create_dir_all(path: &Path) {
    let _ = tokio::fs::create_dir_all(path).await;
}

/// Canary for `std::fs::create_dir`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::create_dir` still resolves in clippy.toml"
)]
fn canary_fs_create_dir(path: &Path) {
    let _ = std::fs::create_dir(path);
}

/// Canary for `tokio::fs::create_dir`.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `tokio::fs::create_dir` still resolves in clippy.toml"
)]
async fn canary_tokio_fs_create_dir(path: &Path) {
    let _ = tokio::fs::create_dir(path).await;
}

/// Canary for `std::fs::DirBuilder::create`, in UFCS form so the guard's full-path match
/// can see it.
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `std::fs::DirBuilder::create` still resolves in clippy.toml"
)]
fn canary_fs_dir_builder_create(path: &Path) {
    let _ = std::fs::DirBuilder::create(&std::fs::DirBuilder::new(), path);
}

/// Canary for `object_store::GetResult::bytes`.
///
/// Written in UFCS form rather than as `result.bytes()`: the guard below matches each ban
/// by its full path, which a method call cannot supply. `std::fs::write` and
/// `tokio::fs::write` share both a final segment and an owner, so a tail match would let
/// one canary discharge both bans.
#[cfg(feature = "s3")]
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `object_store::GetResult::bytes` still resolves in clippy.toml"
)]
async fn canary_get_result_bytes(result: object_store::GetResult) {
    let _ = object_store::GetResult::bytes(result).await;
}

/// Canary for `reqwest::Client::builder`.
#[cfg(feature = "http")]
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `reqwest::Client::builder` still resolves in clippy.toml"
)]
fn canary_reqwest_client_builder() {
    let _ = reqwest::Client::builder();
}

/// Canary for `reqwest::ClientBuilder::new`.
#[cfg(feature = "http")]
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `reqwest::ClientBuilder::new` still resolves in clippy.toml"
)]
fn canary_reqwest_client_builder_new() {
    let _ = reqwest::ClientBuilder::new();
}

/// Canary for `reqwest::get`.
#[cfg(feature = "http")]
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `reqwest::get` still resolves in clippy.toml"
)]
async fn canary_reqwest_get() {
    let _ = reqwest::get("https://example.invalid/").await;
}

/// Canary for `reqwest::Client::new`.
#[cfg(feature = "http")]
#[expect(dead_code, reason = "canary: exists to be linted, never called")]
#[expect(
    clippy::disallowed_methods,
    reason = "canary: proves `reqwest::Client::new` still resolves in clippy.toml"
)]
fn canary_reqwest_client_new() {
    let _ = reqwest::Client::new();
}

#[cfg(test)]
mod tests {
    /// Item-declaration prefixes stripped before the search, so a canary's own name cannot
    /// stand in for the call it is supposed to make.
    const FN_DECL: [&str; 3] = ["fn ", "async fn ", "pub fn "];

    /// Every `disallowed-methods` and `disallowed-types` entry in `clippy.toml` has a canary
    /// in this file.
    ///
    /// The canaries prove that each banned path still resolves, but nothing else ties the
    /// lists together: a ban added without a canary is unguarded from birth. This reads
    /// `clippy.toml` as data rather than restating the list, so there is only one list and
    /// the two cannot drift.
    #[test]
    fn every_disallowed_path_has_a_canary() {
        let toml = include_str!("../../../clippy.toml");

        // Read only the canary bodies. Three kinds of prose in this file would otherwise
        // satisfy the search: comment lines, a canary's own name (`canary_..._builder_new`
        // contains `new(`), and this test module, which quotes every path it checks. What
        // survives the strip is the attribute block and the call. `reason = "..."` strings
        // survive too, which is why the search below demands a call's opening paren, or a
        // type's `None::<`: a mention writes ``reqwest::get``, a call `reqwest::get(`.
        let source = include_str!("lint_canary.rs");
        let bodies = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        let code: String = bodies
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with("//") && !FN_DECL.iter().any(|p| l.starts_with(p)))
            .collect::<Vec<_>>()
            .join("\n");

        for path in entries(toml, "disallowed-methods") {
            // Match the full path, not its tail. `std::fs::write` and `tokio::fs::write`
            // share both their last segment and their owner, so a tail match lets one
            // canary discharge both bans. Every canary is therefore written fully
            // qualified, including `object_store::GetResult::bytes` in UFCS form, which a
            // `result.bytes()` method call could not express.
            //
            // The one path that cannot be written as `clippy.toml` spells it is this
            // crate's own: a canary here says `crate::util::…`. Derived from
            // `CARGO_CRATE_NAME` rather than written out, so a crate rename cannot leave a
            // stale literal.
            let source_form = path.replace(&format!("{}::", env!("CARGO_CRATE_NAME")), "crate::");
            assert!(
                code.contains(&format!("{source_form}(")),
                "clippy.toml bans `{path}` but no canary in lint_canary.rs calls \
                 `{source_form}(`. Without one, an upstream rename silently disables the \
                 ban, clippy ignores a path it cannot resolve, and nothing fails."
            );
        }
        for path in entries(toml, "disallowed-types") {
            assert!(
                code.contains(&format!("None::<{path}")),
                "clippy.toml bans the type `{path}` but no canary in lint_canary.rs names it \
                 as `None::<{path}`, so an upstream rename would silently disable the ban."
            );
        }
    }

    /// The paths in `clippy.toml`'s `name` array.
    ///
    /// Every non-comment line of the array must parse, so an entry in a shape this misses
    /// fails here instead of being skipped. A fixed count would be a second copy of the list.
    fn entries<'a>(toml: &'a str, name: &str) -> Vec<&'a str> {
        let block = toml
            .split_once(&format!("\n{name} = ["))
            .unwrap_or_else(|| panic!("clippy.toml has no `{name} = [` array: this guard is blind"))
            .1;
        let block = block
            .split_once("\n]")
            .unwrap_or_else(|| panic!("the `{name}` array is unterminated"))
            .0;
        let declared: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let paths: Vec<&str> = declared
            .iter()
            .filter_map(|l| l.strip_prefix("{ path = \""))
            .filter_map(|l| l.split_once('"').map(|(p, _)| p))
            .collect();
        assert_eq!(
            paths.len(),
            declared.len(),
            "the {name} array declares {} entries but only {} parsed: an entry's shape \
             changed and this guard would silently skip it",
            declared.len(),
            paths.len()
        );
        paths
    }
}
