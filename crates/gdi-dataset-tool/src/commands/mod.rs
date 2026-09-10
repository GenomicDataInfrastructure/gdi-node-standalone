//! The CLI subcommand handlers — one `cmd_<verb>` module per `gdi-dataset-tool`
//! subcommand. Each exposes a `run(...)` entry the [`crate`] dispatcher calls,
//! plus the cross-command helpers a few verbs reuse (e.g. `cmd_keys` secret
//! loaders, `cmd_build::build_staging_dir`, `cmd_pack::resolve_recipients`).

pub mod cmd_build;
pub mod cmd_catalogs;
pub mod cmd_check;
pub mod cmd_completions;
pub mod cmd_config;
pub mod cmd_delete;
pub mod cmd_deploy;
pub mod cmd_diff;
pub mod cmd_doctor;
pub mod cmd_download;
pub mod cmd_init;
pub mod cmd_inspect;
pub mod cmd_keys;
pub mod cmd_lint;
pub mod cmd_list;
pub mod cmd_pack;
pub mod cmd_preview;
pub mod cmd_profiles;
pub mod cmd_publish;
pub mod cmd_rekey;
pub mod cmd_status;
pub mod cmd_unpack;
pub mod cmd_upload;
pub mod cmd_validate;
