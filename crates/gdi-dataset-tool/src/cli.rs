//! The `gdi-dataset-tool` clap command tree.
//!
//! Grouped as `--help` presents them (see [`Command`]'s `display_order`): get started
//! (`wizard`, `config`, `init`, `keys`), author (`preview`, `build`, `validate`, `lint`,
//! `diff`), package (`pack`, `package`, `rekey`, `inspect`, `unpack`), ship (`upload`,
//! `deploy`, `download`, `list`), lifecycle (`publish`, `unpublish`, `delete`, `status`)
//! and diagnose (`check`, `doctor`, `catalogs`, `profiles`, `completions`).
//! [`crate::run`] dispatches them.

use std::path::PathBuf;
use std::sync::LazyLock;

use clap::builder::TypedValueParser as _;
use clap::{Parser, Subcommand};

/// Extra `--help` footer: the happy path, and how the five validation verbs differ
/// along their two axes (offline or online, pass/fail or advisory).
const AFTER_HELP: &str = "\
One-time setup (before your first dataset):
  gdi-dataset-tool wizard setup                      guided: config + provider keypair
  gdi-dataset-tool doctor                            verify the profile + node reachability

Typical flow, by the delivery your node uses:
  S3 node      init -> build -> pack -> upload -> publish
  inbox node   init -> build -> deploy -> publish      (co-located; no pack, no keys)

Ship verbs differ by how the node takes delivery:
  upload     S3      polled    the node finds it on its next poll (add --wait to block)
  deploy     inbox   watched   the node sees the drop within milliseconds

Validation verbs differ by where and how they judge:
  validate   offline  pass/fail   structural gates on a local dir or .tar.c4gh
  lint       offline  advisory    quality grade of a staging dir (never fails)
  diff       offline  advisory    what changed between two builds (populations, floor, ...)
  check      online   pass/fail   a running node's FDP output vs the package
  doctor     online   advisory    the active profile's config + node reachability";

/// The `--version` string: the crate version plus the shared git-SHA / build-epoch
/// provenance. Computed once, because clap needs a `&'static str` and the value is
/// fixed for a given build.
static LONG_VERSION: LazyLock<String> =
    LazyLock::new(|| gdi_build_info::version_provenance(env!("CARGO_PKG_VERSION")));

/// Prepare and package GDI datasets.
#[derive(Debug, Parser)]
#[command(name = "gdi-dataset-tool", version = LONG_VERSION.as_str(), about, after_help = AFTER_HELP)]
pub struct Cli {
    /// Path to the tool configuration TOML. Without this flag, `<config-dir>/tool.toml`
    /// is still read when present (`$GDI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gdi`, else
    /// `$HOME/.config/gdi`); the `GDI_TOOL__` env overlay wins over whichever file is read.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The active profile (node deployment) to act on; switches the S3 bucket,
    /// `service_url`, recipient, and catalogs together. Omitted, the root
    /// `default_profile` is used, or the sole configured profile when only one exists.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Add diagnostic notes to stderr. The stdout result and `--format json` are
    /// unchanged, and there is no level above `-v`.
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Quiet: suppress per-step progress (warnings, errors, and the result still print).
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Output format for the report- and result-style subcommands (nearly every
/// subcommand's `--format`, e.g. `lint`, `preview`, `validate`, `status`, `download`).
///
/// A `clap::ValueEnum` so `--help` lists the choices, an unknown value fails before
/// the command runs, and the shell completions enumerate `text`/`json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text (default).
    Text,
    /// Machine-readable JSON.
    Json,
}

/// What the packaged `headers/{vcfId}.vcf` members contain (`build`/`package`
/// `--header-policy`).
///
/// The CLI mirror of [`gdi_node_standalone_core::model::HeaderPolicy`]; `--no-headers` is
/// the `none` case and stays a separate flag for compatibility. Kept as its own type so the
/// tool's argument surface does not force `clap` derives onto the wire model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HeaderPolicyArg {
    /// Structural keys only, `#CHROM` truncated to the eight fixed columns (the built-in
    /// default).
    Minimal,
    /// Also keep the `#CHROM` sample columns and `##SAMPLE`/`##PEDIGREE`.
    WithIdentifiers,
    /// The source header byte-for-byte, including tool command lines (which carry sample
    /// identifiers and internal filesystem paths).
    Verbatim,
}

impl From<HeaderPolicyArg> for gdi_node_standalone_core::model::HeaderPolicy {
    fn from(a: HeaderPolicyArg) -> Self {
        match a {
            HeaderPolicyArg::Minimal => Self::Minimal,
            HeaderPolicyArg::WithIdentifiers => Self::WithIdentifiers,
            HeaderPolicyArg::Verbatim => Self::Verbatim,
        }
    }
}

impl BuildArgs {
    /// The effective header policy: `--no-headers` wins as `None`, else `--header-policy`,
    /// else the active profile's `header_policy`, else the built-in
    /// [`HeaderPolicy::Minimal`](gdi_node_standalone_core::model::HeaderPolicy::Minimal).
    ///
    /// Data minimisation is the default that needs no decision. Widening it needs a flag,
    /// or a profile that recorded the decision once at `wizard setup` for every package
    /// built against that deployment. A flag is per-invocation and wins over the profile.
    #[must_use]
    pub fn header_policy(
        &self,
        profile: Option<&gdi_node_standalone_core::config::Profile>,
    ) -> gdi_node_standalone_core::model::HeaderPolicy {
        use gdi_node_standalone_core::model::HeaderPolicy;
        if self.no_headers {
            return HeaderPolicy::None;
        }
        if let Some(flag) = self.header_policy {
            return flag.into();
        }
        profile
            .and_then(|p| p.header_policy)
            .map_or(HeaderPolicy::Minimal, Into::into)
    }
}

/// Sort order for `inspect --files`. A `clap::ValueEnum` giving `--help` enumeration,
/// pre-execution validation, and shell completions over the kebab-case value set
/// (`name` | `name-desc` | `size` | `size-desc`). There is no ordering by member
/// timestamp: `pack` normalizes every member's timestamp to 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OrderArg {
    /// By member name, ascending (default).
    Name,
    /// By member name, descending.
    NameDesc,
    /// By member size, ascending.
    Size,
    /// By member size, descending.
    SizeDesc,
}

/// The top-level subcommands.
///
/// `display_order` lists them in lifecycle order in `--help`, not declaration order, so a
/// first-time provider reading top-to-bottom follows the journey. The groups run: get
/// started, author, package, ship, lifecycle, diagnose. The `--help` footer
/// (`AFTER_HELP`) cuts the same verbs by how a ship verb delivers and how a validation
/// verb judges. Nothing binds the two texts, so a new verb needs a place in both.
#[derive(Debug, Subcommand)]
pub enum Command {
    // --- get started ---
    /// Interactive guided journey: setup -> author -> build -> pack -> optional publish.
    #[command(display_order = 1)]
    Wizard(WizardArgs),
    /// Manage the tool configuration file (`config init` scaffolds a template).
    #[command(display_order = 2)]
    Config(ConfigArgs),
    /// Scaffold a new package.yaml template.
    #[command(display_order = 3)]
    Init(InitArgs),
    /// Manage the provider's crypt4gh identity and the pinned node recipient.
    #[command(display_order = 4)]
    Keys(KeysArgs),

    // --- author ---
    /// Preview a VCF's recognized populations / AF coverage (dry run; writes nothing).
    #[command(display_order = 10)]
    Preview(PreviewArgs),
    /// Convert a package.yaml's VCF(s) into a validated staging directory.
    #[command(display_order = 11)]
    Build(BuildArgs),
    /// Offline pass/fail: structural-gate a local dataset directory or .tar.c4gh package.
    #[command(display_order = 12)]
    Validate(ValidateArgs),
    /// Offline advisory: quality-grade a built staging directory (never fails).
    #[command(display_order = 13)]
    Lint(LintArgs),
    /// Offline advisory: report what changed between two builds (staging dirs and/or .tar.c4gh).
    #[command(display_order = 14)]
    Diff(DiffArgs),

    // --- package ---
    /// Pack a staging directory into an encrypted .tar.c4gh.
    #[command(display_order = 20)]
    Pack(PackArgs),
    /// Build a package.yaml and pack it into an encrypted .tar.c4gh in one step.
    #[command(display_order = 21)]
    Package(PackageArgs),
    /// Re-key a .tar.c4gh: re-wrap its header to a new node recipient (rotation).
    #[command(display_order = 22)]
    Rekey(RekeyArgs),
    /// Inspect a local .tar.c4gh package without deploying it to a node.
    #[command(display_order = 23)]
    Inspect(InspectArgs),
    /// Decrypt, validate, and extract a .tar.c4gh to an arbitrary directory.
    #[command(display_order = 24)]
    Unpack(UnpackArgs),

    // --- ship ---
    /// Upload a package to the active profile's S3 bucket (polled; hidden by default).
    #[command(display_order = 30)]
    Upload(UploadArgs),
    /// Copy a .tar.c4gh or staging dir into the node's local inbox (watched).
    #[command(display_order = 31)]
    Deploy(DeployArgs),
    /// Download a .tar.c4gh package from the active profile's S3 bucket.
    #[command(display_order = 32)]
    Download(DownloadArgs),
    /// List datasets in the active profile's S3 bucket (all / visible / hidden).
    #[command(display_order = 33)]
    List(ListArgs),

    // --- lifecycle ---
    /// Make a hidden dataset visible (channel-routed `.state.json` edit).
    #[command(display_order = 40)]
    Publish(PublishArgs),
    /// Make a visible dataset hidden (channel-routed `.state.json` edit).
    #[command(display_order = 41)]
    Unpublish(PublishArgs),
    /// Remove a dataset from the node (channel-routed; visible-guard).
    #[command(display_order = 42)]
    Delete(DeleteArgs),
    /// Show a dataset's state + sync summary (management plane / remote S3).
    #[command(display_order = 43)]
    Status(StatusArgs),

    // --- diagnose ---
    /// Online pass/fail: verify a running node's FDP output matches the package contents.
    #[command(display_order = 50)]
    Check(CheckArgs),
    /// Online advisory: read-only preflight of the active profile's config + node reachability.
    #[command(display_order = 51)]
    Doctor(DoctorArgs),
    /// List the catalog names this node accepts (online FDP / offline allow-list).
    #[command(display_order = 52)]
    Catalogs(CatalogsArgs),
    /// Show the configured profiles and which one is active (read-only; secrets redacted).
    #[command(display_order = 53)]
    Profiles(ProfilesArgs),
    /// Print a shell-completion script for `gdi-dataset-tool` to stdout.
    #[command(display_order = 54)]
    Completions(CompletionsArgs),
}

impl Command {
    /// The `--format` this subcommand was invoked with, or `None` for the handful that
    /// have no such flag (`init`, `keys`, `unpack`, `completions`, `wizard`, `config`).
    ///
    /// `main` needs this before dispatch: a command that fails without printing its own
    /// object must still emit a machine-readable error envelope, and only the caller knows
    /// whether JSON was asked for. Reading it back off the parsed args keeps that fact in
    /// one place, instead of asking every verb to report its own failures.
    #[must_use]
    pub fn requested_format(&self) -> Option<OutputFormat> {
        match self {
            Self::Build(a) => Some(a.format),
            Self::Validate(a) => Some(a.format),
            Self::Lint(a) => Some(a.format),
            Self::Diff(a) => Some(a.format),
            Self::Pack(a) => Some(a.format),
            Self::Package(a) => Some(a.format),
            Self::Rekey(a) => Some(a.format),
            Self::Upload(a) => Some(a.format),
            Self::Download(a) => Some(a.format),
            Self::List(a) => Some(a.format),
            Self::Deploy(a) => Some(a.format),
            Self::Inspect(a) => Some(a.format),
            Self::Publish(a) | Self::Unpublish(a) => Some(a.format),
            Self::Delete(a) => Some(a.format),
            Self::Status(a) => Some(a.format),
            Self::Catalogs(a) => Some(a.format),
            Self::Check(a) => Some(a.format),
            Self::Doctor(a) => Some(a.format),
            Self::Preview(a) => Some(a.format),
            Self::Profiles(a) => Some(a.format),
            Self::Init(_)
            | Self::Keys(_)
            | Self::Unpack(_)
            | Self::Completions(_)
            | Self::Wizard(_)
            | Self::Config(_) => None,
        }
    }
}

/// Arguments for `diff`.
#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// The old dataset: a built staging directory or a `.tar.c4gh` package.
    #[arg(value_name = "OLD")]
    pub old: PathBuf,

    /// The new dataset: a built staging directory or a `.tar.c4gh` package.
    #[arg(value_name = "NEW")]
    pub new: PathBuf,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

/// Arguments for `wizard`.
#[derive(Debug, clap::Args)]
pub struct WizardArgs {
    /// Optional `wizard setup` subcommand (setup only).
    #[command(subcommand)]
    pub command: Option<WizardCommand>,
    /// Start at this stage, skipping the earlier ones.
    ///
    /// Only the three stages that can begin a run are accepted: pack and publish need
    /// the build output the same run produced. The accepted spellings come from
    /// `ValueEnum::from_str`, so they cannot drift from the enum.
    #[arg(
        long,
        value_name = "STAGE",
        default_value = "setup",
        value_parser = clap::builder::PossibleValuesParser::new(["setup", "author", "build"])
            .try_map(|s: String| <Stage as clap::ValueEnum>::from_str(&s, false))
    )]
    pub from: Stage,
    /// Stop after this stage.
    #[arg(long, value_name = "STAGE", default_value = "publish")]
    pub to: Stage,
    /// Output path for the package.yaml.
    #[arg(
        short,
        long,
        visible_alias = "out",
        value_name = "PATH",
        default_value = "package.yaml"
    )]
    pub output: PathBuf,
    /// Offline setup: use this local crypt4gh recipient file for the node instead of
    /// fetching `{service_url}/.well-known/c4gh-recipient` over the network (air-gapped
    /// setup). Recorded as the profile's `node_recipient_file`; skips the trust prompt.
    /// Named `--recipient` to match `doctor`/`pack`/`package`/`rekey`.
    #[arg(long, value_name = "PATH")]
    pub recipient: Option<PathBuf>,
}

/// The `wizard` subcommands.
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum WizardCommand {
    /// Run only the profile/config setup (re-entry for credential/key rotation).
    Setup,
}

/// A wizard stage (for `--from`/`--to`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Stage {
    /// Profile/config setup.
    Setup,
    /// Author package.yaml.
    Author,
    /// Build + validate.
    Build,
    /// Pack into .tar.c4gh.
    Pack,
    /// Optional publish.
    Publish,
}

impl Stage {
    /// The journey, in order: the enum's own variant list. The wizard's `[n/N]` banner
    /// numbering derives from this list, so adding a stage renumbers the banners and no
    /// second copy of the variant list can fall behind.
    #[must_use]
    pub fn all() -> &'static [Self] {
        <Self as clap::ValueEnum>::value_variants()
    }

    /// This stage's 1-based position in the journey.
    #[must_use]
    pub fn step(self) -> usize {
        Self::all().iter().position(|s| *s == self).unwrap_or(0) + 1
    }

    /// How many stages the journey has.
    #[must_use]
    pub fn count() -> usize {
        Self::all().len()
    }
}

/// Arguments for `profiles`.
#[derive(Debug, clap::Args)]
pub struct ProfilesArgs {
    /// Output format: `text` (default) or `json`. `json` emits a machine-readable
    /// `{active, default_profile, profiles}` object (credentials redacted).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `preview`.
#[derive(Debug, clap::Args)]
pub struct PreviewArgs {
    /// The VCF (plain or bgzipped `.vcf.gz`) to inspect.
    #[arg(value_name = "VCF")]
    pub vcf: PathBuf,

    /// Assembly used for contig validation (`GRCh37` | `GRCh38`).
    #[arg(long, value_name = "ASSEMBLY", default_value = "GRCh38")]
    pub assembly: String,

    /// Position block size (matches `build`'s `blockRange`; `0` = a single group).
    #[arg(long = "block-range", value_name = "N", default_value_t = 10_000_000)]
    pub block_range: u32,

    /// Build-time minimum allele-count floor (`0` = off, matching the node's serve-time
    /// default). Counts alleles, not individuals: a homozygous carrier contributes 2 to AC,
    /// so use ~2*k for k distinct people (10 for k = 5). It bounds singleton
    /// re-identification only. No floor value prevents multi-variant membership inference.
    #[arg(long = "min-allele-count", value_name = "N", default_value_t = 0)]
    pub min_allele_count: u32,

    /// Also report what `--min-allele-count` would withhold: rows below the floor, rows
    /// its coherence collapse removes, and the populations it erases entirely.
    ///
    /// Converts the VCF a second time (with no floor) to get the baseline.
    #[arg(long = "floor-impact")]
    pub floor_impact: bool,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `completions`.
#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    /// The shell to generate a completion script for.
    #[arg(value_name = "SHELL")]
    pub shell: clap_complete::Shell,
}

/// Arguments shared by `publish` / `unpublish` (the same declarative edit).
#[derive(Debug, clap::Args)]
pub struct PublishArgs {
    /// The dataset id to publish / unpublish.
    #[arg(value_name = "ID")]
    pub id: String,

    /// Use the S3 channel when the management plane cannot be reached. Ignored while
    /// it is reachable, because the node's own channel wins. Mutually exclusive with
    /// `--local`.
    #[arg(long, conflicts_with = "local")]
    pub s3: bool,

    /// Use the local (inbox) channel on the same terms as `--s3`: only when the
    /// management plane cannot be reached.
    #[arg(long)]
    pub local: bool,

    /// The node inbox directory to write the `{id}.state.json` sidecar into (overrides the
    /// profile's `inbox`). Implies `--local`, and, like `deploy --inbox`, needs no tool
    /// profile at all: naming the directory fully specifies the target.
    #[arg(long, value_name = "DIR", conflicts_with = "s3")]
    pub inbox: Option<PathBuf>,

    /// The node's management-plane base URL for the state oracle, overriding the
    /// profile's `management_url`. The oracle supplies the dataset's authoritative
    /// channel and confirms it is live. Without one, the channel falls back to the
    /// profile plus `--s3` / `--local`, and liveness is not confirmed.
    #[arg(long, value_name = "URL")]
    pub management_url: Option<String>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `delete`.
#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent CLI flags, not a state machine"
)]
pub struct DeleteArgs {
    /// The dataset id to delete.
    #[arg(value_name = "ID")]
    pub id: String,

    /// Delete even a currently-visible dataset (for an inbox dataset this writes
    /// `{"state":"deleted","force":true}`).
    #[arg(long)]
    pub force: bool,

    /// Preview the delete: resolve the channel and target, run the visibility guard,
    /// then report what would be deleted without writing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// The node inbox directory to write the `{id}.state.json` sidecar into (overrides the
    /// profile's `inbox`). Implies `--local`, and needs no tool profile: the same escape
    /// hatch `deploy --inbox` and `publish --inbox` take.
    #[arg(long, value_name = "DIR", conflicts_with = "s3")]
    pub inbox: Option<PathBuf>,

    /// Use the S3 channel when the management plane cannot be reached. Ignored while
    /// it is reachable, because the node's own channel wins. Mutually exclusive with
    /// `--local`.
    #[arg(long, conflicts_with = "local")]
    pub s3: bool,

    /// Use the local (inbox) channel on the same terms as `--s3`: only when the
    /// management plane cannot be reached.
    #[arg(long)]
    pub local: bool,

    /// The node's management-plane base URL for the visibility guard, overriding the
    /// profile's `management_url`. Without it the profile-less `--inbox` path has no
    /// state oracle, so the guard cannot run and `delete` refuses the dataset rather
    /// than proceeding.
    #[arg(long, value_name = "URL")]
    pub management_url: Option<String>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `status`.
///
/// Exactly one of `<ID>` or `--all` is required: the `status_target` group makes the
/// usage read `status <ID> | --all` and rejects passing both, rather than silently
/// ignoring the id.
#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("status_target").required(true).args(["id", "all"])))]
pub struct StatusArgs {
    /// The node's management-plane base URL for the state oracle, overriding the profile's
    /// `management_url`. Without one, `status` falls back to the S3 sidecar, which is
    /// explicitly non-authoritative.
    #[arg(long, value_name = "URL")]
    pub management_url: Option<String>,

    /// The dataset id to report on (omit with `--all`).
    #[arg(value_name = "ID")]
    pub id: Option<String>,

    /// Report on every dataset (S3 listing, or FDP-visible + named ids on no-S3).
    #[arg(long, conflicts_with = "diff")]
    pub all: bool,

    /// Show the granular file / `ETag` / state diff between the local copy and S3.
    #[arg(long, requires = "id")]
    pub diff: bool,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `catalogs`.
#[derive(Debug, clap::Args)]
pub struct CatalogsArgs {
    /// Use the offline `catalogs` allow-list even when a `service_url` is set.
    #[arg(long)]
    pub offline: bool,

    /// Fetch the node's catalogs and persist them into the active profile's
    /// `catalogs` allow-list (a config-file write). Requires an online node;
    /// mutually exclusive with `--offline`.
    #[arg(long, conflicts_with = "offline")]
    pub sync: bool,

    /// With `--sync`: fetch and report what would change, writing nothing.
    ///
    /// Worth running first, because `--sync` rewrites the whole config file, dropping
    /// comments and any inline S3 credentials.
    #[arg(long, requires = "sync")]
    pub dry_run: bool,

    /// Output format: `text` (default) or `json` (a machine-readable array).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `check`.
///
/// The same topology as `status`: an optional positional id plus mutually exclusive
/// selectors. It needs the same `ArgGroup`, because an ad-hoc `conflicts_with` mesh
/// leaves `id` tied to nothing, so `check <ID> --hidden` parses cleanly and then drops an
/// argument the operator supplied. clap decides instead, and the usage line states the
/// contract.
#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("check_target")
        .required(true)
        .args(["id", "all", "local", "visible", "hidden"])
))]
pub struct CheckArgs {
    /// A concrete dataset id to check against S3 (omit with `--all` / a local path).
    #[arg(value_name = "ID")]
    pub id: Option<String>,

    /// Check every dataset in the S3 bucket.
    #[arg(long, conflicts_with_all = ["id", "local", "visible", "hidden"])]
    pub all: bool,

    /// Check only hidden datasets in the S3 bucket. A listing mode in its own right, so it
    /// cannot be combined with a concrete id, `--all`, `--visible` or `--local`.
    #[arg(long, conflicts_with_all = ["visible", "local", "id"])]
    pub hidden: bool,

    /// Check only visible datasets in the S3 bucket. A listing mode; see `--hidden`.
    #[arg(long, conflicts_with_all = ["local", "id"])]
    pub visible: bool,

    /// Check a local artifact (a `.tar.c4gh` package or a staging directory)
    /// instead of S3 (the no-S3 workflow).
    #[arg(long, value_name = "PATH")]
    pub local: Option<PathBuf>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `doctor`.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Run only the offline checks (skip the FDP / S3 reachability probes).
    #[arg(long)]
    pub offline: bool,

    /// Local crypt4gh recipient file for the node (overrides the profile).
    #[arg(long, value_name = "PATH")]
    pub recipient: Option<PathBuf>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `upload`.
#[derive(Debug, clap::Args)]
pub struct UploadArgs {
    /// The local `{id}.tar.c4gh` package to upload.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Re-upload an id already in the bucket, to retry an `error`ed one with a fixed
    /// package. Preserves the dataset's current visibility, so it neither un-publishes a
    /// live dataset nor re-publishes a hidden one. `upload` reports the result.
    #[arg(long)]
    pub replace: bool,

    /// Block until the node has ingested the package, instead of returning once the bytes
    /// are in the bucket. Exits non-zero with the node's reason if it rejects the package.
    /// Needs the node's management plane: `--management-url`, else the profile's
    /// `management_url`, else its `service_url` (as `deploy --wait` resolves it).
    #[arg(long)]
    pub wait: bool,

    /// How long `--wait` polls before giving up (seconds).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub wait_timeout: u64,

    /// The node's management-plane base URL for `--wait`'s dataset-state oracle, overriding
    /// the profile's `management_url`.
    #[arg(long, value_name = "URL")]
    pub management_url: Option<String>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `download`.
#[derive(Debug, clap::Args)]
pub struct DownloadArgs {
    /// The dataset id to download (`{id}.tar.c4gh` is fetched from the bucket).
    #[arg(value_name = "ID")]
    pub id: String,

    /// Output path for the downloaded `.tar.c4gh` (defaults to `{id}.tar.c4gh` in the
    /// current directory). An existing directory means "into here", as `cp` reads it: the
    /// package lands at `<dir>/{id}.tar.c4gh`.
    #[arg(short, long, visible_alias = "out", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,

    /// Reject the download if the bucket object exceeds this many bytes, checked from
    /// the object's advertised size before any bytes are fetched (guards against a
    /// corrupt or hostile over-sized entry filling the disk). Omit for no cap.
    #[arg(long, value_name = "BYTES")]
    pub max_size: Option<u64>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `list`.
#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Show only visible datasets.
    #[arg(long, conflicts_with = "hidden")]
    pub visible: bool,

    /// Show only hidden datasets.
    #[arg(long)]
    pub hidden: bool,

    /// Output format: `text` (default) or `json` (a machine-readable array).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `deploy`.
#[derive(Debug, clap::Args)]
pub struct DeployArgs {
    /// The artifact to deploy: a `{id}.tar.c4gh` package or a prepared staging
    /// directory (a `build/{id}/` dir containing a `manifest.json`).
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,

    /// The node inbox directory to drop into (overrides the profile's `inbox`).
    #[arg(long, value_name = "DIR")]
    pub inbox: Option<PathBuf>,

    /// Re-present an id already on the node, to retry an `error`ed id with a fixed
    /// package. Cannot overwrite a live dataset: the node ignores a changed source for a
    /// visible/hidden id.
    #[arg(long)]
    pub replace: bool,

    /// Block until the node finishes ingesting, instead of returning once the file lands.
    /// Exits non-zero with the node's reason if it rejects the package. Needs the profile's
    /// `management_url` (or `service_url`) to reach the oracle.
    #[arg(long)]
    pub wait: bool,

    /// How long `--wait` polls before giving up (seconds).
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    pub wait_timeout: u64,

    /// The node's management-plane base URL for `--wait`'s dataset-state oracle,
    /// overriding the profile's `management_url`. Lets `--inbox --wait` run with no
    /// profile: `--inbox` names where to drop the package, this names where to watch it
    /// land.
    #[arg(long, value_name = "URL")]
    pub management_url: Option<String>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `config`.
#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    /// The config subcommand to run.
    #[command(subcommand)]
    pub command: ConfigCommand,
}

/// The `config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Scaffold a commented tool-config TOML template (no secrets).
    Init(ConfigInitArgs),
}

/// Arguments for `config init`.
#[derive(Debug, clap::Args)]
pub struct ConfigInitArgs {
    /// Output path for the scaffolded config TOML. Defaults to
    /// `<config_dir>/tool.toml` (`$GDI_CONFIG_DIR` / `$XDG_CONFIG_HOME/gdi` /
    /// `$HOME/.config/gdi`).
    #[arg(short, long, visible_alias = "out", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `init`.
#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Output path for the scaffolded `package.yaml`.
    #[arg(
        short,
        long,
        visible_alias = "out",
        value_name = "PATH",
        default_value = "package.yaml"
    )]
    pub output: PathBuf,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `validate`.
#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// The target to validate: a staging directory or a `.tar.c4gh` package.
    #[arg(value_name = "PATH")]
    pub target: PathBuf,

    /// Output format: `text` (default) or `json`. `json` emits a machine-readable
    /// `{valid, errors, warnings}` object collecting every problem found.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `lint`.
#[derive(Debug, clap::Args)]
pub struct LintArgs {
    /// The built staging directory (a `build` output) or a `.tar.c4gh` package to
    /// report on (a package is decrypted + extracted first, like `validate`).
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `unpack`.
#[derive(Debug, clap::Args)]
pub struct UnpackArgs {
    /// The `.tar.c4gh` package to decrypt, validate, and extract.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Output directory to extract into (created if missing).
    #[arg(short, long, visible_alias = "out", value_name = "DIR")]
    pub output: PathBuf,

    /// Overwrite a non-empty output directory.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `inspect`.
#[derive(Debug, clap::Args)]
pub struct InspectArgs {
    /// The `.tar.c4gh` package to inspect.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Print the `manifest.json` (the first member) and stop.
    #[arg(long, conflicts_with = "files")]
    pub manifest: bool,

    /// List all members with their sizes.
    #[arg(long)]
    pub files: bool,

    /// Sort order for `--files` (`name` | `name-desc` | `size` | `size-desc`).
    #[arg(long, value_name = "ORDER", default_value = "name", requires = "files")]
    pub order: OrderArg,

    /// Output format: `text` (default) or `json` (manifest mode emits the manifest
    /// object; `--files`/default emit a member array / structure object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `build`.
#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent CLI flags, not a state machine"
)]
pub struct BuildArgs {
    /// Path to the package.yaml describing the dataset.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Two-letter country code for the dataset ID (highest-precedence source;
    /// overrides config and the `GDI_TOOL__COUNTRY_CODE` env var).
    #[arg(long = "country-code", visible_alias = "cc", value_name = "CC")]
    pub country_code: Option<String>,

    /// Output directory; the staging dir is written to `<output>/<datasetId>/`.
    #[arg(
        short,
        long = "output",
        visible_alias = "out",
        value_name = "DIR",
        default_value = "build"
    )]
    pub out: PathBuf,

    /// Overwrite an existing staging directory.
    #[arg(long)]
    pub force: bool,

    /// Exclude VCF headers from the staging directory.
    #[arg(long = "no-headers", conflicts_with = "header_policy")]
    pub no_headers: bool,

    /// What the packaged `headers/{vcfId}.vcf` members contain; see the possible values
    /// below. `verbatim` ships tool command lines, which carry sample identifiers and
    /// internal filesystem paths.
    ///
    /// Defaults to the active profile's `header_policy`, else `minimal`. The choice is
    /// recorded as `internal.headerPolicy` in the manifest.
    #[arg(long = "header-policy", value_name = "POLICY")]
    pub header_policy: Option<HeaderPolicyArg>,

    /// Pin the build timestamp (Unix epoch milliseconds) instead of reading the wall
    /// clock, making the generated `datasetId`, and therefore `manifest.json`, a pure
    /// function of the inputs.
    ///
    /// The parquet bytes and the plaintext tar are already deterministic, so this is the
    /// last piece needed for a `rebuild and compare digests` check. The encrypted
    /// `.tar.c4gh` can never match: crypt4gh draws a fresh random session key and a fresh
    /// nonce per segment.
    #[arg(long = "build-epoch", value_name = "MILLIS")]
    pub build_epoch: Option<u64>,

    /// Preflight the whole package: convert every VCF and run every gate, then discard
    /// the output. Writes nothing durable.
    ///
    /// `preview` covers one VCF and `validate`/`lint` need an already-built staging dir;
    /// this is the only way to check a multi-VCF group before committing to a build.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Fail the build if any `warning:` was emitted.
    ///
    /// Covers both the metadata advisories and the conversion anomalies (a
    /// non-conforming INFO field, a population with AC/AN but no AF, a gVCF input).
    /// `note:` lines are expected consequences of declared configuration (the
    /// `min_allele_count` floor, record drops, a non-PASS FILTER) and never fail a build.
    #[arg(long)]
    pub strict: bool,

    /// Conversion worker-pool size (0 = one per logical CPU). One shared pool converts
    /// all the dataset's VCFs by partition; lower this to cap peak memory by keeping
    /// fewer partitions in flight. A single VCF still uses the whole pool.
    #[arg(long = "jobs", short = 'j', value_name = "N", default_value_t = 0)]
    pub jobs: usize,

    /// Fetch the node's current catalog allow-list live (from the active profile's
    /// `service_url`) instead of the profile's pinned `catalogs`. Falls back to the
    /// pinned list when the node is unreachable, so a refresh never hard-fails the
    /// build; the node re-validates catalogs authoritatively at ingest regardless.
    #[arg(long = "refresh-catalogs")]
    pub refresh_catalogs: bool,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `keys`.
#[derive(Debug, clap::Args)]
pub struct KeysArgs {
    /// The keys subcommand to run.
    #[command(subcommand)]
    pub command: KeysCommand,
}

/// The `keys` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Create the provider crypt4gh identity if missing (secret file 0o600).
    Generate(KeysGenerateArgs),
    /// Print the provider's recipient (public key) and its file path.
    Show,
    /// Fetch + pin the node's crypt4gh recipient to a local file (trust-on-first-use).
    PinRecipient(KeysPinRecipientArgs),
}

/// Arguments for `keys generate`.
#[derive(Debug, clap::Args)]
pub struct KeysGenerateArgs {
    /// Replace an existing provider identity (the previous key is first backed up to a
    /// timestamped `.bak-<ts>` sibling). The new key cannot decrypt or re-key packages
    /// already wrapped to the previous recipient. To rotate without losing access, add
    /// the new key to `[keys].identities` instead.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `keys pin-recipient`.
#[derive(Debug, clap::Args)]
pub struct KeysPinRecipientArgs {
    /// Explicit URL to fetch the recipient from (overrides the profile's
    /// `node_recipient_url` / `{service_url}/.well-known/c4gh-recipient`).
    #[arg(long, value_name = "URL", conflicts_with = "file")]
    pub url: Option<String>,

    /// Pin a recipient handed over offline (a `.pub` on a USB stick) instead of fetching
    /// one: the air-gapped path. With `--force`, this adopts a rotated node key where no
    /// URL is reachable. `wizard setup --recipient` refuses a differing pin and has no
    /// `--force` of its own.
    #[arg(long, value_name = "PATH", conflicts_with = "url")]
    pub file: Option<PathBuf>,

    /// Output path for the pinned recipient PEM. Defaults to the profile's
    /// `node_recipient_file`, else the URL-keyed pin path
    /// `<config_dir>/recipients/<host>.<hash>.pub`.
    #[arg(short, long, visible_alias = "out", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Replace an existing pin that holds a different key (rotation).
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `pack`.
#[derive(Debug, clap::Args)]
pub struct PackArgs {
    /// The staging directory to pack (a `build/{datasetId}/` directory).
    #[arg(value_name = "STAGING_DIR")]
    pub staging: PathBuf,

    /// Local crypt4gh recipient file for the node (overrides the profile).
    #[arg(long, value_name = "PATH")]
    pub recipient: Option<PathBuf>,

    /// Output path for the `{datasetId}.tar.c4gh` (defaults to the current directory). An
    /// existing directory means "into here", as `cp` reads it: the package lands at
    /// `<dir>/{datasetId}.tar.c4gh`.
    #[arg(short, long = "output", visible_alias = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `rekey` (re-wrap a package's crypt4gh header to a new node
/// recipient, for node-identity rotation).
#[derive(Debug, clap::Args)]
pub struct RekeyArgs {
    /// The `.tar.c4gh` package to re-key (decrypted with the provider identities).
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Local crypt4gh recipient file for the new node identity (overrides the
    /// profile, same precedence as `pack --recipient`).
    #[arg(long, value_name = "PATH")]
    pub recipient: Option<PathBuf>,

    /// Output path for the re-keyed `.tar.c4gh` (defaults to overwriting the input
    /// in place, which requires `--force`).
    #[arg(short, long = "output", visible_alias = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Overwrite an existing output file (required for in-place re-keying).
    #[arg(long)]
    pub force: bool,

    /// Re-sign the re-wrapped header as this crypt4gh secret key, so the recovered writer
    /// fingerprint stays stable and allow-listable. Required to rekey for a
    /// `writer_policy = enforce` node: a plain rekey mints a fresh ephemeral writer key
    /// that such a node rejects. Use your provider key (the one that authored the
    /// package), so the fingerprint is the one already on the node's allow-list.
    #[arg(long = "as", value_name = "SECRET_KEY_PATH")]
    pub as_writer: Option<PathBuf>,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

/// Arguments for `package` (build + pack in one step).
#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent CLI flags, not a state machine"
)]
pub struct PackageArgs {
    /// Path to the package.yaml describing the dataset.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Two-letter country code for the dataset ID (highest-precedence source).
    #[arg(long = "country-code", visible_alias = "cc", value_name = "CC")]
    pub country_code: Option<String>,

    /// Build output directory; the staging dir is `<build_out>/<datasetId>/`.
    #[arg(long = "build-out", value_name = "DIR", default_value = "build")]
    pub build_out: PathBuf,

    /// Exclude VCF headers from the package.
    #[arg(long = "no-headers", conflicts_with = "header_policy")]
    pub no_headers: bool,

    /// What the packaged `headers/{vcfId}.vcf` members contain; see `build --header-policy`.
    /// Defaults to the active profile's `header_policy`, else `minimal`.
    #[arg(long = "header-policy", value_name = "POLICY")]
    pub header_policy: Option<HeaderPolicyArg>,

    /// Local crypt4gh recipient file for the node (overrides the profile).
    #[arg(long, value_name = "PATH")]
    pub recipient: Option<PathBuf>,

    /// Output path for the final `{datasetId}.tar.c4gh` (defaults to the current
    /// directory); an existing directory means "into here", as `cp` reads it. This is the
    /// package file itself. `--build-out` and `build -o` instead name the parent directory
    /// the staging dir is created under.
    #[arg(short, long = "output", visible_alias = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Overwrite an existing staging dir and output file.
    #[arg(long)]
    pub force: bool,

    /// Keep the staging directory after a successful pack (it is deleted by
    /// default, as it holds plaintext genotype-derived intermediates).
    #[arg(long)]
    pub keep: bool,

    /// Conversion worker-pool size (0 = one per logical CPU); see `build --jobs`.
    #[arg(long = "jobs", short = 'j', value_name = "N", default_value_t = 0)]
    pub jobs: usize,

    /// Fetch the node's current catalog allow-list live for the build phase; see
    /// `build --refresh-catalogs`.
    #[arg(long = "refresh-catalogs")]
    pub refresh_catalogs: bool,

    /// Output format: `text` (default) or `json` (a single machine-readable result object).
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    use gdi_node_standalone_core::config::{Profile, ProfileHeaderPolicy};
    use gdi_node_standalone_core::model::HeaderPolicy;

    fn build_args(no_headers: bool, flag: Option<HeaderPolicyArg>) -> BuildArgs {
        BuildArgs {
            package: PathBuf::from("package.yaml"),
            country_code: None,
            out: PathBuf::from("build"),
            force: false,
            no_headers,
            header_policy: flag,
            strict: false,
            dry_run: false,
            build_epoch: None,
            jobs: 0,
            refresh_catalogs: false,
            format: OutputFormat::Text,
        }
    }

    fn profile_with(policy: ProfileHeaderPolicy) -> Profile {
        Profile {
            header_policy: Some(policy),
            ..Profile::default()
        }
    }

    #[test]
    fn header_policy_flag_wins_over_the_profile() {
        let args = build_args(false, Some(HeaderPolicyArg::Minimal));
        let profile = profile_with(ProfileHeaderPolicy::WithIdentifiers);
        assert_eq!(args.header_policy(Some(&profile)), HeaderPolicy::Minimal);
    }

    #[test]
    fn no_headers_wins_over_the_profile() {
        let args = build_args(true, None);
        let profile = profile_with(ProfileHeaderPolicy::WithIdentifiers);
        assert_eq!(args.header_policy(Some(&profile)), HeaderPolicy::None);
    }

    #[test]
    fn header_policy_falls_back_to_the_profile() {
        let args = build_args(false, None);
        let profile = profile_with(ProfileHeaderPolicy::WithIdentifiers);
        assert_eq!(
            args.header_policy(Some(&profile)),
            HeaderPolicy::WithIdentifiers
        );
    }

    #[test]
    fn header_policy_is_minimal_without_flag_or_profile_value() {
        let args = build_args(false, None);
        assert_eq!(args.header_policy(None), HeaderPolicy::Minimal);
        let unset = Profile::default();
        assert_eq!(args.header_policy(Some(&unset)), HeaderPolicy::Minimal);
    }

    /// `check` must reject an id combined with a listing selector.
    ///
    /// Without the `ArgGroup`, `check <ID> --hidden` and `check <ID> --local <PATH>` parse
    /// and then drop an argument the operator supplied: the handler short-circuits on the
    /// id before the visibility filter is read, and `--local` wins outright.
    #[test]
    fn check_rejects_an_id_combined_with_a_listing_selector() {
        for argv in [
            vec![
                "gdi-dataset-tool",
                "check",
                "GDI-EE-UTARTU-20260409143052837",
                "--hidden",
            ],
            vec![
                "gdi-dataset-tool",
                "check",
                "GDI-EE-UTARTU-20260409143052837",
                "--visible",
            ],
            vec![
                "gdi-dataset-tool",
                "check",
                "GDI-EE-UTARTU-20260409143052837",
                "--local",
                "p.tar.c4gh",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "must be rejected, not silently ignored: {argv:?}"
            );
        }
    }

    /// The legitimate shapes must still parse, including a filter narrowing `--all`.
    #[test]
    fn check_accepts_each_target_alone() {
        for argv in [
            vec![
                "gdi-dataset-tool",
                "check",
                "GDI-EE-UTARTU-20260409143052837",
            ],
            vec!["gdi-dataset-tool", "check", "--all"],
            vec!["gdi-dataset-tool", "check", "--local", "p.tar.c4gh"],
            vec!["gdi-dataset-tool", "check", "--hidden"],
            vec!["gdi-dataset-tool", "check", "--visible"],
        ] {
            assert!(Cli::try_parse_from(&argv).is_ok(), "must parse: {argv:?}");
        }
    }

    /// The `--order` help must advertise exactly the values `OrderArg` accepts. clap
    /// validates a `ValueEnum` before dispatch, so an extra value named in the prose is a
    /// hard `exit 2` for anyone who follows the documented options.
    #[test]
    fn inspect_order_help_advertises_only_accepted_values() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let inspect = cmd
            .find_subcommand_mut("inspect")
            .expect("inspect subcommand exists");
        let help = inspect.render_long_help().to_string();
        assert!(
            !help.contains("mtime"),
            "--order help must not advertise mtime, which OrderArg rejects:\n{help}"
        );
        for accepted in ["name", "name-desc", "size", "size-desc"] {
            assert!(
                help.contains(accepted),
                "--order help must still list {accepted}"
            );
        }
    }

    #[test]
    fn version_embeds_git_sha_and_build_epoch() {
        use clap::CommandFactory;
        // `--version` must carry the shared git-SHA + build-epoch provenance (parity
        // with the service's version line), not just the bare CARGO_PKG_VERSION.
        let v = Cli::command()
            .get_version()
            .expect("clap version is set")
            .to_owned();
        assert!(
            v.contains("(git "),
            "version must embed the git SHA; got: {v}"
        );
        assert!(
            v.contains("build_epoch "),
            "version must embed the build epoch; got: {v}"
        );
    }

    /// clap renders `--version` as `"{bin_name} {version}"`, so the `version` value must
    /// not carry the binary name itself; doing so prints the name twice. Asserted on the
    /// rendered line, which is the only place the doubling shows.
    #[test]
    fn rendered_version_names_the_binary_exactly_once() {
        use clap::CommandFactory;
        let rendered = Cli::command().render_version();
        assert!(
            rendered.starts_with("gdi-dataset-tool "),
            "the rendered line must lead with the binary name; got: {rendered}"
        );
        assert_eq!(
            rendered.matches("gdi-dataset-tool").count(),
            1,
            "the binary name must appear exactly once (clap prepends it); got: {rendered}"
        );
    }

    /// `requested_format` must report what the caller actually asked for, because `main`
    /// uses it to decide whether a failure needs a machine-readable error envelope.
    ///
    /// Getting this wrong is silent in both directions: `None` for a JSON caller leaves
    /// stdout empty on failure, and `Some(Json)` for a text caller injects a JSON object
    /// into human output. The match carries no wildcard arm, so a new subcommand cannot
    /// compile until it is classified; this pins that the mapping is read, not defaulted.
    #[test]
    fn requested_format_reports_the_callers_choice() {
        let json = Cli::try_parse_from(["gdi-dataset-tool", "validate", "d", "--format", "json"])
            .unwrap()
            .command
            .requested_format();
        assert_eq!(json, Some(OutputFormat::Json));

        let text = Cli::try_parse_from(["gdi-dataset-tool", "validate", "d"])
            .unwrap()
            .command
            .requested_format();
        assert_eq!(
            text,
            Some(OutputFormat::Text),
            "the default is text, not None"
        );

        // A verb with no `--format` at all reports None, so `main` stays silent for it.
        let none = Cli::try_parse_from(["gdi-dataset-tool", "init"])
            .unwrap()
            .command
            .requested_format();
        assert_eq!(none, None);

        // Spot-check the verbs whose failures a pipeline is most likely to branch on.
        for argv in [
            vec![
                "gdi-dataset-tool",
                "upload",
                "p.tar.c4gh",
                "--format",
                "json",
            ],
            vec![
                "gdi-dataset-tool",
                "status",
                "GDI-EE-UTARTU-1",
                "--format",
                "json",
            ],
            vec!["gdi-dataset-tool", "doctor", "--format", "json"],
            vec!["gdi-dataset-tool", "check", "--all", "--format", "json"],
        ] {
            assert_eq!(
                Cli::try_parse_from(&argv)
                    .unwrap()
                    .command
                    .requested_format(),
                Some(OutputFormat::Json),
                "must report json for {argv:?}"
            );
        }
    }

    #[test]
    fn build_requires_package() {
        // Missing the package positional is an argument error.
        let result = Cli::try_parse_from(["gdi-dataset-tool", "build"]);
        assert!(result.is_err());
    }

    #[test]
    fn catalogs_sync_conflicts_with_offline() {
        assert!(Cli::try_parse_from(["gdi-dataset-tool", "catalogs", "--sync"]).is_ok());
        assert!(
            Cli::try_parse_from(["gdi-dataset-tool", "catalogs", "--sync", "--offline"]).is_err()
        );
    }

    /// The CLI's structural argument surface, as a golden.
    ///
    /// Pins what an operator's scripts and the documentation depend on: flag names, value
    /// names, defaults, required-ness, and each enum's accepted values, for every
    /// subcommand and every argument.
    ///
    /// Not a snapshot of `--help`: help text embeds the doc comments, so every prose edit
    /// would churn the golden and train reviewers to re-bless it without reading. This
    /// renders structure only, so it moves when the contract moves.
    #[test]
    fn cli_argument_surface_is_pinned() {
        use clap::CommandFactory as _;

        fn render(cmd: &clap::Command, path: &str, out: &mut String) {
            use std::fmt::Write as _;
            let name = if path.is_empty() {
                cmd.get_name().to_owned()
            } else {
                format!("{path} {}", cmd.get_name())
            };
            let _ = writeln!(out, "{name}");
            let mut args: Vec<String> = cmd
                .get_arguments()
                .map(|a| {
                    let long = a.get_long().map_or_else(String::new, |l| format!("--{l}"));
                    let short = a.get_short().map_or_else(String::new, |c| format!("-{c}"));
                    let vals: Vec<&str> = a.get_value_names().map_or_else(Vec::new, |v| {
                        v.iter().map(clap::builder::Str::as_str).collect()
                    });
                    let defaults: Vec<String> = a
                        .get_default_values()
                        .iter()
                        .map(|d| d.to_string_lossy().into_owned())
                        .collect();
                    let possible: Vec<String> = a
                        .get_possible_values()
                        .iter()
                        .map(|p| p.get_name().to_owned())
                        .collect();
                    format!(
                        "    {id}{short}{long}{vals}{req}{def}{pos}",
                        id = a.get_id(),
                        short = if short.is_empty() {
                            String::new()
                        } else {
                            format!(" {short}")
                        },
                        long = if long.is_empty() {
                            String::new()
                        } else {
                            format!(" {long}")
                        },
                        vals = if vals.is_empty() {
                            String::new()
                        } else {
                            format!(" <{}>", vals.join(","))
                        },
                        req = if a.is_required_set() { " required" } else { "" },
                        def = if defaults.is_empty() {
                            String::new()
                        } else {
                            format!(" default={}", defaults.join(","))
                        },
                        pos = if possible.is_empty() {
                            String::new()
                        } else {
                            format!(" values=[{}]", possible.join("|"))
                        },
                    )
                })
                .collect();
            // Sorted: clap's declaration order is not part of the contract, so a field
            // being moved must not churn this golden.
            args.sort();
            for a in args {
                let _ = writeln!(out, "{a}");
            }
            let mut subs: Vec<&clap::Command> = cmd.get_subcommands().collect();
            subs.sort_by_key(|c| c.get_name().to_owned());
            for sub in subs {
                render(sub, &name, out);
            }
        }

        let mut out = String::new();
        render(&Cli::command(), "", &mut out);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn command_tree_is_valid() {
        // clap's canonical self-check: catches a malformed argument tree (duplicate
        // flags, bad arg relationships, an ill-formed subcommand) at test time rather
        // than at first runtime invocation. `clap_complete::generate` walks the same
        // tree, so a valid tree is what keeps completion generation sound.
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    #[test]
    fn completions_generate_for_every_shell() {
        // Generate completions for every advertised shell into a buffer and assert
        // non-empty, panic-free output, covering the shell-specific generators and not
        // just bash. Walking the real `Cli` tree keeps every registered subcommand
        // present by construction.
        use clap::CommandFactory as _;
        use clap::ValueEnum as _;
        for &shell in clap_complete::Shell::value_variants() {
            let mut buf = Vec::new();
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "gdi-dataset-tool", &mut buf);
            assert!(
                !buf.is_empty(),
                "completion generation produced empty output for {shell:?}"
            );
        }
    }

    #[test]
    fn format_value_enum_validates_pre_execution() {
        // The `--format` ValueEnum rejects an unknown value at parse time (so the
        // command handlers never see a bad format), on both `lint` and `preview`.
        assert!(
            Cli::try_parse_from(["gdi-dataset-tool", "lint", "dir", "--format", "xml"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["gdi-dataset-tool", "preview", "x.vcf", "--format", "yaml"])
                .is_err()
        );
        // The two accepted values parse.
        for fmt in ["text", "json"] {
            assert!(
                Cli::try_parse_from(["gdi-dataset-tool", "lint", "dir", "--format", fmt]).is_ok()
            );
        }
    }

    #[test]
    fn diagnostic_verbs_accept_format_json() {
        // doctor / check / status accept `--format json` (machine-readable output).
        let doctor =
            Cli::try_parse_from(["gdi-dataset-tool", "doctor", "--format", "json"]).unwrap();
        match doctor.command {
            Command::Doctor(a) => assert_eq!(a.format, OutputFormat::Json),
            other => panic!("expected Doctor, got {other:?}"),
        }
        let check = Cli::try_parse_from([
            "gdi-dataset-tool",
            "check",
            "--local",
            "d",
            "--format",
            "json",
        ])
        .unwrap();
        match check.command {
            Command::Check(a) => assert_eq!(a.format, OutputFormat::Json),
            other => panic!("expected Check, got {other:?}"),
        }
        let status =
            Cli::try_parse_from(["gdi-dataset-tool", "status", "GOE-X", "--format", "json"])
                .unwrap();
        match status.command {
            Command::Status(a) => assert_eq!(a.format, OutputFormat::Json),
            other => panic!("expected Status, got {other:?}"),
        }
        // Default stays text, and a bad value is rejected pre-execution.
        let d = Cli::try_parse_from(["gdi-dataset-tool", "doctor"]).unwrap();
        std::assert_matches!(d.command, Command::Doctor(a) if a.format == OutputFormat::Text);
        assert!(
            Cli::try_parse_from(["gdi-dataset-tool", "status", "X", "--format", "xml"]).is_err()
        );
    }
}
