//! First-override advisory for the operator CLI.
//!
//! The node warns at boot when it holds overrides without
//! `[service].require_override_store`, but an operator who records the first override on a
//! running node would not hear about it until the next restart. That first override is the
//! moment the store starts holding something no re-ingest can rebuild.
//!
//! Every command that can populate the store routes its write through
//! [`with_first_override_advice`] rather than sampling the store itself, so a new command
//! cannot half-implement the check by sampling on the wrong side of its write.

use anyhow::Result;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::override_store;

/// Shown once, when an operator's write first takes the store from empty to populated.
const ADVICE: &str = "note: this node now holds operator overrides. They are the one part \
                      of the data volume that re-ingesting from the source cannot rebuild, \
                      and an absent store reads as 'no overrides', so losing it would \
                      re-serve every withheld dataset. Put [service].override_dir on \
                      separately-backed storage and set [service].require_override_store \
                      = true.";

/// Run `write`, then print the advisory if it just took the override store from empty to
/// populated on a node that has not declared the store required.
///
/// Silent on every later write, and silent once the assertion is set: repeating it on
/// every takedown would train the operator to ignore it.
///
/// # Errors
///
/// Propagates `write`'s error unchanged; nothing is advised when the write failed.
pub fn with_first_override_advice<T>(
    config: &ServiceConfig,
    write: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let was_populated = override_store::is_populated(&config.service.override_dir_resolved());
    let written = write()?;
    if advises(config, was_populated) {
        println!("{ADVICE}");
    }
    Ok(written)
}

/// The decision half of [`with_first_override_advice`], split out so the transition can be
/// tested without capturing stdout.
fn advises(config: &ServiceConfig, was_populated: bool) -> bool {
    !config.service.require_override_store
        && !was_populated
        && override_store::is_populated(&config.service.override_dir_resolved())
}

/// Tell the operator how to apply a just-written override immediately.
///
/// Informational only, never a signal attempt: the CLI is a separate process that cannot
/// reliably find the serving node, and guessing wrong is worse than saying nothing.
///
/// Single-sourced so every command says the same thing. The shipped image is distroless,
/// with no shell to run `kill` in, so a container signal has to come from the host.
pub fn print_apply_now_hint() {
    println!(
        "to apply now: POST /reconcile on the management plane (needs [control].enabled), \
         or send SIGUSR1 to the node process. For a container, from the host: \
         `docker kill --signal=USR1 <container>`; the shipped image has no shell. \
         Otherwise it applies on the next reconcile"
    );
}

/// Say so when `id` has no entry in this node's status index, after the override is
/// written and never instead of writing it.
///
/// Without it a typo is accepted in silence: `dataset hide <typo>` reports a withhold that
/// withheld nothing, which is the wrong direction to be quiet in on the consent-withdrawal
/// lever.
///
/// It is a note rather than a refusal, because an id this node has never seen is a
/// supported input twice over. The override store can be shared across serving replicas
/// (`ReadOnlyMany`, see deploy/kubernetes/README.md) while each replica keeps its own status
/// index, so an id absent here can be live on the replica next to it, and refusing would
/// block a fleet-wide withhold everywhere but one node. Withholding an id before it arrives
/// is also a real governance act, as `dataset reingest` documents for the same case.
///
/// Best effort: the override is already durable by the time this runs, so it never turns a
/// successful write into a failure. An unreadable index stays silent rather than asserting
/// an absence it cannot support. An absent index is an empty one, and a node that has
/// ingested nothing genuinely has no such dataset, so the note is right to fire there.
pub fn note_if_this_node_has_no_such_dataset(config: &ServiceConfig, id: &str) {
    if this_node_has_no_such_dataset(config, id) {
        println!(
            "note: this node has no dataset {id}. The override is recorded and applies if \
             one appears. Check the id against `dataset list`; with a shared override store \
             this is expected when the dataset lives on another replica."
        );
    }
}

/// The decision half of [`note_if_this_node_has_no_such_dataset`], split out so it can be
/// tested without capturing stdout, in the same shape as [`advises`].
///
/// `false` when the answer is not knowable, which means an unreadable index: silence is the
/// safe default, and the note is only worth reading while it stays rare. An absent index is
/// knowable, being an empty one, so the id really is unknown there.
fn this_node_has_no_such_dataset(config: &ServiceConfig, id: &str) -> bool {
    let path = config.service.data_dir.join(".status.json");
    gdi_node_standalone_core::cache::StatusIndex::load(&path)
        .is_ok_and(|index| index.get(id).is_none())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::{SuppressMode, Suppression, suppressions_subdir};

    fn config(dir: &std::path::Path, require: bool) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
override_dir = "{}"
require_override_store = {require}

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"
"#,
            dir.display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    fn write_a_suppression(cfg: &ServiceConfig) {
        let sub = suppressions_subdir(&cfg.service.override_dir_resolved());
        gdi_node_standalone_core::suppression::write_file(
            &sub,
            // A real dataset id: `suppression::write_file` routes through a chokepoint that
            // rejects anything `is_valid_dataset_id` rejects, so a placeholder like "ds-1"
            // never reaches the filesystem.
            "GDI-EE-UTARTU-20260409143052837",
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "t".into(),
                at: String::new(),
            },
        )
        .unwrap();
    }

    /// The note fires for an id this node has no entry for and stays silent for one it has.
    ///
    /// Both arms are asserted because only the pair is meaningful: a check that always fired
    /// would be ignored within a day, and one that never fired would leave
    /// `dataset hide <typo>` reporting a withhold that withholds nothing.
    #[test]
    fn the_unknown_dataset_note_fires_only_for_an_id_this_node_lacks() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"
"#,
            data.display()
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();

        let known = "GDI-EE-UTARTU-20260409143052837";
        let unknown = "GDI-EE-UTARTU-20260409143052838";

        // No index yet, as on a node that has ingested nothing: an absent index is an
        // empty one, so the id genuinely is unknown and the note is correct to fire.
        assert!(
            this_node_has_no_such_dataset(&cfg, unknown),
            "a node with no datasets really has no such dataset"
        );

        // A corrupt index is the case that is not knowable: stay silent rather than claim
        // an absence, because the ids may well be in there.
        std::fs::write(data.join(".status.json"), b"{ this is not json").unwrap();
        assert!(
            !this_node_has_no_such_dataset(&cfg, unknown),
            "an unreadable index must not produce a claim either way"
        );

        // With an index that holds `known`, the two ids must be told apart. Written as the
        // on-disk JSON rather than through the in-memory type, because the file is what the
        // function reads: a test going through the type could pass over a shape the loader
        // rejects.
        std::fs::write(
            data.join(".status.json"),
            format!(r#"{{"{known}":{{"state":"visible","channel":"inbox"}}}}"#),
        )
        .unwrap();

        assert!(
            !this_node_has_no_such_dataset(&cfg, known),
            "a dataset this node HAS must not be flagged; that would be noise on every \
             legitimate withhold"
        );
        assert!(
            this_node_has_no_such_dataset(&cfg, unknown),
            "an id absent from the index is exactly the typo case the note exists for"
        );
    }

    #[test]
    fn advises_on_the_transition_from_empty_to_populated() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), false);
        write_a_suppression(&cfg);

        assert!(
            advises(&cfg, false),
            "the first override on an unasserted node must be advised"
        );
    }

    #[test]
    fn stays_silent_on_later_writes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), false);
        write_a_suppression(&cfg);

        assert!(
            !advises(&cfg, true),
            "a store that was ALREADY populated must not re-advise"
        );
    }

    #[test]
    fn stays_silent_once_the_store_is_declared_required() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), true);
        write_a_suppression(&cfg);

        assert!(
            !advises(&cfg, false),
            "nothing to advise once require_override_store is set"
        );
    }

    #[test]
    fn stays_silent_when_the_write_left_the_store_empty() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), false);

        assert!(
            !advises(&cfg, false),
            "a write that populated nothing must not advise"
        );
    }

    #[test]
    fn wrapper_propagates_the_write_error_and_its_value() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), false);

        let ok = with_first_override_advice(&cfg, || Ok(7)).unwrap();
        assert_eq!(ok, 7);

        let err =
            with_first_override_advice(&cfg, || Err::<(), _>(anyhow::anyhow!("write failed")));
        assert!(err.is_err(), "the write's error must propagate unchanged");
    }
}
