//! Service-side Parquet Modular Encryption wiring (compiled only under the `pme`
//! feature, which implies `vault`).
//!
//! This is the Vault-backed half of the `core` PME seam: it mints each file's DEK on
//! ingest and unwraps + caches it on read, so `core`'s parquet write/read stay
//! Vault-agnostic (they see only opaque key bytes + `key_metadata`).
//!
//! * [`VaultDekMinter`] implements [`gdi_node_standalone_core::parquet_io::DekMinter`]:
//!   one `transit/datakey/plaintext/<key>` call (`bits=256`) mints and wraps a fresh
//!   256-bit DEK. The base64 plaintext decodes to the 32 raw footer-key bytes, and the
//!   wrapped ciphertext (`vault:vN:…`) is stored in a self-describing `key_metadata`
//!   record `{"s","m","k","w"}` (scheme / transit-mount / transit-key / wrapped-DEK).
//! * [`CachedKeyRetriever`] implements [`gdi_node_standalone_core::parquet_io::KeyRetriever`]:
//!   it parses that `key_metadata`, checks the scheme `s` and validates `m`/`k` against
//!   the configured key, giving a clear key-mismatch error rather than an opaque decrypt
//!   failure. It then serves the unwrapped DEK from a `zeroize`-backed cache keyed by the
//!   wrapped DEK `w`, or calls `transit/decrypt` once (single-flighted) and caches it.
//!   The cache is flushed on `SIGHUP` and on restart, so steady-state reads never touch
//!   Vault while revocation latency stays bounded to a signal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gdi_node_standalone_core::error::CoreError;
use gdi_node_standalone_core::parquet_io::{
    DekMinter, KeyRetriever, PME_KEY_LEN, PmeError as ParquetError,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::vault::{VaultClient, VaultError};

/// The current `key_metadata` envelope scheme version (`s`). Bumped only on a
/// backwards-incompatible change to the wrapped-DEK format; the retriever rejects
/// an unknown scheme with a clear error rather than attempting a decrypt.
const SCHEME_V1: u32 = 1;

/// The default cached-DEK lifetime. An hour: at-rest key revocation is not time-critical
/// for the public aggregated tier, and a published `datasets/{id}/` file is immutable, so
/// its DEK is stable. A `SIGHUP` or restart flush bounds revocation latency below the TTL.
const DEK_CACHE_TTL: Duration = Duration::from_hours(1);

/// The self-describing `key_metadata` record stored as the parquet `key_metadata`.
///
/// Serialized as compact JSON `{"s":<scheme>,"m":"<mount>","k":"<key>","w":"vault:vN:…"}`.
/// `m`/`k` bind the wrapped DEK to the master key that produced it, so a key rename or a
/// multi-key setup decrypts against the right key. `w` is the wrapped DEK; `s` lets the
/// format evolve.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyMetadata {
    /// Scheme version.
    s: u32,
    /// Transit mount.
    m: String,
    /// Transit key name.
    k: String,
    /// Wrapped DEK (`vault:vN:…`).
    w: String,
}

/// The Vault-backed DEK minter for the ingest store.
///
/// Holds a cheap clone of the [`VaultClient`] plus the configured transit mount/key,
/// recorded into each file's `key_metadata`. [`DekMinter::mint`] runs inside the ingest
/// `spawn_blocking` worker, so it bridges to the async Vault call via the current runtime
/// handle.
pub struct VaultDekMinter {
    vault: VaultClient,
    transit_mount: String,
    transit_key: String,
}

impl VaultDekMinter {
    /// Build a minter from a connected Vault client and the configured transit
    /// mount + key.
    #[must_use]
    pub fn new(vault: VaultClient, transit_mount: String, transit_key: String) -> Self {
        Self {
            vault,
            transit_mount,
            transit_key,
        }
    }
}

impl DekMinter for VaultDekMinter {
    fn mint(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CoreError> {
        // The minter is called on a `spawn_blocking` thread; bridge to the async
        // Vault client via the current runtime handle.
        let (plaintext_b64, wrapped) =
            block_on_vault(self.vault.transit_datakey(&self.transit_key))?;
        let key = VaultClient::decode_b64(&plaintext_b64).map_err(vault_to_core)?;
        if key.len() != PME_KEY_LEN {
            return Err(CoreError::InternalError {
                detail: format!(
                    "Vault datakey returned {} bytes, expected {PME_KEY_LEN}",
                    key.len()
                ),
            });
        }
        let meta = KeyMetadata {
            s: SCHEME_V1,
            m: self.transit_mount.clone(),
            k: self.transit_key.clone(),
            w: wrapped,
        };
        let key_metadata = serde_json::to_vec(&meta).map_err(|e| CoreError::InternalError {
            detail: format!("serializing PME key_metadata: {e}"),
        })?;
        Ok((key, key_metadata))
    }
}

/// One cached unwrapped DEK plus its insertion time (for TTL eviction). The key
/// bytes are held in a `zeroize`-backed buffer (wiped on eviction / drop).
struct CachedDek {
    key: Zeroizing<Vec<u8>>,
    inserted: Instant,
}

/// The cached, Vault-backed key retriever for the query read path.
///
/// Parses each file's `key_metadata`, validates `s`/`m`/`k`, and serves the
/// unwrapped DEK from a `zeroize`-backed cache keyed by the wrapped DEK `w`, only
/// calling `transit/decrypt` on a miss (single-flighted). Cloneable handle over
/// shared state so the same cache backs every scan.
pub struct CachedKeyRetriever {
    vault: VaultClient,
    transit_mount: String,
    transit_key: String,
    ttl: Duration,
    /// `w` -> cached unwrapped DEK. A `std::sync::Mutex` is held only for the short
    /// cache read/insert (never across the Vault `.await`, which runs under
    /// `block_on` on a blocking thread).
    cache: Mutex<HashMap<String, CachedDek>>,
    /// Per-wrapped-key single-flight guards: concurrent unwraps of the same DEK coalesce to
    /// one Transit call, while unwraps of different DEKs proceed independently. One
    /// process-wide lock would serialise every cold-cache read during a Vault outage behind
    /// a Transit call that is timing out, each holding a blocking-pool thread for the full
    /// timeout.
    inflight: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl CachedKeyRetriever {
    /// Build a retriever from a connected Vault client + the configured transit
    /// mount/key, with the default cache TTL.
    #[must_use]
    pub fn new(vault: VaultClient, transit_mount: String, transit_key: String) -> Self {
        Self {
            vault,
            transit_mount,
            transit_key,
            ttl: DEK_CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Flush every cached DEK (on `SIGHUP` / restart), bounding revocation latency
    /// to the signal instead of waiting out the TTL. The `Zeroizing` buffers are
    /// wiped as they drop.
    pub fn flush(&self) {
        let mut cache = self.lock_cache();
        let n = cache.len();
        cache.clear();
        drop(cache);
        // Drop the single-flight guards nobody is holding. `inflight` is keyed by the
        // wrapped DEK and a DEK is minted per parquet file, so without this the map grows
        // with every distinct file the process has read and never shrinks.
        //
        // `strong_count > 1` means some caller cloned this guard out of the map and may be
        // about to lock it. Removing it there would hand the next caller a different mutex
        // and un-single-flight two concurrent unwraps of the same DEK, which matters during
        // a Vault outage. The count is read under the same lock `inflight_lock` clones
        // under, so a new clone must wait for this guard.
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = inflight.len();
        inflight.retain(|_, guard| Arc::strong_count(guard) > 1);
        debug!(
            flushed = n,
            guards_dropped = before - inflight.len(),
            "PME DEK cache flushed"
        );
    }

    /// Look up a live (non-expired) cached DEK for `w`, sweeping every expired entry on
    /// the way.
    ///
    /// The sweep runs on every lookup, hits included, which makes `DEK_CACHE_TTL` a
    /// residency bound and not merely a freshness one. A hot working set never misses, so
    /// sweeping only on a miss would leave a DEK whose file is never read again resident and
    /// un-zeroized behind it. Revocation is unaffected either way: every read re-checks the
    /// TTL before using an entry.
    fn cached(&self, w: &str) -> Option<Zeroizing<Vec<u8>>> {
        let mut cache = self.lock_cache();
        Self::sweep_expired(&mut cache, self.ttl);
        cache.get(w).map(|entry| entry.key.clone())
    }

    /// Drop (zeroizing) every entry whose TTL has run out. The one sweep, called from the
    /// lookup and the insert path alike.
    fn sweep_expired(cache: &mut HashMap<String, CachedDek>, ttl: Duration) {
        cache.retain(|_, entry| entry.inserted.elapsed() < ttl);
    }

    /// Insert a freshly-unwrapped DEK for `w`, sweeping expired entries first. A store
    /// follows a miss whose lookup already swept; sweeping here too holds the residency
    /// bound for any caller, not only that sequence.
    fn store(&self, w: String, key: Zeroizing<Vec<u8>>) {
        let mut cache = self.lock_cache();
        Self::sweep_expired(&mut cache, self.ttl);
        cache.insert(
            w,
            CachedDek {
                key,
                inserted: Instant::now(),
            },
        );
    }

    /// Lock the cache, recovering from a poisoned mutex. A panic while holding it cannot
    /// leave key material in a half-state, since the map is simply a cache.
    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedDek>> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Unwrap a DEK for `meta`: validate it, serve from cache, else single-flight a
    /// `transit/decrypt` and cache it.
    fn unwrap_dek(&self, meta: &KeyMetadata) -> Result<Zeroizing<Vec<u8>>, ParquetError> {
        // Scheme + key-binding validation: a clear mismatch, not an opaque decrypt
        // failure, so a reconfigured transit_key/mount is diagnosable.
        if meta.s != SCHEME_V1 {
            return Err(ParquetError::General(format!(
                "PME key_metadata scheme {} is not supported (expected {SCHEME_V1})",
                meta.s
            )));
        }
        if meta.m != self.transit_mount || meta.k != self.transit_key {
            return Err(ParquetError::General(format!(
                "PME key-mismatch: file was wrapped with transit mount/key {:?}/{:?}, but the node is configured for {:?}/{:?}",
                meta.m, meta.k, self.transit_mount, self.transit_key
            )));
        }

        // Cache hit: no Vault call (steady-state reads never touch Vault).
        if let Some(key) = self.cached(&meta.w) {
            return Ok(key);
        }

        // Miss: single-flight the unwrap under the in-flight lock so concurrent
        // reads of the same file coalesce to one Transit call.
        let per_key = self.inflight_lock(&meta.w);
        let _guard = per_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-check under the in-flight lock: another caller may have filled it.
        if let Some(key) = self.cached(&meta.w) {
            return Ok(key);
        }
        let plaintext_b64 = block_on_vault(self.vault.transit_decrypt(&self.transit_key, &meta.w))
            .map_err(core_to_parquet)?;
        let key = VaultClient::decode_b64(&plaintext_b64)
            .map_err(|e| ParquetError::General(format!("decoding unwrapped DEK: {e}")))?;
        if key.len() != PME_KEY_LEN {
            return Err(ParquetError::General(format!(
                "unwrapped DEK is {} bytes, expected {PME_KEY_LEN}",
                key.len()
            )));
        }
        self.store(meta.w.clone(), key.clone());
        Ok(key)
    }

    /// The per-wrapped-key single-flight guard: returns, creating on first use, the
    /// `Arc<Mutex<()>>` that coalesces concurrent unwraps of the *same* DEK `wrapped`, so
    /// unwraps of different DEKs never queue behind each other.
    fn inflight_lock(&self, wrapped: &str) -> Arc<Mutex<()>> {
        let mut map = self
            .inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(map.entry(wrapped.to_owned()).or_default())
    }
}

impl KeyRetriever for CachedKeyRetriever {
    fn retrieve_key(&self, key_metadata: &[u8]) -> Result<Vec<u8>, ParquetError> {
        let meta: KeyMetadata = serde_json::from_slice(key_metadata)
            .map_err(|e| ParquetError::General(format!("parsing PME key_metadata: {e}")))?;
        let key = self.unwrap_dek(&meta)?;
        // The parquet API takes the key by value. The returned Vec is short-lived, handed
        // straight to the AES-GCM block decryptor; the long-lived copy in the cache stays
        // zeroize-backed.
        Ok(key.to_vec())
    }
}

/// The at-rest sentinel's file name, under `[service].data_dir`.
///
/// Dot-prefixed so it can never collide with a dataset directory, and kept beside the data
/// it vouches for: a restore that brings back the data brings back the sentinel, so the pair
/// cannot disagree.
pub const SENTINEL_FILE: &str = ".pme-sentinel.json";

/// The outcome of the startup at-rest key check.
///
/// Not `#[non_exhaustive]`, unlike [`VaultError`]: that would force callers into a `_` arm,
/// and a future verdict falling into a catch-all is the wrong failure mode for a signal that
/// decides whether the node serves. Exhaustive matching makes the compiler demand a
/// decision. The crate is `publish = false`, so there is no external consumer to break.
#[derive(Debug)]
pub enum SentinelVerdict {
    /// The configured master key unwrapped the sentinel: at-rest data is readable.
    Verified,
    /// No sentinel existed (a fresh store) and one was created. Not a fault.
    Created,
    /// The master key could not unwrap the sentinel: it was replaced, or the secrets
    /// backend was reset. Existing PME data at rest is undecryptable.
    Mismatch(String),
    /// The check could not be completed because the backend was unreachable (Vault down,
    /// lapsed token). It says nothing about the key and is already covered by `vault_ok`, so
    /// it is never latched as a mismatch nor taken as a readiness failure of its own.
    Indeterminate(String),
    /// The check could not be completed because of a local fault: the sentinel could not be
    /// read, did not parse, or names a scheme this build does not know.
    ///
    /// Separate from [`Self::Indeterminate`], whose leniency ("a network blip must not take a
    /// healthy node out of rotation") does not apply here. A truncated or unparseable
    /// sentinel is a local fact that does not heal on its own, and collapsing the two would
    /// report `at_rest: "ok"` for a check that never completed, hiding the incident the check
    /// exists to catch (a restored data volume whose Transit key was replaced). Reported as
    /// `unavailable`, never as a mismatch.
    ///
    /// The next step is `pme reseal`, which re-proves the store first. The exception is an
    /// unknown scheme: that sentinel was written by a newer binary, so `reseal` refuses
    /// rather than overwrite state this build cannot interpret and downgrade the at-rest key
    /// binding to `SCHEME_V1`. Run the newer binary instead.
    Unverifiable(String),
}

impl SentinelVerdict {
    /// A local fault: an I/O, encoding or format failure on this node's own data volume.
    /// Always [`Self::Unverifiable`].
    ///
    /// Paired with [`Self::backend`] so a call site decides only where the fault came from,
    /// instead of re-deriving which verdict latches. Classifying a local write failure as
    /// [`Self::Indeterminate`] renders `at_rest: "ok"` for a check that never completed.
    fn local(context: &str, err: &dyn std::fmt::Display) -> Self {
        Self::Unverifiable(format!("{context}: {err}"))
    }

    /// A backend fault: the secrets backend did not answer. Always [`Self::Indeterminate`],
    /// because it says nothing about the key, `vault_ok` already reports it, and a network
    /// blip must not take an otherwise healthy node out of rotation.
    fn backend(err: &dyn std::fmt::Display) -> Self {
        Self::Indeterminate(err.to_string())
    }
}

/// What a successful [`PmeRuntime::reseal_sentinel`] did, for the operator report and the
/// audit line.
#[derive(Debug)]
pub struct ResealOutcome {
    /// The sentinel that was rewritten.
    pub sentinel: std::path::PathBuf,
    /// The encrypted dataset store that proved the current key can read the existing data,
    /// or `None` when the store holds no encrypted dataset to prove against.
    pub probed_dataset: Option<std::path::PathBuf>,
}

/// The bundled PME runtime stored on `AppState`: the minter (ingest) plus the cached
/// retriever (query), both sharing the connected Vault client. Active only when PME is
/// compiled and a `[vault].transit_key` is configured.
pub struct PmeRuntime {
    minter: Arc<VaultDekMinter>,
    retriever: Arc<CachedKeyRetriever>,
    /// A cheap clone of the connected Vault client, retained for the periodic liveness
    /// probe. The minter and retriever hold their own clones.
    vault: VaultClient,
    /// The configured transit key name, so the liveness probe exercises the transit
    /// capability and not just token liveness.
    transit_key: String,
    /// The configured transit mount, recorded into the at-rest sentinel so it names the same
    /// mount the minter stamps into real files.
    transit_mount: String,
}

impl PmeRuntime {
    /// Build the PME runtime from a connected Vault client and the configured
    /// transit mount + key.
    #[must_use]
    pub fn new(vault: VaultClient, transit_mount: String, transit_key: String) -> Self {
        let mount_for_sentinel = transit_mount.clone();
        Self {
            minter: Arc::new(VaultDekMinter::new(
                vault.clone(),
                transit_mount.clone(),
                transit_key.clone(),
            )),
            retriever: Arc::new(CachedKeyRetriever::new(
                vault.clone(),
                transit_mount,
                transit_key.clone(),
            )),
            vault,
            transit_key,
            transit_mount: mount_for_sentinel,
        }
    }

    /// Probe the Vault transit capability for the periodic readiness check.
    ///
    /// Mints, and immediately discards, a data key: this exercises the `datakey/plaintext`
    /// capability the PME ingest and read paths need. `lookup-self` would not, because it
    /// requires only the default token-lookup capability and so stays green while the transit
    /// mount is denied, leaving `/health/ready` green while every cold-cache encrypted read
    /// degrades. Minting a datakey is stateless and non-destructive, and the returned
    /// plaintext key is wiped on drop.
    ///
    /// # Errors
    ///
    /// Propagates [`VaultError`] from [`VaultClient::transit_datakey`]: transient on an
    /// unreachable server or a lapsed token, and an error whenever the transit capability is
    /// denied.
    pub async fn probe_vault(&self) -> Result<(), VaultError> {
        self.vault
            .transit_datakey(&self.transit_key)
            .await
            .map(|_| ())
    }

    /// The DEK minter handle (as a `DekMinter` trait object for the ingest store).
    #[must_use]
    pub fn minter(&self) -> Arc<dyn DekMinter> {
        self.minter.clone()
    }

    /// The cached key retriever handle (as a `KeyRetriever` trait object for the
    /// query scan).
    #[must_use]
    pub fn retriever(&self) -> Arc<dyn KeyRetriever> {
        self.retriever.clone()
    }

    /// Verify that the configured Transit master key still unwraps a DEK this node
    /// previously wrote, creating the sentinel on first run.
    ///
    /// Complements [`PmeRuntime::probe_vault`], and neither subsumes the other: minting a
    /// datakey proves the transit capability works, which a brand-new key created under the
    /// same name also satisfies. Only unwrapping a *previously wrapped* DEK proves the key is
    /// the one that encrypted the existing store.
    ///
    /// Without this check a replaced key, or a reset secrets backend, is discovered one
    /// dataset at a time as `error`/`scrub-failed`, which reads like data corruption rather
    /// than a key incident. `m`/`k` in each file's `key_metadata` are names, so a recreated
    /// key with the same name passes the retriever's mount/key validation and fails only at
    /// `transit/decrypt`.
    ///
    /// Never returns an error: every failure mode becomes a verdict, because the caller must
    /// distinguish "the key is wrong" (latch, alert) from "I could not tell" (do not latch).
    pub async fn verify_or_create_sentinel(&self, data_dir: &std::path::Path) -> SentinelVerdict {
        let path = data_dir.join(SENTINEL_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => self.verify_sentinel(&bytes).await,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.create_sentinel(&path).await,
            Err(e) => SentinelVerdict::local(&format!("reading {}", path.display()), &e),
        }
    }

    /// Unwrap the stored sentinel and classify the result.
    async fn verify_sentinel(&self, bytes: &[u8]) -> SentinelVerdict {
        let meta: KeyMetadata = match serde_json::from_slice(bytes) {
            Ok(m) => m,
            // A corrupt sentinel says nothing about the key. Reporting a mismatch here
            // would send an operator to Vault over a truncated local file.
            Err(e) => return SentinelVerdict::local("parsing sentinel", &e),
        };
        if meta.s != SCHEME_V1 {
            return SentinelVerdict::Unverifiable(format!("unknown sentinel scheme {}", meta.s));
        }
        if meta.m != self.transit_mount || meta.k != self.transit_key {
            return SentinelVerdict::Mismatch(format!(
                "sentinel was wrapped by {}/{} but this node is configured for {}/{}",
                meta.m, meta.k, self.transit_mount, self.transit_key
            ));
        }
        match self.vault.transit_decrypt(&self.transit_key, &meta.w).await {
            Ok(_) => SentinelVerdict::Verified,
            Err(VaultError::Permanent(e)) => SentinelVerdict::Mismatch(e),
            Err(VaultError::Transient(e)) => SentinelVerdict::backend(&e),
        }
    }

    /// Mint a throwaway DEK and record its wrapped form as the sentinel.
    async fn create_sentinel(&self, path: &std::path::Path) -> SentinelVerdict {
        let wrapped = match self.vault.transit_datakey(&self.transit_key).await {
            // The plaintext half is dropped immediately (it is `Zeroizing`) and only the
            // wrapped form is recorded, so the sentinel file holds no plaintext key
            // material. It does hold a Vault-transit-wrapped data key, which is why it is
            // written owner-only below.
            Ok((_plaintext, wrapped)) => wrapped,
            Err(e) => return SentinelVerdict::backend(&e),
        };
        let meta = KeyMetadata {
            s: SCHEME_V1,
            m: self.transit_mount.clone(),
            k: self.transit_key.clone(),
            w: wrapped,
        };
        let body = match serde_json::to_vec(&meta) {
            Ok(b) => b,
            Err(e) => return SentinelVerdict::local("serializing sentinel", &e),
        };
        // Owner-only: `w` is a Vault-transit-wrapped data key. Wrapped is not plaintext,
        // but ciphertext still has no reason to be world-readable.
        match gdi_node_standalone_core::util::write_durable_atomic_private(path, &body) {
            Ok(()) => SentinelVerdict::Created,
            Err(e) => SentinelVerdict::local("writing sentinel", &e),
        }
    }

    /// Overwrite the at-rest sentinel with one wrapped by the current Transit key: the
    /// documented exit from a latched [`SentinelVerdict::Mismatch`].
    ///
    /// The sentinel is created once, when absent, and lives on the data volume so the key and
    /// the data cannot disagree. It therefore survives the key incident it detects *and the
    /// recovery from it*: after the operator follows `docs/operating.md` §17 (provision a new
    /// Transit key, re-ingest every dataset) or §10 (rotate, re-ingest, raise
    /// `min_decryption_version`), every dataset is decryptable under the new key but the old
    /// sentinel is not, so the node latches `at_rest_ok = false` on every boot and stays out
    /// of rotation with a healthy store. Without this verb the only escape is an undocumented
    /// `rm`.
    ///
    /// It does not re-mint automatically on mismatch. Auto-healing would clear the guard in
    /// the scenario it exists to flag, and an operator who never sees the alarm never learns
    /// their master key was replaced. The reseal instead proves the store is readable under
    /// the current key first, by footer-decrypting a real `PARE` dataset through the same
    /// retriever the query path uses. If that fails it refuses: the mismatch is genuine, and
    /// overwriting the sentinel would destroy the evidence.
    ///
    /// A store with no encrypted dataset yet has nothing to prove against. The reseal is
    /// allowed and says so, because there is no at-rest data a wrong key could be orphaning.
    ///
    /// # Errors
    /// Returns the refusal reason when the store cannot be read under the current key, when
    /// the probe cannot run, or when minting or writing the new sentinel fails.
    pub async fn reseal_sentinel(
        &self,
        data_dir: &std::path::Path,
    ) -> anyhow::Result<ResealOutcome> {
        // A sentinel naming a scheme this build does not know was written by a newer binary,
        // and `create_sentinel` below would overwrite it with `SCHEME_V1` unconditionally,
        // downgrading the at-rest key binding. Refuse instead; the operator's step here is
        // the newer binary. A sentinel that does not parse at all is left to the reseal: it
        // carries no scheme to respect, and rewriting it is the documented recovery.
        let path = data_dir.join(SENTINEL_FILE);
        if let Ok(bytes) = std::fs::read(&path)
            && let Ok(meta) = serde_json::from_slice::<KeyMetadata>(&bytes)
            && meta.s != SCHEME_V1
        {
            anyhow::bail!(
                "refusing to reseal: the sentinel at {} names scheme {} and this build only \
                 knows scheme {SCHEME_V1}, so it was written by a newer node. Resealing would \
                 overwrite state this binary cannot interpret and downgrade the at-rest key \
                 binding. Run the newer binary instead.",
                path.display(),
                meta.s
            );
        }
        let probed = match crate::scrub::first_encrypted_store(data_dir) {
            Some(dir) => {
                let decryptor =
                    gdi_node_standalone_core::parquet_io::DatasetDecryptor::with_retriever(
                        self.retriever(),
                    );
                // Must run on a blocking thread. Unwrapping the file's DEK calls Vault, and
                // `block_on_vault` bridges that with `Handle::block_on`, which panics on a
                // runtime worker thread: the contract stated on `block_on_vault` and pinned
                // by `block_on_vault_on_a_reactor_thread_panics`. `reseal_sentinel` is
                // `async`, so probing inline would run the retriever on a reactor thread,
                // where `probe_dataset_readable`'s `catch_unwind` turns the panic into
                // "malformed file" and this function reports it as a real key mismatch.
                let probe_dir = dir.clone();
                let mount = self.transit_mount.clone();
                let key = self.transit_key.clone();
                tokio::task::spawn_blocking(move || {
                    gdi_node_standalone_core::parquet_io::probe_dataset_readable(
                        &probe_dir, &decryptor,
                    )
                })
                .await
                .map_err(|e| anyhow::anyhow!("the reseal readability probe could not be run: {e}"))?
                .map_err(|e| {
                    anyhow::anyhow!(
                        "refusing to reseal: the configured Transit key {mount}/{key} cannot \
                         read the existing encrypted store (probed {}): {e}. This is a real \
                         key mismatch, not a stale sentinel. Resealing would overwrite the \
                         evidence and leave the store undecryptable. Restore the original \
                         key, or complete the re-ingest in docs/operating.md section 17 \
                         first.",
                        dir.display()
                    )
                })?;
                Some(dir)
            }
            None => None,
        };

        let path = data_dir.join(SENTINEL_FILE);
        match self.create_sentinel(&path).await {
            SentinelVerdict::Created => Ok(ResealOutcome {
                sentinel: path,
                probed_dataset: probed,
            }),
            other => Err(anyhow::anyhow!(
                "could not write a new sentinel at {}: {other:?}",
                path.display()
            )),
        }
    }

    /// Flush the DEK cache (on `SIGHUP` / restart).
    pub fn flush_cache(&self) {
        self.retriever.flush();
    }
}

/// Run a Vault async call to completion from a synchronous context.
///
/// The minter and retriever are invoked only on blocking-pool threads (the ingest worker's
/// `spawn_blocking`, the beacon scan's `spawn_blocking`), which are *not* runtime worker
/// threads, so [`tokio::runtime::Handle::block_on`] runs the future on the existing runtime's
/// reactor without deadlocking it. With no ambient runtime at all, as in a synchronous unit
/// test, a tiny current-thread runtime is built.
fn block_on_vault<T>(
    fut: impl std::future::Future<Output = Result<T, VaultError>>,
) -> Result<T, CoreError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle.block_on(fut).map_err(vault_to_core);
    }
    // No runtime (e.g. a direct synchronous unit test): build a tiny one.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CoreError::InternalError {
            detail: format!("building a runtime for a Vault call: {e}"),
        })?;
    rt.block_on(fut).map_err(vault_to_core)
}

/// Map a [`VaultError`] to a [`CoreError`]: a transient Vault condition becomes a
/// transient core error (retried on the next reconcile on the ingest path); a
/// permanent one becomes an internal error.
fn vault_to_core(e: VaultError) -> CoreError {
    match e {
        VaultError::Transient(msg) => CoreError::Transient {
            detail: format!("vault transient: {msg}"),
        },
        other => CoreError::InternalError {
            detail: format!("vault: {other}"),
        },
    }
}

/// Map a [`CoreError`] from a Vault call into a [`ParquetError`] for the read path, the
/// retriever's error channel. A transient Vault failure on a cold-cache read degrades that
/// dataset with a clear error rather than crashing.
fn core_to_parquet(e: CoreError) -> ParquetError {
    match e {
        CoreError::Transient { detail } => {
            warn!(error = %detail, "PME DEK unwrap failed (Vault transient); degrading this dataset");
            // Carry the shared marker so the core read path (`read_matching_rows`)
            // re-surfaces the transient class instead of misclassifying a Vault outage
            // as corrupt parquet.
            ParquetError::General(format!(
                "{}: {detail}",
                gdi_node_standalone_core::parquet_io::PME_TRANSIENT_MARKER
            ))
        }
        other => ParquetError::General(format!("PME DEK unwrap failed: {other}")),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use super::*;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use gdi_node_standalone_core::config::VaultConfig;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MOUNT: &str = "transit";
    const KEY: &str = "gdi-at-rest";

    /// A `key_metadata` blob with the given wrapped DEK, matching `MOUNT`/`KEY`/scheme.
    fn meta_bytes(wrapped: &str) -> Vec<u8> {
        serde_json::to_vec(&KeyMetadata {
            s: SCHEME_V1,
            m: MOUNT.to_owned(),
            k: KEY.to_owned(),
            w: wrapped.to_owned(),
        })
        .unwrap()
    }

    /// A static-token vault config pointing at `address`.
    fn vault_config(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token: Some("hvs.test".to_owned()),
            transit_mount: MOUNT.to_owned(),
            transit_key: Some(KEY.to_owned()),
            ..VaultConfig::default()
        }
    }

    async fn connected_client(address: &str) -> VaultClient {
        VaultClient::connect(&vault_config(address))
            .await
            .expect("connect static token")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "runtime")]
    async fn block_on_vault_on_a_reactor_thread_panics() {
        // `block_on_vault` bridges via `Handle::block_on`, which panics on a runtime worker
        // thread. The startup store-readability self-test and the ingest/beacon probes
        // therefore call it under `spawn_blocking`, where the bridge is valid. This pins the
        // invariant: a bare on-reactor call panics.
        let _ = block_on_vault(async { Ok::<(), VaultError>(()) });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_hit_avoids_second_vault_call() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([42u8; PME_KEY_LEN]);
        // The decrypt endpoint must be hit exactly once despite two reads.
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = connected_client(&server.uri()).await;
        let retriever = Arc::new(CachedKeyRetriever::new(
            client,
            MOUNT.to_owned(),
            KEY.to_owned(),
        ));
        let meta = meta_bytes("vault:v1:wrapped");

        // Both calls run on blocking threads (as in the real scan path).
        let r1 = retriever.clone();
        let m1 = meta.clone();
        let key1 = tokio::task::spawn_blocking(move || r1.retrieve_key(&m1))
            .await
            .unwrap()
            .expect("first unwrap");
        assert_eq!(key1, vec![42u8; PME_KEY_LEN]);

        let r2 = retriever.clone();
        let m2 = meta.clone();
        let key2 = tokio::task::spawn_blocking(move || r2.retrieve_key(&m2))
            .await
            .unwrap()
            .expect("second unwrap (from cache)");
        assert_eq!(key2, vec![42u8; PME_KEY_LEN]);
        // The `.expect(1)` mount assertion fires on drop: a second Vault call fails it.
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_clears_cache_so_next_read_calls_vault() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        // After a flush the second read must call Vault again -> two calls total.
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .expect(2)
            .mount(&server)
            .await;

        let client = connected_client(&server.uri()).await;
        let retriever = Arc::new(CachedKeyRetriever::new(
            client,
            MOUNT.to_owned(),
            KEY.to_owned(),
        ));
        let meta = meta_bytes("vault:v1:wrapped");

        let r1 = retriever.clone();
        let m1 = meta.clone();
        tokio::task::spawn_blocking(move || r1.retrieve_key(&m1))
            .await
            .unwrap()
            .expect("first unwrap");

        retriever.flush();

        // The single-flight guard the first read created is gone with the cache entry.
        // Asserted here, not at the end: the read below creates a fresh one, and an
        // assertion after it would be testing the wrong instant.
        assert!(
            retriever
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "flush must drop the single-flight guards nobody holds"
        );

        let r2 = retriever.clone();
        let m2 = meta.clone();
        tokio::task::spawn_blocking(move || r2.retrieve_key(&m2))
            .await
            .unwrap()
            .expect("second unwrap after flush");
        // `.expect(2)` confirms the flush forced a fresh Vault call.
    }

    /// An expired DEK must not stay resident just because its file is never read again.
    ///
    /// `cached()` evicts on lookup, which never comes for a one-shot file, so without the
    /// sweep on insert the TTL would be a freshness bound and not a residency one. The
    /// eviction is asserted directly: from a Vault call count, an entry that is gone and one
    /// that is merely stale look identical.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_dek_is_swept_even_though_it_is_never_looked_up_again() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([9u8; PME_KEY_LEN]);
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .mount(&server)
            .await;

        // A TTL short enough to expire between the two reads. Built by hand because the
        // constructor pins the one-hour production TTL.
        let retriever = Arc::new(CachedKeyRetriever {
            vault: connected_client(&server.uri()).await,
            transit_mount: MOUNT.to_owned(),
            transit_key: KEY.to_owned(),
            ttl: Duration::from_millis(20),
            cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
        });

        let read = |r: Arc<CachedKeyRetriever>, w: &str| {
            let meta = meta_bytes(w);
            tokio::task::spawn_blocking(move || r.retrieve_key(&meta))
        };

        read(retriever.clone(), "vault:v1:first")
            .await
            .unwrap()
            .expect("first unwrap");
        assert_eq!(retriever.lock_cache().len(), 1);

        tokio::time::sleep(Duration::from_millis(40)).await;

        // A different wrapped key: the first one is never looked up again, so only the
        // sweep can remove it.
        read(retriever.clone(), "vault:v1:second")
            .await
            .unwrap()
            .expect("second unwrap");

        let cache = retriever.lock_cache();
        assert_eq!(
            cache.len(),
            1,
            "the expired entry must be swept, not accumulated: {:?}",
            cache.keys().collect::<Vec<_>>()
        );
        assert!(
            cache.contains_key("vault:v1:second"),
            "and the survivor is the fresh one: {:?}",
            cache.keys().collect::<Vec<_>>()
        );
    }

    /// The residency bound must hold under a hot working set, which never misses: sweeping
    /// only on a miss leaves a DEK whose file is never read again resident for as long as
    /// every other lookup keeps hitting. Insert `first`; insert `second` while `first` is
    /// still fresh; wait until only `first` has expired; hit `second`. `first` must be gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_dek_is_swept_by_a_hit_on_another_key() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([9u8; PME_KEY_LEN]);
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .mount(&server)
            .await;

        let retriever = Arc::new(CachedKeyRetriever {
            vault: connected_client(&server.uri()).await,
            transit_mount: MOUNT.to_owned(),
            transit_key: KEY.to_owned(),
            // Generous, symmetric margins (400 ms each side of a 1200 ms TTL): this test
            // asserts a wall-clock ordering, and under parallel CPU contention a short sleep
            // can wake hundreds of milliseconds late. `Instant::now` is not injectable here,
            // so the margins stand in for a mock clock.
            ttl: Duration::from_millis(1200),
            cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
        });
        let read = |r: Arc<CachedKeyRetriever>, w: &str| {
            let meta = meta_bytes(w);
            tokio::task::spawn_blocking(move || r.retrieve_key(&meta))
        };

        read(retriever.clone(), "vault:v1:first")
            .await
            .unwrap()
            .expect("first unwrap");
        tokio::time::sleep(Duration::from_millis(800)).await;
        // `first` is ~800 ms old: still fresh (< 1200 ms TTL), so the insert sweep keeps it.
        read(retriever.clone(), "vault:v1:second")
            .await
            .unwrap()
            .expect("second unwrap");
        assert_eq!(retriever.lock_cache().len(), 2, "both fresh");

        tokio::time::sleep(Duration::from_millis(800)).await;
        // `first` is ~1600 ms old (expired, 400 ms past TTL); `second` is ~800 ms old (fresh,
        // 400 ms inside TTL). Only hits on `second` from here: the miss path is never retaken.
        read(retriever.clone(), "vault:v1:second")
            .await
            .unwrap()
            .expect("hit on second");

        let cache = retriever.lock_cache();
        assert_eq!(
            cache.len(),
            1,
            "a hit on another key must sweep the expired entry: {:?}",
            cache.keys().collect::<Vec<_>>()
        );
        assert!(cache.contains_key("vault:v1:second"));
    }

    #[tokio::test]
    async fn wrong_mount_or_key_is_a_clear_mismatch() {
        let server = MockServer::start().await;
        let client = connected_client(&server.uri()).await;
        // The retriever is configured for one key, but the file names a different one.
        let retriever = CachedKeyRetriever::new(client, MOUNT.to_owned(), "other-key".to_owned());
        let meta = meta_bytes("vault:v1:wrapped");
        let err = retriever.retrieve_key(&meta).expect_err("key mismatch");
        let msg = format!("{err}");
        assert!(msg.contains("key-mismatch"), "got {msg}");
        // No Vault decrypt endpoint mounted: a mismatch must fail before any call.
    }

    #[tokio::test]
    async fn unknown_scheme_is_rejected() {
        let server = MockServer::start().await;
        let client = connected_client(&server.uri()).await;
        let retriever = CachedKeyRetriever::new(client, MOUNT.to_owned(), KEY.to_owned());
        let bad = serde_json::to_vec(&json!({ "s": 99, "m": MOUNT, "k": KEY, "w": "vault:v1:x" }))
            .unwrap();
        let err = retriever.retrieve_key(&bad).expect_err("unknown scheme");
        assert!(format!("{err}").contains("scheme"), "got {err}");
    }

    #[tokio::test]
    async fn liveness_probe_fails_when_transit_is_denied_even_if_the_token_is_valid() {
        // The liveness probe must exercise the transit capability, not just lookup-self. A
        // token that can lookup-self but is denied transit must fail the probe, so
        // `/health/ready` degrades instead of staying green while every cold-cache encrypted
        // read fails.
        let server = MockServer::start().await;
        // lookup-self is allowed (the token itself is valid) ...
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
            .mount(&server)
            .await;
        // ... but the transit datakey capability is denied.
        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        assert!(
            pme.probe_vault().await.is_err(),
            "a transit-denied (but token-valid) node must fail the liveness probe"
        );
    }

    /// Mount the datakey route (the sentinel's creation path) on `server`.
    async fn mount_datakey(server: &MockServer, dek_b64: &str) {
        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "data": { "plaintext": dek_b64, "ciphertext": "vault:v1:sentinel" } }),
            ))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn sentinel_is_created_when_absent_then_verifies_on_the_next_boot() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );

        // First boot: no sentinel yet, so one is created from a fresh mint.
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Created,
            "an absent sentinel must be created, not treated as a fault — otherwise every \
             pre-existing store would alarm on upgrade"
        );
        assert!(dir.path().join(".pme-sentinel.json").is_file());

        // Second boot: the same key still unwraps it.
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Verified
        );
    }

    #[tokio::test]
    async fn a_replaced_master_key_is_a_mismatch_not_a_transient() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;
        // A key recreated under the same name cannot decrypt the old ciphertext. Vault
        // answers 400, which the client classifies Permanent. This is the case `m`/`k`
        // validation cannot catch, because those are names and they still match.
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Created
        );
        match pme.verify_or_create_sentinel(dir.path()).await {
            SentinelVerdict::Mismatch(_) => {}
            other => panic!("a replaced master key must be a Mismatch, got {other:?}"),
        }
    }

    /// The documented recovery walk (operating.md §17 / §10), end to end.
    ///
    /// `pme reseal` is what makes the walk terminate. The sentinel is written only when
    /// absent and lives on the data volume, so it survives both the incident and the
    /// recovery: without an explicit reseal, a node whose store has been fully re-ingested
    /// under a new key latches `at_rest_ok = false` on every boot.
    #[tokio::test]
    async fn reseal_clears_a_latched_mismatch_and_the_next_boot_verifies() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;
        // The first unwrap fails 400 (the sentinel was wrapped by the key that is now gone);
        // every later unwrap succeeds (the store has been re-ingested under the new key).
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(400))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );

        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Created
        );
        // The incident: the node latches and refuses to serve.
        match pme.verify_or_create_sentinel(dir.path()).await {
            SentinelVerdict::Mismatch(_) => {}
            other => {
                panic!("expected the latched Mismatch this verb exists to clear, got {other:?}")
            }
        }

        // The recovery. This store holds no encrypted dataset, so there is nothing to prove
        // the key against and the reseal says so rather than claiming a verification it did
        // not perform.
        let outcome = pme
            .reseal_sentinel(dir.path())
            .await
            .expect("reseal must succeed once the store is readable under the current key");
        assert_eq!(outcome.sentinel, dir.path().join(SENTINEL_FILE));
        assert!(
            outcome.probed_dataset.is_none(),
            "an empty store has no encrypted dataset to probe"
        );

        // The next boot is clean.
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Verified,
            "after the documented recovery the node must reach at_rest_ok = true"
        );
    }

    /// The reseal must not be usable to silence a real mismatch: if the current key cannot
    /// read the existing store, overwriting the sentinel would destroy the only evidence and
    /// leave a genuinely undecryptable store reporting healthy.
    #[tokio::test]
    async fn reseal_refuses_when_the_current_key_cannot_read_the_store() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": dek_b64 } })),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        // A PME store the current key demonstrably cannot open: the magic says `PARE`, so it
        // is selected as the proof artifact, but the footer will not decrypt.
        let ds = dir.path().join("GDI-EE-UTARTU-20260409143052837");
        std::fs::create_dir_all(&ds).unwrap();
        std::fs::write(
            ds.join("allele-freq.chr1.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            b"PAREnot-a-real-encrypted-parquet",
        )
        .unwrap();

        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Created
        );
        let before = std::fs::read(dir.path().join(SENTINEL_FILE)).unwrap();

        let err = pme
            .reseal_sentinel(dir.path())
            .await
            .expect_err("an unreadable store must abort the reseal");
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to reseal") && msg.contains("GDI-EE-UTARTU-20260409143052837"),
            "the refusal must name what it could not read: {msg}"
        );
        assert_eq!(
            std::fs::read(dir.path().join(SENTINEL_FILE)).unwrap(),
            before,
            "a refused reseal must leave the existing sentinel untouched"
        );
    }

    /// A sentinel from a newer build must survive an older build's `pme reseal`.
    ///
    /// `create_sentinel` writes `SCHEME_V1` unconditionally, so without this guard an older
    /// binary would overwrite a scheme it had just reported as unknown, downgrading the
    /// at-rest key binding.
    #[tokio::test]
    async fn reseal_refuses_to_overwrite_a_sentinel_from_a_newer_scheme() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([9u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SENTINEL_FILE);
        let future = serde_json::to_vec(&KeyMetadata {
            s: SCHEME_V1 + 1,
            m: MOUNT.to_owned(),
            k: KEY.to_owned(),
            w: "vault:v1:written-by-a-newer-node".to_owned(),
        })
        .unwrap();
        std::fs::write(&path, &future).unwrap();

        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        // The verdict that sends an operator to `reseal` in the first place.
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Unverifiable(d) if d.contains("unknown sentinel scheme")
        );

        let err = pme
            .reseal_sentinel(dir.path())
            .await
            .expect_err("an older build must not reseal over a newer scheme");
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to reseal") && msg.contains("newer"),
            "the refusal must say the sentinel is from a newer node: {msg}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            future,
            "a refused reseal must leave the newer sentinel byte-identical"
        );
    }

    /// A local write failure must not report `at_rest: "ok"`.
    ///
    /// `Indeterminate` is backend-only and non-latching, so `main`'s `Indeterminate` arm calls
    /// `set_at_rest(AtRestHealth::Ok)`. Classifying `create_sentinel`'s write and serialize
    /// failures there would make `/health/ready` report `at_rest: "ok"` for a check that never
    /// completed.
    #[tokio::test]
    async fn a_sentinel_that_cannot_be_written_is_unverifiable_not_indeterminate() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([11u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;

        // Reach the write arm specifically. The data dir must not exist: reading the
        // sentinel then fails with NotFound, which routes to `create_sentinel`, and the
        // durable write fails because it cannot create its temp file in a missing parent. A
        // chmod-based setup is a no-op under uid 0, and an unwritable path lands on the read
        // arm, which reports `Unverifiable` for its own reasons and discriminates nothing.
        let base = tempfile::tempdir().unwrap();
        let missing = base.path().join("data-volume-not-mounted");
        assert!(!missing.exists(), "the arm under test needs a missing dir");

        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        let verdict = pme.verify_or_create_sentinel(&missing).await;
        std::assert_matches!(&verdict, SentinelVerdict::Unverifiable(d) if d.contains("writing sentinel"),
            "a local write failure is a local fault, and `Indeterminate` would render \
             at_rest \"ok\" for a check that never completed; got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_vault_is_indeterminate_not_a_mismatch() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([7u8; PME_KEY_LEN]);
        mount_datakey(&server, &dek_b64).await;
        // 503 => Transient. Latching a mismatch on a network blip would take a healthy node
        // out of rotation for the wrong reason, and the latch needs a restart to clear.
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        std::assert_matches!(
            pme.verify_or_create_sentinel(dir.path()).await,
            SentinelVerdict::Created
        );
        match pme.verify_or_create_sentinel(dir.path()).await {
            SentinelVerdict::Indeterminate(_) => {}
            other => panic!("a transient fault must not latch a mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn liveness_probe_ok_when_transit_datakey_succeeds() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([9u8; PME_KEY_LEN]);
        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "data": { "plaintext": dek_b64, "ciphertext": "vault:v1:probe" } }),
            ))
            .mount(&server)
            .await;
        let pme = PmeRuntime::new(
            connected_client(&server.uri()).await,
            MOUNT.to_owned(),
            KEY.to_owned(),
        );
        assert!(
            pme.probe_vault().await.is_ok(),
            "a healthy transit datakey must pass the liveness probe"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn minter_builds_self_describing_key_metadata() {
        let server = MockServer::start().await;
        let dek_b64 = BASE64.encode([3u8; PME_KEY_LEN]);
        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "plaintext": dek_b64, "ciphertext": "vault:v1:minted" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = connected_client(&server.uri()).await;
        let minter = VaultDekMinter::new(client, MOUNT.to_owned(), KEY.to_owned());
        let (key, meta_raw) = tokio::task::spawn_blocking(move || minter.mint())
            .await
            .unwrap()
            .expect("mint");
        assert_eq!(&key[..], &[3u8; PME_KEY_LEN]);
        let meta: KeyMetadata = serde_json::from_slice(&meta_raw).unwrap();
        assert_eq!(meta.s, SCHEME_V1);
        assert_eq!(meta.m, MOUNT);
        assert_eq!(meta.k, KEY);
        assert_eq!(meta.w, "vault:v1:minted");

        // Wire key set: `CachedKeyRetriever::retrieve` deserializes the persisted
        // `key_metadata`, and serde matches by field name, so a renamed, added or removed key
        // breaks decrypt of already-stored parquet. Field order is not pinned: serde reads by
        // name, and the per-field asserts above already cover `s`/`m`/`k`/`w`.
        let meta_json: serde_json::Value = serde_json::from_slice(&meta_raw).unwrap();
        let keys: std::collections::BTreeSet<&str> = meta_json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["k", "m", "s", "w"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "key_metadata wire keys changed — the at-rest reader \
             (CachedKeyRetriever::retrieve) deserializes these exact keys by name; a \
             rename/add/removal breaks decrypt of stored data. Got: {meta_json}"
        );
    }

    #[derive(Clone)]
    struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Capture JSON `tracing` output emitted on this thread while `f` runs. The `audit.rs`
    /// idiom, replicated because that capture harness is module-private.
    fn capture<R>(f: impl FnOnce() -> R) -> (String, R) {
        use tracing_subscriber::layer::SubscriberExt as _;
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let w = LogBuf(std::sync::Arc::clone(&buf));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || w.clone()),
        );
        let r = tracing::subscriber::with_default(subscriber, f);
        let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        (logs, r)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dek_unwrap_failure_logs_no_secret() {
        // A transit decrypt 503 fires the DEK-unwrap warn; it must carry only a
        // transient-category string — never the Vault token (nor DEK bytes).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let client = connected_client(&server.uri()).await; // token "hvs.test"
        let retriever = Arc::new(CachedKeyRetriever::new(
            client,
            MOUNT.to_owned(),
            KEY.to_owned(),
        ));
        let meta = meta_bytes("vault:v1:SENTINELDEK");
        // Capture on the same blocking thread the warn is emitted on.
        let (logs, res) =
            tokio::task::spawn_blocking(move || capture(|| retriever.retrieve_key(&meta)))
                .await
                .unwrap();
        assert!(res.is_err(), "a transit decrypt 503 must fail the unwrap");
        assert!(
            !logs.contains("hvs.test"),
            "the Vault token must not be logged: {logs}"
        );
    }
}
