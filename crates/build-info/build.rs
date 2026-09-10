//! Build script: inject the git commit SHA and a build epoch as compile-time env
//! vars for the `--version` / `GET /version` / `gdi_build_info` provenance shared by
//! both gdi-node-standalone binaries.
//!
//! `GITHUB_SHA` and `SOURCE_DATE_EPOCH` win when set, else the values come from `git`,
//! else `"unknown"` (as inside the container image, whose `.dockerignore` excludes
//! `.git`). Both git-derived values are commit-stable, so a build from a given commit
//! stays deterministic.
//!
//! The resolution ladder lives in `src/provenance.rs` and is included here rather than
//! duplicated, so the code that stamps the binary is the code the tests exercise. It uses
//! only environment variables and `git` via `std::process`, since a build script cannot
//! depend on the crate it builds.

include!("src/provenance.rs");

fn main() {
    // Cargo runs a build script with the package root as its working directory, and
    // `git` walks up from there to find the repository.
    let dir = Path::new(".");

    let env_sha = std::env::var("GITHUB_SHA").ok();
    println!(
        "cargo::rustc-env=GDI_GIT_SHA={}",
        resolve_sha(dir, env_sha.as_deref())
    );
    println!("cargo::rerun-if-env-changed=GITHUB_SHA");

    let env_epoch = std::env::var("SOURCE_DATE_EPOCH").ok();
    println!(
        "cargo::rustc-env=GDI_BUILD_EPOCH={}",
        resolve_epoch(dir, env_epoch.as_deref())
    );
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // Re-run when the commit moves, so the stamp stays current on local builds.
    for path in watch_paths(dir) {
        println!("cargo::rerun-if-changed={path}");
    }
}
