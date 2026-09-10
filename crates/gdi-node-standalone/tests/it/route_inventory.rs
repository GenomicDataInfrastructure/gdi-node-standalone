//! The route inventory every route-shaped guard reads, derived from `app.rs` itself.
//!
//! axum exposes no way to enumerate a `Router`'s paths, so a guard that wants to say something
//! about every route has to get the list from somewhere. Hand-written lists drift: a route
//! added later joins only the guards someone remembered to update. This module is the single
//! implementation, and it also records which routes sit behind which `[section].flag`, so a
//! new gated route joins every guard by being written in `app.rs` and nowhere else.
//!
//! The parse is textual. It reads the same source the router is built from, which is the only
//! representation that exists at test time. Every function here is paired with a vacuity
//! assertion at its call site (`assert!(… >= n)`), because a parser that matched nothing would
//! turn every guard downstream into a test that examines an empty list.

/// The router source, embedded at compile time (this file lives in `tests/it/`).
const APP_RS: &str = include_str!("../../src/app.rs");

/// One `if cfg.<flag> { … }` block in the router: the flag's path as written, and every
/// route literal mounted inside it.
pub(crate) struct GatedRoutes {
    /// The config expression the block tests, e.g. `cfg.service.expose_dataset_list`.
    pub(crate) gate: String,
    /// The route path literals mounted while that expression is true.
    pub(crate) paths: Vec<String>,
}

/// Strip `//` line comments so brace counting cannot be thrown by a comment.
///
/// Safe for this input: a route path literal never contains `//`, and the router source
/// carries no string containing `//` on a line whose braces matter.
fn without_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| l.split_once("//").map_or(l, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The first double-quoted string literal in `s` (route paths carry no escapes).
fn first_string_literal(s: &str) -> Option<String> {
    let after = &s[s.find('"')? + 1..];
    let end = after.find('"')?;
    Some(after[..end].to_owned())
}

/// Every `.route(` path literal in `src`, in source order.
fn route_literals_in(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, _) in src.match_indices(".route(") {
        // Only a literal first argument is a route path. `.route(SOME_CONST, …)` yields
        // nothing here rather than letting `first_string_literal` steal the next quoted string
        // later in the source. `trim_start` skips the whitespace and newlines of a
        // multi-line-formatted `.route(` before the literal.
        let arg = src[idx + ".route(".len()..].trim_start();
        if !arg.starts_with('"') {
            continue;
        }
        if let Some(path) = first_string_literal(arg) {
            out.push(path);
        }
    }
    out
}

/// Cut the trailing `#[cfg(test)]` module, so a `.route(...)` declared in a unit test is not
/// mistaken for a served route.
fn production_source(src: &str) -> &str {
    src.split("\n#[cfg(test)]").next().unwrap_or(src)
}

/// Every route path literal the router source declares (production routes only).
///
/// This is the list `api_doc_routes` checks against `docs/api.md`; `SOURCES` there adds
/// `metrics.rs`, which declares `/metrics` outside `app.rs`.
#[must_use]
pub(crate) fn all_route_literals(sources: &[&str]) -> Vec<String> {
    sources
        .iter()
        // Strip `//` comments first, as `flag_gated_routes` does. Without this a
        // `.route("/x", …)` written inside a comment would parse as a served route and be
        // demanded of `docs/api.md`.
        .flat_map(|src| route_literals_in(&without_line_comments(production_source(src))))
        .collect()
}

/// Every `if cfg.… { … }` block in the router source, with the routes it mounts.
///
/// These are the opt-in surfaces: a route inside such a block is present only when an operator
/// turned its flag on, which is the property the public-plane and flag-off guards are about.
/// Blocks that mount no route, such as the layer and CORS decisions, are omitted.
#[must_use]
pub(crate) fn flag_gated_routes() -> Vec<GatedRoutes> {
    let src = without_line_comments(production_source(APP_RS));
    let bytes = src.as_bytes();
    let mut out = Vec::new();

    for (idx, _) in src.match_indices("if cfg.") {
        // The gate expression runs from `cfg.` to the block's opening brace.
        let after_if = idx + "if ".len();
        let Some(brace_rel) = src[after_if..].find('{') else {
            continue;
        };
        let gate = src[after_if..after_if + brace_rel].trim().to_owned();
        // Walk braces from the opener to find this block's end.
        let open = after_if + brace_rel;
        let mut depth = 0_i32;
        let mut end = None;
        for (i, b) in bytes.iter().enumerate().skip(open) {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let paths = route_literals_in(&src[open..end]);
        if !paths.is_empty() {
            out.push(GatedRoutes { gate, paths });
        }
    }
    out
}

/// Substitute a concrete, well-formed dataset id for a `{id}` placeholder so a route path can
/// be requested. Braces are not URI characters, so a guard that probed a literal `{id}` would
/// fail in the request builder for an unrelated reason. One definition, so every route-shaped
/// guard concretizes the same way.
#[must_use]
pub(crate) fn concretize(path: &str) -> String {
    path.replace("{id}", "GDI-EE-UTARTU-20260409143052837")
}

/// Every route mounted behind any flag, flattened and deduplicated.
#[must_use]
pub(crate) fn all_flag_gated_paths() -> Vec<String> {
    let mut paths: Vec<String> = flag_gated_routes()
        .into_iter()
        .flat_map(|g| g.paths)
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The routes mounted behind the one flag whose expression contains `needle`.
///
/// Panics when `needle` matches no gate — a renamed flag must break the guard that names it,
/// not silently leave it asserting over an empty list.
#[must_use]
pub(crate) fn paths_gated_on(needle: &str) -> Vec<String> {
    let gated = flag_gated_routes();
    let matched: Vec<&GatedRoutes> = gated.iter().filter(|g| g.gate.contains(needle)).collect();
    assert_eq!(
        matched.len(),
        1,
        "expected exactly one `if cfg.…` route block matching `{needle}`, found {} — the \
         router changed shape and every guard reading this is now asserting the wrong set",
        matched.len()
    );
    matched[0].paths.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parser finds the router's real gated surfaces. The expectations are hard-coded, so
    /// a parse that degrades to nothing fails here rather than greening every guard that reads
    /// it.
    #[test]
    fn the_parser_finds_the_routers_gated_blocks() {
        let gated = flag_gated_routes();
        assert!(
            gated.len() >= 3,
            "expected at least the three opt-in route blocks (dataset list, stats, control), \
             found {}: {:?}",
            gated.len(),
            gated.iter().map(|g| &g.gate).collect::<Vec<_>>()
        );
        let all = all_flag_gated_paths();
        for expected in [
            "/datasets",
            "/datasets/suppressed",
            "/stats/queries",
            "/reload",
            "/reconcile",
            "/log-level",
            "/datasets/{id}/reingest",
        ] {
            assert!(
                all.contains(&expected.to_owned()),
                "the router mounts `{expected}` behind a flag but the parser missed it: {all:?}"
            );
        }
    }

    /// Ungated routes do not appear. `/version` and `/health/live` are always mounted, and a
    /// parser that swept them in would make the public-plane guard demand their absence.
    #[test]
    fn always_mounted_routes_are_not_reported_as_gated() {
        let all = all_flag_gated_paths();
        for always in ["/version", "/catalogs", "/health/live", "/health/ready"] {
            assert!(
                !all.contains(&always.to_owned()),
                "`{always}` is mounted unconditionally but was parsed as flag-gated: {all:?}"
            );
        }
    }

    /// Selecting by flag returns that flag's routes and nothing else.
    #[test]
    fn a_flag_selects_its_own_routes() {
        let mut listing = paths_gated_on("expose_dataset_list");
        listing.sort();
        assert_eq!(listing, ["/datasets", "/datasets/suppressed"]);
        assert_eq!(paths_gated_on("stats").len(), 1);
    }
}
