//! Listing the node's accepted catalog names: online from the node's public FDP root
//! (`{service_url}/fairdp`), offline from the profile's `catalogs` allow-list.
//!
//! The FDP root lists every configured catalog as a dereferenceable `dcat:Catalog` IRI at
//! `{base_url}/fairdp/catalog/{name}` under `ldp:contains` / `fdp-o:metadataCatalog`. The
//! catalog names are extracted as the slug after `/fairdp/catalog/` in the Turtle or
//! JSON-LD body, rather than by pulling in a full RDF parser. That slug set is the
//! accepted-catalog set the tool validates `metadata.catalog` against, and keying on the
//! IRI shape survives Turtle whitespace and prefix variation.
//!
//! Each routine is a CLI-independent library function; `cmd_catalogs` is the wrapper.

use std::collections::BTreeSet;
use std::time::Duration;

use gdi_node_standalone_core::id::is_valid_dataset_id;

use crate::ToolError;

/// Timeout for FDP fetches.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The catalog-IRI path segment the names follow.
const CATALOG_PATH: &str = "/fairdp/catalog/";

/// Build the shared [`FETCH_TIMEOUT`]-bounded HTTP client for FDP fetches.
///
/// The per-request `Accept: text/turtle` header and response/status handling stay
/// at the call sites, whose error messages are endpoint-specific (FDP root vs
/// dataset vs per-catalog crawl).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the client cannot be built.
pub(crate) fn fdp_client() -> Result<reqwest::Client, ToolError> {
    gdi_node_standalone_core::tls::https_client_builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| ToolError::user(format!("cannot build HTTP client: {e}")))
}

/// Maximum FDP-root response body. The root lists catalog IRIs (tens at most), so 16 MiB
/// is far above any real value and bounds a misbehaving or hostile node that streams an
/// unbounded body into the provider host. Mirrors `recipient.rs`'s `MAX_RECIPIENT_BYTES`.
const MAX_FDP_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Error if `total` bytes would exceed [`MAX_FDP_BODY_BYTES`] for `url`.
fn check_fdp_body_len(url: &str, total: usize) -> Result<(), ToolError> {
    if total > MAX_FDP_BODY_BYTES {
        return Err(ToolError::user(format!(
            "{url} body exceeds {MAX_FDP_BODY_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Read an HTTP response body as UTF-8 text with a hard [`MAX_FDP_BODY_BYTES`] cap:
/// reject an oversized `Content-Length` up front, then bound the accumulated chunks, so a
/// hostile or MITM'd node cannot force an unbounded allocation into the provider host.
/// Shared by the FDP root fetch, the per-catalog crawl (`cmd_status`), and the `check`
/// dataset fetch (`cmd_check`).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the declared or streamed body exceeds
/// [`MAX_FDP_BODY_BYTES`], a chunk cannot be read, or the body is not UTF-8.
pub(crate) async fn read_capped_body(
    mut resp: reqwest::Response,
    url: &str,
) -> Result<String, ToolError> {
    if let Some(len) = resp.content_length() {
        check_fdp_body_len(url, usize::try_from(len).unwrap_or(usize::MAX))?;
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ToolError::user(format!("cannot read the body of {url}: {e}")))?
    {
        check_fdp_body_len(url, buf.len().saturating_add(chunk.len()))?;
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| ToolError::user(format!("{url} body is not UTF-8: {e}")))
}

/// Fetch the node's FDP root and return its accepted catalog names (sorted, unique).
///
/// Requests `Accept: text/turtle` (the harvester's content type); the names are
/// parsed from the catalog IRIs in the returned body. Requires HTTPS for a non-loopback
/// host, as the recipient fetch does, and bounds the body size.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the URL is plaintext http to a non-loopback
/// host, the HTTP client cannot be built, the node is unreachable, the root returns a
/// non-2xx, the body exceeds `MAX_FDP_BODY_BYTES`, or the body cannot be read.
pub async fn fetch_node_catalogs(service_url: &str) -> Result<Vec<String>, ToolError> {
    let url = format!("{}/fairdp", service_url.trim_end_matches('/'));
    // `catalogs --sync` persists the returned allow-list to the operator's config, so an
    // on-path attacker over plaintext http could alter it. Require https for a
    // non-loopback host; loopback development is exempt.
    crate::recipient::require_secure_transport(
        &url,
        "a MITM could serve a forged catalog allow-list that is then persisted to your config.",
    )?;
    let client = fdp_client()?;
    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "text/turtle")
        .send()
        .await
        .map_err(|e| ToolError::user(format!("cannot reach the FDP root {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let msg = format!("FDP root {url} returned {status}");
        return Err(
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                ToolError::auth(msg)
            } else {
                ToolError::user(msg)
            },
        );
    }
    let body = read_capped_body(resp, &url).await?;
    Ok(parse_catalog_names(&body))
}

/// Extract the catalog names from an FDP-root body by scanning for catalog IRIs
/// `…/fairdp/catalog/{name}` and taking the `{name}` slug (sorted, unique).
///
/// Works on either Turtle or JSON-LD: it keys on the stable IRI substring, not on any
/// serialization syntax. A name ends at the first character that cannot appear in a
/// catalog name: `>`, `"`, whitespace, `/`, `#`, `?` or `\`.
#[must_use]
pub fn parse_catalog_names(body: &str) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut rest = body;
    while let Some((_, after)) = rest.split_once(CATALOG_PATH) {
        let end = after
            .find(|c: char| {
                c == '>'
                    || c == '"'
                    || c == '/'
                    || c == '#'
                    || c == '?'
                    || c.is_whitespace()
                    || c == '\\'
            })
            .unwrap_or(after.len());
        let (name, tail) = after.split_at(end);
        // The name terminates at whitespace, `>`, `"` or a path separator, so a
        // non-whitespace control character such as ESC would survive and be printed
        // verbatim to the operator's terminal, letting a hostile or MITM'd node inject
        // ANSI escape sequences. A legitimate catalog name is ASCII-alphanumeric plus
        // `-_.`, so a name carrying any control character is invalid: drop it.
        if !name.is_empty() && !name.chars().any(char::is_control) {
            names.insert(name.to_owned());
        }
        rest = tail;
    }
    names.into_iter().collect()
}

/// Extract dataset ids from an FDP graph body by scanning for
/// `…/fairdp/dataset/{id}` IRIs and keeping the slugs that validate as dataset
/// ids. Sibling of [`parse_catalog_names`] (catalog-IRI slugs); used by the
/// no-S3 `status --all` enumeration crawl.
pub(crate) fn dataset_ids_from_graph(body: &str) -> Vec<String> {
    const DATASET_PATH: &str = "/fairdp/dataset/";
    let mut out = Vec::new();
    let mut rest = body;
    while let Some((_, after)) = rest.split_once(DATASET_PATH) {
        let end = after
            .find(|c: char| c == '>' || c == '"' || c == '/' || c.is_whitespace())
            .unwrap_or(after.len());
        let (slug, tail) = after.split_at(end);
        if is_valid_dataset_id(slug) {
            out.push(slug.to_owned());
        }
        rest = tail;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_ids_extracted_from_turtle() {
        let ttl = r"<https://n/fairdp/catalog/c> dcat:dataset
            <https://n/fairdp/dataset/GDI-EE-UTARTU-20260409143052837> ,
            <https://n/fairdp/dataset/GDI-EE-UTARTU-20260409143052838> .";
        let ids = dataset_ids_from_graph(ttl);
        assert_eq!(
            ids,
            vec![
                "GDI-EE-UTARTU-20260409143052837",
                "GDI-EE-UTARTU-20260409143052838"
            ]
        );
    }

    #[test]
    fn dataset_ids_ignore_non_conforming_slugs() {
        let ttl = "<https://n/fairdp/dataset/not-a-valid-id> .";
        assert!(dataset_ids_from_graph(ttl).is_empty());
    }

    #[test]
    fn parses_two_catalogs_from_turtle_root() {
        let ttl = r"
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .

<https://node.example/fairdp>
  a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data>,
               <https://node.example/fairdp/catalog/gdi-aggregated> ;
  fdp-o:metadataCatalog <https://node.example/fairdp/catalog/synthetic-data>,
                        <https://node.example/fairdp/catalog/gdi-aggregated> .
";
        let names = parse_catalog_names(ttl);
        assert_eq!(names, vec!["gdi-aggregated", "synthetic-data"]);
    }

    #[test]
    fn drops_catalog_names_with_control_chars() {
        // A hostile or MITM'd FDP root embedding an ANSI escape in a catalog-IRI slug
        // must not surface a name that injects terminal escapes when `catalogs` prints
        // it. The clean sibling is still returned.
        let ttl = "<https://node.example/fairdp/catalog/evil\u{1b}[2Jboom> \
                    <https://node.example/fairdp/catalog/good-one>";
        let names = parse_catalog_names(ttl);
        assert_eq!(names, vec!["good-one"]);
    }

    #[test]
    fn parses_from_json_ld() {
        let jsonld = r#"{"@id":"https://n/fairdp","ldp:contains":[
            {"@id":"https://n/fairdp/catalog/cat-a"},
            {"@id":"https://n/fairdp/catalog/cat-b"}]}"#;
        let names = parse_catalog_names(jsonld);
        assert_eq!(names, vec!["cat-a", "cat-b"]);
    }

    #[test]
    fn dedups_and_ignores_dataset_iris() {
        // A dataset IRI must not be mistaken for a catalog name.
        let ttl = r"
<https://n/fairdp/catalog/only-one> a dcat:Catalog ;
  dcat:dataset <https://n/fairdp/dataset/GDI-EE-UTARTU-1> ;
  ldp:contains <https://n/fairdp/catalog/only-one> .
";
        let names = parse_catalog_names(ttl);
        assert_eq!(names, vec!["only-one"]);
    }

    #[test]
    fn empty_body_yields_no_catalogs() {
        assert!(parse_catalog_names("").is_empty());
        assert!(parse_catalog_names("no catalogs here").is_empty());
    }

    #[test]
    fn fdp_body_cap_rejects_oversized() {
        // The streaming read is bounded so a hostile or MITM'd node cannot force an
        // unbounded allocation. At or under the cap is accepted; one byte over is not.
        assert!(check_fdp_body_len("https://n/fairdp", MAX_FDP_BODY_BYTES).is_ok());
        assert!(check_fdp_body_len("https://n/fairdp", MAX_FDP_BODY_BYTES + 1).is_err());
    }
}
