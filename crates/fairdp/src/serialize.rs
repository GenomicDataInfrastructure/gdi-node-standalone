//! Serialize an [`oxrdf::Graph`] to Turtle (primary) and JSON-LD (secondary,
//! expanded).
//!
//! Both formats render from the same graph, so they cannot drift. Turtle is what the
//! GDI User Portal harvester fetches (`Accept: text/turtle`); JSON-LD is a convenience,
//! produced in expanded `@graph` form (oxjsonld does not compact against a custom
//! context). The registered prefixes abbreviate IRIs for Turtle readability and fold
//! into the JSON-LD `@context`.

use oxjsonld::JsonLdSerializer;
use oxrdf::{Graph, GraphNameRef, QuadRef};
use oxttl::TurtleSerializer;

/// `(prefix, namespace-IRI)` pairs registered on the Turtle and JSON-LD
/// serializers. Turtle uses them for readability; JSON-LD folds them into
/// `@context` (IRI abbreviation, not custom-context compaction).
const PREFIXES: &[(&str, &str)] = &[
    ("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
    ("xsd", "http://www.w3.org/2001/XMLSchema#"),
    ("dcat", "http://www.w3.org/ns/dcat#"),
    ("dct", "http://purl.org/dc/terms/"),
    ("foaf", "http://xmlns.com/foaf/0.1/"),
    ("adms", "http://www.w3.org/ns/adms#"),
    ("skos", "http://www.w3.org/2004/02/skos/core#"),
    ("dcatap", "http://data.europa.eu/r5r/"),
    ("healthdcatap", "http://healthdataportal.eu/ns/health#"),
    ("dpv", "https://w3id.org/dpv#"),
    ("fdp-o", "https://w3id.org/fdp/fdp-o#"),
    ("ldp", "http://www.w3.org/ns/ldp#"),
    ("vcard", "http://www.w3.org/2006/vcard/ns#"),
];

/// Serialize `graph` to Turtle with the node prefixes registered.
///
/// Returns an empty string only on a serialization failure (see Panics). The HTTP layer
/// relies on this: an empty result becomes a `500`, never a silent empty `200`.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_fairdp::serialize_turtle;
/// use oxrdf::{Graph, Literal, NamedNode, Triple};
///
/// let mut graph = Graph::new();
/// graph.insert(&Triple::new(
///     NamedNode::new("https://example.org/d/1").expect("valid IRI"),
///     NamedNode::new("http://purl.org/dc/terms/title").expect("valid IRI"),
///     Literal::new_simple_literal("Example dataset"),
/// ));
///
/// let turtle = serialize_turtle(&graph);
/// // The registered `dct` prefix abbreviates the predicate IRI.
/// assert!(turtle.contains("dct:title"));
/// assert!(turtle.contains("\"Example dataset\""));
/// ```
///
/// # Panics
///
/// Does not panic: the prefix IRIs are crate constants and the in-memory `Vec` writer
/// is infallible, so neither `with_prefix` nor `serialize_triple`/`finish` can error
/// here. Their fallible results are mapped to an empty string rather than unwrapped.
#[must_use]
pub fn serialize_turtle(graph: &Graph) -> String {
    let mut serializer = TurtleSerializer::new();
    for (prefix, iri) in PREFIXES {
        match serializer.with_prefix(*prefix, *iri) {
            Ok(s) => serializer = s,
            Err(_) => return String::new(),
        }
    }
    let mut writer = serializer.for_writer(Vec::new());
    for triple in graph {
        if writer.serialize_triple(triple).is_err() {
            return String::new();
        }
    }
    match writer.finish() {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Serialize `graph` to expanded JSON-LD with the node prefixes folded into
/// `@context`.
///
/// Every triple is emitted in the default graph (`GraphNameRef::DefaultGraph`),
/// matching the single-graph internal representation.
///
/// Returns an empty string only on a serialization failure (see Panics); the HTTP layer
/// renders an empty result as a `500`, never a silent empty `200`.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_fairdp::serialize_jsonld;
/// use oxrdf::{Graph, NamedNode, Triple};
///
/// let mut graph = Graph::new();
/// graph.insert(&Triple::new(
///     NamedNode::new("https://example.org/d/1").expect("valid IRI"),
///     NamedNode::new("http://www.w3.org/1999/02/22-rdf-syntax-ns#type").expect("valid IRI"),
///     NamedNode::new("http://www.w3.org/ns/dcat#Dataset").expect("valid IRI"),
/// ));
///
/// // The expanded JSON-LD carries the subject IRI and the rdf:type object IRI.
/// let jsonld = serialize_jsonld(&graph);
/// assert!(jsonld.contains("https://example.org/d/1"));
/// assert!(jsonld.contains("http://www.w3.org/ns/dcat#Dataset"));
/// ```
///
/// # Panics
///
/// Does not panic, for the same reasons as [`serialize_turtle`].
#[must_use]
pub fn serialize_jsonld(graph: &Graph) -> String {
    let mut serializer = JsonLdSerializer::new();
    for (prefix, iri) in PREFIXES {
        match serializer.with_prefix(*prefix, *iri) {
            Ok(s) => serializer = s,
            Err(_) => return String::new(),
        }
    }
    let mut writer = serializer.for_writer(Vec::new());
    for triple in graph {
        let quad = QuadRef::new(
            triple.subject,
            triple.predicate,
            triple.object,
            GraphNameRef::DefaultGraph,
        );
        if writer.serialize_quad(quad).is_err() {
            return String::new();
        }
    }
    match writer.finish() {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => String::new(),
    }
}
