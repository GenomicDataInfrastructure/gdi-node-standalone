//! `[fairdp.publish]`: configured edits applied to every FAIR-DP record just before it is
//! served, so the node can follow a change in GDI's metadata model without a code change.
//!
//! The edits run in this order: `add` (per record type and, for datasets and
//! distributions, per dataset kind), then `rename_properties`, `replace_values` and
//! `type_values` over the whole record. Every dataset on this node is `aggregated`, so
//! datasets and distributions get both their `all` and their `aggregated` block. Last, every
//! statement no path from the record's subject reaches, which a drop (`[]`) can leave, is
//! removed.
//!
//! [`Publish::compile`] resolves every name once. The node's startup preflight runs it, so
//! an unknown prefix or a malformed IRI stops the node at start instead of failing a
//! request. Applying a compiled [`Publish`] cannot fail.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use gdi_node_standalone_core::config::{AddValue, FairdpPublish, PublishParts};
use gdi_node_standalone_core::error::CoreError;
use oxrdf::{
    BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Term, TermRef, Triple, TripleRef,
};

use crate::serialize::PREFIXES;
use crate::vocab;

/// Properties whose values are always text, even when they look like an IRI or a prefixed
/// name, since a link there would break the record or fail GDI's shapes.
const TEXT_PROPERTIES: &[&str] = &[
    vocab::DCT_TITLE,
    vocab::DCT_DESCRIPTION,
    vocab::DCT_IDENTIFIER,
    vocab::DCAT_KEYWORD,
    vocab::FOAF_NAME,
    vocab::VCARD_FN,
    vocab::CV_EMAIL,
    vocab::SKOS_NOTATION,
    vocab::RDFS_LABEL,
];

/// Substituted by the FDP root's IRI in an `add` value.
const FDP_URL: &str = "$FDP_URL";
/// Substituted by the record's id (the catalog or dataset id) in an `add` value.
const FDP_ID: &str = "$FDP_ID";

/// Stand-ins for `$FDP_URL` / `$FDP_ID` while [`Publish::compile`] classifies an `add`
/// value. Classification depends only on the shape of the substituted text (an `https://`
/// IRI stays one whatever the host), so the real values land in the same class.
const PROBE_FDP_URL: &str = "https://check.invalid/fairdp";
/// See [`PROBE_FDP_URL`].
const PROBE_FDP_ID: &str = "id";

/// A record type `[fairdp.publish.add]` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Record {
    /// The FDP root (`/fairdp`); it has no id, so its block cannot use `$FDP_ID`.
    Fairdp,
    /// A catalog record; `$FDP_ID` is the catalog id.
    Catalog,
    /// A dataset record; `$FDP_ID` is the dataset id.
    Dataset,
    /// A distribution record; `$FDP_ID` is its dataset's id.
    Distribution,
}

impl Record {
    /// The key under `[fairdp.publish.add]`.
    fn key(self) -> &'static str {
        match self {
            Self::Fairdp => "fairdp",
            Self::Catalog => "catalog",
            Self::Dataset => "dataset",
            Self::Distribution => "distribution",
        }
    }
}

/// A `[fairdp.publish]` setting the node cannot apply, naming the setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError(String);

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PublishError {}

/// A compiled `[fairdp.publish]` section.
#[derive(Debug)]
pub struct Publish {
    /// `add`: the statements for each record type, `all` first, then `aggregated`.
    additions: Vec<(Record, Vec<Statement>)>,
    /// `rename_properties`: old property, new properties.
    renames: Vec<(NamedNode, Vec<NamedNode>)>,
    /// `replace_values`: old value, new values.
    replacements: Vec<(NamedNode, Vec<NamedNode>)>,
    /// `type_values`: property, the class its values are also given.
    value_types: Vec<(NamedNode, NamedNode)>,
}

/// The edits of an empty `[fairdp.publish]`: none.
pub(crate) static NO_EDITS: Publish = Publish {
    additions: Vec::new(),
    renames: Vec::new(),
    replacements: Vec::new(),
    value_types: Vec::new(),
};

/// One `property = value` of an `add` block.
#[derive(Debug)]
struct Statement {
    predicate: NamedNode,
    value: Value,
}

/// A compiled `add` value.
#[derive(Debug)]
enum Value {
    /// One IRI or literal.
    Scalar(Scalar),
    /// A table: fills the subject's existing node for the property, or a new node.
    Fill(Vec<Statement>),
    /// A table inside an array: always a new node.
    New(Vec<Statement>),
    /// An array: each item.
    Many(Vec<Value>),
}

/// A compiled scalar; the text may still carry `$FDP_URL` / `$FDP_ID`.
#[derive(Debug)]
enum Scalar {
    Iri(String),
    Literal {
        text: String,
        datatype: Option<&'static str>,
    },
}

/// Where a compiled block is applied, for the `$FDP_*` substitutions.
struct Vars<'a> {
    fdp_url: &'a str,
    fdp_id: Option<&'a str>,
}

impl Publish {
    /// Resolve `[fairdp.publish]`: every property, class and value name to an IRI, every
    /// `add` value to an IRI or a typed literal.
    ///
    /// Names are prefixed names (the node's serializer prefixes, or ones added under
    /// `namespaces`), full IRIs, or `a` for `rdf:type`.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] naming the setting when a name has an unknown prefix or is
    /// neither a prefixed name nor an IRI, when an IRI is malformed, when a class value
    /// (`a`) is not a name, or when the FDP root's block uses `$FDP_ID`.
    pub fn compile(publish: &FairdpPublish) -> Result<Self, PublishError> {
        let names = Names::new(&publish.namespaces)?;
        let mut additions = Vec::new();
        for (record, parts) in [
            (Record::Fairdp, &publish.add.fairdp),
            (Record::Catalog, &publish.add.catalog),
            (Record::Dataset, &publish.add.dataset),
            (Record::Distribution, &publish.add.distribution),
        ] {
            let Some(PublishParts { all, aggregated }) = parts else {
                continue;
            };
            let vars = Vars {
                fdp_url: PROBE_FDP_URL,
                fdp_id: (record != Record::Fairdp).then_some(PROBE_FDP_ID),
            };
            let mut statements = Vec::new();
            for (part, block) in [("all", all), ("aggregated", aggregated)] {
                let setting = format!("fairdp.publish.add.{}.{part}", record.key());
                statements.extend(names.block(&setting, block, &vars)?);
            }
            if !statements.is_empty() {
                additions.push((record, statements));
            }
        }
        let value_types = publish
            .type_values
            .iter()
            .map(|(property, class)| {
                let at = format!("fairdp.publish.type_values.{property}");
                Ok((names.term(&at, property)?, names.term(&at, class)?))
            })
            .collect::<Result<Vec<_>, PublishError>>()?;
        Ok(Self {
            additions,
            renames: names.mapping(
                "fairdp.publish.rename_properties",
                &publish.rename_properties,
            )?,
            replacements: names
                .mapping("fairdp.publish.replace_values", &publish.replace_values)?,
            value_types,
        })
    }

    /// Apply the edits to `graph`, the rendered `record` with subject `subject`. `fdp_url`
    /// and `id` fill `$FDP_URL` and `$FDP_ID`; `id` is `None` for the FDP root.
    pub(crate) fn apply(
        &self,
        graph: &mut Graph,
        record: Record,
        subject: &str,
        fdp_url: &str,
        id: Option<&str>,
    ) {
        let vars = Vars {
            fdp_url,
            fdp_id: id,
        };
        let subject: NamedOrBlankNode = NamedNode::new_unchecked(subject).into();
        for (_, statements) in self.additions.iter().filter(|(r, _)| *r == record) {
            for statement in statements {
                add_value(
                    graph,
                    &subject,
                    &statement.predicate,
                    &statement.value,
                    &vars,
                );
            }
        }

        for (old, new) in &self.renames {
            let found: Vec<(NamedOrBlankNode, Term)> = graph
                .triples_for_predicate(old)
                .map(|t| (t.subject.into_owned(), t.object.into_owned()))
                .collect();
            for (s, o) in found {
                if !new.contains(old) {
                    graph.remove(&Triple::new(s.clone(), old.clone(), o.clone()));
                }
                for predicate in new {
                    graph.insert(&Triple::new(s.clone(), predicate.clone(), o.clone()));
                }
            }
        }

        if !self.replacements.is_empty() {
            let found: Vec<(Triple, &[NamedNode])> = graph
                .iter()
                .filter_map(|t| {
                    let Term::NamedNode(o) = t.object.into_owned() else {
                        return None;
                    };
                    let (_, new) = self.replacements.iter().find(|(old, _)| *old == o)?;
                    Some((t.into_owned(), new.as_slice()))
                })
                .collect();
            for (triple, new) in found {
                graph.remove(&triple);
                for value in new {
                    graph.insert(&Triple::new(
                        triple.subject.clone(),
                        triple.predicate.clone(),
                        value.clone(),
                    ));
                }
            }
        }

        let rdf_type = NamedNode::new_unchecked(vocab::RDF_TYPE);
        for (predicate, class) in &self.value_types {
            let values: Vec<NamedNode> = graph
                .triples_for_predicate(predicate)
                .filter_map(|t| match t.object.into_owned() {
                    Term::NamedNode(o) => Some(o),
                    _ => None,
                })
                .collect();
            for value in values {
                graph.insert(&Triple::new(value, rdf_type.clone(), class.clone()));
            }
        }

        remove_orphans(graph, &subject);
    }
}

/// Removes every statement that no path from the record's `subject` reaches. A drop can cut
/// a node loose, blank or named, and its statements would still be served, just unlinked.
/// Each node is walked once, so this is linear in the record.
fn remove_orphans(graph: &mut Graph, subject: &NamedOrBlankNode) {
    let mut reached = HashSet::from([subject.clone()]);
    let mut stack = vec![subject.clone()];
    while let Some(node) = stack.pop() {
        for triple in graph.triples_for_subject(&node) {
            let object: NamedOrBlankNode = match triple.object {
                TermRef::NamedNode(n) => n.into_owned().into(),
                TermRef::BlankNode(b) => b.into_owned().into(),
                TermRef::Literal(_) => continue,
            };
            if reached.insert(object.clone()) {
                stack.push(object);
            }
        }
    }
    let orphans: Vec<Triple> = graph
        .iter()
        .filter(|t| !reached.contains(&t.subject.into_owned()))
        .map(TripleRef::into_owned)
        .collect();
    for triple in &orphans {
        graph.remove(triple);
    }
}

/// Add `value` for `predicate` beside the subject's existing values.
fn add_value(
    graph: &mut Graph,
    subject: &NamedOrBlankNode,
    predicate: &NamedNode,
    value: &Value,
    vars: &Vars<'_>,
) {
    match value {
        Value::Scalar(scalar) => {
            let object = scalar.term(vars);
            graph.insert(&Triple::new(subject.clone(), predicate.clone(), object));
        }
        Value::Fill(statements) => {
            let existing = graph
                .objects_for_subject_predicate(subject, predicate)
                .find_map(|o| match o.into_owned() {
                    Term::NamedNode(n) => Some(NamedOrBlankNode::from(n)),
                    Term::BlankNode(b) => Some(NamedOrBlankNode::from(b)),
                    Term::Literal(_) => None,
                });
            let node = existing.unwrap_or_else(|| new_node(graph, subject, predicate));
            for statement in statements {
                add_value(graph, &node, &statement.predicate, &statement.value, vars);
            }
        }
        Value::New(statements) => {
            let node = new_node(graph, subject, predicate);
            for statement in statements {
                add_value(graph, &node, &statement.predicate, &statement.value, vars);
            }
        }
        Value::Many(values) => {
            for value in values {
                add_value(graph, subject, predicate, value, vars);
            }
        }
    }
}

/// `subject predicate [ ]`, returning the new blank node.
fn new_node(
    graph: &mut Graph,
    subject: &NamedOrBlankNode,
    predicate: &NamedNode,
) -> NamedOrBlankNode {
    let node = BlankNode::default();
    graph.insert(&Triple::new(
        subject.clone(),
        predicate.clone(),
        node.clone(),
    ));
    node.into()
}

impl Scalar {
    fn term(&self, vars: &Vars<'_>) -> Term {
        match self {
            // Compilation checked the IRI with probe values. The real ones are the node's
            // validated base URL and an id that is already a path segment of the record's
            // own IRI.
            Self::Iri(template) => NamedNode::new_unchecked(substitute(template, vars)).into(),
            Self::Literal { text, datatype } => {
                let text = substitute(text, vars);
                match datatype {
                    Some(datatype) => {
                        Literal::new_typed_literal(text, NamedNode::new_unchecked(*datatype)).into()
                    }
                    None => Literal::new_simple_literal(text).into(),
                }
            }
        }
    }
}

/// Replace `$FDP_URL` and `$FDP_ID`. Compilation refuses `$FDP_ID` where a record has no
/// id, so a missing id leaves the text as written.
fn substitute(text: &str, vars: &Vars<'_>) -> String {
    let text = text.replace(FDP_URL, vars.fdp_url);
    match vars.fdp_id {
        Some(id) => text.replace(FDP_ID, id),
        None => text,
    }
}

/// The prefixes names resolve against: the serializer's, then `namespaces` (which win).
struct Names<'a> {
    namespaces: Vec<(&'a str, &'a str)>,
}

impl<'a> Names<'a> {
    fn new(extra: &'a BTreeMap<String, String>) -> Result<Self, PublishError> {
        let mut namespaces: Vec<(&str, &str)> = PREFIXES.to_vec();
        for (prefix, iri) in extra {
            NamedNode::new(iri.as_str()).map_err(|_| {
                PublishError(format!(
                    "fairdp.publish.namespaces.{prefix}: `{iri}` is not an IRI"
                ))
            })?;
            namespaces.retain(|(p, _)| p != prefix);
            namespaces.push((prefix.as_str(), iri.as_str()));
        }
        Ok(Self { namespaces })
    }

    /// A prefixed name, a full IRI, or `a`.
    fn term(&self, setting: &str, name: &str) -> Result<NamedNode, PublishError> {
        let name = name.trim();
        if name == "a" {
            return Ok(NamedNode::new_unchecked(vocab::RDF_TYPE));
        }
        if is_full_iri(name) {
            // The same scheme allow-list every other configured IRI passes.
            gdi_node_standalone_core::validate_pkg::validate_iri(setting, name).map_err(|e| {
                PublishError(match e {
                    CoreError::InvalidManifest { detail } => detail,
                    other => other.to_string(),
                })
            })?;
            return NamedNode::new(name)
                .map_err(|_| PublishError(format!("{setting}: `{name}` is not a valid IRI")));
        }
        let Some((prefix, local)) = name.split_once(':') else {
            return Err(PublishError(format!(
                "{setting}: `{name}` is neither a prefixed name like `dct:title` nor a full IRI"
            )));
        };
        let Some((_, namespace)) = self.namespaces.iter().find(|(p, _)| *p == prefix) else {
            return Err(PublishError(format!(
                "{setting}: unknown prefix `{prefix}` in `{name}` (add it under \
                 [fairdp.publish.namespaces])"
            )));
        };
        NamedNode::new(format!("{namespace}{local}"))
            .map_err(|_| PublishError(format!("{setting}: `{name}` is not a valid IRI")))
    }

    /// `old = [new, …]`, as in `rename_properties` and `replace_values`; `= []` maps to
    /// nothing.
    fn mapping(
        &self,
        setting: &str,
        map: &BTreeMap<String, Vec<String>>,
    ) -> Result<Vec<(NamedNode, Vec<NamedNode>)>, PublishError> {
        map.iter()
            .map(|(old, new)| {
                let at = format!("{setting}.{old}");
                let new = new
                    .iter()
                    .map(|n| self.term(&at, n))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((self.term(&at, old)?, new))
            })
            .collect()
    }

    fn block(
        &self,
        setting: &str,
        block: &BTreeMap<String, AddValue>,
        vars: &Vars<'_>,
    ) -> Result<Vec<Statement>, PublishError> {
        block
            .iter()
            .map(|(key, value)| {
                let at = format!("{setting}.{key}");
                let predicate = self.term(&at, key)?;
                let value = self.value(&at, &predicate, value, vars)?;
                Ok(Statement { predicate, value })
            })
            .collect()
    }

    fn value(
        &self,
        setting: &str,
        predicate: &NamedNode,
        value: &AddValue,
        vars: &Vars<'_>,
    ) -> Result<Value, PublishError> {
        let is_text = |v: &AddValue| matches!(v, AddValue::Text(_));
        let names =
            is_text(value) || matches!(value, AddValue::Many(items) if items.iter().all(is_text));
        if predicate.as_str() == vocab::RDF_TYPE && !names {
            return Err(PublishError(format!(
                "{setting}: a class (`a`) must be a name or a list of names"
            )));
        }
        Ok(match value {
            AddValue::Node(block) => Value::Fill(self.block(setting, block, vars)?),
            AddValue::Many(items) => Value::Many(
                items
                    .iter()
                    .map(|item| match item {
                        AddValue::Node(block) => Ok(Value::New(self.block(setting, block, vars)?)),
                        other => self.value(setting, predicate, other, vars),
                    })
                    .collect::<Result<_, PublishError>>()?,
            ),
            scalar => Value::Scalar(self.scalar(setting, predicate, scalar, vars)?),
        })
    }

    /// Classify a scalar: a class (`a`) is a name; text properties stay text; a prefixed
    /// name (an unknown prefix is an error), an `http(s)://` or `mailto:` IRI, or a bare
    /// e-mail address (as `mailto:`) is an IRI; an ISO date or date-time is typed; anything
    /// else is plain text.
    fn scalar(
        &self,
        setting: &str,
        predicate: &NamedNode,
        value: &AddValue,
        vars: &Vars<'_>,
    ) -> Result<Scalar, PublishError> {
        let text = match value {
            AddValue::Bool(b) => {
                return Ok(Scalar::Literal {
                    text: b.to_string(),
                    datatype: Some(vocab::XSD_BOOLEAN),
                });
            }
            AddValue::Integer(n) => {
                return Ok(Scalar::Literal {
                    text: n.to_string(),
                    datatype: Some(if *n >= 0 {
                        vocab::XSD_NON_NEGATIVE_INTEGER
                    } else {
                        vocab::XSD_INTEGER
                    }),
                });
            }
            AddValue::Text(text) => text.trim(),
            AddValue::Many(_) | AddValue::Node(_) => {
                return Err(PublishError(format!("{setting}: expected a single value")));
            }
        };
        if predicate.as_str() == vocab::RDF_TYPE {
            return Ok(Scalar::Iri(self.term(setting, text)?.into_string()));
        }
        if text.contains(FDP_ID) && vars.fdp_id.is_none() {
            return Err(PublishError(format!(
                "{setting}: the FDP root has no id, so its values cannot use {FDP_ID}"
            )));
        }
        let probe = substitute(text, vars);
        if TEXT_PROPERTIES.contains(&predicate.as_str()) {
            return Ok(literal(text, None));
        }
        let iri = if is_uri_like(&probe) {
            Some(text.to_owned())
        } else if is_name_like(&probe) {
            // Resolved as written, so a `$FDP_ID` inside the local name is substituted
            // per record.
            Some(self.term(setting, text)?.into_string())
        } else if is_email(&probe) {
            Some(format!("mailto:{text}"))
        } else {
            None
        };
        if let Some(iri) = iri {
            NamedNode::new(substitute(&iri, vars))
                .map_err(|_| PublishError(format!("{setting}: `{text}` is not a valid IRI")))?;
            return Ok(Scalar::Iri(iri));
        }
        Ok(if is_iso_date_time(&probe) {
            literal(text, Some(vocab::XSD_DATE_TIME))
        } else if is_iso_date(&probe) {
            literal(text, Some(vocab::XSD_DATE))
        } else {
            literal(text, None)
        })
    }
}

fn literal(text: &str, datatype: Option<&'static str>) -> Scalar {
    Scalar::Literal {
        text: text.to_owned(),
        datatype,
    }
}

/// A full IRI where a prefixed name would do: any scheme followed by `://`, or `urn:`.
fn is_full_iri(name: &str) -> bool {
    if name.starts_with("urn:") {
        return true;
    }
    name.split_once("://").is_some_and(|(scheme, rest)| {
        !rest.is_empty()
            && scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    })
}

/// Shaped like a prefixed name (`dct:title`, `urn:…`): a prefix that starts with a letter,
/// a colon, and no spaces. Prose that holds a colon has spaces, and `10:30` a digit first.
fn is_name_like(text: &str) -> bool {
    text.split_once(':').is_some_and(|(prefix, _)| {
        !text.contains(char::is_whitespace)
            && prefix.starts_with(|c: char| c.is_ascii_alphabetic())
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    })
}

/// A value published as an IRI as written: `http://`, `https://` or `mailto:`.
fn is_uri_like(text: &str) -> bool {
    ["http://", "https://", "mailto:"]
        .iter()
        .any(|scheme| text.starts_with(scheme))
}

/// A bare e-mail address: one `@` between a non-empty local part and a dotted domain, no
/// spaces.
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !text.contains(char::is_whitespace)
        && !domain.contains('@')
        && domain
            .split_once('.')
            .is_some_and(|(host, tld)| !host.is_empty() && !tld.is_empty())
}

/// `YYYY-MM-DD`.
fn is_iso_date(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

/// An `xsd:dateTime`: `YYYY-MM-DDThh:mm:ss`, optional fraction, optional `Z` or `±hh:mm`.
fn is_iso_date_time(text: &str) -> bool {
    let Some((date, time)) = text.split_once('T') else {
        return false;
    };
    if !is_iso_date(date) {
        return false;
    }
    let (clock, zone) = match time.find(['Z', '+', '-']) {
        Some(i) => time.split_at(i),
        None => (time, ""),
    };
    let (hms, fraction) = clock.split_once('.').unwrap_or((clock, "0"));
    let hms = hms.as_bytes();
    let hms_ok = hms.len() == 8
        && hms.iter().enumerate().all(|(i, c)| match i {
            2 | 5 => *c == b':',
            _ => c.is_ascii_digit(),
        });
    let zone = zone.as_bytes();
    let zone_ok = zone.is_empty()
        || zone == b"Z"
        || (zone.len() == 6
            && zone.iter().enumerate().all(|(i, c)| match i {
                0 => matches!(c, b'+' | b'-'),
                3 => *c == b':',
                _ => c.is_ascii_digit(),
            }));
    hms_ok && zone_ok && !fraction.is_empty() && fraction.bytes().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdi_node_standalone_core::config::PublishAdd;

    const DATASET: &str = "https://node.example/fairdp/dataset/GDI-EE-X-1";
    const FDP: &str = "https://node.example/fairdp";
    const DCT: &str = "http://purl.org/dc/terms/";

    fn text(s: &str) -> AddValue {
        AddValue::Text(s.to_owned())
    }

    fn node(entries: &[(&str, AddValue)]) -> AddValue {
        AddValue::Node(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn dataset_add(entries: &[(&str, AddValue)]) -> FairdpPublish {
        let AddValue::Node(block) = node(entries) else {
            unreachable!()
        };
        FairdpPublish {
            add: PublishAdd {
                dataset: Some(PublishParts {
                    aggregated: block,
                    ..PublishParts::default()
                }),
                ..PublishAdd::default()
            },
            ..FairdpPublish::default()
        }
    }

    fn apply(publish: &FairdpPublish, graph: &mut Graph) {
        Publish::compile(publish)
            .expect("the publish settings compile")
            .apply(graph, Record::Dataset, DATASET, FDP, Some("GDI-EE-X-1"));
    }

    fn turtle(graph: &Graph) -> String {
        crate::serialize_turtle(graph)
    }

    fn iri(s: &str) -> NamedNode {
        NamedNode::new(s).expect("a valid IRI")
    }

    fn dataset_with(predicate: &str, object: impl Into<Term>) -> Graph {
        let mut graph = Graph::new();
        graph.insert(&Triple::new(iri(DATASET), iri(predicate), object));
        graph
    }

    #[test]
    fn a_drop_takes_a_named_node_cut_loose_along() {
        // A dropped property's value can be an IRI with statements of its own; once nothing
        // reaches that node, its statements go too.
        let licence = "https://licences.example/cc-by-4.0";
        let publish = FairdpPublish {
            rename_properties: BTreeMap::from([("dct:license".to_owned(), Vec::new())]),
            ..FairdpPublish::default()
        };
        let mut graph = dataset_with(&format!("{DCT}license"), iri(licence));
        graph.insert(&Triple::new(
            iri(licence),
            iri("http://www.w3.org/2000/01/rdf-schema#label"),
            Literal::new_simple_literal("CC BY 4.0"),
        ));
        apply(&publish, &mut graph);
        assert!(graph.is_empty(), "{}", turtle(&graph));
    }

    #[test]
    fn values_are_typed_by_their_shape() {
        let publish = dataset_add(&[
            ("healthdcatap:hasStructuredData", AddValue::Bool(true)),
            ("dcat:byteSize", AddValue::Integer(42)),
            ("dct:title", text("https://looks.like/an/iri")),
            ("dct:identifier", text("https://looks.like/an/iri")),
            ("dct:type", text("dct:Dataset")),
            ("dct:source", text("$FDP_URL/dataset/$FDP_ID")),
            ("dct:rightsHolder", text("gdi@example.org")),
            ("dct:issued", text("2026-09-24")),
            ("dct:modified", text("2026-09-24T10:00:00Z")),
            ("dct:subject", text("Note: prose with a colon stays text")),
        ]);
        let mut graph = Graph::new();
        apply(&publish, &mut graph);
        let out = turtle(&graph);
        for expected in [
            "healthdcatap:hasStructuredData true",
            "dcat:byteSize \"42\"^^xsd:nonNegativeInteger",
            "dct:title \"https://looks.like/an/iri\"",
            "dct:identifier \"https://looks.like/an/iri\"",
            "dct:type dct:Dataset",
            "dct:source <https://node.example/fairdp/dataset/GDI-EE-X-1>",
            "dct:rightsHolder <mailto:gdi@example.org>",
            "dct:issued \"2026-09-24\"^^xsd:date",
            "dct:modified \"2026-09-24T10:00:00Z\"^^xsd:dateTime",
            "dct:subject \"Note: prose with a colon stays text\"",
        ] {
            assert!(out.contains(expected), "missing `{expected}` in\n{out}");
        }
    }

    #[test]
    fn a_table_fills_the_existing_node_and_an_array_of_tables_adds_one_node_each() {
        let mut graph = Graph::new();
        let publisher = BlankNode::default();
        graph.insert(&Triple::new(
            iri(DATASET),
            iri(&format!("{DCT}publisher")),
            publisher.clone(),
        ));
        let publish = dataset_add(&[
            ("dct:publisher", node(&[("foaf:name", text("Node"))])),
            (
                "csvw:column",
                AddValue::Many(vec![
                    node(&[("csvw:name", text("POS"))]),
                    node(&[("csvw:name", text("AF"))]),
                ]),
            ),
        ]);
        apply(&publish, &mut graph);
        let name = graph
            .object_for_subject_predicate(&publisher, &iri("http://xmlns.com/foaf/0.1/name"))
            .map(oxrdf::TermRef::into_owned);
        assert_eq!(name, Some(Literal::new_simple_literal("Node").into()));
        let columns = graph
            .objects_for_subject_predicate(&iri(DATASET), &iri("http://www.w3.org/ns/csvw#column"))
            .count();
        assert_eq!(columns, 2);
    }

    #[test]
    fn renames_then_replacements_then_value_types() {
        let hgpd = "http://example.org/ehds/HGPD";
        let publish = FairdpPublish {
            rename_properties: BTreeMap::from([(
                "dct:type".to_owned(),
                vec!["dct:type".to_owned(), "dct:subject".to_owned()],
            )]),
            replace_values: BTreeMap::from([(
                "gdi:HealthCategoryHumanGenomic".to_owned(),
                vec![hgpd.to_owned()],
            )]),
            type_values: BTreeMap::from([("dct:subject".to_owned(), "skos:Concept".to_owned())]),
            ..FairdpPublish::default()
        };
        let mut graph = dataset_with(
            &format!("{DCT}type"),
            iri("http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"),
        );
        apply(&publish, &mut graph);
        let out = turtle(&graph);
        assert!(out.contains(&format!("dct:type <{hgpd}>")), "{out}");
        assert!(out.contains(&format!("dct:subject <{hgpd}>")), "{out}");
        assert!(out.contains(&format!("<{hgpd}> a skos:Concept")), "{out}");
        assert!(!out.contains("HealthCategoryHumanGenomic"), "{out}");
    }

    #[test]
    fn an_empty_list_drops_the_value_or_the_property() {
        let publish = FairdpPublish {
            rename_properties: BTreeMap::from([
                ("dct:subject".to_owned(), Vec::new()),
                ("dct:publisher".to_owned(), Vec::new()),
            ]),
            replace_values: BTreeMap::from([("dct:Dataset".to_owned(), Vec::new())]),
            ..FairdpPublish::default()
        };
        let mut graph = dataset_with(&format!("{DCT}type"), iri(&format!("{DCT}Dataset")));
        graph.insert(&Triple::new(
            iri(DATASET),
            iri(&format!("{DCT}subject")),
            Literal::new_simple_literal("x"),
        ));
        // A dropped node goes with its statements, not left behind unlinked.
        let publisher = BlankNode::default();
        graph.insert(&Triple::new(
            iri(DATASET),
            iri(&format!("{DCT}publisher")),
            publisher.clone(),
        ));
        graph.insert(&Triple::new(
            publisher,
            iri("http://xmlns.com/foaf/0.1/name"),
            Literal::new_simple_literal("Node"),
        ));
        apply(&publish, &mut graph);
        assert!(graph.is_empty(), "{}", turtle(&graph));
    }

    #[test]
    fn a_block_only_reaches_its_own_record_type() {
        let publish = dataset_add(&[("dct:title", text("x"))]);
        let compiled = Publish::compile(&publish).expect("the publish settings compile");
        let mut graph = Graph::new();
        compiled.apply(&mut graph, Record::Catalog, DATASET, FDP, Some("c"));
        assert!(graph.is_empty());
    }

    #[test]
    fn a_namespace_added_in_the_configuration_resolves() {
        let mut publish = dataset_add(&[("ex:flag", text("ex:On"))]);
        publish
            .namespaces
            .insert("ex".to_owned(), "https://example.org/ns#".to_owned());
        let mut graph = Graph::new();
        apply(&publish, &mut graph);
        assert!(graph.contains(&Triple::new(
            iri(DATASET),
            iri("https://example.org/ns#flag"),
            iri("https://example.org/ns#On"),
        )));
    }

    #[test]
    fn a_setting_the_node_cannot_apply_is_refused_with_its_name() {
        let cases = [
            (
                dataset_add(&[("nope:x", text("y"))]),
                "fairdp.publish.add.dataset.aggregated.nope:x",
            ),
            (
                dataset_add(&[("title", text("y"))]),
                "neither a prefixed name",
            ),
            (
                dataset_add(&[("a", text("nope:Class"))]),
                "unknown prefix `nope`",
            ),
            (
                dataset_add(&[("dct:source", text("https://bad iri"))]),
                "not a valid IRI",
            ),
            (
                dataset_add(&[("dct:subject", text("ehds:HGPD"))]),
                "unknown prefix `ehds`",
            ),
            (
                dataset_add(&[("dct:source", text("javascript://x"))]),
                "disallowed URI scheme",
            ),
            (
                dataset_add(&[("a", AddValue::Integer(1))]),
                "must be a name",
            ),
            (
                FairdpPublish {
                    type_values: BTreeMap::from([("dct:license".to_owned(), "x".to_owned())]),
                    ..FairdpPublish::default()
                },
                "fairdp.publish.type_values.dct:license",
            ),
            (
                FairdpPublish {
                    add: PublishAdd {
                        fairdp: Some(PublishParts {
                            all: BTreeMap::from([(
                                "dct:source".to_owned(),
                                text("$FDP_URL/$FDP_ID"),
                            )]),
                            ..PublishParts::default()
                        }),
                        ..PublishAdd::default()
                    },
                    ..FairdpPublish::default()
                },
                "has no id",
            ),
        ];
        for (publish, expected) in cases {
            let error = Publish::compile(&publish)
                .expect_err("the setting is refused")
                .to_string();
            assert!(
                error.contains(expected),
                "`{error}` should contain `{expected}`"
            );
        }
    }

    #[test]
    fn date_shapes() {
        assert!(is_iso_date("2026-09-24"));
        assert!(!is_iso_date("2026-9-24"));
        for ok in [
            "2026-09-24T10:00:00",
            "2026-09-24T10:00:00.5Z",
            "2026-09-24T10:00:00+03:00",
        ] {
            assert!(is_iso_date_time(ok), "{ok}");
        }
        for bad in [
            "2026-09-24T10:00",
            "2026-09-24 10:00:00",
            "2026-09-24T10:00:00+0300",
        ] {
            assert!(!is_iso_date_time(bad), "{bad}");
        }
    }
}
