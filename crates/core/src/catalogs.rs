//! The management-plane catalog listing (`GET /catalogs`): the `[catalogs]` table as
//! plain JSON, for an integrating system that needs the node's accepted catalog ids
//! without parsing the FAIR Data Point's RDF.
//!
//! The FDP root (`/fairdp`) lists the same catalogs as `fdp-o:metadataCatalog`
//! references, which is the surface a harvester reads. Both views are built from the
//! same reloadable config snapshot, so they cannot list different catalogs. The JSON
//! shape is published as `docs/catalogs.schema.json` for a consumer to generate its
//! model from.
//!
//! The catalog table is already public on the FDP root, so this route is always mounted
//! rather than opt-in like the id-keyed `/datasets` and `/stats/queries` surfaces.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One configured catalog: the `[catalogs]` key and its display title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CatalogEntry {
    /// The catalog id: the `[catalogs]` key, which a manifest's `metadata.catalog` must
    /// match for the node to accept the package, and the `{id}` of `/fairdp/catalog/{id}`.
    pub id: String,
    /// The display title: the `[catalogs]` value, served as the catalog's `dct:title`.
    pub title: String,
}

/// The `GET /catalogs` body: every configured catalog, in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CatalogList {
    /// The configured catalogs, sorted by id. Empty when the config declares none.
    pub catalogs: Vec<CatalogEntry>,
}

impl CatalogList {
    /// The listing for a `[catalogs]` table (id → title). A `BTreeMap` iterates in key
    /// order, so the wire order is stable across reloads and restarts.
    #[must_use]
    pub fn from_config(catalogs: &BTreeMap<String, String>) -> Self {
        Self {
            catalogs: catalogs
                .iter()
                .map(|(id, title)| CatalogEntry {
                    id: id.clone(),
                    title: title.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use super::*;

    #[test]
    fn lists_every_configured_catalog_in_id_order() {
        let mut table = BTreeMap::new();
        table.insert("synthetic-data".to_owned(), "Synthetic Data".to_owned());
        table.insert("gdi-aggregated".to_owned(), "Aggregated".to_owned());
        let list = CatalogList::from_config(&table);
        let ids: Vec<&str> = list.catalogs.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["gdi-aggregated", "synthetic-data"]);
        assert_eq!(list.catalogs[1].title, "Synthetic Data");
    }

    #[test]
    fn an_empty_table_is_an_empty_list_not_an_error() {
        let list = CatalogList::from_config(&BTreeMap::new());
        assert!(list.catalogs.is_empty());
        assert_eq!(
            serde_json::to_string(&list).unwrap(),
            r#"{"catalogs":[]}"#,
            "the wire shape is an object carrying the array, so it can grow additively"
        );
    }
}
