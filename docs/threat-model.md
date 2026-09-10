# Disclosure-control threat model — aggregate Beacon

A LINDDUN-style threat model for the aggregate GA4GH Beacon `g_variants` surface:
per-population allele frequencies served unauthenticated over the internet. It records what
is defended, what is not and why, and which levers reduce the residual risk. The claims are
backed by `crates/beacon/tests/it/suppression_properties.rs`.

This covers the aggregated tier only. The authenticated record-level tier is not built; it
returns zeros. Record-level access control is its concern, not this document's.

## Asset and adversary

- **Asset**: the membership and genotype privacy of the individuals in the published
  cohorts. A "cell" is one `(variant, population)` allele count, where a population is
  `Total`, a country (`EE`), a sex (`M`), or a country×sex leaf (`EE_M`).
- **Adversary**: a remote, unauthenticated client issuing arbitrary `g_variants` queries.
  It can query many variants, combine datasets, and hold auxiliary information such as
  public reference panels or another node's output. Per surviving population it always sees
  `alleleFrequency`, and unless withheld also `alleleCount`, `alleleNumber` and the genotype
  sub-counts. It can reconstruct `AC ≈ round(AF·AN)` and `AN ≈ AC/AF`.

## LINDDUN threats in scope

- **Linking and identifying**: recover a suppressed subgroup cell such as `EE_M`'s count by
  differencing marginals, or infer an individual's membership or genotype.
- **Detecting**: distinguish a variant's presence or rarity from responses.

Non-repudiation, unawareness and non-compliance are governance and logging concerns, handled
by the audit trail and the access and retention policy rather than by the query math.

## Controls, and how strong they are

1. **Suppression floor** (`min_allele_count`), applied two-tailed on the client-derivable
   counts: the low tail on `alt_carriers = round(AF·AN)`, so withholding `AC` while emitting
   `AF` and `AN` does not help, and the complement tail on
   `reference_carriers = AN − AC` for near-fixed variants. The effective floor is
   `max(node [beacon].min_allele_count, dataset manifest.min_allele_count)`.
2. **Collapse-to-Total** (`emittable_rows`): as soon as any cell in a variant group is
   suppressed, every non-`Total` row is dropped, including siblings that individually clear
   the floor. A suppressed cell therefore cannot be recovered by single-variant subtraction
   (`EE_F = EE − EE_M`, `F = Total − M`, …). If there is no `Total`, the whole variant is
   dropped.
3. **Genotype sub-count coherence** (`gate_subcounts`, `subcount_in_danger`): the same
   collapse one level down. A below-floor `Hom`, `Het` or `Hemi` withholds all three within a
   row, and any below-floor sub-count withholds every non-`Total` row's sub-counts, so
   `Hom = (AC − Het − Hemi)/2` has no surviving sibling.

Evidence that the single-variant gate is complete:

- `bounded_model_check_single_variant_gate_is_hole_free` exhaustively enumerates 2,401
  coherent variant groups. Wherever a cell is suppressed, the emitted breakdown is
  `Total`-only or empty, with no partial-breakdown holes.
- `suppression_collapses_to_total_never_a_partial_breakdown` asserts the same invariant as
  a proptest over random inputs.
- `raising_the_floor_only_suppresses_never_reveals` asserts monotonicity: a higher floor only
  withholds. It never reveals a previously-suppressed cell or changes a surviving count.
- `adding_a_second_dataset_never_changes_the_first` asserts cross-dataset isolation.

## Residual risks

1. **Multi-variant statistical reconstruction** (Homer/Sankararaman-style). This is an
   accepted residual risk. `alleleFrequency` is emitted at full precision for every
   surviving population and `AN` is stable across a fixed cohort, so many variants of the
   same cohort form an overdetermined system in the latent subgroup and individual counts.
   The per-variant collapse does not couple across variants. `query.rs` records this as out
   of scope: differential privacy is the complete defence.

   The attack is demonstrated, not theoretical, and it was demonstrated **against a
   synthetic cohort with known ground truth**. No real person's data was involved at any
   point, and no production node was queried. The experiment constructs its own cohort by
   sampling common SNPs from a reference panel, publishes that cohort's aggregates through
   this node, and then attacks it using nothing but the public `g_variants` responses —
   which is what makes the result checkable at all: membership is known in advance, so
   false positives and false negatives can both be counted.

   With the floor active at `min_allele_count = 5` and about 3,970 common SNPs harvested,
   a per-allele log-likelihood-ratio test identified 25 of 25 members with 0 of 60 false
   positives; the weakest true member separated at +10.6 σ. An earlier run over a 40-member
   cohort held 100 % classification accuracy at a floor of 10 and 99 % at a floor of 30:
   the higher floor suppressed over half the variants and the survivors still carried the
   signal.

   **Reproducing it.** No harness is committed, because the attacker side is a dozen lines
   and the cohort has to be synthesised anyway. Publish a synthetic cohort through the
   node, harvest the allele frequency for M common variants via `POST /g_variants`, and for
   each candidate genotype vector `g` compute the standard Homer-style statistic against
   the published frequency `Y` and the reference-panel frequency `p`:

   ```text
   LR = Σ g·ln(Y/p) + (2 - g)·ln((1 - Y)/(1 - p))
   ```

   then compare the LR distribution of members against non-members.

   No small-count floor closes this, at any value. A floor is a per-cell test, and the
   signal is in no single cell: it is spread thinly across thousands of independently
   published aggregate frequencies, each well above the floor. Membership inference rides
   the common variants (AF ≈ 0.1–0.5) that clear every floor by construction, and its power
   grows with the number of variants queried rather than with the rarity of any one, so
   suppressing the rare tail removes variants the attack was not using.
   `[beacon].min_allele_count` bounds singleton and rare-cell re-identification, which is a
   different threat; the node's `doctor` output says so. Only a mechanism that perturbs the
   published aggregates bounds the total information released across a query stream.

   The control here is governance, not query math. What bounds this risk is who is permitted
   to query the sensitive tier, enforced by authentication, data-access-committee approval
   and the audit trail, not by a query-time filter on the aggregate plane. Publishing a
   cohort's aggregates on an unauthenticated plane is a governance choice about that cohort's
   sensitivity. If a cohort's sensitivity exceeds what that accepts, the technical options
   are the authenticated record-level tier, coarser population aggregation, or differential
   privacy. A bigger floor is not one of them.
2. **Cross-dataset differencing.** Floors are per-dataset and independent. With the node
   floor at its shipped default of `0`, a permissive dataset leaks a cell that a strict
   sibling suppresses. `cross_dataset_floor_asymmetry_leaks_a_suppressed_cell` demonstrates
   full recovery: dataset A at floor 0 emits the shared `EE_M` cell that dataset B at floor
   200 collapses away.
3. **Suppression ships off by default** (`min_allele_count = 0`). Every control above is
   inert unless an operator sets a floor. The only guard is a startup warning, emitted in
   every environment, because the aggregated `g_variants` plane is unauthenticated
   regardless of the `environment` or `security_level` label.
4. **Cross-node differencing across the federation.** Residual 2 is scoped to datasets within
   one node. GDI is a federation, and the same dataset can be served by several nodes whose
   operators chose different `[beacon].min_allele_count`. Demonstrated with an identical
   dataset — same `datasetId`, byte-identical parquet via a pinned `--build-epoch`, honest
   `manifest.minAlleleCount = 0` — dropped into two nodes:

   | query | node A (floor 0) | node B (floor 100) |
   | --- | --- | --- |
   | chr2:999 | `EE 50, EE_M 3, FI 50, Total 100` | `Total 100` |
   | chr2:3999 | `EE 2, EE_M 1, FI 2, Total 4` (singletons) | withheld |

   A Beacon Network aggregator fans out to both and takes the union, so node B's suppression
   is worth nothing. Because the `datasetId` is identical, an aggregator can recognise them
   as the same data and prefer the permissive answer. The weakest operator in the federation
   sets the effective floor for everyone, and no node-side control changes that; see the
   scope caveat on lever 1 below.

## Where to spend effort

The model check settles the most consequential question: the single-variant marginal gate is
solid. Emitting fewer redundant marginals to frustrate subtraction would therefore add no
protection against single-variant differencing, and would only cost utility.

The residual levers, in priority order:

1. **A non-zero node-wide default floor.** `max(node, manifest)` then enforces a floor on
   every dataset, closing the cross-dataset residual (2) and the off-by-default risk (3).
   This is the cheapest change with the highest value.

   It stops at the node boundary. A node-wide floor is configuration local to one
   deployment, so it does nothing about residual 4: a replica of the same dataset on a more
   permissive node still answers. The portable control is the manifest floor,
   `config.minAlleleCount`, set at build time in `package.yaml`. It travels with the package
   and is re-applied by every node that serves it, which is what `max(node, manifest)`
   guarantees: a node cannot serve a cell below the floor its provider baked in.

   The guidance therefore splits by who owns the risk. Operators set the node floor to
   protect this node. Providers whose cohort must stay protected wherever it is replicated
   set the floor in `package.yaml` at build time, because a node-side setting cannot give
   them that guarantee and a permissive sibling node will undo it.
2. **Per-client query budgeting or rate limiting, plus query-pattern anomaly detection.**
   Raises the query cost of the multi-variant attack (1) without touching utility.
3. **Differential privacy**, the complete defence for 1, at a heavy utility cost on exactly
   the rare variants researchers want. It is a non-goal for the aggregate tier unless
   requirements change. Declining it is what makes 1 an accepted risk rather than an open
   one, so the compensating control is the governance decision named there: which cohorts
   are published on this plane at all.

## References

- Tests: `crates/beacon/tests/it/suppression_properties.rs` (properties, model-check,
  cross-dataset demo); `crates/beacon/tests/it/assemble.rs` (floor / collapse / sub-count
  examples).
- Code: `crates/beacon/src/query.rs` (`row_survives`, `emittable_rows`, `gate_subcounts`;
  the out-of-scope note at the `emittable_rows` doc comment).
- `docs/architecture.md` — "Known limits": the default floor being off, non-minimal
  suppression, and multi-variant and cross-dataset differencing being out of scope.
