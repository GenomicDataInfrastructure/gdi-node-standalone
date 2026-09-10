# Provenance of the committed test fixtures

Why this file exists: a reader who opens
`COVID.monogneic.aggregate.AFs.GRCh38.vcf` alongside `covid-package.yaml` sees a dataset
titled *"Genome of Europe Estonia aggregated allele frequencies"*, an organisation of
`UTARTU`, and `numberOfUniqueIndividuals: 4008`. Nothing beside those files said whether
that describes real people. It does not, and a repository that handles human genomic data
should not leave that to inference.

## The COVID fixture

`COVID.monogneic.aggregate.AFs.GRCh38.vcf`, its `chr7` sibling, and the byte-identical copy
under `crates/gdi-dataset-tool/tests/fixtures/`.

**It is synthetic, public test data. It is not a real cohort and contains no individual's
data.** The accompanying `covid-package.yaml` is an *illustrative* package manifest: its
title, organisation and participant count describe the shape of a real Genome of Europe
Estonia export so that the tool and the node are exercised against realistic metadata. They
are not claims about a real dataset, and no dataset with that identifier exists.

What can be verified from the file itself, without trusting this note:

- It is **sites-only**. The `#CHROM` header carries exactly eight fields
  (`CHROM POS ID REF ALT QUAL FILTER INFO`). There is no `FORMAT` column and there are no
  sample columns, so the file cannot carry a genotype for anybody.
- It holds **one data record**, `3:45823240 T>C` (the file is prefix-less: its contig is
  `3`, not `chr3`). Everything else is header.
- The payload is **aggregate counts and frequencies** in `INFO` (`AC`, `AN`, `AF` and
  their per-country and per-sex strata), which is the summary-statistic form this node is
  built to serve, not record-level data.

The single record is why `scripts/fetch-corpus.sh` exists at all: one variant cannot
exercise real cardinality or INFO variety. See
[testing.md](../../../../docs/testing.md#the-realistic-sample) for the generated
multi-site sample, which is simulated from public gnomAD site data and documents its own
provenance in `scripts/gen-sample-vcf.py`.

## The other fixtures here

- `reference-contigs/*.contigs` are contig-name columns lifted from public reference
  indexes; each source is named in `crates/test-util/src/lib.rs`. They are factual name
  lists and carry no data.
- `sample/` is generated, not collected: `scripts/gen-sample-vcf.py` simulates every count
  from a pinned seed. Only the site list is real, taken from a gnomAD v4.1 slice under the
  [gnomAD Terms of Use](https://gnomad.broadinstitute.org/terms).

## The rule this encodes

No fixture in this repository may contain real individual-level genomic data, and none
does. If you add one, say here where it came from and on what basis it may be published.
An aggregate that *looks* like a real national export is exactly the case that needs the
sentence, because nothing about the file itself will tell the next reader.
