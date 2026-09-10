#!/usr/bin/env python3
"""gen-sample-vcf.py — a realistic, synthetic, sites-only allele-frequency VCF.

The hand-written fixtures in this repository hold one record each, so nothing in the tree
shows what a provider's export actually looks like: a `bcftools +fill-tags -S groups`
sites-only file with country x sex strata, hemizygous X/Y counts, haploid chrM, split
multi-allelic rows, a rare-heavy site-frequency spectrum, a caller's own annotations, and
the provenance header a bcftools chain leaves behind. This script produces that shape.

Two subcommands, split so the second is network-free and reproducible:

  select    read the content-pinned gnomAD chr21 corpus slice (`scripts/fetch-corpus.sh`)
            and write a site list: real GRCh38 positions, alleles and rsIDs, with the
            Finnish / non-Finnish-European allele frequencies as the per-country base
            frequencies; plus synthetic chrX/chrY/chrM sites, which the slice lacks.
            Run once, at creation; the site list is committed.

  generate  read a site list and a seed, simulate a cohort's genotype counts per country x
            sex stratum under Hardy-Weinberg, and write the VCF (BGZF) plus a JSON sidecar
            of the aggregates the converter must reproduce. This is what the guard
            (`scripts/tests/test_gen_sample_vcf.py`) re-runs against the committed fixture.
            With `--synthetic-sites N` instead of `--sites` it needs no site list at all:
            N sites are spread over every GRCh38 contig in proportion to its length (plus a
            few on Y and M), so it scales to a whole-genome export. Output streams to disk
            in fixed-size chunks simulated in parallel (`--jobs`), and the result does not
            depend on the job count: chunk 0 draws from `Random(seed)` exactly as the
            committed fixture always has, and every later chunk from its own seed.

Nothing here is a real person's data. Every count is simulated; only the chr21 site list is
real, taken from a gnomAD v4.1 slice — positions, alleles, rsIDs and the per-ancestry base
frequencies used to seed the simulation.

gnomAD is released for use without restriction, under the gnomAD Terms of Use
(https://gnomad.broadinstitute.org/terms). It is not CC0 and does not carry an SPDX
licence identifier: describe it by its terms, not by a licence label. Aggregate allele
frequencies are not individual-level data, and the frequencies here are in any case only
the seed for a simulation, not the published values.

    scripts/gen-sample-vcf.py select --gnomad target/corpus/gnomad.chr21.slice.vcf \\
        --out crates/test-util/tests/fixtures/sample/sites.tsv.gz
    scripts/gen-sample-vcf.py generate --sites crates/test-util/tests/fixtures/sample/sites.tsv.gz \\
        --out crates/test-util/tests/fixtures/sample/gdi-sample.GRCh38.vcf.gz \\
        --expected crates/test-util/tests/fixtures/sample/gdi-sample.expected.json
    scripts/gen-sample-vcf.py generate --synthetic-sites 10000000 --out big.vcf.gz   # ~10 M sites
"""

from __future__ import annotations

import argparse
import functools
import gzip
import itertools
import json
import math
import operator
import os
import random
import struct
import sys
import zlib
from multiprocessing import Pool
from pathlib import Path

#: The seed the committed fixture was generated with. The guard reads it from here, so the
#: fixture, this script and the guard agree on one number.
DEFAULT_SEED = 20260904

#: GRCh38 primary contigs in reference order, with lengths, as a caller's header lists.
CONTIGS: list[tuple[str, int]] = [
    ("chr1", 248956422),
    ("chr2", 242193529),
    ("chr3", 198295559),
    ("chr4", 190214555),
    ("chr5", 181538259),
    ("chr6", 170805979),
    ("chr7", 159345973),
    ("chr8", 145138636),
    ("chr9", 138394717),
    ("chr10", 133797422),
    ("chr11", 135086622),
    ("chr12", 133275309),
    ("chr13", 114364328),
    ("chr14", 107043718),
    ("chr15", 101991189),
    ("chr16", 90338345),
    ("chr17", 83257441),
    ("chr18", 80373285),
    ("chr19", 58617616),
    ("chr20", 64444167),
    ("chr21", 46709983),
    ("chr22", 50818468),
    ("chrX", 156040895),
    ("chrY", 57227415),
    ("chrM", 16569),
]
CONTIG_ORDER = {name: i for i, (name, _) in enumerate(CONTIGS)}

#: GRCh38 pseudo-autosomal regions on chrX (1-based, inclusive): diploid in males too.
PAR1 = (10001, 2781479)
PAR2 = (155701383, 156030895)

#: The cohort: country code, males, females. Three GDI countries, ~5 000 individuals.
COHORT: list[tuple[str, int, int]] = [
    ("EE", 1012, 1119),
    ("FI", 880, 925),
    ("LV", 498, 552),
]

#: Share of sites kept even though the simulated cohort carries no copy of the allele:
#: what an export that never dropped its monomorphic sites looks like, in small measure.
MONOMORPHIC_SHARE = 0.01

#: Rare-allele count up to which the Hardy-Weinberg p-values come from the exact test. It
#: costs one interpreter loop per rare allele, thirteen times per site, and a common variant
#: in a 5 000-person cohort has thousands of them. Above this the asymptotic test stands in;
#: by then the two agree to the precision a synthetic annotation needs, and the converter
#: never reads these fields anyway.
HWE_EXACT_MAX_RARE = 400

#: Sites simulated per work unit. A chunk is the unit of parallelism and of streaming: its
#: lines are compressed and handed back as BGZF blocks, so memory is bounded by the chunk,
#: not the file. Chunk boundaries never split the rows of one position (they share calls).
CHUNK_SITES = 20_000

#: Drift between the gnomAD base frequency and a country's own: Beta(p*k, (1-p)*k) with
#: k = (1 - Fst) / Fst, Fst ~ 0.004 between neighbouring European cohorts.
DRIFT_K = 250.0

BASES = "ACGT"
TRANSITION = {"A": "G", "G": "A", "C": "T", "T": "C"}


# --------------------------------------------------------------------------- select


def select_sites(gnomad: Path, seed: int, chr21_target: int) -> list[dict]:
    """Pick real chr21 sites from the gnomAD slice and synthesise chrX/chrY/chrM ones."""
    rng = random.Random(seed)
    by_pos: dict[int, list[dict]] = {}
    for line in gnomad.open():
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[6] != "PASS":
            continue
        info = dict(kv.split("=", 1) for kv in f[7].split(";") if "=" in kv)
        af = float_or_zero(info.get("AF"))
        if af <= 0.0:
            continue
        af_fin = float_or_zero(info.get("AF_fin"))
        af_nfe = float_or_zero(info.get("AF_nfe"))
        by_pos.setdefault(int(f[1]), []).append(
            {
                "chrom": "chr21",
                "pos": int(f[1]),
                "id": f[2],
                "ref": f[3],
                "alt": f[4],
                # A variant gnomAD saw in no Finn is rare, not absent, in a Finnish cohort.
                "p_fin": af_fin if af_fin > 0 else af * 0.3,
                "p_nfe": af_nfe if af_nfe > 0 else af,
                "af": af,
                "source": "gnomad",
            }
        )
    # Stratify by frequency: every common site, every low-frequency site, then a random
    # draw of the rare ones up to the target. The result is a rare-heavy spectrum, like a
    # real genome, with enough common variants for a demo to answer queries on.
    common = [p for p, rows in by_pos.items() if max(r["af"] for r in rows) >= 1e-2]
    low = [p for p, rows in by_pos.items() if 1e-3 <= max(r["af"] for r in rows) < 1e-2]
    rare = [p for p, rows in by_pos.items() if max(r["af"] for r in rows) < 1e-3]
    chosen = set(common) | set(low)
    rare_pool = sorted(rare)
    rng.shuffle(rare_pool)
    for p in rare_pool:
        if len(chosen) >= chr21_target:
            break
        chosen.add(p)
    sites = [r for p in sorted(chosen) for r in by_pos[p]]
    sites += synthetic_sites(rng, "chrX", 20, PAR1[0], PAR1[1])
    sites += synthetic_sites(rng, "chrX", 180, PAR1[1] + 1, PAR2[0] - 1)
    sites += synthetic_sites(rng, "chrY", 40, PAR1[1] + 1, 56887902)
    sites += synthetic_sites(rng, "chrM", 30, 1, 16569)
    sites.sort(key=lambda s: (CONTIG_ORDER[s["chrom"]], s["pos"]))
    return sites


def float_or_zero(value: str | None) -> float:
    if value is None or value in (".", ""):
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0


def synthetic_sites(
    rng: random.Random, chrom: str, n: int, lo: int, hi: int
) -> list[dict]:
    """Sites the corpus slice cannot supply: random positions, transition-biased SNVs, a
    few indels, and a log-uniform (rare-heavy) base frequency per site."""
    positions = sorted(rng.sample(range(lo, hi + 1), n))
    sites = []
    for pos in positions:
        ref = rng.choice(BASES)
        roll = rng.random()
        if roll < 0.12:
            tail = "".join(rng.choice(BASES) for _ in range(rng.randint(1, 4)))
            ref, alt = (ref + tail, ref) if rng.random() < 0.5 else (ref, ref + tail)
        elif roll < 0.12 + 0.88 * 2 / 3:
            alt = TRANSITION[ref]
        else:
            alt = rng.choice([b for b in BASES if b not in (ref, TRANSITION[ref])])
        p = math.exp(rng.uniform(math.log(1e-4), math.log(0.5)))
        sites.append(
            {
                "chrom": chrom,
                "pos": pos,
                "id": ".",
                "ref": ref,
                "alt": alt,
                "p_fin": drift(p, rng),
                "p_nfe": p,
                "af": p,
                "source": "synthetic",
            }
        )
    return sites


def write_sites(path: Path, sites: list[dict]) -> None:
    with gzip.open(path, "wt", newline="\n") as out:
        out.write("#chrom\tpos\tid\tref\talt\tp_fin\tp_nfe\tsource\n")
        for s in sites:
            out.write(
                f"{s['chrom']}\t{s['pos']}\t{s['id']}\t{s['ref']}\t{s['alt']}\t"
                f"{s['p_fin']:.6g}\t{s['p_nfe']:.6g}\t{s['source']}\n"
            )


def read_sites(path: Path) -> list[dict]:
    sites = []
    with gzip.open(path, "rt") as inp:
        for line in inp:
            if line.startswith("#"):
                continue
            chrom, pos, vid, ref, alt, p_fin, p_nfe, source = line.rstrip("\n").split(
                "\t"
            )
            sites.append(
                {
                    "chrom": chrom,
                    "pos": int(pos),
                    "id": vid,
                    "ref": ref,
                    "alt": alt,
                    "p_fin": float(p_fin),
                    "p_nfe": float(p_nfe),
                    "source": source,
                }
            )
    return sites


# --------------------------------------------------------------------------- simulate


def drift(p: float, rng: random.Random) -> float:
    """A country's own frequency around a base frequency `p`."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    return min(1.0, max(0.0, rng.betavariate(p * DRIFT_K, (1.0 - p) * DRIFT_K)))


def binomial(rng: random.Random, n: int, p: float) -> int:
    """Binomial draw; exact and cheap enough for the strata sizes here."""
    if n <= 0 or p <= 0.0:
        return 0
    if p >= 1.0:
        return n
    # `binomialvariate` needs Python 3.12, which is why the repo's floor
    # (`ruff.toml` target-version) cannot drop below py312. An older interpreter raises
    # AttributeError here.
    return rng.binomialvariate(n, p)


def hwe_exact(obs_hets: int, obs_hom1: int, obs_hom2: int) -> tuple[float, float]:
    """HWE test: (two-sided p, one-sided excess-heterozygosity p). Wigginton et al. 2005
    exact up to HWE_EXACT_MAX_RARE rare alleles, the asymptotic chi-square / normal test
    beyond it. Memoised: the rare sites that make up most of a genome repeat a handful of
    count triples."""
    n = obs_hets + obs_hom1 + obs_hom2
    if n == 0:
        return 1.0, 1.0
    obs_homr = min(obs_hom1, obs_hom2)
    rare = 2 * obs_homr + obs_hets
    if rare == 0:
        return 1.0, 1.0
    if rare > HWE_EXACT_MAX_RARE:
        return hwe_asymptotic(obs_hets, obs_homr, n - obs_hets - obs_homr)
    return _hwe_exact(obs_hets, obs_homr, n)


def hwe_asymptotic(obs_hets: int, obs_homr: int, obs_homc: int) -> tuple[float, float]:
    """The chi-square (1 d.f.) goodness-of-fit p for HWE and the normal upper-tail p for
    excess heterozygosity, with continuity correction; the large-count limit of the exact
    test above."""
    n = obs_hets + obs_homr + obs_homc
    q = (2 * obs_homr + obs_hets) / (2 * n)
    exp_homr, exp_het, exp_homc = n * q * q, 2 * n * q * (1 - q), n * (1 - q) * (1 - q)
    chi2 = sum(
        (obs - exp) ** 2 / exp
        for obs, exp in (
            (obs_homr, exp_homr),
            (obs_hets, exp_het),
            (obs_homc, exp_homc),
        )
        if exp > 0
    )
    p_hwe = math.erfc(math.sqrt(chi2 / 2))
    h = 2 * q * (1 - q)
    sd = math.sqrt(n * h * (1 - h))
    p_exc = (
        0.5 * math.erfc((obs_hets - 0.5 - exp_het) / (sd * math.sqrt(2))) if sd else 1.0
    )
    return min(1.0, p_hwe), min(1.0, max(0.0, p_exc))


@functools.lru_cache(maxsize=1 << 17)
def _hwe_exact(obs_hets: int, obs_homr: int, n: int) -> tuple[float, float]:
    rare = 2 * obs_homr + obs_hets
    probs = [0.0] * (rare + 1)
    mid = rare * (2 * n - rare) // (2 * n)
    if (rare & 1) != (mid & 1):
        mid += 1
    probs[mid] = 1.0
    total = 1.0
    hets, homr, homc = mid, (rare - mid) // 2, n - mid - (rare - mid) // 2
    while hets > 1:
        probs[hets - 2] = (
            probs[hets] * hets * (hets - 1.0) / (4.0 * (homr + 1.0) * (homc + 1.0))
        )
        total += probs[hets - 2]
        hets -= 2
        homr += 1
        homc += 1
    hets, homr, homc = mid, (rare - mid) // 2, n - mid - (rare - mid) // 2
    while hets <= rare - 2:
        probs[hets + 2] = (
            probs[hets] * 4.0 * homr * homc / ((hets + 2.0) * (hets + 1.0))
        )
        total += probs[hets + 2]
        hets += 2
        homr -= 1
        homc -= 1
    p_obs = probs[obs_hets] / total
    # `sum(pr for pr in probs if pr / total <= p_obs)` and `sum(probs[h] for h in
    # range(obs_hets, rare + 1))` with the interpreter loop taken out: same divisions, same
    # summation order, same printed p-values. This is the hot path: thirteen tests per
    # site, each over the rare-allele count.
    scaled = map(operator.truediv, probs, itertools.repeat(total))
    p_hwe = min(1.0, sum(itertools.compress(probs, map(p_obs.__ge__, scaled))) / total)
    p_exc = min(1.0, sum(probs[obs_hets:]) / total)
    return p_hwe, p_exc


class Stratum:
    """One country x sex leaf of the cohort, and the genotype counts drawn for one site."""

    def __init__(self, country: str, sex: str, size: int) -> None:
        self.country, self.sex, self.size = country, sex, size
        self.reset()

    def reset(self) -> None:
        self.called = 0  # samples with a genotype
        self.diploid = 0  # of which diploid
        self.hom = 0  # homozygous-alternate individuals (diploid)
        self.het = 0  # heterozygous individuals (diploid)
        self.hemi = 0  # hemizygous-alternate individuals (haploid)

    @property
    def an(self) -> int:
        return 2 * self.diploid + (self.called - self.diploid)

    @property
    def ac(self) -> int:
        return 2 * self.hom + self.het + self.hemi

    def draw_calls(self, rng: random.Random, call_rate: float, ploidy: int) -> None:
        """Which samples have a genotype here, and with what ploidy. Drawn once per
        position: the rows a split multi-allelic site produces share one set of calls."""
        self.reset()
        if ploidy == 0:
            return
        self.called = binomial(rng, self.size, call_rate)
        self.diploid = self.called if ploidy == 2 else 0

    def draw_genotypes(self, rng: random.Random, p: float) -> None:
        """The alternate-allele genotypes among the called samples, under Hardy-Weinberg."""
        self.hom = self.het = self.hemi = 0
        if self.diploid:
            self.hom = binomial(rng, self.diploid, p * p)
            rest = self.diploid - self.hom
            q = 0.0 if p >= 1.0 else 2.0 * p * (1.0 - p) / (1.0 - p * p)
            self.het = binomial(rng, rest, q)
        else:
            self.hemi = binomial(rng, self.called, p)


def ploidy_for(chrom: str, pos: int, sex: str) -> int:
    """Copies of the site an individual of `sex` carries; 0 = no genotype at all."""
    if chrom == "chrY":
        return 1 if sex == "M" else 0
    if chrom == "chrM":
        return 1
    if (
        chrom == "chrX"
        and sex == "M"
        and not (PAR1[0] <= pos <= PAR1[1] or PAR2[0] <= pos <= PAR2[1])
    ):
        return 1
    return 2


class Group:
    """An aggregate over strata: a country, a sex, or `Total`."""

    def __init__(self, name: str, members: list[Stratum], size: int) -> None:
        self.name, self.members, self.size = name, members, size

    def sums(self) -> dict[str, int]:
        return {
            "NS": sum(s.called for s in self.members),
            "AN": sum(s.an for s in self.members),
            "AC": sum(s.ac for s in self.members),
            "AC_Hom": sum(2 * s.hom for s in self.members),
            "AC_Het": sum(s.het for s in self.members),
            "AC_Hemi": sum(s.hemi for s in self.members),
            "hom": sum(s.hom for s in self.members),
            "het": sum(s.het for s in self.members),
            "dip": sum(s.diploid for s in self.members),
        }


def g(x: float) -> str:
    """bcftools prints floats with C's `%g`: six significant digits."""
    return f"{x:g}"


def build_groups(rng: random.Random) -> tuple[list[Stratum], list[Group], list[str]]:
    """The strata, the reporting groups, and the group order, which is the order the
    groups first appear in a metadata file, that of a shuffled sample table."""
    strata = {
        (c, s): Stratum(c, s, n) for c, m, f in COHORT for s, n in (("M", m), ("F", f))
    }
    samples = [(c, s) for (c, s), st in strata.items() for _ in range(st.size)]
    rng.shuffle(samples)
    order: list[str] = []
    for c, s in samples:
        for name in (s, c, f"{c}_{s}"):
            if name not in order:
                order.append(name)
        if len(order) == 3 * len(COHORT) + 2:
            break
    groups = []
    for name in order:
        if "_" in name:
            c, s = name.split("_")
            members = [strata[(c, s)]]
        elif name in ("M", "F"):
            members = [st for (_, s), st in strata.items() if s == name]
        else:
            members = [st for (c, _), st in strata.items() if c == name]
        groups.append(Group(name, members, sum(m.size for m in members)))
    return list(strata.values()), groups, order


def simulate_site(
    rng: random.Random,
    site: dict,
    strata: list[Stratum],
    calls: dict[tuple[str, int], list[tuple[int, int]]],
) -> None:
    """Draw one site's counts; redraw a cohort-wide absence unless it is one of the
    monomorphic sites the export keeps. `calls` remembers each position's call counts so
    the rows of a split multi-allelic site share them."""
    key = (site["chrom"], site["pos"])
    if key in calls:
        for st, (called, diploid) in zip(strata, calls[key], strict=True):
            st.reset()
            st.called, st.diploid = called, diploid
    else:
        call_rate = rng.betavariate(60.0, 1.2)
        for st in strata:
            st.draw_calls(
                rng, call_rate, ploidy_for(site["chrom"], site["pos"], st.sex)
            )
        calls[key] = [(st.called, st.diploid) for st in strata]
    p_country = {
        "FI": site["p_fin"],
        "EE": drift(site["p_nfe"], rng),
        "LV": drift(site["p_nfe"], rng),
    }
    keep_monomorphic = rng.random() < MONOMORPHIC_SHARE
    for _attempt in range(40):
        for st in strata:
            st.draw_genotypes(rng, p_country[st.country])
        if sum(st.ac for st in strata) > 0 or keep_monomorphic:
            return
    # Reached only when 40 redraws all came back empty: place a single carrier.
    eligible = [st for st in strata if st.called > 0]
    if eligible:
        st = rng.choice(eligible)
        if st.diploid > 0:
            st.het = 1
        else:
            st.hemi = 1


def caller_annotations(rng: random.Random, ns: int, ac: int) -> tuple[str, list[str]]:
    """QUAL and the joint caller's own INFO fields, in the alphabetical order it writes."""
    qual = (
        rng.lognormvariate(math.log(50.0 + 30.0 * ac), 0.35)
        if ac
        else rng.uniform(40.0, 400.0)
    )
    qual = min(qual, 3.0e6)
    dp = round(30.0 * ns * rng.lognormvariate(0.0, 0.12))
    fields = [
        f"BaseQRankSum={rng.gauss(0.0, 0.9):.3f}",
        f"DP={dp}",
        f"ExcessHet={max(0.0, rng.gauss(3.0103, 0.6)):.4f}",
        f"FS={rng.expovariate(1.0 / 1.5):.3f}",
        f"InbreedingCoeff={rng.gauss(0.0, 0.03):.4f}",
        f"MQ={min(60.0, 60.0 - abs(rng.gauss(0.0, 0.4))):.2f}",
        f"MQRankSum={rng.gauss(0.0, 0.3):.2f}",
        f"QD={min(40.0, max(2.0, rng.triangular(2.0, 40.0, 20.0))):.2f}",
        f"ReadPosRankSum={rng.gauss(0.0, 0.9):.3f}",
        f"SOR={rng.lognormvariate(math.log(0.69), 0.4):.3f}",
    ]
    return f"{qual:.2f}", fields


def freq_fields(sums: dict[str, int], suffix: str) -> list[str]:
    an, ac = sums["AN"], sums["AC"]
    if an == 0:
        return [f"AF{suffix}=.", f"MAF{suffix}=."]
    af = ac / an
    return [f"AF{suffix}={g(af)}", f"MAF{suffix}={g(min(af, 1.0 - af))}"]


def hwe_fields(sums: dict[str, int], suffix: str) -> list[str]:
    hom_ref = sums["dip"] - sums["hom"] - sums["het"]
    p_hwe, p_exc = hwe_exact(sums["het"], hom_ref, sums["hom"])
    return [f"HWE{suffix}={g(p_hwe)}", f"ExcHet{suffix}={g(p_exc)}"]


def info_column(
    site_fields: list[str],
    groups: list[Group],
    total: Group,
    per: dict[str, dict[str, int]],
    tot: dict[str, int],
) -> str:
    """The INFO column in the order `bcftools +fill-tags -S` leaves it: the caller's fields
    (with `AC`/`AF`/`AN` updated in place), then every added tag, per-group values before
    the cohort-wide one. `per` and `tot` are the groups' and the cohort's `sums()`, computed
    once per site by the caller."""
    out = list(site_fields)
    out += [
        f"F_MISSING_{n}={g(1.0 - per[n]['NS'] / grp.size)}"
        for n, grp in zip(per, groups, strict=True)
    ]
    out.append(f"F_MISSING={g(1.0 - tot['NS'] / total.size)}")
    out += [f"NS_{n}={per[n]['NS']}" for n in per]
    out.append(f"NS={tot['NS']}")
    out += [f"AN_{n}={per[n]['AN']}" for n in per]
    for n in per:
        out += freq_fields(per[n], f"_{n}")
    out += freq_fields(tot, "")[1:]  # the cohort AF already sits in the caller's slot
    out += [f"AC_{n}={per[n]['AC']}" for n in per]
    for tag in ("AC_Het", "AC_Hom", "AC_Hemi"):
        out += [f"{tag}_{n}={per[n][tag]}" for n in per]
        out.append(f"{tag}={tot[tag]}")
    for n in per:
        out += hwe_fields(per[n], f"_{n}")
    out += hwe_fields(tot, "")
    return ";".join(out)


# --------------------------------------------------------------------------- header


def info_line(tag: str, number: str, kind: str, desc: str) -> str:
    return f'##INFO=<ID={tag},Number={number},Type={kind},Description="{desc}">'


def header_lines(order: list[str]) -> list[str]:
    """The header a GATK joint call carries after the bcftools chain: the caller's own
    definitions, the bcftools provenance in the order the steps ran, and the tags
    `+fill-tags` appended, group-suffixed definitions before the cohort-wide one."""
    caller = [
        "##fileformat=VCFv4.2",
        '##FILTER=<ID=PASS,Description="All filters passed">',
        (
            '##GATKCommandLine=<ID=GenotypeGVCFs,CommandLine="GenotypeGVCFs --output cohort.vcf.gz'
            ' --variant gendb://cohort_db --reference GRCh38_full_analysis_set_plus_decoy_hla.fa",'
            'Version="4.5.0.0",Date="2026-05-11T09:14:37Z">'
        ),
        info_line(
            "AC",
            "A",
            "Integer",
            "Allele count in genotypes, for each ALT allele, in the same order as listed",
        ),
        info_line(
            "AF",
            "A",
            "Float",
            "Allele Frequency, for each ALT allele, in the same order as listed",
        ),
        info_line("AN", "1", "Integer", "Total number of alleles in called genotypes"),
        info_line(
            "BaseQRankSum",
            "1",
            "Float",
            "Z-score from Wilcoxon rank sum test of Alt Vs. Ref base qualities",
        ),
        info_line(
            "DP",
            "1",
            "Integer",
            "Approximate read depth; some reads may have been filtered",
        ),
        info_line(
            "ExcessHet",
            "1",
            "Float",
            "Phred-scaled p-value for exact test of excess heterozygosity",
        ),
        info_line(
            "FS",
            "1",
            "Float",
            "Phred-scaled p-value using Fisher's exact test to detect strand bias",
        ),
        info_line(
            "InbreedingCoeff",
            "1",
            "Float",
            "Inbreeding coefficient as estimated from the genotype likelihoods per-sample when compared against the Hardy-Weinberg expectation",
        ),
        info_line("MQ", "1", "Float", "RMS Mapping Quality"),
        info_line(
            "MQRankSum",
            "1",
            "Float",
            "Z-score From Wilcoxon rank sum test of Alt vs. Ref read mapping qualities",
        ),
        info_line("QD", "1", "Float", "Variant Confidence/Quality by Depth"),
        info_line(
            "ReadPosRankSum",
            "1",
            "Float",
            "Z-score from Wilcoxon rank sum test of Alt vs. Ref read position bias",
        ),
        info_line(
            "SOR",
            "1",
            "Float",
            "Symmetric Odds Ratio of 2x2 contingency table to detect strand bias",
        ),
    ]
    caller += [f"##contig=<ID={name},length={length}>" for name, length in CONTIGS]
    caller.append(
        "##reference=file:///references/GRCh38_full_analysis_set_plus_decoy_hla.fa"
    )
    caller.append("##source=GenotypeGVCFs")
    date = "Mon Jun  1 08:02:11 2026"
    chain = [
        "##bcftools_normVersion=1.24+htslib-1.24",
        f"##bcftools_normCommand=norm -m -any -f GRCh38_full_analysis_set_plus_decoy_hla.fa -Oz -o cohort_split-multiallelic.vcf.gz cohort.vcf.gz; Date={date}",
        "##bcftools_pluginVersion=1.24+htslib-1.24",
        f"##bcftools_pluginCommand=plugin setGT -Oz -o cohort_split-multiallelic-GTmasked.vcf.gz -- cohort_split-multiallelic.vcf.gz -t q -n . -i 'FMT/GQ < 20 | FMT/DP < 10'; Date={date}",
        "##bcftools_viewVersion=1.24+htslib-1.24",
        f"##bcftools_viewCommand=view -e 'QUAL < 30 | INFO/QD < 2.0 | INFO/DP < 10 | INFO/MQ < 40 | INFO/FS > 60 | INFO/ReadPosRankSum < -8.0' -Oz -o cohort_split-multiallelic-GTmasked-variantQC.vcf.gz cohort_split-multiallelic-GTmasked.vcf.gz; Date={date}",
        f"##bcftools_viewCommand=view -S sample-keep.txt -Oz -o cohort_split-multiallelic-GTmasked-variantQC-sampleQC.vcf.gz cohort_split-multiallelic-GTmasked-variantQC.vcf.gz; Date={date}",
        f"##bcftools_pluginCommand=plugin fixploidy -Oz -o cohort_split-multiallelic-GTmasked-variantQC-sampleQC-ploidy_fixed.vcf.gz -- cohort_split-multiallelic-GTmasked-variantQC-sampleQC.vcf.gz -s gender.txt -p ploidy_grch38.txt; Date={date}",
    ]
    added: list[str] = []
    added += [
        info_line(
            f"F_MISSING_{n}",
            "1",
            "Float",
            f"Added by +fill-tags expression F_MISSING:1=F_MISSING in {n}",
        )
        for n in order
    ]
    added.append(
        info_line(
            "F_MISSING",
            "1",
            "Float",
            "Added by +fill-tags expression F_MISSING:1=F_MISSING",
        )
    )
    added += [
        info_line(
            f"AN_{n}",
            "1",
            "Integer",
            f"Total number of alleles in called genotypes in {n}",
        )
        for n in order
    ]
    added += [
        info_line(f"AC_{n}", "A", "Integer", f"Allele count in genotypes in {n}")
        for n in order
    ]
    added += [
        info_line(f"NS_{n}", "1", "Integer", f"Number of samples with data in {n}")
        for n in order
    ]
    added.append(info_line("NS", "1", "Integer", "Number of samples with data"))
    for tag, word in (
        ("AC_Hom", "homozygous"),
        ("AC_Het", "heterozygous"),
        ("AC_Hemi", "hemizygous"),
    ):
        added += [
            info_line(
                f"{tag}_{n}",
                "A",
                "Integer",
                f"Allele counts in {word} genotypes in {n}",
            )
            for n in order
        ]
        added.append(
            info_line(tag, "A", "Integer", f"Allele counts in {word} genotypes")
        )
    added += [
        info_line(f"AF_{n}", "A", "Float", f"Allele frequency in {n}") for n in order
    ]
    added += [
        info_line(
            f"MAF_{n}",
            "1",
            "Float",
            f"Frequency of the second most common allele in {n}",
        )
        for n in order
    ]
    added.append(
        info_line("MAF", "1", "Float", "Frequency of the second most common allele")
    )
    added += [
        info_line(
            f"HWE_{n}", "A", "Float", f"HWE test in {n} (PMID:15789306); 1=good, 0=bad"
        )
        for n in order
    ]
    added.append(
        info_line("HWE", "A", "Float", "HWE test (PMID:15789306); 1=good, 0=bad")
    )
    added += [
        info_line(
            f"ExcHet_{n}",
            "A",
            "Float",
            f"Test excess heterozygosity in {n}; 1=good, 0=bad",
        )
        for n in order
    ]
    added.append(
        info_line("ExcHet", "A", "Float", "Test excess heterozygosity; 1=good, 0=bad")
    )
    tail = [
        f"##bcftools_pluginCommand=plugin fill-tags -Ou -- cohort_split-multiallelic-GTmasked-variantQC-sampleQC-ploidy_fixed.vcf.gz -S groups.txt; Date={date}",
        f"##bcftools_viewCommand=view -G -Ou; Date={date}",
        "##bcftools_annotateVersion=1.24+htslib-1.24",
        f"##bcftools_annotateCommand=annotate -x FORMAT -Oz -o cohort-AF_recalc.vcf.gz; Date={date}",
        "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO",
    ]
    return caller + chain + added + tail


# --------------------------------------------------------------------------- generate


def chunk_rng(seed: int, index: int) -> random.Random:
    """Chunk 0 is the stream the committed fixture was drawn from; later chunks get their
    own, so a file is the same whatever the job count and however it was chunked."""
    return random.Random(seed) if index == 0 else random.Random(f"{seed}:{index}")


def split_sites(sites: list[dict]) -> list[list[dict]]:
    """Cut a site list into chunks of about CHUNK_SITES without separating the rows of one
    position, which must share one set of calls."""
    chunks: list[list[dict]] = []
    start = 0
    while start < len(sites):
        end = min(start + CHUNK_SITES, len(sites))
        while end < len(sites) and (sites[end]["chrom"], sites[end]["pos"]) == (
            sites[end - 1]["chrom"],
            sites[end - 1]["pos"],
        ):
            end += 1
        chunks.append(sites[start:end])
        start = end
    return chunks


def synthetic_plan(n: int) -> list[tuple[str, int, int, int]]:
    """Where `--synthetic-sites N` puts its sites: over chr1-22 and X in proportion to
    contig length, in position-ordered pieces of at most CHUNK_SITES; a sparse Y outside
    the PAR (a callable Y is a tenth of its length) and a handful on M."""
    autos = [(name, length) for name, length in CONTIGS if name not in ("chrY", "chrM")]
    genome = sum(length for _, length in autos)
    plan: list[tuple[str, int, int, int]] = []
    for name, length in autos:
        k = max(1, round(n * length / genome))
        pieces = max(1, math.ceil(k / CHUNK_SITES))
        edges = [1 + (length - 1) * i // pieces for i in range(pieces + 1)]
        for i in range(pieces):
            k_i = k // pieces + (1 if i < k % pieces else 0)
            plan.append((name, k_i, edges[i], edges[i + 1] - 1))
    plan.append(("chrY", max(1, n // 500), PAR1[1] + 1, 56887902))
    plan.append(("chrM", max(1, min(3000, n // 2000)), 1, 16569))
    return plan


def simulate_chunk(job: tuple) -> tuple[int, bytes, dict]:
    """One work unit: simulate a chunk's sites and return its records as BGZF blocks plus
    the aggregates the sidecar sums. `job` is (index, seed, sites) for a site list, or
    (index, seed, (chrom, n, lo, hi)) to synthesise the sites first."""
    index, seed, spec = job
    rng = chunk_rng(seed, index)
    strata, groups, order = build_groups(rng if index == 0 else random.Random(seed))
    total = Group("Total", strata, sum(s.size for s in strata))
    sites = spec if isinstance(spec, list) else synthetic_sites(rng, *spec)
    calls: dict[tuple[str, int], list[tuple[int, int]]] = {}
    rows_per_population = dict.fromkeys(["Total", *order], 0)
    per_contig: dict[str, int] = {}
    total_af_zero = 0
    ns_peak = 0
    lines: list[str] = []
    blocks: list[bytes] = []
    pending = 0

    def flush() -> None:
        nonlocal lines, pending
        data = "".join(lines).encode()
        blocks.extend(
            bgzf_block(data[i : i + 0xFF00]) for i in range(0, len(data), 0xFF00)
        )
        lines, pending = [], 0

    for site in sites:
        simulate_site(rng, site, strata, calls)
        per = {grp.name: grp.sums() for grp in groups}
        tot = total.sums()
        qual, caller = caller_annotations(rng, tot["NS"], tot["AC"])
        af_total = tot["AC"] / tot["AN"] if tot["AN"] else None
        site_fields = [
            f"AC={tot['AC']}",
            f"AF={g(af_total) if af_total is not None else '.'}",
            f"AN={tot['AN']}",
            *caller,
        ]
        info = info_column(site_fields, groups, total, per, tot)
        line = f"{site['chrom']}\t{site['pos']}\t{site['id']}\t{site['ref']}\t{site['alt']}\t{qual}\tPASS\t{info}\n"
        lines.append(line)
        pending += len(line)
        if pending >= 4 * 0xFF00:
            flush()
        per_contig[site["chrom"]] = per_contig.get(site["chrom"], 0) + 1
        ns_peak = max(ns_peak, tot["NS"])
        if tot["AN"] > 0:
            rows_per_population["Total"] += 1
            if tot["AC"] == 0:
                total_af_zero += 1
        for grp in groups:
            if per[grp.name]["AN"] > 0:
                rows_per_population[grp.name] += 1
    flush()
    stats = {
        "records": len(sites),
        "recordsPerContig": per_contig,
        "rowsPerPopulation": rows_per_population,
        "totalAfZeroVariants": total_af_zero,
        "nsPeak": ns_peak,
    }
    return index, b"".join(blocks), stats


def generate(
    out: Path,
    seed: int,
    jobs: int,
    sites: list[dict] | None = None,
    synthetic: int | None = None,
) -> dict:
    """Write the VCF to `out` and return the sidecar aggregates. Exactly one of `sites`
    (a site list) and `synthetic` (a site count for `synthetic_plan`) is given. The header
    goes first, then every chunk's blocks in chunk order, then the BGZF EOF marker. Chunks
    are simulated `jobs` at a time and written in order as they finish; `Pool.imap` applies
    no backpressure, so a writer slower than the workers would let finished chunks queue in
    the parent. Writing bytes is far cheaper than simulating them, so it does not."""
    if (sites is None) == (synthetic is None):
        raise ValueError("give exactly one of sites and synthetic")
    _, _, order = build_groups(random.Random(seed))
    if sites is not None:
        specs: list = split_sites(sites)
    else:
        specs = synthetic_plan(synthetic)
    work = [(i, seed, spec) for i, spec in enumerate(specs)]
    per_contig: dict[str, int] = {}
    rows_per_population = dict.fromkeys(["Total", *order], 0)
    records = total_af_zero = ns_peak = 0
    header = ("\n".join(header_lines(order)) + "\n").encode()

    def consume(results) -> None:
        nonlocal records, total_af_zero, ns_peak
        for _index, blocks, stats in results:
            fh.write(blocks)
            records += stats["records"]
            total_af_zero += stats["totalAfZeroVariants"]
            ns_peak = max(ns_peak, stats["nsPeak"])
            for name, count in stats["recordsPerContig"].items():
                per_contig[name] = per_contig.get(name, 0) + count
            for name, count in stats["rowsPerPopulation"].items():
                rows_per_population[name] += count

    with out.open("wb") as fh:
        for i in range(0, len(header), 0xFF00):
            fh.write(bgzf_block(header[i : i + 0xFF00]))
        if jobs <= 1:
            consume(map(simulate_chunk, work))
        else:
            with Pool(jobs) as pool:
                consume(pool.imap(simulate_chunk, work))
        fh.write(bgzf_block(b""))  # the 28-byte EOF marker readers look for
    populations = ["Total", *order]
    return {
        "seed": seed,
        "cohort": {c: {"M": m, "F": f} for c, m, f in COHORT},
        "individuals": sum(m + f for _, m, f in COHORT),
        "populations": sorted(populations),
        "sites": records,
        "recordsPerContig": per_contig,
        "records": records,
        "rowsEmitted": sum(rows_per_population.values()),
        "rowsPerPopulation": rows_per_population,
        "totalAfZeroVariants": total_af_zero,
        "nsPeak": ns_peak,
    }


def bgzf_block(chunk: bytes) -> bytes:
    """One BGZF block: a gzip member with the `BC` extra field carrying its own size."""
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    cdata = comp.compress(chunk) + comp.flush()
    header = (
        b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\xff\x06\x00BC\x02\x00"
        + struct.pack("<H", len(cdata) + 25)
    )
    return (
        header + cdata + struct.pack("<II", zlib.crc32(chunk) & 0xFFFFFFFF, len(chunk))
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sel = sub.add_parser(
        "select",
        help="build the site list from the gnomAD corpus slice (creation only)",
    )
    sel.add_argument("--gnomad", type=Path, required=True)
    sel.add_argument("--seed", type=int, default=DEFAULT_SEED)
    sel.add_argument("--chr21", type=int, default=1200, help="chr21 positions to keep")
    sel.add_argument("--out", type=Path, required=True)
    gen = sub.add_parser(
        "generate", help="simulate the cohort and write the VCF (BGZF)"
    )
    source = gen.add_mutually_exclusive_group(required=True)
    source.add_argument("--sites", type=Path, help="a site list written by `select`")
    source.add_argument(
        "--synthetic-sites",
        type=int,
        metavar="N",
        help="no site list: about N synthetic sites spread over every GRCh38 contig "
        "(chrY, chrM and per-contig rounding add a fraction of a percent; the sidecar "
        "records the exact count)",
    )
    gen.add_argument("--seed", type=int, default=DEFAULT_SEED)
    gen.add_argument("--out", type=Path, required=True)
    gen.add_argument(
        "--expected", type=Path, help="write the aggregates the converter must report"
    )
    gen.add_argument(
        "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="chunks simulated in parallel; the output does not depend on it",
    )
    args = ap.parse_args(argv)
    if args.cmd == "select":
        sites = select_sites(args.gnomad, args.seed, args.chr21)
        write_sites(args.out, sites)
        print(f"wrote {len(sites)} sites to {args.out}", file=sys.stderr)
        return 0
    if args.sites is not None:
        expected = generate(
            args.out, args.seed, args.jobs, sites=read_sites(args.sites)
        )
    else:
        expected = generate(
            args.out, args.seed, args.jobs, synthetic=args.synthetic_sites
        )
    if args.expected:
        args.expected.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    print(
        f"wrote {expected['records']} records, {expected['rowsEmitted']} rows to {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
