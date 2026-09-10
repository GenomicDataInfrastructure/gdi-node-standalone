"""The realistic sample fixture is what `scripts/gen-sample-vcf.py` produces, and it is
internally coherent.

Two invariants, one guard each:

* **Reproducibility.** The committed `gdi-sample.GRCh38.vcf.gz` and its
  `gdi-sample.expected.json` sidecar are exactly what `generate` writes from the committed
  site list and the script's pinned seed. Compared as decompressed text, so the guard does
  not depend on the zlib build that compressed the fixture. A drift here means the script
  changed without the fixture being regenerated, or the reverse; the two must move
  together.
* **Coherence.** Every record obeys the rules the converter enforces, checked here in plain
  Python without the converter: the genotype sub-counts partition `AC`, `AC <= AN`, `AF` is
  `AC / AN` to six significant digits, `AF` is `.` exactly when `AN` is `0`, sexes and
  countries each sum to the cohort, and `NS` never exceeds the stratum. A generator bug
  that the converter would reject is caught by the script's own suite, where the message
  names the generator.
"""

import gzip
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _helpers import REPO_ROOT, SCRIPTS, load_module

SAMPLE_DIR = REPO_ROOT / "crates" / "test-util" / "tests" / "fixtures" / "sample"
VCF = SAMPLE_DIR / "gdi-sample.GRCh38.vcf.gz"
SITES = SAMPLE_DIR / "sites.tsv.gz"
EXPECTED = SAMPLE_DIR / "gdi-sample.expected.json"
GENERATOR = SCRIPTS / "gen-sample-vcf.py"

COUNTRIES = ("EE", "FI", "LV")
SEXES = ("M", "F")


def records() -> list[dict]:
    out = []
    with gzip.open(VCF, "rt") as inp:
        for line in inp:
            if line.startswith("#"):
                continue
            chrom, pos, _vid, ref, alt, _qual, filt, info = line.rstrip("\n").split(
                "\t"
            )
            fields = dict(kv.split("=", 1) for kv in info.split(";") if "=" in kv)
            out.append(
                {
                    "chrom": chrom,
                    "pos": int(pos),
                    "ref": ref,
                    "alt": alt,
                    "filter": filt,
                    **fields,
                }
            )
    return out


class Reproducibility(unittest.TestCase):
    def test_committed_fixture_is_what_the_generator_writes(self) -> None:
        seed = load_module("scripts/gen-sample-vcf.py", "gen_sample_vcf").DEFAULT_SEED
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "regen.vcf.gz"
            expected = Path(tmp) / "regen.json"
            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    "generate",
                    "--sites",
                    str(SITES),
                    "--seed",
                    str(seed),
                    "--out",
                    str(out),
                    "--expected",
                    str(expected),
                ],
                check=True,
                capture_output=True,
            )
            with gzip.open(out, "rb") as regen, gzip.open(VCF, "rb") as committed:
                self.assertEqual(
                    regen.read(),
                    committed.read(),
                    "the committed sample VCF is not what the generator writes from the "
                    "committed site list and seed; regenerate it, or the sidecar, so the "
                    "script and the fixture move together",
                )
            self.assertEqual(
                json.loads(expected.read_text()), json.loads(EXPECTED.read_text())
            )

    def test_fixture_is_bgzf(self) -> None:
        # The converter's preflight requires BGZF (a `BC` extra field), not plain gzip.
        head = VCF.read_bytes()[:18]
        self.assertEqual(head[:4], b"\x1f\x8b\x08\x04")
        self.assertEqual(head[12:14], b"BC")


class Coherence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = records()
        cls.expected = json.loads(EXPECTED.read_text())

    def test_sidecar_counts_the_records(self) -> None:
        self.assertEqual(len(self.records), self.expected["records"])
        self.assertTrue(all(r["filter"] == "PASS" for r in self.records))
        self.assertEqual(
            len({(r["chrom"], r["pos"], r["ref"], r["alt"]) for r in self.records}),
            self.expected["records"],
            "every record is a distinct (chrom, pos, ref, alt)",
        )

    def test_every_stratum_partitions_ac_and_agrees_with_af(self) -> None:
        groups = [""] + [f"_{g}" for g in self.expected["populations"] if g != "Total"]
        for r in self.records:
            for suffix in groups:
                ac, an = int(r[f"AC{suffix}"]), int(r[f"AN{suffix}"])
                hom, het, hemi = (
                    int(r[f"AC_{k}{suffix}"]) for k in ("Hom", "Het", "Hemi")
                )
                where = (
                    f"{r['chrom']}:{r['pos']} {r['ref']}>{r['alt']} {suffix or 'Total'}"
                )
                self.assertEqual(
                    hom + het + hemi, ac, f"{where}: sub-counts must partition AC"
                )
                self.assertLessEqual(ac, an, f"{where}: AC exceeds AN")
                af = r[f"AF{suffix}"]
                if an == 0:
                    self.assertEqual(
                        af, ".", f"{where}: AF must be missing when AN is 0"
                    )
                    self.assertEqual(ac, 0, where)
                else:
                    self.assertEqual(
                        af, f"{ac / an:g}", f"{where}: AF is not AC/AN at six digits"
                    )
                    self.assertLessEqual(abs(round(float(af) * an) - ac), 1, where)

    def test_axes_sum_to_the_cohort(self) -> None:
        cohort = self.expected["cohort"]
        for r in self.records:
            where = f"{r['chrom']}:{r['pos']} {r['ref']}>{r['alt']}"
            for tag in ("AN", "AC", "NS"):
                total = int(r[tag])
                self.assertEqual(
                    sum(int(r[f"{tag}_{s}"]) for s in SEXES),
                    total,
                    f"{where}: {tag} by sex",
                )
                self.assertEqual(
                    sum(int(r[f"{tag}_{c}"]) for c in COUNTRIES),
                    total,
                    f"{where}: {tag} by country",
                )
                for c in COUNTRIES:
                    self.assertEqual(
                        sum(int(r[f"{tag}_{c}_{s}"]) for s in SEXES),
                        int(r[f"{tag}_{c}"]),
                        f"{where}: {tag} {c} by sex",
                    )
            for c in COUNTRIES:
                for s in SEXES:
                    self.assertLessEqual(
                        int(r[f"NS_{c}_{s}"]),
                        cohort[c][s],
                        f"{where}: NS_{c}_{s} exceeds the stratum",
                    )

    def test_sex_chromosomes_are_hemizygous_where_they_should_be(self) -> None:
        par1, par2 = (10001, 2781479), (155701383, 156030895)
        for r in self.records:
            where = f"{r['chrom']}:{r['pos']}"
            if r["chrom"] == "chrY":
                self.assertEqual(int(r["AN_F"]), 0, f"{where}: females carry no Y")
                self.assertEqual(r["AF_F"], ".", where)
                self.assertEqual(
                    int(r["AC_Hom"]) + int(r["AC_Het"]), 0, f"{where}: Y is haploid"
                )
            elif r["chrom"] == "chrM":
                self.assertEqual(
                    int(r["AC_Hom"]) + int(r["AC_Het"]), 0, f"{where}: M is haploid"
                )
                self.assertEqual(
                    int(r["AN"]), int(r["NS"]), f"{where}: one copy per sample"
                )
            elif r["chrom"] == "chrX":
                in_par = (
                    par1[0] <= r["pos"] <= par1[1] or par2[0] <= r["pos"] <= par2[1]
                )
                if in_par:
                    self.assertEqual(
                        int(r["AN_M"]),
                        2 * int(r["NS_M"]),
                        f"{where}: PAR is diploid in males",
                    )
                else:
                    self.assertEqual(
                        int(r["AN_M"]),
                        int(r["NS_M"]),
                        f"{where}: non-PAR X is haploid in males",
                    )
                    self.assertEqual(int(r["AC_Hom_M"]) + int(r["AC_Het_M"]), 0, where)
            else:
                self.assertEqual(
                    int(r["AC_Hemi"]), 0, f"{where}: an autosome has no hemizygotes"
                )
                self.assertEqual(int(r["AN"]), 2 * int(r["NS"]), where)

    def test_sidecar_aggregates_are_recomputable_from_the_records(self) -> None:
        rows = dict.fromkeys(self.expected["populations"], 0)
        af_zero = 0
        for r in self.records:
            for pop in rows:
                suffix = "" if pop == "Total" else f"_{pop}"
                if int(r[f"AN{suffix}"]) > 0:
                    rows[pop] += 1
            if int(r["AN"]) > 0 and int(r["AC"]) == 0:
                af_zero += 1
        self.assertEqual(rows, self.expected["rowsPerPopulation"])
        self.assertEqual(sum(rows.values()), self.expected["rowsEmitted"])
        self.assertEqual(af_zero, self.expected["totalAfZeroVariants"])
        self.assertEqual(
            max(int(r["NS"]) for r in self.records), self.expected["nsPeak"]
        )


class SyntheticMode(unittest.TestCase):
    """`generate --synthetic-sites N` needs no site list, and what it writes does not
    depend on `--jobs`: chunks are cut by a fixed size, chunk 0 draws from `Random(seed)`
    and every later chunk from its own seed, so a parallel run and a serial run must write
    the same bytes. Sorted output, one contig order, and a sidecar that counts the records
    are what the converter relies on."""

    def test_output_is_job_count_independent_and_sorted(self) -> None:
        gen = load_module("scripts/gen-sample-vcf.py", "gen_sample_vcf")
        with tempfile.TemporaryDirectory() as tmp:
            runs = []
            for jobs in (1, 3):
                out = Path(tmp) / f"jobs{jobs}.vcf.gz"
                sidecar = Path(tmp) / f"jobs{jobs}.json"
                subprocess.run(
                    [
                        sys.executable,
                        str(GENERATOR),
                        "generate",
                        "--synthetic-sites",
                        "300",
                        "--jobs",
                        str(jobs),
                        "--out",
                        str(out),
                        "--expected",
                        str(sidecar),
                    ],
                    check=True,
                    capture_output=True,
                )
                runs.append((out.read_bytes(), json.loads(sidecar.read_text())))
            (data, expected), (data3, expected3) = runs
            self.assertEqual(data, data3)
            self.assertEqual(expected, expected3)
            self.assertEqual(data[-28:], gen.bgzf_block(b""))
            lines = gzip.decompress(data).decode().splitlines()
            recs = [line.split("\t") for line in lines if not line.startswith("#")]
            self.assertEqual(len(recs), expected["records"])
            self.assertTrue(all(r[6] == "PASS" for r in recs))
            keys = [(gen.CONTIG_ORDER[r[0]], int(r[1])) for r in recs]
            self.assertEqual(keys, sorted(keys))
            self.assertEqual(len(keys), len(set(keys)))
            self.assertGreaterEqual(len({r[0] for r in recs}), 24)


if __name__ == "__main__":
    unittest.main()
