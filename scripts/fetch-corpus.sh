#!/usr/bin/env bash
# scripts/fetch-corpus.sh — fetch the real-data conformance corpus.
#
# The hand-built fixtures cannot exercise real cardinality, real INFO-field variety, real
# multi-allelic representation, or real line width: the in-repo COVID fixture the
# population machinery is tested against holds a single data record. Whole classes of
# defect live in that gap, from k-anonymity collapse on `AN = 0` sites to silent variant
# loss and non-minimal allele storage.
#
# So the gate gets two real slices, pinned by content:
#
#   1000 Genomes phase 3, chr21   — GRCh37, unprefixed contig, 2504 genotype columns
#                                   (a ~10 KB line whose INFO is 1.1%), the suffix
#                                   population convention (`EAS_AF`), symbolic SV ALTs,
#                                   multi-allelic lines, non-left-aligned alleles.
#   gnomAD v4.1 genomes, chr21    — GRCh38, `chr` prefix, 240 INFO definitions, sites-only
#                                   (a ~4.9 KB line that is 99.2% INFO), `AN = 0` sites,
#                                   77% non-PASS.
#
# Data sources and terms. Neither slice is redistributed: `corpus/` is gitignored, nothing
# in a release or an image contains this data, and the leg that uses it fetches on demand.
# Cite the sources if you publish anything derived from them.
#
#   1000 Genomes / IGSR  https://www.internationalgenome.org/IGSR_disclaimer
#                        Available without embargo. IGSR asks that use of the data be
#                        cited in the usual way, and notes that rights claimed over
#                        individual pieces of data within IGSR vary.
#   gnomAD v4.1          https://gnomad.broadinstitute.org/terms
#                        Released for use without restriction. It is *not* CC0 and carries
#                        no SPDX identifier, so describe it by its terms rather than
#                        labelling it with a licence.
#
# The gnomAD slice is sites-only aggregate; the 1000 Genomes slice is individual-level
# genotype data from consented, openly published reference samples.
#
# Both hosts honour HTTP range requests, so a slice is a deterministic prefix of the
# object. BGZF is a concatenation of self-contained deflate blocks, so a byte prefix
# decompresses on its own. It does land mid-record, and the resulting partial last line
# looks exactly like a parser bug, so `bgzf_prefix` drops it and keeps only whole lines.
# That trimming is what makes the sha256s below reproducible.
#
# Usage:
#   scripts/fetch-corpus.sh [DEST]     # default DEST: ./corpus
#
# Then:
#   GDI_CORPUS_DIR=$PWD/corpus cargo test -p gdi-node-standalone-core --test corpus
#
# Re-running is a no-op when the files are present and verify.

set -euo pipefail

DEST="${1:-corpus}"

KG_URL='https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502/ALL.chr21.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz'
KG_BYTES=1500000
KG_OUT="$DEST/kg.chr21.slice.vcf"
KG_SHA='8ed107649e0eb9c4b0319cb898b0353d663cd73fd1e9e8c6c5be26aa1573e726'

GN_URL='https://storage.googleapis.com/gcp-public-data--gnomad/release/4.1/vcf/genomes/gnomad.genomes.v4.1.sites.chr21.vcf.bgz'
GN_BYTES=12000000
GN_OUT="$DEST/gnomad.chr21.slice.vcf"
GN_SHA='8d35c50fd2f8a5b7373a5d49c8a0397e5ad360043e5e1dd8a9f35e4f4c87bd90'

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null || die 'python3 is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'

mkdir -p "$DEST"

# Decompress the complete BGZF blocks of a byte prefix, then drop the partial trailing line.
bgzf_prefix() {
    local url="$1" nbytes="$2" out="$3"
    python3 - "$url" "$nbytes" "$out" <<'PY'
import sys, zlib, urllib.request

url, nbytes, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
req = urllib.request.Request(url, headers={'Range': f'bytes=0-{nbytes - 1}'})
with urllib.request.urlopen(req) as fh:
    buf = fh.read()

pos, blocks, chunks = 0, 0, []
while pos + 18 <= len(buf):
    if buf[pos:pos + 4] != b'\x1f\x8b\x08\x04':
        break                                   # not a BGZF block: stop cleanly
    xlen = int.from_bytes(buf[pos + 10:pos + 12], 'little')
    bsize, xp, xend = None, pos + 12, pos + 12 + xlen
    while xp < xend:                            # walk the extra subfields for 'BC'
        si1, si2 = buf[xp], buf[xp + 1]
        slen = int.from_bytes(buf[xp + 2:xp + 4], 'little')
        if (si1, si2) == (66, 67):
            bsize = int.from_bytes(buf[xp + 4:xp + 6], 'little') + 1
        xp += 4 + slen
    if bsize is None or pos + bsize > len(buf):
        break                                   # truncated final block
    chunks.append(zlib.decompress(buf[pos + 12 + xlen:pos + bsize - 8], -15))
    pos += bsize
    blocks += 1

data = b''.join(chunks)
# The prefix ends mid-record. Keep only whole lines, so the slice is a valid VCF and its
# digest is reproducible.
cut = data.rfind(b'\n')
if cut < 0:
    sys.exit('no complete line in the fetched prefix')
with open(out, 'wb') as fh:
    fh.write(data[:cut + 1])
print(f'{blocks} bgzf blocks -> {out} ({cut + 1} bytes)', file=sys.stderr)
PY
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

verify() {
    local out="$1" want="$2" name="$3"
    local got
    got="$(sha256_of "$out")"
    # No unpinned escape: a `__NAME_SHA__` placeholder is a failure, not a note. The
    # digests are the only thing that makes these fixtures reproducible, so accepting one
    # unpinned means accepting whatever bytes the network returned as the corpus.
    if [ "$want" = "__${name}_SHA__" ]; then
        die "$out has no pinned sha256; the placeholder ${want} is still in place. Its digest is $got. Pin that in this script rather than accepting whatever the network returned."
    fi
    [ "$got" = "$want" ] || die "$out sha256 $got != pinned $want, so the upstream object changed"
    printf 'ok: %s (sha256 %s)\n' "$out" "$got"
}

fetch() {
    local url="$1" bytes="$2" out="$3" sha="$4" name="$5"
    if [ -f "$out" ] && [ "$sha" != "__${name}_SHA__" ] \
        && [ "$(sha256_of "$out")" = "$sha" ]; then
        printf 'ok: %s already present\n' "$out"
        return 0
    fi
    printf '==> fetching %s bytes of %s\n' "$bytes" "$(basename "$url")"
    bgzf_prefix "$url" "$bytes" "$out"
    verify "$out" "$sha" "$name"
}

fetch "$KG_URL" "$KG_BYTES" "$KG_OUT" "$KG_SHA" KG
fetch "$GN_URL" "$GN_BYTES" "$GN_OUT" "$GN_SHA" GN

printf '\ncorpus ready in %s\n' "$DEST"
printf 'run: GDI_CORPUS_DIR=%s cargo test -p gdi-node-standalone-core --test corpus\n' "$(cd "$DEST" && pwd)"
