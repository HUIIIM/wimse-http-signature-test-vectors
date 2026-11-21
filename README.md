# wimse-http-signature-test-vectors

HTTP Message Signatures (RFC 9421) test vectors for the WIMSE workload-to-workload
signature profile, [draft-ietf-wimse-http-signature-08](https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/).
The set has positive and negative cases, an extraction log and a schema validator.

**Archival copy:** vector set v4 is archived on Zenodo, DOI
[10.5281/zenodo.24203971](https://doi.org/10.5281/zenodo.24203971). This repository is
the machine-readable working form of that same set. The previous version (v3, 28 vectors)
is DOI [10.5281/zenodo.24184599](https://doi.org/10.5281/zenodo.24184599).

## What this is

A conformance vector set for implementers of the WIMSE HTTP signature profile:

- **29 judged vectors**: 6 positive (`P-01`…`P-06`) and 23 negative.
  - 17 message-level negatives (`N-01`…`N-15`, `N-09b`, `N-21`). Each applies a single
    mutation to a positive vector and states its expected outcome, primary failing stage
    and any cascades.
  - 6 behaviour-level negatives (`N-16`…`N-20`, `N-22`). These are probes of sender,
    server or verifier behaviour, not single-message checks.
- **3 observation items** (`O-1`…`O-3`). They are recorded but never judged.
- Fixed clock: `T0 = 1795000000`. The default verification time is `T0+60`, and
  `expires` is always `created+300`. `N-09b` is a two-evaluation contrast vector
  (`T0+300` accept / `T0+301` reject) that pins the closed upper bound of the validity
  window.

The set was published for review on the WIMSE draft's GitHub issue #419 and the WIMSE
mailing list. It was revised after review by a draft co-author. Two independent
implementers reproduced earlier revisions of the set in full. v4 adds only the `N-09b`
boundary vector on top of v3. The revision history is in
`vectors/v4/source.md` §0.

This repository currently contains wave W1 (first cut): the canonical JSON form of the
set, the extraction log and the validator. A reference runner that executes each
vector's decision rule, plus CI, will follow in later waves.

## ⚠ Test keys only

Every key in this repository, private keys included, is **test-only**, fully published
and deterministically derived from a public seed string. Never use these keys for
anything other than reproducing these vectors.

## Layout

```
README.md
CITATION.cff
schema/
  vectors.schema.json      # JSON Schema (2020-12) for vectors.json
tools/
  extract_v4.py            # source.md -> vectors.json + extraction-log.md (deterministic)
  validate.py              # schema + set-level + source-fidelity validator
vectors/
  v4/
    source.md              # verbatim copy of the archived v4 set (MD5 5df4f19a8a4a7f0ddd0ff792d0f09bc4)
    vectors.json           # canonical machine-readable vectors + shared materials
    extraction-log.md      # per-vector trace back to source lines, plus reconciliation results
```

`vectors.json` holds:

- `materials`: keys, WITs, trusted configuration and clock.
- `vectors`: the 29 judged entries.
- `observations`: the 3 unjudged items.

Every entry carries a `source_anchor`: the source MD5 plus line range. This lets you
trace each field back to the archived text.

## Run the validator

Requires Python 3.8+ and nothing else. If the `jsonschema` package happens to be
installed, it is used as a second, independent schema check.

```sh
python3 tools/validate.py
```

Expected last line:

```
RESULT: PASS — vectors.json set v4: 29 vectors (6 positive / 23 negative), 3 observations
```

To regenerate `vectors.json` from the source and confirm the output is byte-identical:

```sh
python3 tools/extract_v4.py vectors/v4/source.md --out vectors/v4
git diff --exit-code vectors/v4/vectors.json
```

The extraction log in the repository was produced with two optional extra checks:
`--supplement` (the A-11 quote supplement) and `--draft` (the draft-08 text).
Regenerating without those flags gives the same `vectors.json`, but the log omits those
two result lines.

## Citation

Cite the archived vector set: Miao, Jiahui. *Test Vectors for the WIMSE S2S Protocol
HTTP Signature Scheme — v4*. Zenodo, 2026. DOI 10.5281/zenodo.24203971.
Machine-readable metadata is in [`CITATION.cff`](CITATION.cff).

The vector data is licensed CC-BY-4.0, the same as the archived set. The code in this repository (tools/) is licensed under the MIT License - see [`LICENSE`](LICENSE).

## Versioning and maintenance

Each vector set version maps to exactly one draft version (v4 ↔ draft-08). When the
draft is revised (for example to -09), the vector set is revised first. This repository
follows: new source, new MD5, re-extraction, and a reconciled count. Earlier versions
stay in place under `vectors/<version>/`. Corrections are tracked on issue #419 of the
draft's repository.
