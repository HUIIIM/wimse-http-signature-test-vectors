# Self-checks

Regeneration self-checks for the vector set (design section 4.6),
implemented in `selfcheck/regen/`:

- **key re-derivation** -- every key is re-derived from the set's seed
  rules and compared byte-for-byte with the published JWK material;
- **literal-base re-signing** -- each published literal signature base
  (the positives and N-15) is re-signed with the re-derived keys
  (Ed25519 directly, ES256 via RFC 6979 deterministic nonces) and
  compared byte-for-byte with the stored signature;
- **anti-mixing firmware** -- `anti-mixing/old-base-signatures.json`
  pins the pre-correction (`@query` without the leading `?`) bases and
  their deterministic signatures as data; the old signatures are
  verified on the old bases. The corrected-base verdicts are null
  pending open item U4 and are not judged by this batch.

Run from the repository root (requires Python 3.11+ and the
`cryptography` package):

```sh
python3 -m selfcheck.regen.run_regen \
    --vectors vectors/v4/vectors.json \
    --firmware-out selfcheck/anti-mixing/old-base-signatures.json \
    --report-json reports/regen-report-v4.json \
    --report-md reports/regen-report-v4.md
python3 -m pytest selfcheck/tests -q
```

The runner exits non-zero if any judged check fails. Reports carry no
wall-clock timestamp: the same vector set yields the same report bytes.
