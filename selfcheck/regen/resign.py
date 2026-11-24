"""Literal-base re-signing checks (batch item 2).

For every positive vector and for N-15, the set publishes the literal
signature base (``signature_base_provided``) and the literal signature
value.  Re-signing the literal base with the signer's re-derived key
must reproduce the stored signature byte-for-byte: Ed25519 directly,
ES256 through the RFC 6979 deterministic pipeline (design section 4.6).

Only literal bases are used.  No signature base is reconstructed here;
reconstruction belongs to the BASE stage and is out of this batch.
"""

from __future__ import annotations

from selfcheck.regen.keys import DerivedKey, derive_key
from selfcheck.regen.signing import decode_stored_signature, sign

# Signer of each stored signature, per the set's materials references and
# the WIT cnf bindings: P-06 sig1 is the decoy signed by the "other" key
# (its @signature-params carry keyid="other-key"); N-15 is signed by svcC
# (ES256) although its WIT binds svcA -- that mismatch is the vector's
# E_ALG_BINDING point, and reproducing it is part of this check.
SIGNERS: dict[tuple[str, str], str] = {
    ("P-01", "sig1"): "svcA",
    ("P-02", "sig1"): "svcB",
    ("P-03", "sig1"): "svcC",
    ("P-04", "sig1"): "svcA",
    ("P-05", "sig1"): "svcA",
    ("P-06", "sig1"): "other",
    ("P-06", "sig2"): "svcA",
    ("N-15", "sig1"): "svcC",
}

ALGS: dict[str, str] = {
    "issuer": "Ed25519",
    "svcA": "Ed25519",
    "svcB": "Ed25519",
    "svcC": "ES256",
    "other": "Ed25519",
}


def derived_keys() -> dict[str, DerivedKey]:
    """Re-derive the full key set once, keyed by key name."""
    return {name: derive_key(name, alg) for name, alg in ALGS.items()}


def check_resign(vectors: list[dict], keys: dict[str, DerivedKey]) -> list[dict]:
    """Re-sign every in-scope literal base and compare byte-for-byte."""
    by_id = {vector["id"]: vector for vector in vectors}
    checks: list[dict] = []
    for (vector_id, label), signer_name in sorted(SIGNERS.items()):
        vector = by_id[vector_id]
        base_text = vector["signature_base_provided"][label]
        stored = next(
            entry["value"]
            for entry in vector["signatures"]
            if entry["label"] == label
        )
        key = keys[signer_name]
        regenerated = sign(key, base_text.encode("utf-8"))
        match = regenerated == decode_stored_signature(stored)
        checks.append(
            {
                "vector": vector_id,
                "label": label,
                "signer": signer_name,
                "alg": key.alg,
                "byte_match": match,
                "verdict": "PASS" if match else "FAIL",
            }
        )
    return checks
