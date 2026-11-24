"""Anti-mixing firmware: old-base signatures (batch items 3 and 4).

The published (pre-correction) vector set carried a defect in the
``@query`` signature-base line of P-01, P-02, P-06 sig2 and N-15: the
value lacked the leading ``?`` required by RFC 9421 section 2.2.7
(source section 0, revision rows S1/T1).  The corrected set signs the
fixed bases.  The anti-mixing firmware (design section 4.6) pins the
old behaviour down as data:

- ``old_base``: the corrected literal base with the defect reintroduced
  (the ``?`` stripped from the ``@query`` line, nothing else changed).
- ``old_signature``: the deterministic signature over ``old_base``.
  Ed25519 and RFC 6979 ES256 signing are both deterministic, so this
  value is byte-identical to the signature published with the defective
  set; the set's own section 0 evidence records the same reproduction
  for the ES256 entries.

Item 3 verifies each old signature on its old base (pipeline-equivalence
evidence).  The corrected-base side -- old signatures must fail on the
corrected bases -- is prepared here as data only: its verdict fields are
explicitly null in this batch because rendering that verdict requires
the BASE-stage reconstruction chain, which is gated on open item U4
(the RFC 9421 section 2.5 normalisation detail for
``@signature-params``).  It is not judged here.
"""

from __future__ import annotations

import re

from selfcheck.regen.keys import DerivedKey
from selfcheck.regen.resign import SIGNERS
from selfcheck.regen.signing import (
    decode_stored_signature,
    encode_signature_value,
    sign,
    verify,
)

FIRMWARE_IDS: list[tuple[str, str]] = [
    ("P-01", "sig1"),
    ("P-02", "sig1"),
    ("P-06", "sig2"),
    ("N-15", "sig1"),
]

_QUERY_LINE = re.compile(r'^("@query"(?:;req)?: )\?flavor=vanilla$', re.MULTILINE)


def make_old_base(corrected_base: str) -> str:
    """Reintroduce the published defect into a corrected literal base.

    Strips the leading ``?`` from the ``@query`` line value; the result
    must differ from the input by exactly that one character.
    """
    old_base, replacements = _QUERY_LINE.subn(r"\1flavor=vanilla", corrected_base)
    if replacements != 1:
        raise ValueError("expected exactly one @query line to rewrite")
    if len(corrected_base) - len(old_base) != 1:
        raise ValueError("old base must differ by exactly one character")
    return old_base


def build_firmware(
    vectors: list[dict], keys: dict[str, DerivedKey]
) -> list[dict]:
    """Build the firmware entries (data preparation, batch item 4)."""
    by_id = {vector["id"]: vector for vector in vectors}
    entries: list[dict] = []
    for vector_id, label in FIRMWARE_IDS:
        vector = by_id[vector_id]
        corrected_base = vector["signature_base_provided"][label]
        old_base = make_old_base(corrected_base)
        signer_name = SIGNERS[(vector_id, label)]
        key = keys[signer_name]
        old_signature = sign(key, old_base.encode("utf-8"))
        entries.append(
            {
                "vector": vector_id,
                "label": label,
                "signer": signer_name,
                "alg": key.alg,
                "defect": (
                    "@query line value lacks the leading '?' "
                    "(RFC 9421 section 2.2.7; source section 0, S1/T1)"
                ),
                "corrected_base": corrected_base,
                "old_base": old_base,
                "old_signature": encode_signature_value(old_signature),
                "old_base_verdict": None,
                "corrected_base_verdict": None,
                "corrected_base_note": (
                    "PENDING U4: not judged in batch W2b. The verdict "
                    "(old signature must fail on the corrected base) is "
                    "rendered only after the BASE-stage reconstruction "
                    "chain is settled (open item U4, RFC 9421 section 2.5 "
                    "@signature-params normalisation)."
                ),
            }
        )
    return entries


def check_old_base_evidence(
    entries: list[dict], keys: dict[str, DerivedKey]
) -> list[dict]:
    """Verify each old signature on its old base (batch item 3)."""
    checks: list[dict] = []
    for entry in entries:
        key = keys[entry["signer"]]
        ok = verify(
            key,
            decode_stored_signature(entry["old_signature"]),
            entry["old_base"].encode("utf-8"),
        )
        entry["old_base_verdict"] = "PASS" if ok else "FAIL"
        checks.append(
            {
                "vector": entry["vector"],
                "label": entry["label"],
                "signer": entry["signer"],
                "alg": entry["alg"],
                "verifies_on_old_base": ok,
                "verdict": "PASS" if ok else "FAIL",
            }
        )
    return checks
