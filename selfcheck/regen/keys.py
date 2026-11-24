"""Key re-derivation from the vector set's published derivation rules.

The set's materials block fixes the derivation (design section 2.3 /
vectors.json ``materials.key_derivation``):

- Ed25519 keys: ``seed = SHA-256("s01-validation-vectors:<name>")`` and
  the JWK ``d`` is ``base64url(seed)``.
- The ES256 key (svcC): ``scalar = SHA-256("s01-validation-vectors:svcC")
  mod (n-1) + 1`` over the P-256 group order ``n``.

All key material is test-only and fully published in the set.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED_PREFIX = "s01-validation-vectors:"
P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)

SigningKey = Ed25519PrivateKey | EllipticCurvePrivateKey


def b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding (JWK form)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode base64url, tolerating missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def seed_for(name: str) -> bytes:
    """Return the SHA-256 seed bytes for a named key."""
    return hashlib.sha256((SEED_PREFIX + name).encode("ascii")).digest()


@dataclass(frozen=True)
class DerivedKey:
    """A key re-derived from the set's seed material."""

    name: str
    alg: str
    private_d: str  # JWK form: base64url, no padding
    public_jwk: dict[str, str]  # coordinate fields only (x, or x and y)

    def signing_key(self) -> SigningKey:
        """Return the private key object for signing."""
        if self.alg == "Ed25519":
            return Ed25519PrivateKey.from_private_bytes(
                b64url_decode(self.private_d)
            )
        scalar = int.from_bytes(b64url_decode(self.private_d), "big")
        return derive_private_key(scalar, SECP256R1())


def derive_key(name: str, alg: str) -> DerivedKey:
    """Re-derive one key from its seed per the set's derivation rules."""
    seed = seed_for(name)
    if alg == "Ed25519":
        private = Ed25519PrivateKey.from_private_bytes(seed)
        raw_public = private.public_key().public_bytes_raw()
        return DerivedKey(
            name=name,
            alg=alg,
            private_d=b64url_encode(seed),
            public_jwk={"x": b64url_encode(raw_public)},
        )
    if alg == "ES256":
        scalar = int.from_bytes(seed, "big") % (P256_ORDER - 1) + 1
        private = derive_private_key(scalar, SECP256R1())
        numbers = private.public_key().public_numbers()
        return DerivedKey(
            name=name,
            alg=alg,
            private_d=b64url_encode(scalar.to_bytes(32, "big")),
            public_jwk={
                "x": b64url_encode(numbers.x.to_bytes(32, "big")),
                "y": b64url_encode(numbers.y.to_bytes(32, "big")),
            },
        )
    raise ValueError(f"unsupported alg: {alg}")


def check_key_rederivation(materials: dict) -> list[dict]:
    """Re-derive every key in the materials block and compare to the JWKs.

    Returns one check record per key: the derived public JWK coordinate
    fields and the private ``d`` must match the set's published values
    exactly (string equality on the base64url forms).
    """
    checks: list[dict] = []
    for entry in materials["keys"]:
        derived = derive_key(entry["name"], entry["alg"])
        published = entry["public_jwk"]
        public_match = all(
            derived.public_jwk[field] == published[field]
            for field in derived.public_jwk
        )
        private_match = derived.private_d == entry["private_d"]
        checks.append(
            {
                "key": entry["name"],
                "alg": entry["alg"],
                "public_jwk_match": public_match,
                "private_d_match": private_match,
                "verdict": "PASS" if public_match and private_match else "FAIL",
            }
        )
    return checks
