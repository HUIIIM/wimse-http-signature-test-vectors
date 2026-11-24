"""Deterministic signing and verification for the regen self-check.

Ed25519 is deterministic by construction (RFC 8032).  ES256 re-signing
uses the RFC 6979 section 3.2 deterministic nonce generation with
HMAC-SHA256 over NIST P-256, so the same input yields the same signature
bytes; the signature value form is the raw ``r || s`` concatenation used
by the vector set.  No low-S normalisation is applied: RFC 6979 does not
prescribe one, and the set's published ES256 values were produced with a
plain RFC 6979 pipeline (source section 0 evidence).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicNumbers,
    derive_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from selfcheck.regen.keys import P256_ORDER, DerivedKey, b64url_decode

QLEN = 256  # bit length of the P-256 group order
ROLEN = 32  # octet length of the P-256 group order


def _bits2int(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - QLEN
    if excess > 0:
        value >>= excess
    return value


def _bits2octets(data: bytes) -> bytes:
    z1 = _bits2int(data)
    z2 = z1 - P256_ORDER if z1 >= P256_ORDER else z1
    return z2.to_bytes(ROLEN, "big")


def rfc6979_nonce_stream(private_scalar: int, message: bytes) -> Iterator[int]:
    """Yield candidate deterministic nonces per RFC 6979 section 3.2."""
    digest = hashlib.sha256(message).digest()
    bx = private_scalar.to_bytes(ROLEN, "big") + _bits2octets(digest)
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b""
        while len(t) < ROLEN:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        candidate = _bits2int(t)
        if 1 <= candidate <= P256_ORDER - 1:
            yield candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def es256_sign_deterministic(key: DerivedKey, message: bytes) -> bytes:
    """Sign with ES256 using the RFC 6979 deterministic nonce.

    Returns the raw ``r || s`` signature (64 bytes).
    """
    private = key.signing_key()
    if not isinstance(private, EllipticCurvePrivateKey):
        raise TypeError("ES256 signing requires an EC key")
    scalar = private.private_numbers().private_value
    e = _bits2int(hashlib.sha256(message).digest())
    for nonce in rfc6979_nonce_stream(scalar, message):
        ephemeral = derive_private_key(nonce, SECP256R1())
        r = ephemeral.public_key().public_numbers().x % P256_ORDER
        if r == 0:
            continue
        s = (pow(nonce, -1, P256_ORDER) * (e + r * scalar)) % P256_ORDER
        if s == 0:
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise AssertionError("unreachable")


def sign(key: DerivedKey, message: bytes) -> bytes:
    """Deterministically sign ``message`` with the derived key."""
    if key.alg == "Ed25519":
        private = key.signing_key()
        if not isinstance(private, Ed25519PrivateKey):
            raise TypeError("Ed25519 signing requires an Ed25519 key")
        return private.sign(message)
    if key.alg == "ES256":
        return es256_sign_deterministic(key, message)
    raise ValueError(f"unsupported alg: {key.alg}")


def verify(key: DerivedKey, signature: bytes, message: bytes) -> bool:
    """Verify a raw signature under the derived key's public part."""
    if key.alg == "Ed25519":
        public = Ed25519PublicKey.from_public_bytes(
            b64url_decode(key.public_jwk["x"])
        )
        try:
            public.verify(signature, message)
            return True
        except InvalidSignature:
            return False
    if key.alg == "ES256":
        if len(signature) != 64:
            return False
        numbers = EllipticCurvePublicNumbers(
            x=int.from_bytes(b64url_decode(key.public_jwk["x"]), "big"),
            y=int.from_bytes(b64url_decode(key.public_jwk["y"]), "big"),
            curve=SECP256R1(),
        )
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            numbers.public_key().verify(
                encode_dss_signature(r, s), message, ECDSA(SHA256())
            )
            return True
        except InvalidSignature:
            return False
    raise ValueError(f"unsupported alg: {key.alg}")


def decode_stored_signature(value: str) -> bytes:
    """Decode a signature value as stored in the vector set (base64)."""
    return base64.b64decode(value)


def encode_signature_value(signature: bytes) -> str:
    """Encode a signature in the vector set's stored form (base64)."""
    return base64.b64encode(signature).decode("ascii")
