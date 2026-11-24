# Regen self-check report

- Set: v4 / draft-ietf-wimse-http-signature-08
- Vectors MD5: `b08b4063023d6194d90d273ce343e1af`
- Overall: **PASS** (17/17 judged checks pass)

Scope: Batch W2b scope: key re-derivation, literal-base re-signing, old-base anti-mixing evidence, firmware data preparation, merged report. NOT in this batch: any verdict that requires reconstructing a signature base through the BASE stage (the corrected-base side of the anti-mixing firmware); that chain is gated on open item U4 (RFC 9421 section 2.5 @signature-params normalisation) and its verdict fields are explicitly null in the firmware data.

## key-rederivation -- PASS

Re-derive every key from the set's seed rules; the public JWK coordinates and private d must match the published materials byte-for-byte.

- [PASS] key=issuer, alg=Ed25519, public_jwk_match=True, private_d_match=True
- [PASS] key=svcA, alg=Ed25519, public_jwk_match=True, private_d_match=True
- [PASS] key=svcB, alg=Ed25519, public_jwk_match=True, private_d_match=True
- [PASS] key=svcC, alg=ES256, public_jwk_match=True, private_d_match=True
- [PASS] key=other, alg=Ed25519, public_jwk_match=True, private_d_match=True

## literal-base-resign -- PASS

Re-sign each literal signature base (positives and N-15) with the signer's re-derived key; Ed25519 directly, ES256 via RFC 6979; byte-for-byte match with the stored signature required.

- [PASS] vector=N-15, label=sig1, signer=svcC, alg=ES256, byte_match=True
- [PASS] vector=P-01, label=sig1, signer=svcA, alg=Ed25519, byte_match=True
- [PASS] vector=P-02, label=sig1, signer=svcB, alg=Ed25519, byte_match=True
- [PASS] vector=P-03, label=sig1, signer=svcC, alg=ES256, byte_match=True
- [PASS] vector=P-04, label=sig1, signer=svcA, alg=Ed25519, byte_match=True
- [PASS] vector=P-05, label=sig1, signer=svcA, alg=Ed25519, byte_match=True
- [PASS] vector=P-06, label=sig1, signer=other, alg=Ed25519, byte_match=True
- [PASS] vector=P-06, label=sig2, signer=svcA, alg=Ed25519, byte_match=True

## anti-mixing-old-base-evidence -- PASS

Each old (pre-correction) signature verifies on its old base: pipeline-equivalence evidence for the anti-mixing firmware.

- [PASS] vector=P-01, label=sig1, signer=svcA, alg=Ed25519, verifies_on_old_base=True
- [PASS] vector=P-02, label=sig1, signer=svcB, alg=Ed25519, verifies_on_old_base=True
- [PASS] vector=P-06, label=sig2, signer=svcA, alg=Ed25519, verifies_on_old_base=True
- [PASS] vector=N-15, label=sig1, signer=svcC, alg=ES256, verifies_on_old_base=True

## anti-mixing-firmware-data -- PREPARED

Firmware entries prepared as structured data for both sides; corrected-base verdict fields are null pending U4 (not judged in this batch).

- entries: 4; corrected-base verdicts: null (pending U4)

