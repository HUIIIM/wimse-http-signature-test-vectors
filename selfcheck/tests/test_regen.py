"""Tests for the regen self-check (batch W2b).

Run from the repository root:

    python3 -m pytest selfcheck/tests -q

The tests read the published v4 vector set from ``vectors/v4/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from selfcheck.regen.firmware import build_firmware, make_old_base
from selfcheck.regen.keys import check_key_rederivation, derive_key
from selfcheck.regen.resign import check_resign, derived_keys
from selfcheck.regen.run_regen import run
from selfcheck.regen.signing import sign

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS_PATH = REPO_ROOT / "vectors" / "v4" / "vectors.json"


@pytest.fixture(scope="module")
def data() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_key_rederivation_all_match(data: dict) -> None:
    checks = check_key_rederivation(data["materials"])
    assert len(checks) == 5
    assert all(check["verdict"] == "PASS" for check in checks)


def test_svcc_scalar_derivation(data: dict) -> None:
    entry = next(k for k in data["materials"]["keys"] if k["name"] == "svcC")
    derived = derive_key("svcC", "ES256")
    assert derived.private_d == entry["private_d"]
    assert derived.public_jwk["x"] == entry["public_jwk"]["x"]
    assert derived.public_jwk["y"] == entry["public_jwk"]["y"]


def test_resign_all_byte_match(data: dict) -> None:
    checks = check_resign(data["vectors"], derived_keys())
    assert len(checks) == 8  # 7 positive signatures + N-15
    assert all(check["verdict"] == "PASS" for check in checks)


def test_es256_resign_is_deterministic(data: dict) -> None:
    vector = next(v for v in data["vectors"] if v["id"] == "P-03")
    base = vector["signature_base_provided"]["sig1"].encode("utf-8")
    key = derive_key("svcC", "ES256")
    assert sign(key, base) == sign(key, base)


def test_old_base_differs_by_exactly_the_question_mark(data: dict) -> None:
    vector = next(v for v in data["vectors"] if v["id"] == "P-01")
    corrected = vector["signature_base_provided"]["sig1"]
    old = make_old_base(corrected)
    assert corrected.replace("?flavor=vanilla", "flavor=vanilla") == old
    assert len(corrected) - len(old) == 1


def test_firmware_corrected_verdicts_pending_u4(data: dict) -> None:
    entries = build_firmware(data["vectors"], derived_keys())
    assert len(entries) == 4
    for entry in entries:
        assert entry["corrected_base_verdict"] is None
        assert "PENDING U4" in entry["corrected_base_note"]


def test_full_report_passes() -> None:
    report, _firmware = run(VECTORS_PATH)
    assert report["summary"]["overall"] == "PASS"
    assert report["summary"]["fail"] == 0
    assert report["summary"]["judged_checks"] == 5 + 8 + 4
