"""Regen self-check runner: merges batch items 1-4 into one report.

Usage (from the repository root):

    python3 -m selfcheck.regen.run_regen \
        --vectors vectors/v4/vectors.json \
        --firmware-out selfcheck/anti-mixing/old-base-signatures.json \
        --report-json reports/regen-report-v4.json \
        --report-md reports/regen-report-v4.md

Exit code is 0 when every judged check passes, 1 otherwise.  The report
carries no wall-clock timestamp (determinism, design section 4.5): the
same vector set yields the same report bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from selfcheck.regen.firmware import build_firmware, check_old_base_evidence
from selfcheck.regen.keys import check_key_rederivation
from selfcheck.regen.resign import check_resign, derived_keys

SCOPE_NOTE = (
    "Batch W2b scope: key re-derivation, literal-base re-signing, "
    "old-base anti-mixing evidence, firmware data preparation, merged "
    "report. NOT in this batch: any verdict that requires reconstructing "
    "a signature base through the BASE stage (the corrected-base side of "
    "the anti-mixing firmware); that chain is gated on open item U4 "
    "(RFC 9421 section 2.5 @signature-params normalisation) and its "
    "verdict fields are explicitly null in the firmware data."
)


def _verdict(checks: list[dict]) -> str:
    return "PASS" if all(check["verdict"] == "PASS" for check in checks) else "FAIL"


def _counts(checks: list[dict]) -> dict[str, int]:
    passed = sum(1 for check in checks if check["verdict"] == "PASS")
    return {"total": len(checks), "pass": passed, "fail": len(checks) - passed}


def run(vectors_path: Path) -> tuple[dict, list[dict]]:
    """Execute items 1-4 and return (report, firmware entries)."""
    raw = vectors_path.read_bytes()
    data = json.loads(raw)
    keys = derived_keys()

    key_checks = check_key_rederivation(data["materials"])
    resign_checks = check_resign(data["vectors"], keys)
    firmware = build_firmware(data["vectors"], keys)
    old_base_checks = check_old_base_evidence(firmware, keys)

    judged = key_checks + resign_checks + old_base_checks
    report = {
        "report": "regen",
        "set_version": data["set_version"],
        "draft_version": data["draft_version"],
        "scope": SCOPE_NOTE,
        "fingerprints": {
            "vectors_file": vectors_path.name,
            "vectors_md5": hashlib.md5(raw).hexdigest(),
            "vectors_sha256": hashlib.sha256(raw).hexdigest(),
        },
        "items": [
            {
                "item": "key-rederivation",
                "description": (
                    "Re-derive every key from the set's seed rules; the "
                    "public JWK coordinates and private d must match the "
                    "published materials byte-for-byte."
                ),
                "verdict": _verdict(key_checks),
                "counts": _counts(key_checks),
                "checks": key_checks,
            },
            {
                "item": "literal-base-resign",
                "description": (
                    "Re-sign each literal signature base (positives and "
                    "N-15) with the signer's re-derived key; Ed25519 "
                    "directly, ES256 via RFC 6979; byte-for-byte match "
                    "with the stored signature required."
                ),
                "verdict": _verdict(resign_checks),
                "counts": _counts(resign_checks),
                "checks": resign_checks,
            },
            {
                "item": "anti-mixing-old-base-evidence",
                "description": (
                    "Each old (pre-correction) signature verifies on its "
                    "old base: pipeline-equivalence evidence for the "
                    "anti-mixing firmware."
                ),
                "verdict": _verdict(old_base_checks),
                "counts": _counts(old_base_checks),
                "checks": old_base_checks,
            },
            {
                "item": "anti-mixing-firmware-data",
                "description": (
                    "Firmware entries prepared as structured data for "
                    "both sides; corrected-base verdict fields are null "
                    "pending U4 (not judged in this batch)."
                ),
                "verdict": "PREPARED",
                "entries": len(firmware),
                "corrected_base_verdicts": "null (pending U4)",
            },
        ],
        "summary": {
            "judged_checks": len(judged),
            "pass": sum(1 for check in judged if check["verdict"] == "PASS"),
            "fail": sum(1 for check in judged if check["verdict"] != "PASS"),
            "overall": _verdict(judged),
        },
    }
    return report, firmware


def render_markdown(report: dict) -> str:
    """Render the human-readable regen report."""
    lines = [
        "# Regen self-check report",
        "",
        f"- Set: {report['set_version']} / {report['draft_version']}",
        f"- Vectors MD5: `{report['fingerprints']['vectors_md5']}`",
        (
            f"- Overall: **{report['summary']['overall']}** "
            f"({report['summary']['pass']}/{report['summary']['judged_checks']} "
            "judged checks pass)"
        ),
        "",
        f"Scope: {report['scope']}",
        "",
    ]
    for item in report["items"]:
        lines.append(f"## {item['item']} -- {item['verdict']}")
        lines.append("")
        lines.append(item["description"])
        lines.append("")
        if "checks" in item:
            for check in item["checks"]:
                detail = ", ".join(
                    f"{name}={value}"
                    for name, value in check.items()
                    if name not in {"verdict"}
                )
                lines.append(f"- [{check['verdict']}] {detail}")
            lines.append("")
        if item["item"] == "anti-mixing-firmware-data":
            lines.append(
                f"- entries: {item['entries']}; corrected-base verdicts: "
                f"{item['corrected_base_verdicts']}"
            )
            lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the regen self-check.")
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--firmware-out", type=Path, required=True)
    parser.add_argument("--report-json", type=Path, required=True)
    parser.add_argument("--report-md", type=Path, required=True)
    args = parser.parse_args(argv)

    report, firmware = run(args.vectors)

    firmware_doc = {
        "firmware": "anti-mixing-old-base-signatures",
        "set_version": report["set_version"],
        "note": (
            "Old-base signatures for the anti-mixing self-check (design "
            "section 4.6). corrected_base_verdict is null pending U4; "
            "see the entry note."
        ),
        "entries": firmware,
    }
    args.firmware_out.parent.mkdir(parents=True, exist_ok=True)
    args.firmware_out.write_text(
        json.dumps(firmware_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.report_md.parent.mkdir(parents=True, exist_ok=True)
    args.report_md.write_text(render_markdown(report), encoding="utf-8")

    summary = report["summary"]
    print(
        f"regen: {summary['pass']}/{summary['judged_checks']} judged checks "
        f"pass; overall {summary['overall']}"
    )
    return 0 if summary["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
