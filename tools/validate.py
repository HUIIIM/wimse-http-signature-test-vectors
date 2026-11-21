#!/usr/bin/env python3
"""Validate a vectors.json file against schema/vectors.schema.json plus set-level rules.

Usage:
  python3 tools/validate.py [vectors/v4/vectors.json] [--schema schema/vectors.schema.json]

Checks:
  1. JSON Schema validation with a built-in, standard-library interpreter of the
     keyword subset the schema uses. If the third-party `jsonschema` package is
     installed, the file is validated by it as well (second, independent check).
  2. Set-level rules: declared counts vs actual, judged total = positive + negative,
     ID roster and uniqueness, kind/mode/expectation consistency, references
     (base_ref, paired_request_ref, materials_ref), source MD5 on every entry.
  3. Source fidelity, when the source file named in `source.file` sits next to
     vectors.json: source MD5, and every signature value, JWK, private key and WIT
     present verbatim in the source.
  4. Content-Digest: SHA-256 of each provided message body equals its header value.

Exit status 0 = PASS, 1 = FAIL. Standard library only.
"""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_IDS = {
    "v4": ([f"P-0{i}" for i in range(1, 7)]
           + [f"N-{i:02d}" for i in range(1, 10)] + ["N-09b"] + [f"N-{i:02d}" for i in range(10, 23)]),
}
EXPECTED_OBS = {"v4": ["O-1", "O-2", "O-3"]}


# ---------------------------------------------------------------- schema ---
TYPES = {"object": dict, "array": list, "string": str, "null": type(None), "boolean": bool}


def type_ok(inst, t):
    if t == "integer":
        return isinstance(inst, int) and not isinstance(inst, bool)
    if t == "number":
        return isinstance(inst, (int, float)) and not isinstance(inst, bool)
    return isinstance(inst, TYPES[t])


def schema_errors(inst, sch, root, path="$"):
    errs = []
    if "$ref" in sch:
        ref = sch["$ref"]
        if not ref.startswith("#/"):
            return [f"{path}: unsupported $ref {ref}"]
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        errs += schema_errors(inst, node, root, path)
    if "type" in sch:
        ts = sch["type"] if isinstance(sch["type"], list) else [sch["type"]]
        if not any(type_ok(inst, t) for t in ts):
            return errs + [f"{path}: type {type(inst).__name__} not in {ts}"]
    if "const" in sch and inst != sch["const"]:
        errs.append(f"{path}: {inst!r} != const {sch['const']!r}")
    if "enum" in sch and inst not in sch["enum"]:
        errs.append(f"{path}: {inst!r} not in enum")
    if isinstance(inst, str) and "pattern" in sch and not re.search(sch["pattern"], inst):
        errs.append(f"{path}: {inst[:40]!r} does not match {sch['pattern']}")
    if type_ok(inst, "number") and "minimum" in sch and inst < sch["minimum"]:
        errs.append(f"{path}: {inst} < minimum {sch['minimum']}")
    if isinstance(inst, list):
        if "minItems" in sch and len(inst) < sch["minItems"]:
            errs.append(f"{path}: {len(inst)} items < minItems {sch['minItems']}")
        if "maxItems" in sch and len(inst) > sch["maxItems"]:
            errs.append(f"{path}: {len(inst)} items > maxItems {sch['maxItems']}")
        if "items" in sch:
            for i, x in enumerate(inst):
                errs += schema_errors(x, sch["items"], root, f"{path}[{i}]")
    if isinstance(inst, dict):
        for r in sch.get("required", []):
            if r not in inst:
                errs.append(f"{path}: missing required {r!r}")
        props = sch.get("properties", {})
        for k, v in inst.items():
            if k in props:
                errs += schema_errors(v, props[k], root, f"{path}.{k}")
            elif "additionalProperties" in sch:
                ap = sch["additionalProperties"]
                if ap is False:
                    errs.append(f"{path}: unexpected property {k!r}")
                elif isinstance(ap, dict):
                    errs += schema_errors(v, ap, root, f"{path}.{k}")
    return errs


# ----------------------------------------------------------------- rules ---
def rule_errors(doc, vec_path):
    errs, info = [], []
    vs, obs = doc["vectors"], doc["observations"]
    ids = [v["id"] for v in vs]
    sv = doc["set_version"]

    # counts
    n_pos = sum(v["kind"] == "positive" for v in vs)
    n_msg = sum(v["kind"] == "negative-message" for v in vs)
    n_beh = sum(v["kind"] == "negative-behavior" for v in vs)
    n_neg = n_msg + n_beh
    actual = {"positive": n_pos, "negative": n_neg, "negative_message": n_msg,
              "negative_behavior": n_beh, "observation": len(obs), "judged_total": len(vs)}
    if actual != doc["counts"]:
        errs.append(f"counts: declared {doc['counts']} != actual {actual}")
    if len(vs) != n_pos + n_neg:
        errs.append("counts: judged total != positive + negative")
    info.append(f"count reconciliation: {len(vs)} = {n_pos} positive + {n_neg} negative "
                f"({n_msg} message-level + {n_beh} behaviour-level); {len(obs)} observations (not judged)")

    # roster
    if len(set(ids)) != len(ids):
        errs.append("ids: duplicates present")
    if sv in EXPECTED_IDS:
        if ids != EXPECTED_IDS[sv]:
            errs.append(f"ids: roster differs from expected {sv} roster")
        if [o["id"] for o in obs] != EXPECTED_OBS[sv]:
            errs.append("observations: roster differs")
    info.append(f"ID roster: {len(ids)} unique vector IDs, {len(obs)} observation IDs")

    # references
    byid = {v["id"]: v for v in vs}
    mats = doc["materials"]
    mat_keys = {"key:" + k["name"] for k in mats["keys"]} | set(mats["wits"]) | {"config:default"}
    t0 = mats["clock"]["t0"]
    md5 = doc["source"]["md5"]
    for v in vs:
        vid = v["id"]
        if v["source_anchor"]["md5"] != md5 or v["source_anchor"]["entry"] != vid:
            errs.append(f"{vid}: source_anchor does not point at set source / own entry")
        for b in (v["base_ref"] or "").split("+"):
            if b and b not in byid:
                errs.append(f"{vid}: base_ref {b} unresolved")
        if v["paired_request_ref"] and v["paired_request_ref"] not in byid:
            errs.append(f"{vid}: paired_request_ref unresolved")
        for r in v["materials_ref"]:
            if r not in mat_keys:
                errs.append(f"{vid}: materials_ref {r} unresolved")
        k, mode, evs = v["kind"], v["mode"], v["evaluations"]
        if k == "positive":
            if mode != "oracle" or v["base_ref"] is not None or v["message"] is None \
                    or not v["signatures"] or not v["signature_base_provided"] \
                    or v.get("expect_stages") != "all-pass" \
                    or [e["expect"] for e in evs] != [{"outcome": "ACCEPT"}]:
                errs.append(f"{vid}: positive entry shape invalid")
            if v["signature_source"] != "literal":
                errs.append(f"{vid}: positive signatures must be literal")
        elif k == "negative-message":
            if not v["base_ref"] or v["mutation"] is None or mode not in ("oracle", "contrast"):
                errs.append(f"{vid}: negative-message needs base_ref, mutation, oracle/contrast mode")
            rejects = [e for e in evs if e["expect"]["outcome"] in ("REJECT", "CLIENT_REJECT")]
            if not rejects:
                errs.append(f"{vid}: no rejecting evaluation")
            for e in rejects:
                x = e["expect"]
                if "failing_stage" not in x or "failing_code" not in x or "cascades" not in x:
                    errs.append(f"{vid}: rejecting evaluation lacks failing_stage/failing_code/cascades")
                if x["outcome"] == "REJECT" and (x.get("http_status") != 400 or x.get("problem_type") != "wimse-signature-invalid"):
                    errs.append(f"{vid}: REJECT must be 400 + wimse-signature-invalid")
                if x.get("failing_stage") in x.get("cascades", []):
                    errs.append(f"{vid}: primary stage repeated in cascades")
            if mode == "oracle" and len(evs) != 1:
                errs.append(f"{vid}: oracle entry must have exactly one evaluation")
            if mode == "contrast":
                if len(evs) < 2 or "contrast" not in v:
                    errs.append(f"{vid}: contrast entry needs >=2 evaluations and time_invariant_stages")
                if len({e['verify_time'] for e in evs}) != len(evs):
                    errs.append(f"{vid}: contrast evaluations must differ in verify_time")
            if v["signature_source"] == "literal" and v["message"] is not None and not v["signatures"]:
                errs.append(f"{vid}: literal signature source with message but no signature")
        elif k == "negative-behavior":
            if mode != "probe" or v["message"] is not None or evs or "probe" not in v \
                    or v.get("expect", {}).get("outcome") != "NONCONFORMANT" \
                    or v["expect"].get("subject") != v["probe"]["subject"]:
                errs.append(f"{vid}: negative-behavior entry shape invalid")
        for e in evs:
            if e["verify_time"] < t0:
                errs.append(f"{vid}: verify_time before T0")
    info.append("kind/mode/expectation rules and references: checked for all vectors")
    return errs, info


def fidelity_errors(doc, vec_path):
    errs, info = [], []
    src_path = vec_path.parent / doc["source"]["file"]
    if not src_path.exists():
        info.append(f"source fidelity: skipped ({src_path.name} not present)")
        return errs, info
    raw = src_path.read_bytes()
    if hashlib.md5(raw).hexdigest() != doc["source"]["md5"]:
        return [f"source MD5 mismatch for {src_path.name}"], info
    text = raw.decode("utf-8")
    n = 0
    for v in doc["vectors"]:
        for s in v["signatures"]:
            n += 1
            if f"{s['label']}=:{s['value']}:" not in text:
                errs.append(f"{v['id']}: signature {s['label']} not verbatim in source")
    for k in doc["materials"]["keys"]:
        for lit in (k["private_d"], json.dumps(k["public_jwk"], separators=(",", ":"))):
            n += 1
            if lit not in text:
                errs.append(f"key {k['name']}: literal not verbatim in source")
    for name, w in doc["materials"]["wits"].items():
        n += 1
        if w["jws"] not in text:
            errs.append(f"{name}: JWS not verbatim in source")
    info.append(f"source fidelity: MD5 {doc['source']['md5']} ok; {n} literal fields found verbatim in {src_path.name}")
    return errs, info


def digest_errors(doc):
    errs, n = [], 0
    for v in doc["vectors"]:
        m = v["message"]
        if m and m["body"] is not None:
            hit = re.search(r"\r\nContent-Digest: sha-256=:([A-Za-z0-9+/=]+):\r\n", m["raw"])
            if not hit:
                errs.append(f"{v['id']}: body present but no Content-Digest header")
                continue
            n += 1
            if base64.b64encode(hashlib.sha256(m["body"].encode()).digest()).decode() != hit.group(1):
                errs.append(f"{v['id']}: Content-Digest mismatch")
            if not m["raw"].endswith("\r\n\r\n" + m["body"]):
                errs.append(f"{v['id']}: raw message does not end with its body")
    return errs, [f"Content-Digest: {n} message bodies recomputed"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vectors", nargs="?", default=str(ROOT / "vectors" / "v4" / "vectors.json"))
    ap.add_argument("--schema", default=str(ROOT / "schema" / "vectors.schema.json"))
    a = ap.parse_args()
    vec_path = Path(a.vectors)
    doc = json.loads(vec_path.read_text(encoding="utf-8"))
    schema = json.loads(Path(a.schema).read_text(encoding="utf-8"))

    failures = []
    errs = schema_errors(doc, schema, schema)
    print(f"[{'PASS' if not errs else 'FAIL'}] schema (built-in interpreter): {len(errs)} error(s)")
    failures += errs
    try:
        import jsonschema  # optional independent check
        js = sorted(e.message for e in jsonschema.Draft202012Validator(schema).iter_errors(doc))
        print(f"[{'PASS' if not js else 'FAIL'}] schema (jsonschema package): {len(js)} error(s)")
        failures += js
    except ImportError:
        print("[SKIP] schema (jsonschema package not installed)")
    if not errs:
        for label, fn in (("set rules", lambda: rule_errors(doc, vec_path)),
                          ("source fidelity", lambda: fidelity_errors(doc, vec_path)),
                          ("content digest", lambda: digest_errors(doc))):
            e, info = fn()
            print(f"[{'PASS' if not e else 'FAIL'}] {label}")
            for i in info:
                print(f"       {i}")
            failures += e
    for f in failures:
        print(f"  error: {f}")
    vs = doc["vectors"]
    n_pos = sum(v["kind"] == "positive" for v in vs)
    n_neg = sum(v["kind"].startswith("negative") for v in vs)
    verdict = "PASS" if not failures else "FAIL"
    print(f"RESULT: {verdict} — {vec_path.name} set {doc['set_version']}: {len(vs)} vectors "
          f"({n_pos} positive / {n_neg} negative), {len(doc['observations'])} observations")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
