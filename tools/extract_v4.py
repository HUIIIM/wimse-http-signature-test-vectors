#!/usr/bin/env python3
"""Extract the v4 vector set (markdown) into canonical vectors.json + extraction log.

Method (three steps):
  1. Structural parse (automatic): section 2 materials (JWKs, private d, WITs,
     trusted configuration), per-entry ID anchors, message / signature-base fences,
     machine-readable anchor lines.
  2. Manifest transcription (manual, in MANIFEST below): structured fields per
     entry. Every transcribed scalar is cross-checked against that entry's
     machine-readable anchor line in the source; a mismatch aborts extraction.
  3. Reconciliation (automatic): counts, ID roster, literal fields vs source text,
     key derivation, WIT claims, Content-Digest recomputation.

Usage:
  python3 tools/extract_v4.py vectors/v4/source.md --out vectors/v4 \
      [--supplement PATH] [--draft PATH]

--supplement / --draft are optional extra checks (A-11 supplement quotes and
draft-08 text); their results are written into the extraction log only when given.
Standard library only. Output is deterministic.
"""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_SOURCE_MD5 = "5df4f19a8a4a7f0ddd0ff792d0f09bc4"
DRAFT = "draft-ietf-wimse-http-signature-08"
T0 = 1795000000
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

STAGES = ["CONTEXT", "PARSE", "WIT", "SELECT", "PARAMS", "COVERAGE", "BASE",
          "DIGEST", "CRYPTO", "AUD", "BINDING", "WINDOW"]

REJECT400 = {"outcome": "REJECT", "http_status": 400, "problem_type": "wimse-signature-invalid"}
CLIENT = {"outcome": "CLIENT_REJECT"}


def q(sec, head, tail, src="entry-anchor", doc=DRAFT, loc=None):
    c = {"doc": doc, "section": sec, "quote_head": head, "quote_tail": tail, "quote_source": src}
    if loc:
        c["quote_loc"] = loc
    return c


def noquote(sec, doc=DRAFT):
    return {"doc": doc, "section": sec, "quote_head": None, "quote_tail": None,
            "quote_source": "none-in-entry"}


A11 = "a11-supplement"

# ---------------------------------------------------------------------------
# Step 2 manifest. Fields marked in `anchor_checks` are verified verbatim
# against the entry's machine-readable anchor line ("机读锚｜...").
# ---------------------------------------------------------------------------
MANIFEST = [
    # ---- positives -------------------------------------------------------
    dict(id="P-01", kind="positive", mode="oracle", section="3", role="request",
         materials=["WIT-A", "key:svcA", "key:issuer", "config:default"],
         clauses=[
             q("3", "The request is signed", "components MUST be signed", A11),
             q("3", "In addition, the following", "MUST be signed when they exist", A11),
             q("3", "For both requests and responses", "MUST be included", A11),
             q("3", "For requests only, the following", "MUST also be included", A11),
             q("3", "Recipients MUST reject signatures", "their validity time window", A11),
             q("3", "Recipients of signed HTTP messages", "the HTTP message signature", A11),
             q("3.3", "When present with the value true", "if it cannot (Section 3.6)", A11),
             q("3.3", "If the client is configured", "the request's Signature-Input", A11),
         ]),
    dict(id="P-02", kind="positive", mode="oracle", section="3", role="response",
         paired_request_ref="P-01",
         materials=["WIT-B", "key:svcB", "key:issuer", "config:default"],
         clauses=[
             q("3", "If the response is signed", "components MUST be signed", A11),
             q("3", "To protect the integrity", "as defined in [RFC9530]", A11),
             q("3.4", "Every signed response MUST include", "that triggered the response", A11),
             q("3.5", "If the server is required", "as described in Section 3.6", A11),
             q("3.5", "The client MUST reject", "with the Boolean value true", A11),
             q("3.5", "When validating a signed response", "from the corresponding request", A11),
             q("3.5", "Whenever a signed response", "reject it if validation fails", A11),
         ]),
    dict(id="P-03", kind="positive", mode="oracle", section="3", role="request",
         materials=["WIT-C", "key:svcC", "key:issuer", "config:default"],
         clauses=[
             q("3.1", "The HTTP message signature algorithm", "object in the WIT", A11),
             q("3.1", "Recipients MUST verify the HTTP", "for the peer's trust domain", A11),
             q("3", "To protect the integrity", "as defined in [RFC9530]", A11),
             q("3", "In addition, the following", "MUST be signed when they exist", A11),
         ]),
    dict(id="P-04", kind="positive", mode="oracle", section="3", role="request",
         materials=["WIT-A", "key:svcA", "key:issuer", "config:default"],
         clauses=[
             noquote("3 (CONNECT exception)"),
             q("2.2.3", "the default port", "port is omitted", doc="RFC 9421", loc="§0 K1 row"),
         ]),
    dict(id="P-05", kind="positive", mode="oracle", section="3", role="request",
         materials=["WIT-A", "key:svcA", "key:issuer", "config:default"],
         clauses=[q("3", "@query is included even", "its value is ?")]),
    dict(id="P-06", kind="positive", mode="oracle", section="3", role="request",
         materials=["WIT-A", "key:svcA", "key:other", "key:issuer", "config:default"],
         clauses=[q("3", "recipients MUST use that", "NOT choose by label")]),
    # ---- message-level negatives ----------------------------------------
    dict(id="N-01", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "remove-component", "component": "@query"},
         expect=REJECT400, stage="COVERAGE", code="E_COVERAGE_MISSING", sig="literal",
         clauses=[q("3", "The following derived components", "@method, @path, @query")]),
    dict(id="N-02", kind="negative-message", mode="oracle", base="P-04",
         mutation={"op": "add-component", "component": "@path"},
         expect=REJECT400, stage="COVERAGE", code="E_COVERAGE_FORBIDDEN", sig="regen",
         clauses=[q("3", "For a CONNECT request,", "cover @path or @query")]),
    dict(id="N-03", kind="negative-message", mode="oracle", base="P-03",
         mutation={"op": "remove-component", "component": "content-digest",
                   "note": "remove both the Content-Digest header and its coverage item"},
         expect=REJECT400, stage="COVERAGE", code="E_DIGEST_MISSING", sig="literal",
         clauses=[q("3", "if the request or", "verify) a Content-Digest header")]),
    dict(id="N-04", kind="negative-message", mode="oracle", base="P-03",
         mutation={"op": "set-body", "body": "{\"flavor\":\"chocolate\",\"amount\":1}"},
         expect=REJECT400, stage="DIGEST", code="E_DIGEST_MISMATCH", cascades=["CRYPTO"],
         sig="literal",
         clauses=[q("3", "the receiver MUST compute", "Content-Digest value provided")]),
    dict(id="N-05", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "remove-param", "param": "expires"},
         expect=REJECT400, stage="PARAMS", code="E_PARAM_MISSING", sig="literal",
         clauses=[q("3", "the following signature parameters", "created, expires, nonce, tag")]),
    dict(id="N-06", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "add-param", "param": "keyid=\"vec-a-key\""},
         expect=REJECT400, stage="PARAMS", code="E_PARAM_FORBIDDEN", sig="regen",
         notes="Author confirmation (S4): reject reading confirmed by draft co-author on the WIMSE list, 2026-11-07.",
         clauses=[q("3", "The following signature parameters", "NOT be used: keyid")]),
    dict(id="N-07", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "add-param", "param": "alg=\"ed25519\""},
         expect=REJECT400, stage="PARAMS", code="E_PARAM_FORBIDDEN", sig="regen",
         notes="Author confirmation (S4): same as N-06.",
         clauses=[q("3, 3.1", "The alg signature parameter", "MUST NOT be used")]),
    dict(id="N-08", kind="negative-message", mode="oracle", base="P-06",
         mutation={"op": "set-param", "member": "sig1", "param": "tag=\"wimse-workload-to-workload\""},
         expect=REJECT400, stage="SELECT", code="E_TAG_AMBIGUOUS", sig="regen",
         clauses=[q("3", "If more than one", "MUST reject the message")]),
    dict(id="N-09", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "set-verify-time", "verify_time": T0 + 3600},
         expect=REJECT400, stage="WINDOW", code="E_WINDOW_OUTSIDE", sig="literal",
         verify_time=T0 + 3600, same_message_as="P-01",
         notes="At T0+3600 WIT-A is also expired (exp=T0+3600); attribution isolation is weak, see N-09b.",
         clauses=[q("3", "Recipients MUST reject signatures", "validity time window")]),
    dict(id="N-09b", kind="negative-message", mode="contrast", base="P-01",
         mutation={"op": "set-verify-time"}, sig="literal", same_message_as="P-01",
         evaluations=[
             {"verify_time": T0 + 300, "expect": {"outcome": "ACCEPT"}},
             {"verify_time": T0 + 301, "expect": dict(REJECT400, failing_stage="WINDOW",
                                                       failing_code="E_WINDOW_OUTSIDE", cascades=[])},
         ],
         time_invariant=["WIT", "SELECT", "PARAMS", "COVERAGE", "BASE", "DIGEST", "CRYPTO", "AUD"],
         clauses=[q("3", "Recipients MUST reject signatures", "validity time window")]),
    dict(id="N-10", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "set-param", "param": "wimse-aud=\"https://svcb.example.com/gimme-ice-cream/\""},
         expect=REJECT400, stage="AUD", code="E_AUD_MISMATCH", sig="regen",
         clauses=[q("3.2", "The recipient MUST verify", "of RFC 3986 §6.2.1")]),
    dict(id="N-11", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "remove-param", "param": "wimse-aud"},
         expect=REJECT400, stage="PARAMS", code="E_PARAM_MISSING", sig="regen",
         clauses=[q("3", "For requests only, the", "be included: wimse-aud")]),
    dict(id="N-12", kind="negative-message", mode="oracle", base="P-02", paired_request_ref="P-01",
         mutation={"op": "remove-param", "param": "wimse-req-nonce"},
         expect=CLIENT, stage="PARAMS", code="E_REQNONCE_MISSING", sig="regen",
         clauses=[q("3.4", "Every signed response MUST", "MUST include wimse-req-nonce")]),
    dict(id="N-13", kind="negative-message", mode="oracle", base="P-02", paired_request_ref="P-01",
         mutation={"op": "set-param", "param": "wimse-req-nonce=\"00000000000000000000000000000000\""},
         expect=CLIENT, stage="BINDING", code="E_REQNONCE_MISMATCH", sig="regen",
         clauses=[q("3.5", "the client MUST verify", "the corresponding request")]),
    dict(id="N-14", kind="negative-message", mode="oracle", base="P-01+P-02", paired_request_ref="P-01",
         mutation={"op": "custom-construct",
                   "note": "response with P-02 status line and body; all Signature / Signature-Input headers removed"},
         expect=CLIENT, stage="BINDING", code="E_RESPONSE_UNSIGNED", sig="none",
         clauses=[q("3.5", "The client MUST reject", "Boolean value true")]),
    dict(id="N-15", kind="negative-message", mode="oracle", base="P-01",
         mutation={"op": "custom-construct",
                   "note": "literal ES256 signature by svcC over a P-01-shaped signature base; WIT-A cnf binds Ed25519/vec-a-key"},
         expect=REJECT400, stage="CRYPTO", code="E_ALG_BINDING", sig="literal",
         materials=["WIT-A", "key:svcA", "key:svcC", "key:issuer", "config:default"],
         clauses=[q("3.1", "Recipients MUST verify the", "is not acceptable")]),
    # ---- behaviour-level negatives (probe) -------------------------------
    dict(id="N-16", kind="negative-behavior", mode="probe", subject="sender", code="E_ENTROPY",
         clauses=[q("3", "the nonce MUST contain", "64 bits of entropy")]),
    dict(id="N-17", kind="negative-behavior", mode="probe", subject="server", code="E_ERROR_SURFACE",
         clauses=[q("3.6", "The server MUST NOT", "which check failed")]),
    dict(id="N-18", kind="negative-behavior", mode="probe", subject="server", code="E_UNSIGNED_SUCCESS",
         clauses=[q("3.5, 3.6", "it MUST NOT return", "MUST return an error")]),
    dict(id="N-19", kind="negative-behavior", mode="probe", subject="sender", code="E_ACCEPT_SIG_WEAK",
         clauses=[q("3.5", "Accept-Signature MUST NOT be", "weaker than this profile")]),
    dict(id="N-20", kind="negative-behavior", mode="probe", subject="verifier", code="E_PROCESS_ORDER",
         clauses=[q("3", "Recipients ... MUST validate", "been fully validated")]),
    dict(id="N-21", kind="negative-message", mode="oracle", base="P-02",
         mutation={"op": "add-component", "component": "\"@path\";req",
                   "note": "P-02 shape migrated to a CONNECT exchange (A-04 regeneration)"},
         notes="CONNECT-migration construction (paired CONNECT request, ;req component values) is not specified "
               "in the source; construction rule to be fixed with the runner (design A-03).",
         expect=CLIENT, stage="COVERAGE", code="E_COVERAGE_FORBIDDEN", sig="regen",
         clauses=[q("3", "When the signed response", "cover @path;req or @query;req")]),
    dict(id="N-22", kind="negative-behavior", mode="probe", subject="verifier", code="E_SELECTION_BY_LABEL",
         base="P-06",
         clauses=[q("3", "recipients MUST use that", "NOT choose by label")]),
]

OBSERVATIONS = [
    dict(id="O-1", clauses=[q("3", "Recipients MAY maintain a", "they have already seen")]),
    dict(id="O-2", clauses=[q("3", "MUST contain at least", "64 bits of entropy")]),
    dict(id="O-3", clauses=[
        q("3", "The @authority derived component", "signature parameter (Section 3.2)", A11),
        q("3", "For a CONNECT request", "cover @path or @query", A11),
        q("5.1", "The audience is a signed", "for that reason (Section 3)", A11),
    ]),
]

KEY_NAMES = {"issuer": "Issuer", "svcA": "svcA", "svcB": "svcB", "svcC": "svcC", "other": "other"}


def base_materials(base):
    """Union of the materials of the base entries named in base ("P-01+P-02")."""
    out = []
    for b in base.split("+"):
        for r in next(x for x in MANIFEST if x["id"] == b)["materials"]:
            if r not in out:
                out.append(r)
    return out


def fail(msg):
    sys.exit(f"EXTRACTION ABORTED: {msg}")


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def norm_ws(s):
    return re.sub(r"\s+", " ", s)


class Source:
    def __init__(self, path):
        self.raw = Path(path).read_bytes()
        self.md5 = hashlib.md5(self.raw).hexdigest()
        self.text = self.raw.decode("utf-8")
        self.lines = self.text.split("\n")

    def find_line(self, pattern, start=0):
        rx = re.compile(pattern)
        for i in range(start, len(self.lines)):
            if rx.search(self.lines[i]):
                return i
        fail(f"pattern not found: {pattern}")

    def fences_after(self, start, stop):
        """Return [(open_line_idx, [lines])] of ``` fences in [start, stop)."""
        out, i = [], start
        while i < stop:
            if self.lines[i].lstrip().startswith("```"):
                j = i + 1
                while not self.lines[j].lstrip().startswith("```"):
                    j += 1
                out.append((i, self.lines[i + 1:j]))
                i = j + 1
            else:
                i += 1
        return out


ANNOT = re.compile(r"\s*\[修订·因[^\]]*\]\s*$")
PLACEHOLDER = re.compile(r"\[WIT-([ABC])，§2 全文\]")


def parse_materials(src):
    keys = {}
    for name, label in KEY_NAMES.items():
        i = src.find_line(r"^\*\*" + re.escape(label) + r"[（ *]")
        header = src.lines[i]
        jwk_line = src.lines[i + 1]
        d_line = src.lines[i + 2]
        jwk = json.loads(jwk_line.split("：", 1)[1])
        d = d_line.split("：", 1)[1].strip()
        sub = re.search(r"sub＝(wimse://\S+?)）", header)
        keys[name] = {"name": name, "alg": jwk["alg"], "kid": jwk["kid"],
                      "sub": sub.group(1) if sub else None,
                      "public_jwk": jwk, "private_d": d, "source_line": i + 1}
    wits = {}
    for w in "ABC":
        i = src.find_line(r"^\*\*WIT-" + w + r"\*\*")
        tok = src.lines[i + 1].strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", tok):
            fail(f"WIT-{w} not a compact JWS")
        hdr = json.loads(b64url_dec(tok.split(".")[0]))
        claims = json.loads(b64url_dec(tok.split(".")[1]))
        wits["WIT-" + w] = {"jws": tok, "protected_header": hdr, "claims": claims,
                            "source_line": i + 2}
    # trusted configuration: A-07 JSON block, cross-checked with prose sentence
    i = src.find_line(r"机读材料块（A-07")
    (fi, flines), = src.fences_after(i, i + 30)[:1]
    block = json.loads("\n".join(flines))
    prose_i = src.find_line(r"^受信任配置（全部向量共用")
    prose_aud = re.findall(r'"(https://[^"]+)"', src.lines[prose_i])
    if prose_aud != block["trusted_config"]["wimse_aud_trusted"]:
        fail("trusted wimse-aud set: prose and A-07 block disagree")
    if block["trusted_config"]["issuer_anchor_jwk"] != keys["issuer"]["public_jwk"]:
        fail("issuer anchor JWK in A-07 block differs from section 2 JWK")
    return keys, wits, block, prose_i + 1, fi + 1


def expand(line, wits):
    return PLACEHOLDER.sub(lambda m: wits["WIT-" + m.group(1)]["jws"], line)


def clean(line, wits):
    return expand(ANNOT.sub("", line), wits)


def parse_positive(src, pid, wits, stop_markers):
    start = src.find_line(r"^### " + re.escape(pid) + r" .*<!-- id:" + re.escape(pid) + r" -->")
    stop = src.find_line(r"^(### |## )", start + 1)
    fences = src.fences_after(start, stop)
    # first fence = input message; following fences = signature bases
    msg_idx, msg_lines = fences[0]
    body = None
    m_intro = src.lines[msg_idx - 1]
    head_lines, body_lines = msg_lines, []
    if "" in msg_lines:
        k = msg_lines.index("")
        head_lines, body_lines = msg_lines[:k], msg_lines[k + 1:]
    mb = re.search(r'响应体为 "(.+?)"，(\d+) 字节', m_intro) or re.search(r"体：(.+?)，(\d+) 字节", m_intro)
    if mb:
        body = mb.group(1).encode().decode("unicode_escape") if "\\n" in mb.group(1) else mb.group(1)
        if len(body.encode()) != int(mb.group(2)):
            fail(f"{pid}: body length {len(body.encode())} != stated {mb.group(2)}")
        if body_lines and body_lines[0] != body.rstrip("\n"):
            fail(f"{pid}: fenced body differs from stated body")
    heads = [clean(l, wits) for l in head_lines]
    bases = {}
    for fidx, flines in fences[1:]:
        intro = src.lines[fidx - 1]
        label = "sig1"
        ml = re.search(r"签名基（(sig\d)", intro)
        if ml:
            label = ml.group(1)
        bases[label] = {"text": "\n".join(clean(l, wits) for l in flines),
                        "source_lines": [fidx + 2, fidx + 1 + len(flines)]}
    anchor_i = src.find_line(r"机读锚｜id=" + re.escape(pid) + ";", start)
    return {"start": start + 1, "stop": stop, "heads": heads, "body": body,
            "msg_lines": [msg_idx + 2, msg_idx + 1 + len(msg_lines)], "bases": bases,
            "anchor_line": src.lines[anchor_i], "anchor_lineno": anchor_i + 1}


def build_raw(heads, body):
    raw = "\r\n".join(heads) + "\r\n\r\n"
    if body is not None:
        raw += body
    return raw


def parse_sig_header(heads):
    sig = next((h for h in heads if h.startswith("Signature: ")), None)
    if sig is None:
        return []
    return [{"label": m.group(1), "value": m.group(2)}
            for m in re.finditer(r"(sig\d+)=:([A-Za-z0-9+/=]+):", sig)]


def anchor_check(anchor, needles, vid):
    for n in needles:
        if n not in anchor:
            fail(f"{vid}: manifest value {n!r} not found in source anchor line")


def entry_anchor(src, vid):
    i = src.find_line(r"<!-- id:" + re.escape(vid) + r" -->")
    a = src.find_line(r"机读锚｜id=" + re.escape(vid) + ";", i)
    return i, a


def check_quote(text, head, tail):
    t = norm_ws(text)
    return norm_ws(head) in t and norm_ws(tail) in t


def strip_rfc_pagination(txt):
    out = []
    for l in txt.split("\n"):
        if "\f" in l or re.match(r"^(Internet-Draft|[A-Z][a-z]+ & .*)\s{2,}", l) or re.search(r"\[Page \d+\]\s*$", l):
            continue
        out.append(l)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("--out", required=True)
    ap.add_argument("--supplement")
    ap.add_argument("--draft")
    args = ap.parse_args()

    src = Source(args.source)
    if src.md5 != EXPECTED_SOURCE_MD5:
        fail(f"source MD5 {src.md5} != expected {EXPECTED_SOURCE_MD5}")
    log = []          # per-vector log rows
    checks = []       # set-level reconciliation lines

    # ---- version header (A-10)
    hi = src.find_line(r"^set_version: v4$")
    header_text = "\n".join(src.lines[hi:hi + 6])
    mc = re.search(r"counts: \{ positive: (\d+), negative: (\d+), observation: (\d+), judged_total: (\d+) \}", header_text)
    declared = dict(zip(["positive", "negative", "observation", "judged_total"], map(int, mc.groups())))
    if f"t0: {T0}" not in header_text or f"draft_version: {DRAFT}" not in header_text:
        fail("version header t0/draft mismatch")
    checks.append(f"version header (source line {hi + 1}): set_version v4, {DRAFT}, t0 {T0}, declared counts {declared}")

    keys, wits, a07, prose_line, a07_line = parse_materials(src)

    # ---- key derivation checks (stdlib-checkable parts)
    for name, k in keys.items():
        seed = hashlib.sha256(f"s01-validation-vectors:{name}".encode()).digest()
        if k["alg"] == "Ed25519":
            ok = b64url_nopad(seed) == k["private_d"]
        else:
            scalar = int.from_bytes(seed, "big") % (P256_N - 1) + 1
            ok = int.from_bytes(b64url_dec(k["private_d"]), "big") == scalar
        if not ok:
            fail(f"key derivation mismatch for {name}")
        k["derivation"] = (f'd = base64url(SHA-256("s01-validation-vectors:{name}"))' if k["alg"] == "Ed25519"
                           else 'scalar = SHA-256("s01-validation-vectors:svcC") mod (n-1) + 1')
    checks.append("key derivation: private d of issuer/svcA/svcB/other = base64url(SHA-256(seed string)); "
                  "svcC scalar = SHA-256 mod (n-1)+1 — 5/5 match (public-key re-derivation deferred to W5 regen)")

    # ---- WIT checks
    wit_owner = {"WIT-A": "svcA", "WIT-B": "svcB", "WIT-C": "svcC"}
    for wname, w in wits.items():
        c, h = w["claims"], w["protected_header"]
        own = keys[wit_owner[wname]]
        exp_jti = f"wit-{wname[-1].lower()}-{T0}"
        if not (h == {"alg": "Ed25519", "kid": "issuer-key", "typ": "wit+jwt"}
                and c["iat"] == T0 - 60 and c["exp"] == T0 + 3600 and c["jti"] == exp_jti
                and c["sub"] == own["sub"] and c["cnf"]["jwk"] == own["public_jwk"]
                and c["iss"] == "https://example.com/issuer"):
            fail(f"{wname} claims do not match section 2 prose / owner JWK")
    checks.append("WIT-A/B/C: header {alg Ed25519, kid issuer-key, typ wit+jwt}; iat=T0-60, exp=T0+3600, jti, sub "
                  "match section 2 prose; cnf.jwk equals owner public JWK — 3/3 (issuer signature check deferred to W2/W5)")

    materials = {
        "keys": [{kk: vv for kk, vv in k.items() if kk != "source_line"} for k in keys.values()],
        "wits": {n: {"jws": w["jws"], "protected_header": w["protected_header"], "claims": w["claims"]}
                 for n, w in wits.items()},
        "trusted_config": {
            "wimse_aud_trusted": a07["trusted_config"]["wimse_aud_trusted"],
            "issuer_anchor_jwk": a07["trusted_config"]["issuer_anchor_jwk"],
        },
        "key_derivation": a07["key_derivation"],
        "clock": {"t0": T0, "default_verify_offset": 60, "expires_offset": 300},
        "conventions": {
            "problem_type_uri": "https://iana.org/assignments/http-problem-types#wimse-signature-invalid",
            "message_line_ending": "CRLF",
            "signature_base_line_ending": "LF, no trailing newline",
            "placeholder_expansion": "[WIT-x，§2 全文] -> materials.wits[WIT-x].jws",
        },
    }
    mat_keys = {"key:" + n for n in keys} | set(wits) | {"config:default"}

    vectors = []
    positives = {}
    for m in MANIFEST:
        vid = m["id"]
        entry = {"id": vid, "kind": m["kind"], "mode": m["mode"], "set_version": "v4", "draft_version": "-08"}
        interp = []
        if m["kind"] == "positive":
            p = parse_positive(src, vid, wits, None)
            positives[vid] = p
            anchor = p["anchor_line"]
            anchor_check(anchor, [f"id={vid};", "kind=positive;", "mode=oracle;", "base=-;",
                                  "expect={outcome: ACCEPT}", "verify_time=T0+60;", "sig=literal;"], vid)
            sigs = parse_sig_header(p["heads"])
            entry.update({
                "source_anchor": {"md5": src.md5, "section": "3", "entry": vid,
                                  "lines": [p["start"], p["stop"]], "anchor_line": p["anchor_lineno"]},
                "anchor_clauses": m["clauses"],
                "base_ref": None,
                "paired_request_ref": m.get("paired_request_ref"),
                "materials_ref": m["materials"],
                "message": {"role": m["role"], "raw": build_raw(p["heads"], p["body"]),
                            "body": p["body"]},
                "signatures": sigs,
                "signature_base_provided": {lbl: b["text"] for lbl, b in p["bases"].items()},
                "mutation": None,
                "signature_source": "literal",
                "evaluations": [{"verify_time": T0 + 60, "expect": {"outcome": "ACCEPT"}}],
                "expect_stages": "all-pass",
            })
            interp.append(f"message fence lines {p['msg_lines'][0]}-{p['msg_lines'][1]}; "
                          + "; ".join(f"base {lbl} lines {b['source_lines'][0]}-{b['source_lines'][1]}"
                                      for lbl, b in p["bases"].items()))
            if p["body"] is not None:
                interp.append(f"body taken from entry prose ({len(p['body'].encode())} bytes, as stated)")
            if any(ANNOT.search(l) for l in src.lines[p["start"]:p["stop"]]):
                interp.append("[抽取判读] trailing editorial markers `[修订·因 …]` stripped from fenced lines (not message content)")
        else:
            ei, ai = entry_anchor(src, vid)
            anchor = src.lines[ai]
            needles = [f"id={vid};", f"kind={m['kind']};", f"mode={m['mode']};"]
            if m["kind"] == "negative-message":
                if m["mode"] == "oracle":
                    needles += [f"failing_stage={m['stage']};", f"failing_code={m['code']};",
                                f"outcome: {m['expect']['outcome']}"]
                    if "http_status" in m["expect"]:
                        needles.append("http_status: 400, problem_type: wimse-signature-invalid")
                    casc = m.get("cascades", [])
                    needles.append("cascades=[" + ", ".join(casc) + "]")
                needles.append(f"op: {m['mutation']['op']}")
                needles.append(f"sig={m['sig']}")
                needles.append(f"base={m['base']}")
                for fld in ("component", "param", "member"):
                    if fld in m["mutation"]:
                        v = m["mutation"][fld]
                        needles.append(json.dumps(v, ensure_ascii=False) if fld != "component" or v.startswith('"') else v)
                if "body" in m["mutation"]:
                    needles.append(json.dumps(m["mutation"]["body"]))
            else:
                needles += [f"subject: {m['subject']}", f"failing_code={m['code']};", "sig=probe",
                            f"outcome: NONCONFORMANT, subject: {m['subject']}"]
            for c in m["clauses"]:
                needles += [c["quote_head"], c["quote_tail"], f'sec: "{c["section"]}"']
            anchor_check(anchor, needles, vid)
            # entry prose block = lines from ID line up to (excl.) next "- **" entry / section
            stop = ai + 1
            while stop < len(src.lines) and not re.match(r"^(- \*\*|## |负例条款对应自查)", src.lines[stop]):
                stop += 1
            entry["source_anchor"] = {"md5": src.md5, "section": "4", "entry": vid,
                                      "lines": [ei + 1, stop], "anchor_line": ai + 1}
            entry["anchor_clauses"] = m["clauses"]
            entry["base_ref"] = m.get("base")
            entry["paired_request_ref"] = m.get("paired_request_ref")
            if m["kind"] == "negative-behavior":
                pc = re.search(r'pass_condition: "([^"]+)"', anchor).group(1)
                entry.update({
                    "materials_ref": [], "message": None, "signatures": [], "signature_base_provided": None,
                    "mutation": None, "signature_source": "probe", "evaluations": [],
                    "probe": {"subject": m["subject"], "procedure": "see source entry construction and decision rule (source_anchor.lines)",
                              "pass_condition": pc},
                    "expect": {"outcome": "NONCONFORMANT", "subject": m["subject"], "failing_code": m["code"]},
                })
                interp.append("probe entry: pass_condition copied verbatim from anchor line; procedure left as pointer to source prose (A-09 three-part prose not split in source)")
            else:
                entry["materials_ref"] = m.get("materials") or base_materials(m["base"])
                entry["mutation"] = m["mutation"]
                entry["signature_source"] = {"literal": "literal", "regen": "regen", "none": "none"}[m["sig"]]
                msg, sigs, bases = None, [], None
                if m.get("same_message_as"):
                    base_entry = next(v for v in vectors if v["id"] == m["same_message_as"])
                    msg = dict(base_entry["message"])
                    sigs = base_entry["signatures"]
                    bases = base_entry["signature_base_provided"]
                    interp.append(f"message, signature and base copied from {m['same_message_as']} (source: \"其余与 P-01 逐字同\" / \"不变异消息\")")
                elif vid == "N-15":
                    fl = src.fences_after(ai, ai + 10)[0]
                    si = next(l for l in fl[1] if l.startswith("Signature-Input: "))
                    sv = clean(next(l for l in fl[1] if l.startswith("Signature: ")), wits)
                    p01 = positives["P-01"]
                    heads = [p01["heads"][0], p01["heads"][1], p01["heads"][2], si, sv]
                    msg = {"role": "request", "raw": build_raw(heads, None), "body": None}
                    sigs = parse_sig_header(heads)
                    member = si.split("sig1=", 1)[1]
                    p01_base = positives["P-01"]["bases"]["sig1"]["text"].split("\n")
                    bases = {"sig1": "\n".join(p01_base[:-1] + ['"@signature-params": ' + member])}
                    if 'nonce="abcdef0123456789abcdef0123456789"' not in member or "wimse-sign-response" in member:
                        fail("N-15 derived base inconsistent with prose")
                    interp.append(f"[抽取判读] Signature-Input/Signature taken literally from fence lines {fl[0] + 2}-{fl[0] + 1 + len(fl[1])}; "
                                  "request line, Host and WIT-A header taken from P-01 (source: \"消息与 P-01 同形、WIT 为 WIT-A\")")
                    interp.append("[抽取判读] signature base derived: P-01 base with @signature-params replaced by the N-15 Signature-Input member "
                                  "(source prose: same as revised P-01 except nonce abcdef… and no wimse-sign-response) — checked")
                else:
                    interp.append("message not materialised: base_ref + mutation are the normative input (runner applies mutation, W2); "
                                  + ("signature value is the base entry's literal (not recomputed)" if m["sig"] == "literal"
                                     else "signature regenerated by runner per A-04 (deterministic)" if m["sig"] == "regen"
                                     else "unsigned construct"))
                entry["message"] = msg
                entry["signatures"] = sigs
                entry["signature_base_provided"] = bases
                if m["mode"] == "contrast":
                    entry["evaluations"] = m["evaluations"]
                    entry["contrast"] = {"time_invariant_stages": m["time_invariant"]}
                    needles2 = ['verify_time: "T0+300", expect: {outcome: ACCEPT}', 'verify_time: "T0+301"',
                                "failing_stage: WINDOW, failing_code: E_WINDOW_OUTSIDE, cascades: []",
                                "contrast.time_invariant_stages=[" + ", ".join(m["time_invariant"]) + "]"]
                    anchor_check(anchor, needles2, vid)
                else:
                    vt = m.get("verify_time", T0 + 60)
                    anchor_check(anchor, [f"verify_time=T0+{vt - T0}"], vid)
                    entry["evaluations"] = [{"verify_time": vt,
                                             "expect": dict(m["expect"], failing_stage=m["stage"],
                                                            failing_code=m["code"], cascades=m.get("cascades", []))}]
            if m.get("notes"):
                entry["notes"] = m["notes"]
        for r in entry["materials_ref"]:
            if r not in mat_keys:
                fail(f"{vid}: unknown material {r}")
        vectors.append(entry)
        log.append((vid, entry, interp))

    # ---- observations
    observations = []
    for o in OBSERVATIONS:
        ei, ai = entry_anchor(src, o["id"])
        anchor = src.lines[ai]
        needles = [f"id={o['id']};", "kind=observation;", "judged=false"]
        for c in o["clauses"]:
            if c["quote_source"] == "entry-anchor":
                needles += [c["quote_head"], c["quote_tail"]]
        anchor_check(anchor, needles, o["id"])
        observations.append({"id": o["id"], "kind": "observation", "judged": False,
                             "source_anchor": {"md5": src.md5, "section": "5", "entry": o["id"],
                                               "lines": [ei + 1, ai + 1], "anchor_line": ai + 1},
                             "anchor_clauses": o["clauses"]})

    # ---- reconciliation
    n_pos = sum(v["kind"] == "positive" for v in vectors)
    n_neg = sum(v["kind"].startswith("negative") for v in vectors)
    n_msg = sum(v["kind"] == "negative-message" for v in vectors)
    n_beh = sum(v["kind"] == "negative-behavior" for v in vectors)
    actual = {"positive": n_pos, "negative": n_neg, "observation": len(observations), "judged_total": len(vectors)}
    if actual != declared or n_pos + n_neg != len(vectors) or n_msg != 17 or n_beh != 6:
        fail(f"count reconciliation failed: actual {actual} vs declared {declared}; msg {n_msg} beh {n_beh}")
    checks.append(f"counts: judged {len(vectors)} = positive {n_pos} + negative {n_neg} "
                  f"(message-level {n_msg} + behaviour-level {n_beh}); observations {len(observations)}; matches declared header")
    roster_src = re.findall(r"<!-- id:([PNO]-\d+b?) -->", src.text)
    roster_out = [v["id"] for v in vectors] + [o["id"] for o in observations]
    if roster_src != roster_out:
        fail(f"ID roster mismatch: source {roster_src} vs output {roster_out}")
    checks.append(f"ID roster: {len(roster_src)} source ID anchors == output IDs, same order")

    # literal fidelity: every literal field re-found in source text
    lit = 0
    for v in vectors:
        for s in v["signatures"]:
            if f"{s['label']}=:{s['value']}:" not in src.text:
                fail(f"{v['id']}: signature {s['label']} not literal in source")
            lit += 1
        for lbl, b in (v["signature_base_provided"] or {}).items():
            for line in b.split("\n"):
                rev = line
                for wn, w in wits.items():
                    rev = rev.replace(w["jws"], f"[{wn}，§2 全文]")
                if rev not in src.text and v["id"] != "N-15":
                    fail(f"{v['id']}: base line not found in source: {rev[:60]}")
                lit += 1
    for k in keys.values():
        for val in [k["private_d"], json.dumps(k["public_jwk"], separators=(",", ":"))]:
            if val not in src.text:
                fail(f"key literal not in source: {k['name']}")
            lit += 1
    for w in wits.values():
        if w["jws"] not in src.text:
            fail("WIT literal not in source")
        lit += 1
    checks.append(f"literal fidelity: {lit} literal fields (signature values, signature-base lines, JWKs, private d, WITs) "
                  "found verbatim in source (WIT placeholders re-collapsed for base-line comparison; N-15 derived @signature-params line excluded, checked separately)")

    # content-digest recomputation
    nd = 0
    for v in vectors:
        msg = v["message"]
        if msg and msg.get("body") is not None:
            cd = re.search(r"Content-Digest: sha-256=:([A-Za-z0-9+/=]+):", msg["raw"]).group(1)
            calc = base64.b64encode(hashlib.sha256(msg["body"].encode()).digest()).decode()
            if cd != calc:
                fail(f"{v['id']}: Content-Digest mismatch")
            nd += 1
    checks.append(f"Content-Digest: recomputed SHA-256 of body equals header value for {nd} messages with bodies (P-02, P-03)")

    # optional: quotes vs A-11 supplement and draft text
    extra = []
    if args.supplement:
        sup = Path(args.supplement).read_bytes()
        st = sup.decode()
        miss = [(e["id"], c["quote_head"]) for e in vectors + observations for c in e["anchor_clauses"]
                if c["quote_source"] == A11 and not (f'quote_head: "{c["quote_head"]}"' in st and f'quote_tail: "{c["quote_tail"]}"' in st)]
        n = sum(c["quote_source"] == A11 for e in vectors + observations for c in e["anchor_clauses"])
        if miss:
            fail(f"A-11 supplement quote mismatch: {miss}")
        extra.append(f"A-11 supplement (MD5 {hashlib.md5(sup).hexdigest()}): {n}/{n} supplement-sourced quote head/tail pairs found verbatim")
    if args.draft:
        dr = Path(args.draft).read_bytes()
        dt = strip_rfc_pagination(dr.decode())
        tot, hits, misses = 0, 0, []
        for e in vectors + observations:
            for c in e["anchor_clauses"]:
                if c["doc"] != DRAFT or c["quote_head"] is None:
                    continue
                tot += 1
                h = c["quote_head"].replace(" ... ", " ")
                if norm_ws(c["quote_head"]) in norm_ws(dt) or ("..." in c["quote_head"] and all(norm_ws(x.strip()) in norm_ws(dt) for x in c["quote_head"].split("..."))):
                    if norm_ws(c["quote_tail"]) in norm_ws(dt):
                        hits += 1
                        continue
                misses.append(f"{e['id']}: \"{c['quote_head']}\" … \"{c['quote_tail']}\"")
        extra.append(f"draft-08 text (MD5 {hashlib.md5(dr).hexdigest()}): {hits}/{tot} draft quote head/tail pairs located "
                     "(whitespace-normalised, pagination stripped)")
        for x in misses:
            extra.append(f"  [抽取判读] not located verbatim in draft text: {x}")

    out = Path(args.out)
    doc = {
        "suite": "wimse-http-signature-test-vectors",
        "set_version": "v4",
        "draft_version": DRAFT,
        "source": {"file": "source.md", "md5": src.md5,
                   "archive_doi": "10.5281/zenodo.24203971",
                   "previous_version_doi": "10.5281/zenodo.24184599",
                   "license": "CC-BY-4.0"},
        "counts": {"positive": n_pos, "negative": n_neg, "negative_message": n_msg,
                   "negative_behavior": n_beh, "observation": len(observations), "judged_total": len(vectors)},
        "stage_codes": STAGES,
        "materials": materials,
        "vectors": vectors,
        "observations": observations,
    }
    (out / "vectors.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_log(out / "extraction-log.md", src, log, observations, checks, extra, prose_line, a07_line)
    print(f"wrote {out / 'vectors.json'}: {len(vectors)} vectors ({n_pos} positive / {n_neg} negative), "
          f"{len(observations)} observations")


def write_log(path, src, log, observations, checks, extra, prose_line, a07_line):
    L = []
    L.append("# Extraction log — vector set v4\n")
    L.append("Generated by `tools/extract_v4.py`; regenerate with "
             "`python3 tools/extract_v4.py vectors/v4/source.md --out vectors/v4`.\n")
    L.append(f"- Source: `vectors/v4/source.md`, verbatim copy of the Zenodo-archived v4 file "
             f"(DOI 10.5281/zenodo.24203971), MD5 `{src.md5}`, {len(src.raw)} bytes, {len(src.lines) - 1} lines.")
    L.append("- The finalized-v4 working copy (MD5 `eb0ae3da0ccef91c38a949c216ae40b6`) is identical to this source "
             "except for the file header (title / status / archive lines) and one maintenance ruling line in Appendix C.2; "
             "the 29 vector bodies, materials and anchor lines are identical. The v4 draft (MD5 `03b0b528eebed6d3c658c8d0f7ef3cfe`) "
             "has the same vector bodies but no machine-readable anchor layer (source §6 finalization note).")
    L.append("- A-11 quotes for P-01, P-02, P-03 and O-3 (marked `quote_source: a11-supplement`) come from the A-11 supplement "
             "(2026-11-14, MD5 `1c843619ac8db6e6a597e98152f55a3e`), which quotes draft-ietf-wimse-http-signature-08 directly. "
             "The supplement is not redistributed here; the quotes are embedded in the extractor manifest.\n")
    L.append("## Method\n")
    L.append("1. **Structural parse (automatic)**: section 2 materials, `<!-- id:… -->` anchors, fenced messages and "
             "signature bases, `机读锚｜` machine-readable anchor lines.")
    L.append("2. **Manifest transcription (manual)**: structured fields in `MANIFEST` in the extractor. Every transcribed "
             "kind / mode / base / mutation operator and operand / outcome / failing stage / failing code / cascades / "
             "verify time / signature source / clause quote is checked verbatim against the entry's anchor line; any "
             "mismatch aborts.")
    L.append("3. **Reconciliation (automatic)**: results below.\n")
    L.append("Placeholder expansion: `[WIT-x，§2 全文]` is replaced by the WIT-x compact JWS from section 2 (design §2.2 step 1). "
             "HTTP messages are stored with CRLF line endings and the body appended verbatim; signature bases are LF-joined "
             "with no trailing newline.\n")
    L.append("## Reconciliation results\n")
    for c in checks:
        L.append(f"- {c}")
    L.append(f"- materials: trusted wimse-aud set from the A-07 block (line {a07_line}) equals the prose sentence (line {prose_line}); "
             "issuer anchor JWK equals section 2 Issuer JWK")
    for e in extra:
        L.append(f"- {e}" if not e.startswith("  ") else e)
    L.append("")
    L.append("**Count reconciliation: 29 = 6 positive + 23 negative (17 message-level + 6 behaviour-level); "
             "3 observations outside the judged set.**\n")
    L.append("## Per-vector trace\n")
    L.append("| id | kind / mode | source lines (anchor line) | base | taken literally | transcribed (anchor-checked) | interpretation notes |")
    L.append("|---|---|---|---|---|---|---|")
    for vid, e, interp in log:
        sa = e["source_anchor"]
        lits = []
        if e["signatures"]:
            lits.append("signature " + ", ".join(s["label"] for s in e["signatures"]))
        if e["signature_base_provided"]:
            lits.append("base " + ", ".join(e["signature_base_provided"]))
        if e["message"]:
            lits.append("message")
        trans = [f"{len(e['anchor_clauses'])} clause(s)"]
        if e["mutation"]:
            trans.append("mutation " + e["mutation"]["op"])
        if e["kind"] == "negative-behavior":
            trans.append(f"probe {e['probe']['subject']} / {e['expect']['failing_code']}")
        elif e["evaluations"]:
            ev = e["evaluations"][-1]["expect"]
            trans.append(f"{len(e['evaluations'])} evaluation(s), {ev['outcome']}"
                         + (f" @{ev['failing_stage']}/{ev['failing_code']}" if ev.get("failing_stage") else ""))
        L.append(f"| {vid} | {e['kind']} / {e['mode']} | {sa['lines'][0]}–{sa['lines'][1]} ({sa['anchor_line']}) | "
                 f"{e['base_ref'] or '—'} | {'; '.join(lits) or '—'} | {'; '.join(trans)} | {'<br>'.join(interp) or '—'} |")
    L.append("\n## Observations (not judged)\n")
    for o in observations:
        L.append(f"- {o['id']}: source lines {o['source_anchor']['lines'][0]}–{o['source_anchor']['lines'][1]}, "
                 f"{len(o['anchor_clauses'])} clause(s), judged=false (set-level rule A-12)")
    L.append("\n## Open items carried from the source\n")
    L.append("- A-02 (placeholder normalisation) is not applied in the source; expansion happens at extraction (Appendix C.2).")
    L.append("- P-04 draft clause has no in-entry quote (`none-in-entry`); its RFC 9421 §2.2.3 quote lives in the §0 K1 row.")
    L.append("- Signatures for `regen` entries (N-02, N-06, N-07, N-08, N-10, N-11, N-12, N-13, N-21) and mutated messages "
             "are produced by the runner (wave W2), not stored here.")
    L.append("- Public-key re-derivation, issuer/WIT signature checks and signature verification are wave W2/W5 work; "
             "W1 checks only what the standard library can check (private-key derivation, WIT claims, Content-Digest).")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
