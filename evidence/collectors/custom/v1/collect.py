"""Custom: whatever a squad wants to declare about its own release.

The squad's JSON goes under "claims" and is labelled with who declared it. It
has no "result": the platform did not verify anything here, and it is signed
with the self key so nobody can read it as platform-verified.
"""
import json

from evidence_sdk import commit, emit, param, repository, unable

path = param("predicate-file")
try:
    with open(path, encoding="utf-8") as handle:
        claims = json.load(handle)
except (OSError, ValueError) as exc:
    unable(f"cannot read a JSON document from {path}: {exc}")
if not isinstance(claims, dict):
    unable("the predicate file must hold one JSON object")

emit({"declaredBy": repository(), "commit": commit(), "claims": claims})
