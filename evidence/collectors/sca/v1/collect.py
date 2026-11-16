"""Software composition analysis: known vulnerabilities in the dependencies of this commit, found by Grype.

Scans a directory (its manifests and lock files) or an SBOM. Records every
vulnerability found, with its severity and the versions that fix it, and when
the vulnerability database was built: without that date, "nothing found" means
little. Grype refuses to scan with a database older than its maximum age, and
that refusal is a collection error, not a pass.

The result is "fail" when any vulnerability is at or above sca-fail-on (default
high). The counts per severity let policy decide differently.

Grype runs from an empty directory, so a .grype.yaml in the scanned repository
cannot hide findings. Accepted risks belong in policy, not in the repository.
"""
import json
import os
import tempfile

from evidence_sdk import commit, emit, param, run_tool, unable

SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unknown"]
FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown")

target = param("sca-target", "dir:.")
fail_on = param("sca-fail-on", "high")
if fail_on not in SEVERITIES[:-1]:
    unable(f"sca-fail-on must be one of {', '.join(SEVERITIES[:-1])}, not '{fail_on}'")
scheme, _, location = target.partition(":")
if scheme not in ("dir", "sbom") or not location:
    unable(f"sca-target must be dir:<path> or sbom:<file>, not '{target}'")

env = dict(os.environ, GRYPE_CHECK_FOR_APP_UPDATE="false")
with tempfile.TemporaryDirectory() as empty:
    output = run_tool(["grype", f"{scheme}:{os.path.abspath(location)}", "--output", "json"], cwd=empty, env=env)
try:
    report = json.loads(output)
except ValueError:
    unable("Grype did not print a JSON report")

descriptor = report.get("descriptor") or {}
database = (descriptor.get("db") or {}).get("status") or {}
if not database.get("built"):
    unable("Grype did not report when its vulnerability database was built")

findings = {}
for match in report.get("matches") or []:
    vulnerability, package = match.get("vulnerability") or {}, match.get("artifact") or {}
    key = (vulnerability.get("id"), package.get("name"), package.get("version"), package.get("type"))
    paths = {place["path"] for place in package.get("locations") or [] if place.get("path")}
    if key in findings:
        findings[key]["locations"] = sorted(paths | set(findings[key]["locations"]))
        continue
    severity = str(vulnerability.get("severity") or "unknown").lower()
    fix = vulnerability.get("fix") or {}
    findings[key] = {
        "id": vulnerability.get("id", ""),
        "aliases": sorted({related["id"] for related in match.get("relatedVulnerabilities") or []
                           if related.get("id") and related["id"] != vulnerability.get("id")}),
        "severity": severity if severity in SEVERITIES else "unknown",
        "package": {name: package.get(name) or "" for name in ("name", "version", "type", "purl")},
        "fixedIn": fix.get("versions") or [],
        "fixState": fix.get("state") if fix.get("state") in FIX_STATES else "unknown",
        "locations": sorted(paths),
    }
ordered = sorted(findings.values(), key=lambda f: (SEVERITIES.index(f["severity"]), f["id"], f["package"]["name"]))
threshold = SEVERITIES.index(fail_on)

emit({
    "result": "fail" if any(SEVERITIES.index(f["severity"]) <= threshold for f in ordered) else "pass",
    "commit": commit(),
    "scanner": {"name": "grype", "version": descriptor.get("version", "")},
    "database": {"built": database["built"], "schemaVersion": database.get("schemaVersion", "")},
    "target": target,
    "failOn": fail_on,
    "summary": {severity: sum(f["severity"] == severity for f in ordered) for severity in SEVERITIES},
    "findings": ordered,
})
