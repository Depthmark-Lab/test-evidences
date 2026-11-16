"""Secret detection: the secrets TruffleHog finds in the files of this commit.

Scans the checked-out files, which are what gets released, not the git history:
.git is excluded, or TruffleHog would also unpack its objects and report each
secret twice. Records which detector found each secret and where, never the
secret itself. TruffleHog prints it in Raw, RawV2, Redacted and SecretParts, so
only the fields named below are copied.

Any finding makes the result "fail". Whether a finding is a false positive is a
policy question, answered elsewhere from the findings. Lines marked
trufflehog:ignore in the scanned files are not reported at all.

Verification is off by default because it sends each secret found to its
provider to see whether it works. Set secrets-verify=true where that is acceptable.
"""
import json
import os
import tempfile

from evidence_sdk import commit, emit, param, run_tool, unable

path = param("secrets-path", ".")
verify = param("secrets-verify", "false")
if verify not in ("true", "false"):
    unable(f"secrets-verify must be true or false, not '{verify}'")

# TruffleHog reads path regexes to exclude from a file.
EXCLUDE = r"(^|/)\.git/"

version = run_tool(["trufflehog", "--version"]).split()[-1]
with tempfile.TemporaryDirectory() as scratch:
    exclude = os.path.join(scratch, "exclude.txt")
    with open(exclude, "w", encoding="utf-8") as handle:
        handle.write(EXCLUDE + "\n")
    command = ["trufflehog", "filesystem", path, "--json", "--no-update", "--exclude-paths", exclude]
    if verify == "false":
        command.append("--no-verification")
    output = run_tool(command)

findings = []
for line in output.splitlines():
    if not line.strip():
        continue
    try:
        found = json.loads(line)
    except ValueError:
        unable("TruffleHog printed a result that is not JSON")
    location = ((found.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
    if found.get("Verified"):
        state = "verified"
    elif found.get("VerificationError"):
        state = "unknown"
    else:
        state = "unverified"
    findings.append({
        "detector": found.get("DetectorName") or str(found.get("DetectorType", "unknown")),
        "file": location.get("file", ""),
        "line": location.get("line", 0),
        "verification": state,
    })
findings.sort(key=lambda f: (f["file"], f["line"], f["detector"]))

emit({
    "result": "fail" if findings else "pass",
    "commit": commit(),
    "scanner": {"name": "trufflehog", "version": version},
    "path": path,
    "verification": verify == "true",
    "summary": {
        "total": len(findings),
        **{state: sum(f["verification"] == state for f in findings) for state in ("verified", "unverified", "unknown")},
    },
    "findings": findings,
})
