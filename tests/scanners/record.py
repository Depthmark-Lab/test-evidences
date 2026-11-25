#!/usr/bin/env python3
"""Record real scanner output for the tests to replay.

The tests do not run TruffleHog, Grype or gh: they put stand-ins on PATH that
print what this script recorded. Run it again to refresh the recordings, for
example after moving to a new version, then fix whatever the tests report.

  python3 tests/scanners/record.py

Needs trufflehog, grype, openssl and gh, logged in, on PATH. Grype downloads its
vulnerability database on first use.

The sample it scans comes from sample.py. It is built in a temporary directory
and deleted afterwards, so the repository never holds a manifest that its own
scanners would flag, or a string that secret scanning would block. Secret values in TruffleHog's output
are replaced with REMOVED before anything is written, and local paths with
runner-like ones.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import date
from pathlib import Path

from sample import build_sample

HERE = Path(__file__).resolve().parent
INSTALLER = HERE.parent.parent / "scripts" / "install-scanners.sh"
REMOVED = "SECRET-REMOVED-BY-RECORD-PY"
SECRET_FIELDS = ("Raw", "RawV2", "Redacted")
WORKSPACE = "/home/runner/work/payments/payments"


def run(command, cwd=None, env=None):
    done = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"{command[0]} exited with {done.returncode}: {done.stderr.strip()[-500:]}")
    return done.stdout


def record_trufflehog(app):
    """Same command as the secret-detection collector with its default parameters."""
    exclude = app.parent / "exclude.txt"
    exclude.write_text("(^|/)\\.git/\n")
    lines = run(["trufflehog", "filesystem", ".", "--json", "--no-update", "--local-dev",
                 "--exclude-paths", str(exclude), "--no-verification"], cwd=app).splitlines()
    scrubbed = []
    for line in lines:
        found = json.loads(line)
        for field in SECRET_FIELDS:
            if found.get(field):
                found[field] = REMOVED
        found["SecretParts"] = {name: REMOVED for name in found.get("SecretParts") or {}}
        scrubbed.append(json.dumps(found))
    (HERE / "trufflehog.jsonl").write_text("\n".join(scrubbed) + "\n")
    return run(["trufflehog", "--version"]).split()[-1]


def record_grype(app):
    """Same command as the sca collector with its default parameters: from an empty directory."""
    with tempfile.TemporaryDirectory() as empty:
        output = run(["grype", f"dir:{app}", "--output", "json"], cwd=empty,
                     env=dict(os.environ, GRYPE_CHECK_FOR_APP_UPDATE="false"))
    output = output.replace(str(app), WORKSPACE).replace(str(Path.home()), "/home/runner")
    report = json.loads(output)
    (HERE / "grype.json").write_text(json.dumps(report, indent=1) + "\n")
    return report["descriptor"]["version"]


def record_gh():
    """Same command as the provenance-attestation collector, on the gh release archive install-scanners.sh pins.

    The lab's repository holds no GitHub attestation: a private repository needs GitHub
    Enterprise Cloud for them. GitHub's CLI attests its own releases, publicly, so this
    verifies that attestation, signed by cli/cli's deployment workflow at the release's commit.
    """
    version = re.search(r'(?m)^GH_VERSION="([^"]+)"', INSTALLER.read_text())[1]
    archive = f"gh_{version}_linux_amd64.tar.gz"
    commit = run(["gh", "api", f"repos/cli/cli/commits/v{version}", "--jq", ".sha"]).strip()
    with tempfile.TemporaryDirectory() as tmp:
        run(["gh", "release", "download", f"v{version}", "--repo", "cli/cli", "--pattern", archive, "--dir", tmp])
        sha256 = hashlib.sha256((Path(tmp) / archive).read_bytes()).hexdigest()
        output = run(["gh", "attestation", "verify", str(Path(tmp) / archive), "--repo", "cli/cli",
                      "--signer-workflow", "cli/cli/.github/workflows/deployment.yml", "--source-digest", commit,
                      "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"])
    (HERE / "gh-attestation.json").write_text(json.dumps(json.loads(output), indent=1) + "\n")
    return {"version": version, "file": archive, "sha256": sha256, "commit": commit}


def main():
    with tempfile.TemporaryDirectory() as tmp:
        app = Path(tmp).resolve() / "app"
        build_sample(app)
        versions = {"trufflehog": record_trufflehog(app), "grype": record_grype(app), "gh": record_gh(),
                    "recorded": date.today().isoformat()}
    (HERE / "versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    print(f"recorded {versions}")


if __name__ == "__main__":
    main()
