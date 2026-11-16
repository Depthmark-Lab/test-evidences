#!/usr/bin/env python3
"""Record real scanner output for the tests to replay.

The tests do not run TruffleHog or Grype: they put stand-ins on PATH that print
what this script recorded. Run it again to refresh the recordings, for example
after moving to a new scanner version, then fix whatever the tests report.

  python3 tests/scanners/record.py

Needs trufflehog, grype and openssl on PATH. Grype downloads its vulnerability
database on first use.

The sample it scans comes from sample.py. It is built in a temporary directory
and deleted afterwards, so the repository never holds a manifest that its own
scanners would flag, or a string that secret scanning would block. Secret values in TruffleHog's output
are replaced with REMOVED before anything is written, and local paths with
runner-like ones.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import date
from pathlib import Path

from sample import build_sample

HERE = Path(__file__).resolve().parent
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
    lines = run(["trufflehog", "filesystem", ".", "--json", "--no-update", "--exclude-paths", str(exclude),
                 "--no-verification"], cwd=app).splitlines()
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


def main():
    with tempfile.TemporaryDirectory() as tmp:
        app = Path(tmp).resolve() / "app"
        build_sample(app)
        versions = {"trufflehog": record_trufflehog(app), "grype": record_grype(app),
                    "recorded": date.today().isoformat()}
    (HERE / "versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    print(f"recorded {versions}")


if __name__ == "__main__":
    main()
