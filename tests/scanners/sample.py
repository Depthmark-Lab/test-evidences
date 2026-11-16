#!/usr/bin/env python3
"""Build a small application with two leaked secrets and vulnerable dependencies.

  python3 tests/scanners/sample.py <directory>

record.py scans it to refresh the recordings, and the demo workflow builds it on
the runner to collect real evidence from. It is generated at run time so the
repository never holds a manifest its own scanners would flag, or a string that
secret scanning would block. The secrets are random and work nowhere.

Needs openssl on PATH.
"""
from __future__ import annotations

import secrets
import string
import subprocess
import sys
from pathlib import Path

# Old versions with published vulnerabilities, at several severities.
REQUIREMENTS = "requests==2.19.0\nPyYAML==5.3\nJinja2==2.10\n"


def random_text(length):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def build_sample(app):
    """Write the sample application into app, which must not exist yet."""
    (app / "config").mkdir(parents=True)
    (app / "requirements.txt").write_text(REQUIREMENTS)
    (app / "main.py").write_text('print("hello")\n')
    # Assembled here so that this file holds no complete webhook address.
    webhook = "/".join(["https://hooks.slack.com/services", "T" + random_text(8).upper(),
                        "B" + random_text(10).upper(), random_text(24)])
    (app / "config" / "settings.py").write_text(f'SLACK_WEBHOOK = "{webhook}"\n')
    key = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, text=True, check=True).stdout
    (app / "deploy-key.pem").write_text(key)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    build_sample(Path(sys.argv[1]).resolve())
