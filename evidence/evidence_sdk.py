"""Helpers for collector scripts.

A collector establishes facts and writes them with emit(). It does not decide
whether a release may proceed: it sets "result" to "pass" or "fail" and the
policy engine decides what a failure means.

If the facts cannot be established at all (an API is down, an analysis is not
finished), call unable(). No evidence is attached and the job reports an error.

A collector knows nothing of Vault or JFrog: it hands over a predicate and
stops. Where the predicate is signed and stored is decided elsewhere, so this
module and every collector must never import signing.py (`cli.py check` fails
if one does). Collectors run with a scrubbed environment. They never see the
Vault or JFrog tokens, only the secrets and variables their catalog entry
declares.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

from core import EvidenceError, http_json


def unable(message):
    """Stop: the facts cannot be established. Nothing is attached."""
    print(message, file=sys.stderr)
    sys.exit(2)


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        unable(f"{name} is not set")
    return value


def param(name, default=None):
    """A parameter the pipeline passed, for example param('sonar-project-key')."""
    return env("EVD_PARAM_" + name.upper().replace("-", "_"), default)


def repository():
    return env("EVD_REPOSITORY")


def commit():
    return env("EVD_COMMIT")


def basic_auth(user, password=""):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def get_json(url, headers=None):
    try:
        return http_json("GET", url, headers=headers)
    except EvidenceError as exc:
        unable(str(exc))


def run_tool(command, cwd=None, env=None):
    """Run a scanner and return what it printed on stdout. Stops with unable() if it cannot run or fails."""
    try:
        done = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    except FileNotFoundError:
        unable(f"{command[0]} is not installed on this runner")
    if done.returncode != 0:
        reason = (done.stderr.strip().splitlines() or ["no message"])[-1]
        unable(f"{command[0]} exited with {done.returncode}: {reason}")
    return done.stdout


def emit(predicate):
    """Write the predicate. The kit validates it against schema.json before it goes anywhere."""
    with open(env("EVD_OUT"), "w", encoding="utf-8") as handle:
        json.dump(predicate, handle)
