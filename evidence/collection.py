"""Collection: run a collector with a scrubbed environment and check what it wrote.

This is the evidence logic, and it knows nothing of Vault or JFrog. Its secrets
arrive through a resolver the caller supplies (Vault in `run`, the environment
in `collect`), and it hands back a predicate checked against its schema. What
happens to the predicate next is up to the caller: cli.py passes it to
signing.py, or writes it to a file. When another job collected it, `sign`
runs it through check() again before anything is signed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import schema as schemas
from core import EvidenceError, load_json

ROOT = Path(__file__).resolve().parent
COLLECTORS = ROOT / "collectors"
DEFAULT_TIMEOUT = 180

# The only variables a collector inherits from the job, besides what its catalog entry declares.
PASSTHROUGH = (
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "GITHUB_API_URL", "GITHUB_SERVER_URL",
)


def param_variable(name):
    return "EVD_PARAM_" + name.upper().replace("-", "_")


def collector_env(entry, params, shared, secrets, out_path):
    """Build the scrubbed environment a collector runs with.

    shared holds the variables every collector gets (settings "collectorEnv").
    """
    env = {name: os.environ[name] for name in PASSTHROUGH if name in os.environ}
    for name in entry.get("env", []):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(shared)
    env.update(secrets)
    for name in entry.get("params", {}):
        if name in params:
            env[param_variable(name)] = params[name]
    env["EVD_REPOSITORY"] = os.environ.get("EVD_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY", "")
    env["EVD_COMMIT"] = os.environ.get("EVD_COMMIT") or os.environ.get("GITHUB_SHA", "")
    env["EVD_OUT"] = str(out_path)
    env["PYTHONPATH"] = str(ROOT)
    return env


def run_collector(type_id, version, entry, params, shared, secrets, workdir):
    out_path = workdir / f"{type_id}.json"
    script = COLLECTORS / type_id / version / "collect.py"
    timeout = entry.get("timeout", DEFAULT_TIMEOUT)
    try:
        done = subprocess.run(
            [sys.executable, str(script)],
            env=collector_env(entry, params, shared, secrets, out_path),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise EvidenceError(f"the collector timed out after {timeout} seconds") from None
    if done.returncode != 0:
        reason = (done.stderr.strip().splitlines() or ["no message"])[-1]
        raise EvidenceError(f"the facts could not be established: {reason}")
    try:
        return load_json(out_path)
    except (OSError, ValueError):
        raise EvidenceError("the collector did not write a JSON predicate") from None


def collect(type_id, entry, params, shared, resolve_secret, workdir):
    """Collect one evidence type and return its predicate, checked against its schema.

    resolve_secret(name, spec) returns the value of a secret the catalog entry
    declares. It is only called once the parameters are known to be complete.
    """
    missing = [name for name, spec in entry.get("params", {}).items() if spec.get("required") and not params.get(name)]
    if missing:
        raise EvidenceError(f"missing parameter(s): {', '.join(missing)}")

    secrets = {name: resolve_secret(name, spec) for name, spec in entry.get("secrets", {}).items()}
    predicate = run_collector(type_id, entry["current"], entry, params, shared, secrets, workdir)
    return check(type_id, entry["current"], predicate)


def check(type_id, version, predicate):
    """Return the predicate if it matches the schema of that type and version, or raise."""
    problems = schemas.validate(predicate, load_json(COLLECTORS / type_id / version / "schema.json"))
    if problems:
        raise EvidenceError("the predicate does not match its schema: " + "; ".join(problems[:5]))
    return predicate
