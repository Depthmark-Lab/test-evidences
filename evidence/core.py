"""Shared by every part of the kit: the error type, log masking, JSON files, JSON over HTTP, DSSE encoding
and predicate types.

Knows nothing of Vault or JFrog, so collectors, evidence processing and
verification can use it. Anything that talks to Vault or JFrog belongs in
signing.py instead. Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


class EvidenceError(Exception):
    """A step failed in a way the pipeline owner should read."""


def predicate_type(settings, type_id, entry, version):
    """The predicateType a statement of this evidence type and version carries.

    A version listed in the entry's "predicateTypes" uses that standard type,
    such as SLSA provenance, so other tools can read it. Every other version
    is <predicateBase>/<type>/<version>.
    """
    return entry.get("predicateTypes", {}).get(version) or f"{settings['predicateBase']}/{type_id}/{version}"


def evidence_type(kind, catalog, settings):
    """The (type id, version) a predicateType names, or raise: the reverse of predicate_type()."""
    for type_id, entry in catalog.items():
        for version, declared in entry.get("predicateTypes", {}).items():
            if declared == kind:
                return type_id, version
    base = settings["predicateBase"].rstrip("/") + "/"
    type_id, _, version = kind[len(base):].partition("/") if kind.startswith(base) else ("", "", "")
    if (type_id in catalog and re.fullmatch(r"v[0-9]+", version)
            and version not in catalog[type_id].get("predicateTypes", {})):
        return type_id, version
    raise EvidenceError(f"unknown predicate type '{kind}'")


def mask(value):
    """Ask the GitHub runner to hide a secret value in logs."""
    if value and os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}", flush=True)


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def pae(payload_type, payload):
    """DSSE pre-authentication encoding: the exact bytes that get signed."""
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def http_json(method, url, body=None, headers=None, timeout=30):
    """Call a JSON API. On failure, raise with the status and the server's own message."""
    request_headers = {"Accept": "application/json"}
    request_headers.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:1000]
        raise EvidenceError(f"{method} {url} returned {exc.code}: {detail}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise EvidenceError(f"{method} {url} failed: {getattr(exc, 'reason', exc)}") from None
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        raise EvidenceError(f"{method} {url} did not return JSON") from None
