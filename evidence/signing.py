"""Signing and attaching: workload identity, Vault, JFrog and DSSE.

The only module that talks to Vault or JFrog. It takes a finished predicate and
never interprets it: it only checks that JFrog's statement carries it unchanged.
Evidence logic (collectors, evidence_sdk.py, collection.py, schema.py, core.py)
and verification.py must never import this module, directly or not. `cli.py
check` fails if one does.

Two stores, chosen by settings "store": "jfrog" has JFrog prepare the statement
and attaches the signed envelope to the artifact, "file" builds the same
statement here and returns the signed envelope for the caller to write. Either
way the private key never leaves Vault Transit.

Every step with Vault goes to the job's log as it happens: the claims of the
identity token Vault checks, the login, the key, the bytes signed and Vault's
request id for each call, which its audit log also records. Vault keeps the same
facts in its trail, for cli.py to add to the step summary.

Standard library only, so nothing is installed at run time in the signing path.
Tokens stay in memory. They are never written to disk or to the job environment,
and never printed: they are masked, and only the token's claims are shown.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
import urllib.parse

from core import PAYLOAD_TYPE, STATEMENT_TYPE, EvidenceError, http_json, mask, pae

ALGORITHMS = {"pkcs1v15": "RSA PKCS#1 v1.5", "pss": "RSA-PSS"}
# The claims of the identity token that Vault's evidence roles bind or record, in the order the log shows them.
CLAIMS = ("aud", "job_workflow_ref", "runner_environment", "repository", "repository_owner_id", "ref", "sha",
          "run_id", "run_attempt")


def say(line):
    """A line in the job's log, as the step happens."""
    print(line, flush=True)


def claims(token):
    """A JWT's claims, read without checking its signature: Vault checks it. Empty for any other token."""
    try:
        part = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def lasting(seconds):
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
        return "an unknown time"
    return f"{seconds // 60}m" if seconds % 60 == 0 else f"{seconds}s"


def id_token(settings, target):
    """Return this job's workload identity token (a JWT) for 'vault' or 'jfrog'.

    identity = "github": ask the GitHub Actions OIDC endpoint for the audience.
    identity = "file":   read a token another CI system wrote to a file
                         (EVD_VAULT_JWT_FILE / EVD_JFROG_JWT_FILE).
    """
    source = settings.get("identity", "github")
    if source == "file":
        variable = f"EVD_{target.upper()}_JWT_FILE"
        path = os.environ.get(variable)
        if not path:
            raise EvidenceError(f"identity is 'file' but {variable} is not set")
        try:
            with open(path, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise EvidenceError(f"cannot read {variable}: {exc}") from None
        mask(token)
        return token
    if source != "github":
        raise EvidenceError(f"unknown identity source '{source}'")

    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise EvidenceError("no GitHub OIDC endpoint: the job needs 'permissions: id-token: write'")
    audience = settings[target]["audience"]
    joiner = "&" if "?" in url else "?"
    reply = http_json(
        "GET",
        f"{url}{joiner}audience={urllib.parse.quote(audience, safe='')}",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    if not reply.get("value"):
        raise EvidenceError("the GitHub OIDC endpoint returned no token")
    mask(reply["value"])
    return reply["value"]


class Vault:
    """Vault Enterprise: one login per key family, Transit signing, KV reads.

    trail holds one dict per login and per signature, in order: what the log said, for the step summary.
    """

    def __init__(self, settings):
        self.settings = settings
        self.conf = settings["vault"]
        self.tier = settings["tier"]
        self._tokens = {}
        self.trail = []

    def describe(self):
        """One line naming the Vault, its mounts and the signature algorithm."""
        algorithm = self.conf.get("signatureAlgorithm", "pkcs1v15")
        namespace = f", namespace {self.conf['namespace']}" if self.conf.get("namespace") else ""
        return (f"🏦 Vault {self.conf['addr']}{namespace}: login at auth/{self.conf['authPath']}, "
                f"Transit at {self.conf['transitMount']}, {ALGORITHMS.get(algorithm, algorithm)} with SHA-256")

    def _call(self, step, path, body, token=None):
        """POST to Vault for one step of the trail, and record Vault's request id and the time it took, or its refusal."""
        started = time.monotonic()
        try:
            reply = http_json("POST", f"{self.conf['addr']}/v1/{path}", body, self._headers(token))
        except EvidenceError as exc:
            step["error"] = str(exc)
            say(f"⛔ {exc}")
            raise
        step.update(request=str(reply.get("request_id") or "none"), ms=round((time.monotonic() - started) * 1000))
        return reply

    def _headers(self, token=None):
        headers = {}
        if self.conf.get("namespace"):
            headers["X-Vault-Namespace"] = self.conf["namespace"]
        if token:
            headers["X-Vault-Token"] = token
        return headers

    def key_name(self, family):
        return f"evd-{family}-{self.tier}"

    def login(self, family):
        if family not in self._tokens:
            role = f"evidence-{family}-{self.tier}"
            jwt = id_token(self.settings, "vault")
            read = claims(jwt)
            step = {"step": "login", "role": role, "claims": {name: str(read[name]) for name in CLAIMS if name in read}}
            self.trail.append(step)
            source = ("the file in EVD_VAULT_JWT_FILE" if self.settings.get("identity", "github") == "file"
                      else "GitHub's OIDC endpoint")
            if step["claims"]:
                until = (f", valid until {time.strftime('%H:%M:%S UTC', time.gmtime(read['exp']))}"
                         if isinstance(read.get("exp"), int) else "")
                say(f"🪪 Identity token from {source}{until}. Vault checks these claims against role {role}:")
                width = max(map(len, step["claims"]))
                for name, value in step["claims"].items():
                    say(f"     {name:<{width}}  {value}")
            else:
                say(f"🪪 Identity token from {source}: not a JWT, so its claims are not shown. "
                    f"Vault checks it against role {role}")

            reply = self._call(step, f"auth/{self.conf['authPath']}/login", {"jwt": jwt, "role": role})
            auth = reply.get("auth") or {}
            token = auth.get("client_token")
            if not token:
                step["error"] = "Vault login returned no token"
                raise EvidenceError(step["error"])
            mask(token)
            step.update(tokenType=str(auth.get("token_type") or "a"), valid=lasting(auth.get("lease_duration")),
                        policies=[str(p) for p in auth.get("token_policies") or auth.get("policies") or []])
            say(f"🔐 Vault login with role {role}: {step['tokenType']} token, valid {step['valid']}, "
                f"policies {', '.join(step['policies']) or 'none'}. Request {step['request']}, {step['ms']} ms. "
                "The token is masked, never printed")
            self._tokens[family] = token
        return self._tokens[family]

    def read_secret(self, family, path, field):
        """Read one field of a KV v2 secret with the family's token."""
        reply = http_json("GET", f"{self.conf['addr']}/v1/{path}", headers=self._headers(self.login(family)))
        value = ((reply.get("data") or {}).get("data") or {}).get(field)
        if not value:
            raise EvidenceError(f"no field '{field}' in Vault secret {path}")
        mask(value)
        say(f"🔑 Vault secret {path}, field {field}: read with the {family} family's token, masked, never printed")
        return value

    def sign(self, family, data, about=""):
        """Sign bytes with the family's Transit key. Returns (key id, base64 signature).

        The key id is <key name>-v<Transit key version>, which is also the alias of
        the public key in JFrog. For PSS it carries the ';PS256' suffix JFrog expects.
        about is the predicate type of the statement the bytes encode, for the trail.
        """
        algorithm = self.conf.get("signatureAlgorithm", "pkcs1v15")
        body = {
            "input": base64.b64encode(data).decode(),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": algorithm,
        }
        if algorithm == "pss":
            body["salt_length"] = "hash"
        key = self.key_name(family)
        token = self.login(family)
        step = {"step": "sign", "about": about, "key": key, "algorithm": ALGORITHMS.get(algorithm, algorithm),
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.trail.append(step)
        say(f"✍️ Transit sign with {key}: {step['algorithm']} over the SHA-256 of {len(data):,} bytes, "
            f"the statement's DSSE encoding. Their SHA-256: {step['sha256']}")

        reply = self._call(step, f"{self.conf['transitMount']}/sign/{key}", body, token)
        parts = str((reply.get("data") or {}).get("signature", "")).split(":")
        if len(parts) != 3 or parts[0] != "vault" or not parts[1].startswith("v") or not parts[2]:
            step["error"] = "unexpected signature format from Vault"
            raise EvidenceError(step["error"])
        key_id = f"{key}-{parts[1]}"
        if algorithm == "pss":
            key_id += ";PS256"
        try:
            size = f"a {len(base64.b64decode(parts[2], validate=True))}-byte signature"
        except binascii.Error:
            size = "a signature that is not base64"
        step.update(version=parts[1][1:], keyId=key_id)
        say(f"✅ Vault signed with {key} version {step['version']}, key id {key_id}: {size}. "
            f"Request {step['request']}, {step['ms']} ms. The private key never left Vault")
        return key_id, parts[2]


class JFrog:
    """JFrog Evidence: token exchange, prepare a statement, deploy the signed envelope."""

    def __init__(self, settings):
        self.settings = settings
        self.conf = settings["jfrog"]
        self._token = None

    def _headers(self):
        if self._token is None:
            reply = http_json(
                "POST",
                f"{self.conf['url']}/access/api/v1/oidc/token",
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                    "subject_token": id_token(self.settings, "jfrog"),
                    "provider_name": self.conf["oidcProvider"],
                },
            )
            if not reply.get("access_token"):
                raise EvidenceError("JFrog token exchange returned no token")
            mask(reply["access_token"])
            self._token = reply["access_token"]
        return {"Authorization": f"Bearer {self._token}"}

    def prepare(self, repo_path, sha256, predicate_type, predicate):
        """Ask JFrog to build the in-toto statement for an artifact. Returns it unsigned."""
        subject = {"subject_type": "artifact", "repo_path": repo_path}
        if sha256:
            subject["subject_sha256"] = sha256
        reply = http_json(
            "POST",
            f"{self.conf['url']}/evidence/api/v1/evidence/prepare",
            {"subject": subject, "predicate": predicate, "predicate_type": predicate_type},
            self._headers(),
        )
        for field in ("post_url", "dsse_payload", "dsse_payload_type"):
            if not reply.get(field):
                raise EvidenceError(f"JFrog prepare response has no '{field}'")
        return reply

    def deploy(self, post_url, envelope):
        return http_json("POST", f"{self.conf['url']}{post_url}", envelope, self._headers())


def check_statement(payload, expected_type, predicate, sha256):
    """Refuse to sign unless the statement JFrog prepared says what was collected."""
    try:
        statement = json.loads(payload)
    except ValueError:
        raise EvidenceError("JFrog returned a statement that is not JSON; refusing to sign") from None
    if statement.get("predicateType") != expected_type or statement.get("predicate") != predicate:
        raise EvidenceError("JFrog returned a statement that differs from what was collected; refusing to sign")
    if sha256:
        digests = [(subject.get("digest") or {}).get("sha256") for subject in statement.get("subject", [])]
        if sha256 not in digests:
            raise EvidenceError("JFrog resolved the subject to a different SHA-256; refusing to sign")


def publish(predicate, predicate_type, family, repo_path, sha256, vault, jfrog):
    """Sign one predicate with the family's key and attach it to the artifact. Returns the key id."""
    prepared = jfrog.prepare(repo_path, sha256, predicate_type, predicate)
    payload = base64.b64decode(prepared["dsse_payload"])
    check_statement(payload, predicate_type, predicate, sha256)
    say(f"📜 JFrog prepared the in-toto statement about {repo_path}, {predicate_type}: it carries what was collected")

    key_id, signature = vault.sign(family, pae(prepared["dsse_payload_type"], payload), about=predicate_type)
    result = jfrog.deploy(prepared["post_url"], {
        "payload": prepared["dsse_payload"],
        "payloadType": prepared["dsse_payload_type"],
        "signatures": [{"keyid": key_id, "sig": signature}],
    })
    if result.get("verified") is not True:
        raise EvidenceError(f"JFrog stored the evidence but did not verify it. Is public key '{key_id}' in trusted keys?")
    return key_id


def envelope(predicate, predicate_type, family, repo_path, sha256, vault):
    """Sign one predicate with the family's key, with no JFrog. Returns (key id, DSSE envelope).

    The statement is the one JFrog would prepare for the same artifact: the
    subject is named by its repository path and pinned by its SHA-256.
    """
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": repo_path, "digest": {"sha256": sha256}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    say(f"📜 In-toto statement about {repo_path}, SHA-256 {sha256}: {predicate_type}, {len(payload):,} bytes")
    key_id, signature = vault.sign(family, pae(PAYLOAD_TYPE, payload), about=predicate_type)
    return key_id, {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": key_id, "sig": signature}],
    }
