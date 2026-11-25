"""Stand-ins for GitHub (OIDC and API), Vault, JFrog Evidence, SonarQube and the scanners.

One local HTTP server plays the first four. Its Vault signs with a throwaway RSA
key through the openssl command, and its JFrog verifies every signature against
the matching public key over the DSSE bytes it rebuilds itself. With the file
store there is no JFrog: the tests verify the envelopes with openssl and with
`cli.py verify`. The scanners are
small scripts that print output recorded from the real tools (scanners/record.py).
Test use only.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SHA = "a" * 40
HEAD = "b" * 40
REPO = "acme-bank/payments"
SCANNERS = Path(__file__).resolve().parent / "scanners"


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True)


def jwt(claims):
    """A token shaped like GitHub's OIDC token: real claims, a signature nobody checks."""
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJl"


def github_claims(audience):
    """What GitHub puts in the token of a job of evidence.yml on main, on a self-hosted runner."""
    return {"iss": "https://token.actions.githubusercontent.com", "aud": audience, "sub": f"repo:{REPO}:ref:refs/heads/main",
            "repository": REPO, "repository_owner_id": "71595780", "ref": "refs/heads/main", "sha": SHA,
            "run_id": "4242", "run_attempt": "1",
            "job_workflow_ref": f"{REPO}/.github/workflows/evidence.yml@refs/heads/main",
            "runner_environment": "self-hosted", "iat": 1_800_000_000, "exp": 1_800_000_300}


_FAKE_SCANNER = """#!{python}
import json, os, sys
with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:], "cwd": os.getcwd(), "cwdEntries": os.listdir("."),
                             "env": dict(os.environ)}}) + "\\n")
if sys.argv[1:] == ["--version"]:
    print({version!r})
    sys.exit(0)
if {exit_code!r}:
    print({stderr!r}, file=sys.stderr)
    sys.exit({exit_code!r})
sys.stdout.write({output!r})
"""


def fake_scanner(directory, name, output="", version="", exit_code=0, stderr=""):
    """Put a stand-in for a scanner in directory. Returns its log: one JSON line per call."""
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / f"{name}.calls"
    script = directory / name
    script.write_text(_FAKE_SCANNER.format(python=sys.executable, log=str(log), version=version,
                                           exit_code=exit_code, stderr=stderr, output=output))
    script.chmod(0o755)
    return log


class Services:
    """Start with Services(); change the public attributes to stage a scenario."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="evidence-mock-"))
        self.key = self._new_key("signing")
        self.trusted_public_key = self.key.with_suffix(".pub")

        # Scenario switches
        self.has_pull_request = True
        self.second_reviewer_approves = True
        self.gate_status = "OK"
        self.has_analysis = True
        self.tamper_statement = False
        self.refuse_logins = False

        # What the services saw
        self.vault_logins = []      # (role, jwt)
        self.jfrog_exchanges = []   # jwt
        self.sign_calls = []        # key name
        self.deployed = []          # dicts: keyid, verified, statement
        self.sonar_auth = []        # Authorization headers
        self._statements = {}

        handler = type("Handler", (_Handler,), {"services": self})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _new_key(self, name):
        key = self.dir / f"{name}.pem"
        openssl("genrsa", "-out", str(key), "2048")
        openssl("rsa", "-in", str(key), "-pubout", "-out", str(key.with_suffix(".pub")))
        return key

    def trust_a_different_key(self):
        """JFrog now holds a public key that does not match Vault's signing key."""
        self.trusted_public_key = self._new_key("other").with_suffix(".pub")

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def settings(self, **overrides):
        settings = {
            "identity": "github",
            "tier": "prod",
            "store": "jfrog",
            "predicateBase": "https://evidence.acme-bank.example",
            "families": ["scan", "approval", "self", "build"],
            "vault": {"addr": self.url, "namespace": "platform", "authPath": "github-actions",
                      "audience": "https://vault.acme-bank.example", "transitMount": "transit-evidence",
                      "signatureAlgorithm": "pkcs1v15"},
            "jfrog": {"url": self.url, "oidcProvider": "github-evidence", "audience": "jfrog-evidence"},
            "collectorEnv": {"SONAR_URL": self.url + "/sonar"},
        }
        for dotted, value in overrides.items():
            section, _, name = dotted.partition(".")
            if name:
                settings[section][name] = value
            else:
                settings[section] = value
        return settings


class _Handler(BaseHTTPRequestHandler):
    services: Services

    def log_message(self, *_):
        pass

    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    # ---- GET: OIDC, Vault KV, GitHub API, SonarQube -----------------------

    def do_GET(self):
        s = self.services
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/oidc":
            if self.headers.get("Authorization") != "Bearer runner-token":
                return self.reply(401, {"message": "bad runner token"})
            return self.reply(200, {"value": jwt(github_claims(query["audience"][0]))})

        if url.path == "/v1/kv/data/evidence/sonarqube":
            if self.headers.get("X-Vault-Token") != "hvs.evidence-scan-prod":
                return self.reply(403, {"errors": ["permission denied"]})
            return self.reply(200, {"data": {"data": {"token": "squ_secret"}}})

        if url.path == f"/gh/repos/{REPO}/commits/{SHA}/pulls":
            return self.reply(200, [{"number": 7, "merged_at": "2026-11-01T10:00:00Z"}] if s.has_pull_request else [])
        if url.path == f"/gh/repos/{REPO}/pulls/7":
            return self.reply(200, {
                "number": 7, "html_url": f"https://github.com/{REPO}/pull/7", "user": {"login": "alice"},
                "merged_by": {"login": "bob"}, "merged_at": "2026-11-01T10:00:00Z",
                "base": {"ref": "main"}, "head": {"sha": HEAD}})
        if url.path == f"/gh/repos/{REPO}/pulls/7/reviews":
            reviews = [
                {"user": {"login": "alice"}, "state": "APPROVED", "submitted_at": "2026-10-31T09:00:00Z", "commit_id": HEAD},
                {"user": {"login": "bob"}, "state": "CHANGES_REQUESTED", "submitted_at": "2026-10-31T10:00:00Z", "commit_id": HEAD},
                {"user": {"login": "carol"}, "state": "COMMENTED", "submitted_at": "2026-10-31T11:00:00Z", "commit_id": HEAD},
            ]
            if s.second_reviewer_approves:
                reviews.append({"user": {"login": "bob"}, "state": "APPROVED",
                                "submitted_at": "2026-10-31T12:00:00Z", "commit_id": HEAD})
            return self.reply(200, reviews)

        if url.path == "/sonar/api/project_analyses/search":
            s.sonar_auth.append(self.headers.get("Authorization"))
            analyses = [{"key": "AX-old", "revision": "f" * 40}]
            if s.has_analysis:
                analyses.append({"key": "AX-1", "revision": SHA})
            return self.reply(200, {"analyses": analyses})
        if url.path == "/sonar/api/qualitygates/project_status":
            return self.reply(200, {"projectStatus": {"status": s.gate_status, "conditions": [
                {"status": s.gate_status, "metricKey": "new_coverage", "comparator": "LT", "errorThreshold": "80"}]}})

        self.reply(404, {"errors": [f"no route GET {url.path}"]})

    # ---- POST: Vault login and sign, JFrog token, prepare and deploy -----------

    def do_POST(self):
        s = self.services
        url = urlparse(self.path)
        body = self.body()

        if url.path == "/v1/auth/github-actions/login":
            if self.headers.get("X-Vault-Namespace") != "platform":
                return self.reply(400, {"errors": ["missing namespace"]})
            s.vault_logins.append((body["role"], body["jwt"]))
            if s.refuse_logins:
                return self.reply(400, {"errors": [
                    'error validating claims: claim "job_workflow_ref" does not match any associated bound claim values']})
            return self.reply(200, {"request_id": f"login-{len(s.vault_logins)}", "auth": {
                "client_token": "hvs." + body["role"], "token_type": "batch", "lease_duration": 600,
                "token_policies": [body["role"] + "-transit-sign"]}})

        if url.path.startswith("/v1/transit-evidence/sign/"):
            key_name = url.path.rsplit("/", 1)[1]
            # Like a Vault policy: a family's token may only use that family's key.
            if self.headers.get("X-Vault-Token") != "hvs.evidence-" + key_name[len("evd-"):]:
                return self.reply(403, {"errors": ["permission denied"]})
            if body.get("hash_algorithm") != "sha2-256":
                return self.reply(400, {"errors": ["unexpected hash algorithm"]})
            s.sign_calls.append(key_name)
            args = ["dgst", "-sha256", "-sign", str(s.key)]
            if body.get("signature_algorithm") == "pss":
                if body.get("salt_length") != "hash":
                    return self.reply(400, {"errors": ["pss needs salt_length=hash"]})
                args += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
            signature = openssl(*args, data=base64.b64decode(body["input"])).stdout
            return self.reply(200, {"request_id": f"sign-{len(s.sign_calls)}", "data": {
                "signature": "vault:v3:" + base64.b64encode(signature).decode(), "key_version": 3}})

        if url.path == "/access/api/v1/oidc/token":
            if body.get("provider_name") != "github-evidence" or not body.get("grant_type", "").endswith("token-exchange"):
                return self.reply(400, {"errors": ["bad exchange request"]})
            s.jfrog_exchanges.append(body["subject_token"])
            return self.reply(200, {"access_token": "jf.token"})

        if url.path.startswith("/evidence/") and self.headers.get("Authorization") != "Bearer jf.token":
            return self.reply(401, {"errors": ["bad credentials"]})

        if url.path == "/evidence/api/v1/evidence/prepare":
            subject = body["subject"]
            predicate = dict(body["predicate"], injected=True) if s.tamper_statement else body["predicate"]
            statement = json.dumps({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": subject["repo_path"],
                             "digest": {"sha256": subject.get("subject_sha256") or "0" * 64}}],
                "predicateType": body["predicate_type"],
                "predicate": predicate,
                "createdAt": "2026-11-14T00:00:00Z",
                "createdBy": "évidence",          # non-ASCII on purpose: byte counts must still be right
            }, ensure_ascii=False).encode()
            encoded = base64.b64encode(statement).decode()
            s._statements[encoded] = statement
            return self.reply(200, {"post_url": "/evidence/api/v1/subject/" + subject["repo_path"],
                                    "dsse_payload": encoded, "dsse_payload_type": "application/vnd.in-toto+json"})

        if url.path.startswith("/evidence/api/v1/subject/"):
            statement = s._statements.get(body["payload"])
            if statement is None:
                return self.reply(400, {"errors": ["payload was not prepared by this server"]})
            key_id = body["signatures"][0]["keyid"]
            kind = body["payloadType"].encode()
            signed_bytes = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(statement), statement)
            signature_file = s.dir / "signature.bin"
            signature_file.write_bytes(base64.b64decode(body["signatures"][0]["sig"]))
            args = ["dgst", "-sha256", "-verify", str(s.trusted_public_key), "-signature", str(signature_file)]
            if key_id.endswith(";PS256"):
                args += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
            verified = openssl(*args, data=signed_bytes).returncode == 0
            s.deployed.append({"keyid": key_id, "verified": verified, "statement": json.loads(statement)})
            return self.reply(201, {"verified": verified, "signing_key": {"alias": key_id}})

        self.reply(404, {"errors": [f"no route POST {url.path}"]})
