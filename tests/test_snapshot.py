"""Tests for scripts/snapshot-repository.py: a repository's controls as JSON to commit, read with a github-sts token.

Standard library only. One local server plays GitHub's OIDC endpoint, its REST
API and github-sts. Run from the repository root:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "snapshot-repository.py"
REPO = "acme-bank/payments"
STS_TOKEN = "ghs_sts_installation_token"
DEPLOY_KEY = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519 stand-in public key").decode()
PLAN_LIMIT = "Upgrade to GitHub Pro or make this repository public to enable this feature."


def jwt(claims):
    """A token shaped like GitHub's OIDC token: real claims, a signature nobody checks."""
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJl"


class StandIn:
    """GitHub and github-sts on a local port. Change the public attributes to stage a scenario."""

    def __init__(self):
        # Scenario switches
        self.plan_limits = False            # rulesets and branch protection, as on a private repository on Free
        self.sts_refuses = False
        self.new_collaborator = None        # a login that gained access since the last snapshot
        # What the services saw
        self.sts_exchanges = []             # dicts: scope, identity, app, aud
        self.revoked = []                   # installation tokens
        self.settings_auth = []             # Authorization headers on the repository's settings
        handler = type("Handler", (_Handler,), {"stand_in": self})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _Handler(BaseHTTPRequestHandler):
    stand_in: StandIn

    def log_message(self, *_):
        pass

    def reply(self, status, body, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/oidc":
            if self.headers.get("Authorization") != "Bearer runner-token":
                return self.reply(401, {"message": "bad runner token"})
            return self.reply(200, {"value": jwt({"aud": query["audience"][0], "repository": REPO})})
        if url.path == "/sts/exchange":
            return self.sts_exchange(query)
        if not self.repository_settings(url, query):
            self.reply(404, {"message": f"no route GET {url.path}"})

    def do_DELETE(self):
        if urlparse(self.path).path == "/gh/installation/token":
            self.stand_in.revoked.append(self.headers.get("Authorization", "").removeprefix("Bearer "))
            self.send_response(204)
            self.end_headers()
            return
        self.reply(404, {"message": f"no route DELETE {self.path}"})

    def sts_exchange(self, query):
        """github-sts: an installation token for a workflow whose OIDC token is for its audience."""
        s = self.stand_in
        bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            part = bearer.split(".")[1]
            audience = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["aud"]
        except (IndexError, ValueError, KeyError):
            return self.reply(401, {"error": "unauthorized", "code": "invalid_token", "detail": "not a JWT"})
        s.sts_exchanges.append({"scope": query.get("scope", [""])[0], "identity": query.get("identity", [""])[0],
                                "app": query.get("app", [""])[0], "aud": audience})
        if s.sts_refuses:
            return self.reply(403, {"error": "forbidden", "code": "policy_denied", "detail": "no trust policy matched",
                                    "trace_id": "t-1"})
        return self.reply(200, {"token": STS_TOKEN, "expires_at": "2026-11-18T14:00:00Z"})

    def repository_settings(self, url, query):
        """GitHub's answers about a repository's controls and access. Returns False for a path it does not know."""
        s = self.stand_in
        s.settings_auth.append(self.headers.get("Authorization"))
        repo = f"/gh/repos/{REPO}"
        user = lambda login, number: {"login": login, "id": number, "type": "User", "node_id": f"U_{number}",
                                      "avatar_url": f"https://avatars.example/{number}", "html_url": f"https://github.com/{login}"}
        if url.path in (f"{repo}/rules/branches/main", f"{repo}/rulesets", f"{repo}/rulesets/42",
                        f"{repo}/branches/main/protection") and s.plan_limits:
            self.reply(403, {"message": PLAN_LIMIT})
        elif url.path == repo:
            # updated_at changes on every answer, as GitHub's does whenever anything is pushed.
            self.reply(200, {"id": 1, "full_name": REPO, "visibility": "private", "private": True, "archived": False,
                             "default_branch": "main", "allow_merge_commit": False, "allow_squash_merge": True,
                             "allow_rebase_merge": False, "allow_auto_merge": False, "delete_branch_on_merge": True,
                             "node_id": "R_1", "html_url": f"https://github.com/{REPO}", "updated_at": str(time.time()),
                             "owner": {"login": "acme-bank", "type": "Organization"}})
        elif url.path == f"{repo}/rules/branches/main":
            self.reply(200, [
                {"type": "required_status_checks", "ruleset_source_type": "Repository", "ruleset_source": REPO,
                 "ruleset_id": 42, "parameters": {"required_status_checks": [{"context": "verify", "integration_id": 15368}],
                                                  "strict_required_status_checks_policy": True}},
                {"type": "deletion", "ruleset_source_type": "Repository", "ruleset_source": REPO, "ruleset_id": 42}])
        elif url.path == f"{repo}/rulesets":
            self.reply(200, [{"id": 42, "name": "main-change-control", "node_id": "RRS_42", "_links": {"self": {}}}])
        elif url.path == f"{repo}/rulesets/42":
            self.reply(200, {"id": 42, "name": "main-change-control", "target": "branch", "source_type": "Repository",
                             "source": REPO, "enforcement": "active", "bypass_actors": [], "node_id": "RRS_42",
                             "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
                             "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 1,
                                                                               "require_last_push_approval": True}},
                                       {"type": "deletion"}],
                             "current_user_can_bypass": "never", "created_at": "2026-11-01T00:00:00Z",
                             "updated_at": str(time.time()), "_links": {"self": {"href": "https://api.example"}}})
        elif url.path == f"{repo}/branches/main/protection":
            self.reply(404, {"message": "Branch not protected"})
        elif url.path == f"{repo}/actions/permissions":
            self.reply(200, {"enabled": True, "allowed_actions": "selected",
                             "selected_actions_url": f"https://api.example/{REPO}/actions/permissions/selected-actions"})
        elif url.path == f"{repo}/actions/permissions/selected-actions":
            self.reply(200, {"github_owned_allowed": True, "verified_allowed": False, "patterns_allowed": ["acme-bank/*"]})
        elif url.path == f"{repo}/actions/permissions/workflow":
            self.reply(200, {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False})
        elif url.path == f"{repo}/collaborators":
            carol, bob = dict(user("carol", 3), role_name="write"), dict(user("bob", 2), role_name="maintain")
            affiliation, page = query.get("affiliation", ["all"])[0], query.get("page", ["1"])[0]
            if affiliation == "outside":
                self.reply(200, [carol])
            elif affiliation == "direct":
                self.reply(200, [bob, carol])
            elif page == "1":     # GitHub pages its lists: the rest comes from the next page
                following = f"<{s.url}{repo}/collaborators?affiliation=all&per_page=100&page=2>; rel=\"next\""
                self.reply(200, [dict(user("alice", 1), role_name="admin")], {"Link": following})
            else:
                extra = [dict(user(s.new_collaborator, 9), role_name="admin")] if s.new_collaborator else []
                self.reply(200, [carol, bob, *extra])
        elif url.path == f"{repo}/teams":
            self.reply(200, [{"slug": "payments-devs", "id": 7, "permission": "push", "html_url": "https://github.com/t"}])
        elif url.path == "/gh/orgs/acme-bank/members" and query.get("role") == ["admin"]:
            self.reply(200, [user("olivia", 5)])
        elif url.path == f"{repo}/invitations":
            self.reply(200, [{"id": 3, "invitee": user("dave", 4), "permissions": "write", "html_url": "https://x"}])
        elif url.path == f"{repo}/keys":
            self.reply(200, [{"id": 11, "title": "deploy", "key": DEPLOY_KEY, "read_only": False,
                              "created_at": "2026-10-01T00:00:00Z", "url": "https://api.example/keys/11"}])
        elif url.path == f"{repo}/environments":
            self.reply(200, {"total_count": 1, "environments": [{
                "id": 5, "node_id": "EN_5", "name": "production", "can_admins_bypass": False,
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
                "created_at": "2026-10-01T00:00:00Z", "updated_at": str(time.time()),
                "protection_rules": [
                    {"id": 1, "node_id": "GA_1", "type": "required_reviewers", "prevent_self_review": True,
                     "reviewers": [{"type": "Team", "reviewer": {"slug": "release-managers", "id": 8}},
                                   {"type": "User", "reviewer": user("olivia", 5)}]},
                    {"id": 2, "node_id": "GA_2", "type": "wait_timer", "wait_timer": 5}]}]})
        else:
            s.settings_auth.pop()
            return False
        return True


class SnapshotTest(unittest.TestCase):
    """scripts/snapshot-repository.py: a repository's controls as JSON to commit, read with a github-sts token."""

    STS = ("--sts-identity", "repository-controls", "--sts-app", "settings-reader")

    def setUp(self):
        self.services = StandIn()
        self.addCleanup(self.services.close)
        self.tmp = Path(tempfile.mkdtemp(prefix="snapshot-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def snapshot(self, *args, sts_url=None, **env):
        """Run the script as a job would. Returns (exit code, standard output, standard error)."""
        sts = ("--sts-url", sts_url or self.services.url, *self.STS) if sts_url != "" else ()
        done = subprocess.run([sys.executable, str(SCRIPT), *sts, *args], capture_output=True, text=True, env={
            "PATH": os.environ["PATH"], "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPO,
            "GITHUB_API_URL": self.services.url + "/gh",
            "ACTIONS_ID_TOKEN_REQUEST_URL": self.services.url + "/oidc?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-token", **env})
        return done.returncode, done.stdout, done.stderr

    def test_every_control_is_read_with_a_github_sts_token_that_is_then_revoked(self):
        code, out, err = self.snapshot()
        self.assertEqual(code, 0, err)
        taken = json.loads(out)       # standard output is the snapshot alone: workflow commands go to standard error
        self.assertEqual(self.services.sts_exchanges, [{"scope": REPO, "identity": "repository-controls",
                                                        "app": "settings-reader", "aud": "github-sts"}])
        self.assertEqual(set(self.services.settings_auth), {f"Bearer {STS_TOKEN}"})
        self.assertEqual(self.services.revoked, [STS_TOKEN])
        self.assertIn(f"::add-mask::{STS_TOKEN}", err)
        self.assertNotIn(STS_TOKEN, out + err.replace(f"::add-mask::{STS_TOKEN}", ""))

        self.assertEqual((taken["format"], taken["repository"], taken["branch"]), ("repository-controls/v1", REPO, "main"))
        self.assertEqual(taken["settings"]["delete_branch_on_merge"], True)
        self.assertNotIn("updated_at", json.dumps(taken))       # what changes on its own, and every URL, is left out
        self.assertNotIn("https://", json.dumps(taken))
        ruleset = taken["rules"]["rulesets"][0]
        self.assertEqual((ruleset["bypass_actors"], ruleset["created_at"]), ([], "2026-11-01T00:00:00Z"))
        self.assertEqual([rule["type"] for rule in ruleset["rules"]], ["deletion", "pull_request"])   # sorted
        self.assertEqual(taken["branch_protection"], {"protected": False})
        self.assertEqual(taken["actions"]["selectedActions"]["patterns_allowed"], ["acme-bank/*"])
        self.assertIs(taken["actions"]["workflow"]["can_approve_pull_request_reviews"], False)
        # Who has access, and how: across the API's pages, and through the org, directly or from outside it.
        self.assertEqual(taken["access"]["collaborators"], [
            {"id": 1, "login": "alice", "role": "admin", "type": "User", "via": "team or organization"},
            {"id": 2, "login": "bob", "role": "maintain", "type": "User", "via": "direct"},
            {"id": 3, "login": "carol", "role": "write", "type": "User", "via": "outside"}])
        self.assertEqual(taken["access"]["organization_owners"], ["olivia"])
        self.assertEqual(taken["access"]["teams"], [{"id": 7, "permission": "push", "slug": "payments-devs"}])
        self.assertEqual(taken["access"]["invitations"], [{"id": 3, "invitee": "dave", "permissions": "write"}])
        key = taken["access"]["deploy_keys"][0]
        blob = base64.b64decode(DEPLOY_KEY.split()[1])
        self.assertEqual(key["fingerprint"], "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="))
        self.assertNotIn(DEPLOY_KEY.split()[1], out)            # names the key, never holds it
        reviewers = taken["environments"][0]["protection_rules"][0]
        self.assertEqual((reviewers["prevent_self_review"], reviewers["reviewers"]),
                         (True, [{"name": "release-managers", "type": "Team"}, {"name": "olivia", "type": "User"}]))

    def test_the_same_controls_give_the_same_bytes_and_check_finds_what_changed(self):
        committed, live, summary = self.tmp / "repository-controls.json", self.tmp / "live.json", self.tmp / "summary.md"
        code, _, err = self.snapshot("--out", str(committed), GITHUB_STEP_SUMMARY=str(summary))
        self.assertEqual(code, 0, err)
        self.assertIn("📸 Snapshot taken. Review it, then commit it as the declared state.", summary.read_text())
        code, out, err = self.snapshot("--check", str(committed))
        self.assertEqual((code, out), (0, ""), err)
        self.assertIn(f"✅ {REPO}: the controls match", err)

        # The workflow's form: compare, and keep the live snapshot to commit when the change was intended.
        self.services.new_collaborator = "mallory"
        code, out, err = self.snapshot("--check", str(committed), "--out", str(live), GITHUB_STEP_SUMMARY=str(summary))
        self.assertEqual(code, 1, err)
        self.assertRegex(out, r'(?m)^\+\s+"login": "mallory",$')
        self.assertIn(f"::error::{REPO}: the controls differ from {committed}", err)
        self.assertIn("mallory", live.read_text())
        written = summary.read_text()
        self.assertIn(f"❌ The controls differ from the declared ones, `{committed}`.", written)
        self.assertRegex(written, r'(?s)```diff\n.*\n\+\s+"login": "mallory",\n.*\n```')

    def test_what_github_will_not_show_is_recorded_not_left_out(self):
        self.services.plan_limits = True
        code, out, err = self.snapshot()
        self.assertEqual(code, 0, err)
        taken = json.loads(out)
        unavailable = {"unavailable": f"HTTP 403: {PLAN_LIMIT}"}
        self.assertEqual((taken["rules"]["branch"], taken["rules"]["rulesets"], taken["branch_protection"]),
                         (unavailable, unavailable, unavailable))
        self.assertIn(f"::warning::rulesets: not read, HTTP 403: {PLAN_LIMIT}", err)
        self.assertEqual(len(taken["access"]["collaborators"]), 3)   # the rest is still read
        summary = self.tmp / "summary.md"
        self.snapshot("--out", str(self.tmp / "s.json"), GITHUB_STEP_SUMMARY=str(summary))
        self.assertIn(f"- ⚠️ `rules.rulesets`: HTTP 403: {PLAN_LIMIT}", summary.read_text())

    def test_a_refused_exchange_reads_nothing(self):
        self.services.sts_refuses = True
        code, out, err = self.snapshot()
        self.assertEqual((code, out), (2, ""))
        self.assertIn(f"github-sts refused identity 'repository-controls' for {REPO}: HTTP 403 policy_denied:"
                      " no trust policy matched", err)
        self.assertEqual((self.services.settings_auth, self.services.revoked), ([], []))

    def test_tokens_go_only_to_https_and_one_must_be_given(self):
        code, _, err = self.snapshot(sts_url="http://sts.example.com")
        self.assertEqual(code, 2)
        self.assertIn("--sts-url must be an https URL, not 'http://sts.example.com'", err)
        self.assertEqual(self.services.sts_exchanges, [])

        code, _, err = self.snapshot(sts_url="", GITHUB_API_URL="http://api.example.com", GH_TOKEN="ghp_given")
        self.assertEqual(code, 2)
        self.assertIn("--api-url must be an https URL", err)

        code, _, err = self.snapshot(sts_url="")
        self.assertEqual(code, 2)
        self.assertIn("no token: pass --sts-url and --sts-identity, or set GH_TOKEN", err)

        # A token from elsewhere, such as github-sts-action's, is used as given, and left for its owner to revoke.
        code, out, err = self.snapshot(sts_url="", GH_TOKEN="ghs_from_the_action")
        self.assertEqual(code, 0, err)
        self.assertEqual(set(self.services.settings_auth), {"Bearer ghs_from_the_action"})
        self.assertEqual(self.services.revoked, [])

    def test_only_repository_snapshot_yml_can_get_the_token(self):
        workflows = REPO_ROOT / ".github" / "workflows"
        reusable = (workflows / "repository-snapshot.yml").read_text()
        app = re.search(r"--sts-app (\S+)", reusable)[1]
        identity = re.search(r"--sts-identity (\S+)", reusable)[1]
        # One identity for the pool, and it trusts the job of repository-snapshot.yml alone, whoever calls it.
        self.assertEqual(sorted(p.name for p in (REPO_ROOT / ".github" / "sts" / app).glob("*.sts.yaml")),
                         [f"{identity}.sts.yaml"])
        policy = (REPO_ROOT / ".github" / "sts" / app / f"{identity}.sts.yaml").read_text()
        pattern = re.search(r"job_workflow_ref: '([^']+)'", policy)[1]
        self.assertRegex("Depthmark-Lab/test-evidences/.github/workflows/repository-snapshot.yml@refs/heads/main", pattern)
        for other in ("Depthmark-Lab/test-evidences/.github/workflows/repository-snapshot.yml@refs/heads/feature/x",
                      "Depthmark-Lab/test-evidences/.github/workflows/repository-controls.yml@refs/heads/main",
                      "Depthmark-Lab/test-evidences/.github/workflows/evidence.yml@refs/heads/main",
                      "Depthmark-Lab/other/.github/workflows/repository-snapshot.yml@refs/heads/main"):
            self.assertNotRegex(other, pattern)
        self.assertIn("runner_environment: '^self-hosted$'", policy)
        granted = dict(re.findall(r"(?m)^  ([a-z_]+): (read|write)$", policy.split("\npermissions:\n", 1)[1]))
        self.assertEqual(granted, {"administration": "read", "environments": "read", "members": "read", "metadata": "read"})
        self.assertIn("id-token: write", reusable)
        # No other workflow names the pool or runs the script: they call repository-snapshot.yml.
        for path in workflows.glob("*.yml"):
            if path.name != "repository-snapshot.yml":
                self.assertNotIn(app, path.read_text(), path.name)
                self.assertNotIn("snapshot-repository.py", path.read_text(), path.name)
        self.assertIn("uses: ./.github/workflows/repository-snapshot.yml", (workflows / "repository-controls.yml").read_text())

    def test_the_declared_controls_are_read_from_inside_the_repository(self):
        """repository-snapshot.yml's step, run with bash, python3 replaced by a recorder of its arguments."""
        workflow = (REPO_ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        step = workflow.split("      - name: 📸 Snapshot the repository's controls\n", 1)[1].split("        run: |\n", 1)[1]
        script = []
        for line in step.splitlines():
            if line.strip() and not line.startswith(" " * 10):
                break                       # a comment that heads the next step
            script.append(line[10:])
        recorder = self.tmp / "bin" / "python3"
        recorder.parent.mkdir()
        recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >"$RUNNER_TEMP/args"\n')
        recorder.chmod(0o755)
        (self.tmp / "declared" / "controls").mkdir(parents=True)
        (self.tmp / "declared" / "controls" / "repository-controls.json").write_text("{}")

        def run(check):
            (self.tmp / "args").unlink(missing_ok=True)
            done = subprocess.run(["bash", "-e", "-c", "\n".join(script)], capture_output=True, text=True, cwd=self.tmp,
                                  env={"PATH": f"{recorder.parent}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(self.tmp),
                                       "GITHUB_REPOSITORY": REPO, "EVD_IN_CHECK": check})
            args = (self.tmp / "args").read_text().splitlines() if (self.tmp / "args").exists() else None
            return done.returncode, done.stdout + done.stderr, args

        code, output, args = run("controls/repository-controls.json")
        self.assertEqual(code, 0, output)
        self.assertEqual(args[args.index("--check") + 1], "declared/controls/repository-controls.json")
        self.assertEqual(args[args.index("--sts-identity") + 1], "repository-snapshot")

        code, output, args = run("controls/not-yet.json")       # nothing committed yet: a snapshot, and a notice
        self.assertEqual(code, 0, output)
        self.assertNotIn("--check", args)
        self.assertIn("::notice title=📸 No declared controls yet::", output)

        for outside in ("../secrets.json", "controls/../../x.json", "controls/$(id).json"):
            code, output, args = run(outside)
            self.assertEqual((code, args), (1, None), outside)
            self.assertIn("check must be a relative path inside the repository", output)
            self.assertNotIn(outside, output)                   # what failed the check is not echoed

if __name__ == "__main__":
    unittest.main()
