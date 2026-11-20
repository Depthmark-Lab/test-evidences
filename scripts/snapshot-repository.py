#!/usr/bin/env python3
"""Snapshot the controls of a GitHub repository as JSON that can be committed and compared.

  scripts/snapshot-repository.py [--repo owner/repo] [--branch main] [--out snapshot.json]
  scripts/snapshot-repository.py --check snapshot.json      # exit 1 when the live controls differ
  scripts/snapshot-repository.py --check snapshot.json --out live.json     # both: compare, and keep the live one

Reads what decides who can change the code and how: the repository's merge
settings, the rules that apply to the branch and the rulesets they come from,
classic branch protection, what workflows may do, everyone with access and how
they got it, pending invitations, deploy keys, and who may approve deployments.

The output holds no URL, timestamp of an edit or other value that changes on its
own, and every list is sorted: a diff between two snapshots is a change of a
control. Committed to a repository, the snapshot is the declared state, and
--check is the drift check.

What the API refuses, because of the plan or the token's permissions, is recorded
as {"unavailable": "HTTP <status>: <GitHub's message>"}, never left out. On
GitHub Actions, the step summary says what was taken, what GitHub did not show,
and with --check whether the controls match, with the difference when not.

The token, in this order:
  --sts-url and --sts-identity  on GitHub Actions, exchange the job's OIDC token
                                (permissions: id-token: write) at github-sts for an
                                installation token, then revoke it on exit
  GH_TOKEN                      a token from elsewhere, such as Depthmark/github-sts-action
The token needs administration: read and metadata: read on the repository, and
members: read on the organization for its owners.

Standard library only. The token is masked on GitHub Actions and never printed.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FORMAT = "repository-controls/v1"
# Fields of the repository that bear on who may merge what, and how.
SETTINGS = ("id", "full_name", "visibility", "private", "archived", "default_branch", "allow_merge_commit",
            "allow_squash_merge", "allow_rebase_merge", "allow_auto_merge", "allow_update_branch",
            "delete_branch_on_merge", "allow_forking", "web_commit_signoff_required", "security_and_analysis")
# Values that change without any control changing, or that only point elsewhere.
VOLATILE = {"node_id", "_links", "updated_at", "current_user_can_bypass", "avatar_url", "gravatar_id"}
# What a list is sorted by, so that its order reads well: the first of these an item has, then the item itself.
NAMES = ("type", "login", "slug", "name", "context", "id")
# The step summary holds 1 MiB at most: a larger difference is cut, and the log keeps it all.
DIFF_LINES = 400


class Failure(Exception):
    """The snapshot cannot be taken: a refused token, a network failure, a server error."""


class Unavailable(Exception):
    """GitHub will not show this part, because of the plan or the token's permissions."""


def say(line):
    print(line, file=sys.stderr, flush=True)


def on_github():
    return os.environ.get("GITHUB_ACTIONS") == "true"


def mask(value):
    # On standard error, like every other line here: standard output may be the snapshot itself.
    if value and on_github():
        say(f"::add-mask::{value}")


def warn(message):
    say(f"::warning::{message}" if on_github() else f"warning: {message}")


def request(method, url, token, accept="application/vnd.github+json"):
    """One HTTP call. Returns (status, JSON body or None, Link header). Raises Failure if there is no answer."""
    headers = {"Accept": accept, "Authorization": f"Bearer {token}", "User-Agent": "snapshot-repository",
               "X-GitHub-Api-Version": "2022-11-28"}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method, headers=headers), timeout=30) as reply:
            status, raw, link = reply.status, reply.read(), reply.headers.get("Link", "")
    except urllib.error.HTTPError as exc:
        status, raw, link = exc.code, exc.read(), ""
    except (urllib.error.URLError, OSError) as exc:
        raise Failure(f"{method} {url} failed: {getattr(exc, 'reason', exc)}") from None
    try:
        body = json.loads(raw) if raw else None
    except ValueError:
        body = None
    return status, body, link


def message(body):
    if isinstance(body, dict):
        return str(body.get("message") or body.get("detail") or body.get("error") or "no message")
    return "no message"


# ---- the token -------------------------------------------------------------------------------


def https_only(url, what):
    """The OIDC token and the installation token go nowhere but HTTPS, or a loopback address for tests."""
    parsed = urllib.parse.urlparse(url)
    loopback = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not loopback:
        raise Failure(f"{what} must be an https URL, not '{url}'")
    return url.rstrip("/")


def oidc_token(audience):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise Failure("--sts-url needs the job's OIDC token: run on GitHub Actions with permissions: id-token: write")
    joiner = "&" if "?" in url else "?"
    status, body, _ = request("GET", f"{url}{joiner}audience={urllib.parse.quote(audience, safe='')}", bearer)
    if status != 200 or not isinstance(body, dict) or not body.get("value"):
        raise Failure(f"GitHub gave no OIDC token: HTTP {status}: {message(body)}")
    mask(body["value"])
    return body["value"]


def exchange(sts_url, scope, identity, app, audience):
    """Exchange the job's OIDC token at github-sts for an installation token. Retries what may pass on a retry."""
    query = {"scope": scope, "identity": identity, **({"app": app} if app else {})}
    url = f"{https_only(sts_url, '--sts-url')}/sts/exchange?{urllib.parse.urlencode(query)}"
    jwt = oidc_token(audience)
    for attempt in range(1, 4):
        try:
            status, body, _ = request("GET", url, jwt, accept="application/json")
        except Failure:
            if attempt == 3:
                raise
            status, body = None, None
        if status is not None and status < 500:
            break
        if attempt < 3:
            time.sleep(2 ** attempt)
    if status != 200 or not isinstance(body, dict) or not body.get("token"):
        code = body.get("code", "") if isinstance(body, dict) else ""
        raise Failure(f"github-sts refused identity '{identity}' for {scope}: HTTP {status}"
                      f"{' ' + code if code else ''}: {message(body)}")
    mask(body["token"])
    say(f"🪪 github-sts gave an installation token for {scope}, identity {identity}"
        f"{', app ' + app if app else ''}. It is masked, and revoked when the snapshot is taken")
    return body["token"]


def revoke(api, token):
    try:
        status, _, _ = request("DELETE", f"{api}/installation/token", token)
    except Failure as exc:
        warn(f"the installation token was not revoked: {exc}")
        return
    if status == 204:
        say("🔒 Installation token revoked")
    else:
        warn(f"revoking the installation token answered HTTP {status}")


# ---- reading ---------------------------------------------------------------------------------


class GitHub:
    def __init__(self, api, token):
        self.api, self.token = api, token

    def get(self, path, items=None):
        """GET a path, following pagination. items names the list in a paged object, such as 'environments'."""
        url = f"{self.api}/{path}"
        collected = None
        while url:
            status, body, link = request("GET", url, self.token)
            if status == 401:
                raise Failure(f"GitHub refused the token for {path}: {message(body)}")
            if status == 403 and "rate limit" in message(body).lower():
                raise Failure(f"GitHub's rate limit stopped the snapshot at {path}: {message(body)}")
            if status in (403, 404):
                raise Unavailable(f"HTTP {status}: {message(body)}")
            if status != 200:
                raise Failure(f"GET {path} answered HTTP {status}: {message(body)}")
            page = body.get(items, []) if items else body
            if not isinstance(page, list):
                return page
            collected = (collected or []) + page
            found = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = found[1] if found else None
        return collected or []


def order(item):
    named = next((str(item[key]) for key in NAMES if key in item), "") if isinstance(item, dict) else ""
    return named.lower(), json.dumps(item, sort_keys=True)


def clean(value):
    """Drop volatile values and links, and sort every list: two snapshots of the same controls are equal bytes."""
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()
                if key not in VOLATILE and key != "url" and not key.endswith("_url")}
    if isinstance(value, list):
        return sorted((clean(item) for item in value), key=order)
    return value


def section(name, read):
    try:
        return read()
    except Unavailable as exc:
        warn(f"{name}: not read, {exc}")
        return {"unavailable": str(exc)}


def fingerprint(public_key):
    """The SHA256 fingerprint ssh-keygen shows, so the snapshot names a key without holding it."""
    try:
        blob = base64.b64decode(public_key.split()[1], validate=True)
    except (IndexError, ValueError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def reviewer(entry):
    found = entry.get("reviewer") or {}
    return {"type": entry.get("type", ""), "name": found.get("login") or found.get("slug") or ""}


def snapshot(github, repo, branch=None):
    r = f"repos/{repo}"
    try:
        settings = github.get(r)
    except Unavailable as exc:
        raise Failure(f"cannot read {repo}: {exc}") from None
    branch = branch or settings.get("default_branch") or "main"
    owner = settings.get("owner") or {}
    quoted = urllib.parse.quote(branch, safe="")

    def rulesets():
        listed = github.get(f"{r}/rulesets?includes_parents=true&per_page=100")
        return clean([github.get(f"{r}/rulesets/{ruleset['id']}") for ruleset in listed])

    def branch_protection():
        try:
            return clean(github.get(f"{r}/branches/{quoted}/protection"))
        except Unavailable as exc:
            if "Branch not protected" in str(exc):
                return {"protected": False}
            raise

    def actions():
        found = {"permissions": clean(github.get(f"{r}/actions/permissions")),
                 "workflow": clean(github.get(f"{r}/actions/permissions/workflow"))}
        if found["permissions"].get("allowed_actions") == "selected":
            found["selectedActions"] = clean(github.get(f"{r}/actions/permissions/selected-actions"))
        return found

    def collaborators():
        everyone = github.get(f"{r}/collaborators?affiliation=all&per_page=100")
        direct = {c["login"] for c in github.get(f"{r}/collaborators?affiliation=direct&per_page=100")}
        outside = {c["login"] for c in github.get(f"{r}/collaborators?affiliation=outside&per_page=100")}
        return sorted(({"login": c["login"], "id": c["id"], "type": c.get("type", ""), "role": c.get("role_name", ""),
                        "via": "outside" if c["login"] in outside else "direct" if c["login"] in direct
                        else "team or organization"} for c in everyone), key=lambda c: c["login"].lower())

    def owners():
        if owner.get("type") != "Organization":
            return []
        return sorted((m["login"] for m in github.get(f"orgs/{owner['login']}/members?role=admin&per_page=100")),
                      key=str.lower)

    def environments():
        found = []
        for environment in github.get(f"{r}/environments?per_page=100", items="environments"):
            rules = []
            for rule in environment.get("protection_rules") or []:
                rule = {key: value for key, value in rule.items() if key not in ("id", "node_id")}
                if "reviewers" in rule:
                    rule["reviewers"] = [reviewer(entry) for entry in rule["reviewers"]]
                rules.append(rule)
            found.append({"name": environment["name"], "can_admins_bypass": environment.get("can_admins_bypass"),
                          "deployment_branch_policy": environment.get("deployment_branch_policy"),
                          "protection_rules": rules})
        return clean(found)

    return {
        "format": FORMAT,
        "repository": repo,
        "branch": branch,
        "settings": {key: clean(settings.get(key)) for key in SETTINGS} | {"owner_type": owner.get("type")},
        "rules": {
            "branch": section("branch rules", lambda: clean(github.get(f"{r}/rules/branches/{quoted}?per_page=100"))),
            "rulesets": section("rulesets", rulesets),
        },
        "branch_protection": section("branch protection", branch_protection),
        "actions": section("actions permissions", actions),
        "access": {
            "collaborators": section("collaborators", collaborators),
            "teams": section("teams", lambda: clean([{"slug": t["slug"], "id": t["id"], "permission": t.get("permission")}
                                                    for t in github.get(f"{r}/teams?per_page=100")])),
            "organization_owners": section("organization owners", owners),
            "invitations": section("invitations", lambda: clean([
                {"invitee": (i.get("invitee") or {}).get("login", ""), "id": i["id"], "permissions": i.get("permissions")}
                for i in github.get(f"{r}/invitations?per_page=100")])),
            "deploy_keys": section("deploy keys", lambda: clean([
                {"id": k["id"], "title": k.get("title", ""), "read_only": k.get("read_only"),
                 "fingerprint": fingerprint(k.get("key", "")), "created_at": k.get("created_at")}
                for k in github.get(f"{r}/keys?per_page=100")])),
        },
        "environments": section("environments", environments),
    }


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def unavailable(taken, where=""):
    """The parts GitHub would not show, as (where, why)."""
    found = []
    for key, value in taken.items():
        path = f"{where}.{key}" if where else key
        if isinstance(value, dict) and set(value) == {"unavailable"}:
            found.append((path, value["unavailable"]))
        elif isinstance(value, dict):
            found += unavailable(value, path)
    return found


def summarize(repo, taken, lines, diff=()):
    """Add what was taken, and what GitHub did not show, to the step summary on GitHub Actions."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    text = ["", f"### 📸 The controls of `{repo}`", "", *lines]
    gaps = unavailable(taken)
    if gaps:
        text += ["", "GitHub did not show:", ""] + [f"- ⚠️ `{path}`: {why.replace('|', '/')}" for path, why in gaps]
    if diff:
        # Longer than any run of backticks in what GitHub returned, so nothing ends the block early.
        fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", "".join(diff))), default=0) + 1)
        text += ["", fence + "diff", *(line.rstrip("\n") for line in diff[:DIFF_LINES]), fence]
        if len(diff) > DIFF_LINES:
            text += ["", f"_The first {DIFF_LINES} lines of {len(diff)}: the job's log has them all._"]
    with open(summary, "a", encoding="utf-8") as handle:
        handle.write("\n".join(text) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo (default $GITHUB_REPOSITORY)")
    parser.add_argument("--branch", default="", help="branch whose rules to read (default the repository's default branch)")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--out", default="", help="file to write the snapshot to (default standard output, unless --check)")
    parser.add_argument("--check", default="", metavar="SNAPSHOT", help="compare with a committed snapshot; exit 1 if they differ")
    parser.add_argument("--sts-url", default="", help="github-sts base URL, to exchange the job's OIDC token")
    parser.add_argument("--sts-identity", default="", help="trust policy identity, .github/sts/<app>/<identity>.sts.yaml")
    parser.add_argument("--sts-app", default="", help="GitHub App name on the github-sts instance")
    parser.add_argument("--sts-scope", default="", help="scope to ask for (default the repository)")
    parser.add_argument("--sts-audience", default="github-sts")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", args.repo):
        parser.error("--repo must be owner/repo")
    if bool(args.sts_url) != bool(args.sts_identity):
        parser.error("--sts-url and --sts-identity go together")
    api = args.api_url.rstrip("/")
    token = None
    try:
        api = https_only(api, "--api-url")
        if args.sts_url:
            token = exchange(args.sts_url, args.sts_scope or args.repo, args.sts_identity, args.sts_app, args.sts_audience)
        elif os.environ.get("GH_TOKEN"):
            mask(os.environ["GH_TOKEN"])
        else:
            raise Failure("no token: pass --sts-url and --sts-identity, or set GH_TOKEN")
        taken = snapshot(GitHub(api, token or os.environ["GH_TOKEN"]), args.repo, args.branch or None)
    except Failure as exc:
        say(f"::error::{exc}" if on_github() else f"error: {exc}")
        return 2
    finally:
        if token:
            revoke(api, token)

    text = dump(taken)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        say(f"📸 {args.repo}: snapshot written to {args.out}")
    if not args.check:
        if not args.out:
            sys.stdout.write(text)
        summarize(args.repo, taken, ["📸 Snapshot taken. Review it, then commit it as the declared state."])
        return 0

    try:
        with open(args.check, encoding="utf-8") as handle:
            declared = handle.read()
    except OSError as exc:
        say(f"error: cannot read {args.check}: {exc.strerror}")
        return 2
    if declared == text:
        say(f"✅ {args.repo}: the controls match {args.check}")
        summarize(args.repo, taken, [f"✅ The controls match the declared ones, `{args.check}`."])
        return 0
    diff = list(difflib.unified_diff(declared.splitlines(True), text.splitlines(True),
                                     f"{args.check} (declared)", f"{args.repo} (live)"))
    sys.stdout.writelines(diff)
    summarize(args.repo, taken, [f"❌ The controls differ from the declared ones, `{args.check}`. If the change was"
                                 " intended, commit the live snapshot as the new declared state."], diff)
    say(f"::error::{args.repo}: the controls differ from {args.check}" if on_github()
        else f"{args.repo}: the controls differ from {args.check}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
