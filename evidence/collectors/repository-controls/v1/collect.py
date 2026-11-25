"""Repository controls: what protects the branch the artifact comes from, and who could change it.

evidence.yml's read-controls job snapshots the repository with
scripts/snapshot-repository.py and a read-only github-sts token. This collector
reads that file and never GitHub: it holds no token. It checks the controls a
release relies on against the platform's minimums, counts who had access and
how, and keeps the snapshot itself, so the evidence holds the population an
auditor samples from: every rule and every person with access, at release time.

A check passes when a source holds it: the branch rules, which rulesets of the
repository and the organization make, classic branch protection, or the
repository's Actions settings. It is unknown when GitHub would not show a
source that might have held it, as for rules on a private repository on the
Free plan. A control that cannot be shown counts as not in place: any check
that fails or is unknown makes the result fail.
"""
import hashlib
import json
import os

from evidence_sdk import commit, emit, param, repository, unable

FORMAT = "repository-controls/v1"
ROLES = ("admin", "maintain", "write", "triage", "read")


def shown(value):
    """The value, or None when GitHub would not show it."""
    return None if isinstance(value, dict) and set(value) == {"unavailable"} else value


def check(check_id, title, *sources):
    """pass when a source holds it, unknown when none does but one could not be read, fail otherwise."""
    if any(source is True for source in sources):
        result = "pass"
    elif any(source is None for source in sources):
        result = "unknown"
    else:
        result = "fail"
    return {"id": check_id, "title": title, "result": result}


path = param("controls-snapshot")
try:
    with open(path, "rb") as handle:
        raw = handle.read()
    snapshot = json.loads(raw)
except OSError as exc:
    unable(f"controls-snapshot {path} cannot be read: {exc.strerror}")
except ValueError:
    unable(f"controls-snapshot {path} is not JSON")
if not isinstance(snapshot, dict) or snapshot.get("format") != FORMAT:
    unable(f"controls-snapshot {path} is not a {FORMAT} snapshot")
if str(snapshot.get("repository", "")).lower() != repository().lower():
    unable(f"the snapshot is of {snapshot.get('repository')}, not of {repository()}")

rules = shown(snapshot["rules"]["branch"])
rulesets = shown(snapshot["rules"]["rulesets"])
protection = shown(snapshot["branch_protection"])
actions = shown(snapshot["actions"])
workflow = None if actions is None else actions.get("workflow") or {}


def by_rule(kind, test=lambda parameters: True):
    """Whether a branch rule holds it: None when the rules are unknown, False when there is no such rule."""
    if rules is None:
        return None
    found = [r for r in rules if r.get("type") == kind]
    return bool(found) and bool(test(found[0].get("parameters") or {}))


def by_classic(test):
    """Whether classic branch protection holds it: None when unknown, False when the branch is not protected."""
    if protection is None:
        return None
    return protection.get("protected") is not False and bool(test(protection))


def reviews(protection):
    return protection.get("required_pull_request_reviews") or {}


def by_workflow(test):
    return None if workflow is None else bool(test(workflow))


def no_bypass_by_rules():
    """No ruleset that makes the branch's rules lets anyone bypass them."""
    if rules is None or rulesets is None:
        return None
    making = {r.get("ruleset_id") for r in rules}
    return bool(making) and all(not ruleset.get("bypass_actors") for ruleset in rulesets if ruleset.get("id") in making)


checks = [
    check("pull-request-required", "Changes reach the branch through a pull request",
          by_rule("pull_request"), by_classic(lambda p: p.get("required_pull_request_reviews"))),
    check("one-approval", "A pull request needs at least one approval",
          by_rule("pull_request", lambda p: p.get("required_approving_review_count", 0) >= 1),
          by_classic(lambda p: reviews(p).get("required_approving_review_count", 0) >= 1)),
    check("stale-approvals-dismissed", "A new commit dismisses the approvals given before it",
          by_rule("pull_request", lambda p: p.get("dismiss_stale_reviews_on_push") is True),
          by_classic(lambda p: reviews(p).get("dismiss_stale_reviews") is True)),
    check("last-pusher-cannot-approve", "Whoever pushed last cannot approve",
          by_rule("pull_request", lambda p: p.get("require_last_push_approval") is True),
          by_classic(lambda p: reviews(p).get("require_last_push_approval") is True)),
    check("no-force-push", "The branch's history cannot be rewritten",
          by_rule("non_fast_forward"), by_classic(lambda p: (p.get("allow_force_pushes") or {}).get("enabled") is False)),
    check("no-deletion", "The branch cannot be deleted",
          by_rule("deletion"), by_classic(lambda p: (p.get("allow_deletions") or {}).get("enabled") is False)),
    check("no-bypass", "Nobody can bypass the rules, administrators included",
          no_bypass_by_rules(),
          by_classic(lambda p: (p.get("enforce_admins") or {}).get("enabled") is True
                     and not any((reviews(p).get("bypass_pull_request_allowances") or {}).values()))),
    check("workflows-cannot-approve", "Workflows cannot approve pull requests",
          by_workflow(lambda w: w.get("can_approve_pull_request_reviews") is False)),
    check("workflow-token-read-only", "A workflow's token is read-only unless the workflow asks for more",
          by_workflow(lambda w: w.get("default_workflow_permissions") == "read")),
]

access = snapshot["access"]
collaborators = shown(access["collaborators"])
owners = shown(access["organization_owners"])
keys = shown(access["deploy_keys"])
invitations = shown(access["invitations"])
sections = {"rules.branch": snapshot["rules"]["branch"], "rules.rulesets": snapshot["rules"]["rulesets"],
            "branch_protection": snapshot["branch_protection"], "actions": snapshot["actions"],
            "environments": snapshot["environments"], **{f"access.{name}": value for name, value in access.items()}}
counts = {state: sum(c["result"] == state for c in checks) for state in ("pass", "fail", "unknown")}

emit({
    "result": "pass" if counts["pass"] == len(checks) else "fail",
    "commit": commit(),
    "repository": snapshot["repository"],
    "branch": snapshot.get("branch", ""),
    "summary": {"passed": counts["pass"], "failed": counts["fail"], "unknown": counts["unknown"]},
    "checks": checks,
    "access": {
        "roles": None if collaborators is None else {role: sum(c.get("role") == role for c in collaborators)
                                                     for role in ROLES},
        "outsideWriters": None if collaborators is None else sum(
            c.get("via") == "outside" and c.get("role") in ("admin", "maintain", "write") for c in collaborators),
        "organizationOwners": None if owners is None else len(owners),
        "writeDeployKeys": None if keys is None else sum(k.get("read_only") is False for k in keys),
        "invitations": None if invitations is None else len(invitations),
    },
    "unavailable": sorted(name for name, value in sections.items() if shown(value) is None),
    "snapshot": {"file": os.path.basename(path), "sha256": hashlib.sha256(raw).hexdigest(), "controls": snapshot},
})
