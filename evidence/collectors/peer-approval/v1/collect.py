"""Peer approval: who approved the pull request that produced this commit.

Records facts only. A commit with no merged pull request is recorded as a
"fail" with pullRequest null: that is a real finding, not a collection error.
How many approvals a release needs is a policy question, answered elsewhere
from approvalCount.
"""
from evidence_sdk import commit, emit, env, get_json, repository

api = env("GITHUB_API_URL", "https://api.github.com")
headers = {
    "Authorization": f"Bearer {env('GH_TOKEN')}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
repo, sha = repository(), commit()

merged = [p for p in get_json(f"{api}/repos/{repo}/commits/{sha}/pulls", headers) if p.get("merged_at")]

pull_request, approvers = None, []
if merged:
    number = merged[0]["number"]
    pr = get_json(f"{api}/repos/{repo}/pulls/{number}", headers)
    # First 100 reviews. Add paging if your pull requests ever exceed that.
    reviews = get_json(f"{api}/repos/{repo}/pulls/{number}/reviews?per_page=100", headers)

    # Keep each reviewer's latest verdict. Comments are not verdicts.
    latest = {}
    for review in reviews:
        if review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED") and review.get("user"):
            login = review["user"]["login"]
            if login not in latest or review["submitted_at"] > latest[login]["submitted_at"]:
                latest[login] = review

    author = pr["user"]["login"]
    approvers = sorted(
        (
            {"login": login, "reviewedCommit": review["commit_id"], "submittedAt": review["submitted_at"]}
            for login, review in latest.items()
            if review["state"] == "APPROVED" and login != author   # self-approval does not count
        ),
        key=lambda approver: approver["login"],
    )
    pull_request = {
        "number": pr["number"],
        "url": pr["html_url"],
        "author": author,
        "mergedBy": (pr.get("merged_by") or {}).get("login"),
        "mergedAt": pr["merged_at"],
        "baseRef": pr["base"]["ref"],
        "headCommit": pr["head"]["sha"],
    }

emit({
    "result": "pass" if approvers else "fail",
    "repository": repo,
    "commit": sha,
    "pullRequest": pull_request,
    "approvers": approvers,
    "approvalCount": len(approvers),
})
