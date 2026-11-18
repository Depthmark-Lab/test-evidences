"""How evidence reads in a job's log and step summary: an icon, the result and a line of facts per type.

Shows what collect, sign and verify decided, and decides nothing itself. Reads
predicates, and the signing trail cli.py hands it as plain data: it never calls
Vault or JFrog. Squads write some of what predicates hold (test names, claims,
paths), so every value goes into Markdown escaped.
"""
from __future__ import annotations

import html
import json
import os
import re
import sys

FAILED = "❌"
DONE = "✅"
RESULTS = {"pass": "🟢", "fail": "🔴"}
OTHER_RESULT = "⚪"
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
# A step summary holds 1 MiB at most; an sca predicate of a large application can pass that alone.
STATEMENT_LIMIT = 20_000


def announce(level, message, title=""):
    """An annotation on GitHub Actions, a line on stderr elsewhere."""
    message = " ".join(str(message).split())
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # The workflow command encoding: % first, then what would end the message or a property.
        data = message.replace("%", "%25")
        title = title.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
        print(f"::{level}{' title=' + title if title else ''}::{data}", flush=True)
    else:
        print(f"{level}: {message}", file=sys.stderr, flush=True)


def plural(count, singular, plural_form=None):
    return f"{count} {singular if count == 1 else plural_form or singular + 's'}"


def counted(summary, keys):
    return ", ".join(f"{summary[key]} {key}" for key in keys if summary.get(key))


def facts(type_id, predicate):
    """One line saying what a predicate found. A shape it does not know gets the predicate's summary counts."""
    summary = predicate.get("summary") if isinstance(predicate.get("summary"), dict) else {}
    try:
        if type_id == "secret-detection":
            total = summary["total"]
            if not total:
                return "🔑 no secrets found"
            return f"🔑 {plural(total, 'secret')} found: {counted(summary, ('verified', 'unverified', 'unknown'))}"
        if type_id == "sca":
            total = sum(summary.get(severity, 0) for severity in SEVERITIES)
            if not total:
                return "🐞 no known vulnerabilities"
            return (f"🐞 {plural(total, 'vulnerability', 'vulnerabilities')}: {counted(summary, SEVERITIES)}"
                    f" (fails on {predicate['failOn']})")
        if type_id == "test-results":
            if not summary["tests"]:
                return "🧪 no tests ran"
            failures = counted(summary, ("failed", "errored", "skipped", "flaky"))
            return f"🧪 {plural(summary['tests'], 'test')}: {summary['passed']} passed{', ' + failures if failures else ''}"
        if type_id == "provenance":
            workflow = predicate["buildDefinition"]["externalParameters"]["workflow"]
            commit = predicate["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"]
            run, _, attempt = predicate["runDetails"]["metadata"]["invocationId"].split("/runs/", 1)[1].partition(
                "/attempts/")
            return (f"🏗️ {workflow['path'].rsplit('/', 1)[-1]} on {workflow['ref']}, commit {commit[:12]},"
                    f" run {run} attempt {attempt}")
        if type_id == "provenance-attestation":
            found = predicate["attestations"]
            if not found:
                return "🪪 GitHub holds no attestation for these bytes"
            signer, _, ref = found[0]["signer"].partition("@")
            signer = signer.rsplit("/", 1)[-1]
            config = found[0]["buildConfig"].partition("@")[0].rsplit("/", 1)[-1]
            logged = ", ".join(dict.fromkeys(t["authority"].split("//")[-1].split("/")[0] or t["type"]
                                             for t in found[0]["timestamps"]))
            return (f"🪪 {plural(len(found), 'GitHub attestation')} verified: signed by {signer} on {ref}"
                    f"{' for ' + config if config and config != signer else ''}{', logged by ' + logged if logged else ''}")
        if type_id == "peer-approval":
            if not predicate["pullRequest"]:
                return "👥 no pull request for this commit"
            return f"👥 {plural(predicate['approvalCount'], 'approval')} on pull request #{predicate['pullRequest']['number']}"
        if type_id == "code-quality-gate":
            failing = [c["metricKey"] for c in predicate["conditions"] if c.get("status") == "ERROR"]
            return f"📏 quality gate {predicate['status']}{': ' + ', '.join(failing) if failing else ''}"
        if type_id == "custom":
            claims = predicate["claims"]
            return f"📝 {plural(len(claims), 'claim')} by {predicate['declaredBy']}: {', '.join(sorted(claims))}"
    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
        pass
    return ", ".join(f"{value} {key}" for key, value in summary.items()
                     if isinstance(value, int) and not isinstance(value, bool))


def text(value):
    """Plain text for Markdown: no table, link, HTML, emphasis or code markup gets through."""
    return re.sub(r"([\\|`\[\]*_<>~])", r"\\\1", " ".join(str(value).split()))


def code(value):
    """A code span for Markdown, in a table cell or not."""
    value = " ".join(str(value).split()).replace("|", "\\|")
    fence = "`" * (max(map(len, re.findall(r"`+", value)), default=0) + 1)
    return f"{fence} {value} {fence}" if "`" in value else f"`{value}`"


def result_of(row):
    return f"{RESULTS.get(row['result'], OTHER_RESULT)} {row['result']}"


def totals(rows, status):
    done = [row for row in rows if row["status"] != "error"]
    parts = [f"{len(done)} of {len(rows)} {status}"]
    for result in ("pass", "fail", "n/a"):
        count = sum(row["result"] == result for row in done)
        if count:
            parts.append(f"{RESULTS.get(result, OTHER_RESULT)} {count} {result}")
    if len(done) < len(rows):
        parts.append(f"{FAILED} {plural(len(rows) - len(done), 'error')}")
    return " · ".join(parts)


def report(rows, heading, status, done_as, detail_heading, subject=None, statements=False):
    """Print a line per type, announce each error, and add a table to the job's step summary.

    rows hold type, version, status, result and detail, plus the predicate when there is
    one, and the statement after verify. subject is (name, sha256), either may be empty. With
    statements, each verified statement follows the table, folded.
    """
    print(heading, flush=True)
    name, sha256 = subject or ("", "")
    if name:
        print(f"🎯 {name}{'  sha256:' + sha256 if sha256 else ''}", flush=True)
    for row in rows:
        label = f"{row['type']} {row['version']}".strip()
        if row["status"] == "error":
            # The log shows the message only; the title heads the annotation on the run's page.
            announce("error", f"{row['type']}: {row['detail']}", title=f"{FAILED} {label}")
            continue
        found = facts(row["type"], row.get("predicate") or {})
        print(f"{DONE} {label}: {row['status']} · {result_of(row)}{' · ' + found if found else ''}"
              f" · {done_as} {row['detail']}", flush=True)
    print(f"🧾 {totals(rows, status)}", flush=True)
    github = os.environ.get("GITHUB_ACTIONS") == "true"
    if statements and github:
        for row in rows:
            if row.get("statement"):
                print(f"::group::🧾 {row['type']} {row['version']}: the verified statement", flush=True)
                print(json.dumps(row["statement"], indent=2), flush=True)
                print("::endgroup::", flush=True)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    lines = ["", f"### {heading}", ""]
    if name:
        lines += [f"🎯 {code(name)}{' · SHA-256 ' + code(sha256) if sha256 else ''}", ""]
    lines += [f"| | Evidence | Result | Facts | {detail_heading} |", "|:-:|---|---|---|---|"]
    for row in rows:
        evidence = f"{code(row['type'])} {text(row['version'])}"
        if row["status"] == "error":
            lines.append(f"| {FAILED} | {evidence} | | | {text(row['detail'])} |")
        else:
            found = text(facts(row["type"], row.get("predicate") or {}))
            lines.append(f"| {DONE} | {evidence} | {result_of(row)} | {found} | {code(row['detail'])} |")
    lines += ["", f"**{totals(rows, status)}**", ""]
    if statements:
        lines += [folded(row) for row in rows if row.get("statement")]
    with open(summary, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def folded(row):
    """A verified statement for the step summary, folded under its type, result and facts."""
    statement = row["statement"]
    title = " · ".join(part for part in (
        f"{DONE} <code>{html.escape(row['type'])}</code> {html.escape(row['version'])}",
        html.escape(result_of(row)), html.escape(facts(row["type"], statement.get("predicate") or {})),
        f"signed by <code>{html.escape(str(row['detail']))}</code>") if part)
    body = json.dumps(statement.get("predicate"), indent=2)
    cut = len(body) > STATEMENT_LIMIT
    body = body[:STATEMENT_LIMIT]
    fence = "`" * max(3, max(map(len, re.findall(r"`+", body)), default=0) + 1)
    lines = [f"<details><summary>{title}</summary>", "",
             f"- **Predicate type** {code(statement.get('predicateType', ''))}"]
    lines += [f"- **Subject** {code(s.get('name', ''))} · SHA-256 {code(s.get('digest', {}).get('sha256', ''))}"
              for s in statement.get("subject", [])]
    lines += ["", fence + "json", body, fence]
    if cut:
        lines += ["", f"_Cut at {STATEMENT_LIMIT:,} characters: its envelope holds it all._"]
    return "\n".join(lines + ["", "</details>", ""])


def transit(trail, vault, names):
    """Add how Vault Transit signed to the step summary: each login and each signature, in order.

    trail is the Vault's, as plain data: a dict per login (role, claims, token, request) and per
    signature (key, version, bytes signed, request), with an error where Vault refused. vault is
    its one-line description. names maps a predicate type to its (type, version).
    """
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary or not trail:
        return
    lines = ["", "### 🔐 How Vault Transit signed", "", text(vault), ""]
    logins = [step for step in trail if step["step"] == "login"]
    if logins:
        lines += ["| | Login | The identity token's claims, which Vault checks | Vault's token | Request |",
                  "|:-:|---|---|---|---|"]
        for step in logins:
            claims = "<br>".join(f"{code(name)} {code(value)}" for name, value in step["claims"].items())
            claims = claims or "not a JWT, so not shown"
            role = f"role {code(step['role'])}"
            if step.get("error"):
                lines.append(f"| {FAILED} | {role} | {claims} | {text(step['error'])} | |")
            else:
                token = (f"{text(step['tokenType'])} token, valid {text(step['valid'])}, policies "
                         f"{', '.join(code(policy) for policy in step['policies']) or 'none'}")
                lines.append(f"| {DONE} | {role} | {claims} | {token} | {code(step['request'])} · {step['ms']} ms |")
        lines.append("")
    signatures = [step for step in trail if step["step"] == "sign"]
    if signatures:
        lines += ["| | Evidence | Key | What Vault signed | Vault's answer |", "|:-:|---|---|---|---|"]
        for step in signatures:
            type_id, version = names.get(step["about"], (step["about"] or "a statement", ""))
            evidence = f"{code(type_id)} {text(version)}".strip()
            signed = f"{step['bytes']:,} bytes, SHA-256 {code(step['sha256'][:16] + '…')}"
            if step.get("error"):
                lines.append(f"| {FAILED} | {evidence} | {code(step['key'])}, {text(step['algorithm'])} | {signed}"
                             f" | {text(step['error'])} |")
            else:
                key = f"{code(step['key'])} version {text(step['version'])}, {text(step['algorithm'])}"
                answer = f"key id {code(step['keyId'])} · request {code(step['request'])} · {step['ms']} ms"
                lines.append(f"| {DONE} | {evidence} | {key} | {signed} | {answer} |")
        lines.append("")
    lines += ["_The tokens are masked and never printed. Vault's audit log records each request by its id._", ""]
    with open(summary, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
