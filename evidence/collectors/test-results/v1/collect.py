"""Test results: what the tests of the build that produced the artifact reported, read from its JUnit XML.

The squad's own build ran the tests, with its own tools and flags. The platform
did not run them and cannot: it would have to run the squad's code. Maven
Surefire and Failsafe, Gradle, pytest, Node's test runner and most other tools
write JUnit XML, so this one collector reads them all. It counts the test cases
in every report under test-reports and records each report's SHA-256, so the
evidence points at the exact files it was read from. Other XML files there,
such as failsafe-summary.xml, are skipped. The reports reach the collect job as
an artifact of the same run, so they belong to this run's commit.

Signed with the build key: it says what the build reported, not that the
platform saw the tests pass.

The result is "fail" when a test failed or errored, or when the reports hold no
test at all: a build run with -DskipTests reports nothing, and that is not a
pass. A test that passed only when rerun counts as passed and as flaky. Failed
tests are named, never their messages, which can hold anything the test printed.
"""
import hashlib
import os
import xml.etree.ElementTree as ElementTree

from evidence_sdk import commit, emit, param, unable

LISTED = 100

folder = param("test-reports")
if not os.path.isdir(folder):
    unable(f"test-reports '{folder}' is not a directory")

paths = sorted(os.path.relpath(os.path.join(root, name), folder)
               for root, _dirs, names in os.walk(folder) for name in names if name.endswith(".xml"))

summary = {"tests": 0, "passed": 0, "failed": 0, "errored": 0, "skipped": 0, "flaky": 0}
reports, failed = [], []


def count(case, suite, report):
    children = {child.tag for child in case}
    if "error" in children:
        outcome = "errored"
    elif "failure" in children:
        outcome = "failed"
    elif "skipped" in children:
        outcome = "skipped"
    else:
        outcome = "passed"
        summary["flaky"] += bool(children & {"flakyFailure", "flakyError"})
    summary["tests"] += 1
    summary[outcome] += 1
    if outcome in ("failed", "errored") and len(failed) < LISTED:
        failed.append({"suite": case.get("classname") or suite, "test": case.get("name") or "(unnamed)",
                       "outcome": outcome, "report": report})


for path in paths:
    with open(os.path.join(folder, path), "rb") as handle:
        raw = handle.read()
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        unable(f"{path} is not well-formed XML: {exc}")
    if root.tag not in ("testsuites", "testsuite"):
        continue
    cases = [(case, suite.get("name") or "") for suite in root.iter("testsuite") for case in suite.findall("testcase")]
    # Node's runner puts a test that is in no describe() block straight under <testsuites>.
    cases += [(case, "") for case in root.findall("testcase")] if root.tag == "testsuites" else []
    for case, suite in cases:
        count(case, suite, path)
    reports.append({"file": path, "sha256": hashlib.sha256(raw).hexdigest(), "tests": len(cases)})

if not reports:
    unable(f"no JUnit XML report in {folder}: the build uploaded no test report")

emit({
    "result": "pass" if summary["tests"] and not summary["failed"] and not summary["errored"] else "fail",
    "commit": commit(),
    "format": "junit-xml",
    "summary": summary,
    "reports": reports,
    "failedTests": failed,
})
