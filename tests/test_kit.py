"""Tests for the evidence kit. Standard library plus the openssl command.

Run from the repository root:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = REPO_ROOT / "evidence"
sys.path.insert(0, str(EVIDENCE))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cli  # noqa: E402
import collection  # noqa: E402
import display  # noqa: E402
import schema  # noqa: E402
import signing  # noqa: E402
import verification  # noqa: E402
from core import EvidenceError, pae  # noqa: E402
from core import evidence_type as core_evidence_type  # noqa: E402
from mock_services import REPO, SCANNERS, SHA, Services, fake_scanner, openssl  # noqa: E402

SUBJECT = "apps-generic-local/payments/1.0/payments.jar"
SUBJECT_SHA = "0" * 64
ALL_TYPES = "peer-approval,code-quality-gate,custom"

# Recorded from the real scanners by scanners/record.py.
TRUFFLEHOG_OUTPUT = (SCANNERS / "trufflehog.jsonl").read_text()
GRYPE_OUTPUT = (SCANNERS / "grype.json").read_text()
SCANNER_VERSIONS = json.loads((SCANNERS / "versions.json").read_text())
REMOVED_SECRET = "SECRET-REMOVED-BY-RECORD-PY"
# JUnit XML written by Maven Surefire, pytest and Node's test runner for samples/, passing and failing.
REPORTS = Path(__file__).resolve().parent / "reports"


class Kit(unittest.TestCase):
    """Stand-in services, a scratch directory and helpers to run the CLI the way a job would."""

    def setUp(self):
        self.services = Services()
        self.addCleanup(self.services.close)
        self.tmp = Path(tempfile.mkdtemp(prefix="evidence-test-"))
        self.bin = self.tmp / "bin"        # stand-in scanners go here, first on PATH
        self.bin.mkdir()
        self.out = self.tmp / "out"        # where collect writes predicates
        self.predicate_file = self.tmp / "predicate.json"
        self.predicate_file.write_text('{"loadTest": {"p95Ms": 180}}')

    def run_cli(self, *args, settings=None, extra_env=None):
        """Run the CLI the way a job would. Returns (exit code, output, step summary)."""
        settings_file = self.tmp / "settings.json"
        settings_file.write_text(json.dumps(settings or self.services.settings()))
        summary = self.tmp / "summary.md"
        summary.write_text("")
        env = {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "EVD_SETTINGS": str(settings_file),
            "GITHUB_ACTIONS": "true",
            "GITHUB_STEP_SUMMARY": str(summary),
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_SHA": SHA,
            "GITHUB_API_URL": self.services.url + "/gh",
            "GH_TOKEN": "ghs_token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": self.services.url + "/oidc?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-token",
        }
        env.update(extra_env or {})
        done = subprocess.run([sys.executable, str(EVIDENCE / "cli.py"), *args],
                              env=env, capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr, summary.read_text()

    def run_all(self, *extra, **kwargs):
        return self.run_cli("run", "--types", ALL_TYPES, "--subject-repo-path", SUBJECT,
                            "--subject-sha256", SUBJECT_SHA,
                            "--param", "sonar-project-key=acme-bank_payments",
                            "--param", f"predicate-file={self.predicate_file}", *extra, **kwargs)

    def deployed(self, type_id):
        wanted = f"https://evidence.acme-bank.example/{type_id}/v1"
        return [d for d in self.services.deployed if d["statement"]["predicateType"] == wanted]

    def collect(self, types, *params, **kwargs):
        args = ["collect", "--types", types, "--out", str(self.out)]
        for pair in params:
            args += ["--param", pair]
        return self.run_cli(*args, **kwargs)

    def collected(self, type_id):
        return json.loads((self.out / f"{type_id}.json").read_text())

    def fake(self, name, output="", **kwargs):
        """Put a stand-in scanner on the CLI's PATH. Returns the calls it saw, read later with calls()."""
        if name == "trufflehog":
            kwargs.setdefault("version", f"trufflehog {SCANNER_VERSIONS['trufflehog']}")
        return fake_scanner(self.bin, name, output, **kwargs)

    @staticmethod
    def calls(log):
        return [json.loads(line) for line in log.read_text().splitlines()]

    def trusted_keys(self, *key_ids, public_key=None):
        """A folder of trusted public keys, as a verifier would hold them: one <key id>.pub.pem each."""
        folder = self.tmp / "trusted-keys"
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir()
        for key_id in key_ids:
            shutil.copy(public_key or self.services.trusted_public_key, folder / f"{key_id}.pub.pem")
        return folder

    def openssl_verifies(self, envelope):
        """Verify a DSSE envelope with openssl, independently of the kit's own verifier."""
        signature = self.tmp / "envelope.sig"
        signature.write_bytes(base64.b64decode(envelope["signatures"][0]["sig"]))
        args = ["dgst", "-sha256", "-verify", str(self.services.trusted_public_key), "-signature", str(signature)]
        if envelope["signatures"][0]["keyid"].endswith(";PS256"):
            args += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-2"]
        data = pae(envelope["payloadType"], base64.b64decode(envelope["payload"]))
        return openssl(*args, data=data).returncode == 0


class KitTest(Kit):
    # ---- the happy path ------------------------------------------------------

    def test_all_types_are_collected_signed_and_verified(self):
        code, output, summary = self.run_all()
        self.assertEqual(code, 0, output)
        self.assertEqual(len(self.services.deployed), 3)
        self.assertTrue(all(d["verified"] for d in self.services.deployed))
        self.assertEqual({d["keyid"] for d in self.services.deployed},
                         {"evd-approval-prod-v3", "evd-scan-prod-v3", "evd-self-prod-v3"})

        approval = self.deployed("peer-approval")[0]["statement"]
        self.assertEqual(approval["subject"][0]["digest"]["sha256"], SUBJECT_SHA)
        self.assertEqual(approval["predicate"]["result"], "pass")
        # alice is the author, so only bob's latest verdict counts.
        self.assertEqual([a["login"] for a in approval["predicate"]["approvers"]], ["bob"])
        self.assertEqual(self.deployed("code-quality-gate")[0]["statement"]["predicate"]["analysisId"], "AX-1")
        self.assertEqual(self.deployed("custom")[0]["statement"]["predicate"]["declaredBy"], REPO)
        self.assertIn("| ✅ | `peer-approval` v1 | 🟢 pass | 👥 1 approval on pull request #7 |", summary)

    def test_one_login_per_key_family_and_one_jfrog_exchange(self):
        self.run_all()
        self.assertEqual(sorted(role for role, _ in self.services.vault_logins),
                         ["evidence-approval-prod", "evidence-scan-prod", "evidence-self-prod"])
        # Each token was asked for its own audience.
        self.assertEqual({signing.claims(jwt)["aud"] for _, jwt in self.services.vault_logins},
                         {"https://vault.acme-bank.example"})
        self.assertEqual([signing.claims(jwt)["aud"] for jwt in self.services.jfrog_exchanges], ["jfrog-evidence"])

    def test_secrets_are_masked_and_never_printed(self):
        _, output, summary = self.run_all()
        self.assertIn("::add-mask::squ_secret", output)
        self.assertIn("::add-mask::jf.token", output)
        self.assertIn("::add-mask::eyJ", output)    # GitHub's identity tokens: a JWT starts with eyJ
        leaks = [line for line in output.splitlines()
                 if any(token in line for token in ("squ_secret", "hvs.", "jf.token", "eyJ"))
                 and not line.startswith("::add-mask::")]
        self.assertEqual(leaks, [])
        self.assertFalse(any(token in summary for token in ("squ_secret", "hvs.", "jf.token", "eyJ")))

    def test_pss_signatures_carry_the_ps256_key_id(self):
        code, output, _ = self.run_all(settings=self.services.settings(**{"vault.signatureAlgorithm": "pss"}))
        self.assertEqual(code, 0, output)
        self.assertTrue(all(d["verified"] and d["keyid"].endswith(";PS256") for d in self.services.deployed))

    def test_identity_can_come_from_files_for_other_ci_systems(self):
        vault_jwt, jfrog_jwt = self.tmp / "vault.jwt", self.tmp / "jfrog.jwt"
        vault_jwt.write_text("ado-jwt-for-vault\n")
        jfrog_jwt.write_text("ado-jwt-for-jfrog\n")
        code, output, _ = self.run_all(
            settings=self.services.settings(identity="file"),
            extra_env={"EVD_VAULT_JWT_FILE": str(vault_jwt), "EVD_JFROG_JWT_FILE": str(jfrog_jwt),
                       "EVD_REPOSITORY": REPO, "EVD_COMMIT": SHA,
                       "ACTIONS_ID_TOKEN_REQUEST_URL": "", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""})
        self.assertEqual(code, 0, output)
        self.assertEqual({jwt for _, jwt in self.services.vault_logins}, {"ado-jwt-for-vault"})
        self.assertEqual(self.services.jfrog_exchanges, ["ado-jwt-for-jfrog"])

    # ---- record, do not judge ------------------------------------------------

    def test_a_failed_check_is_attached_and_does_not_block_by_default(self):
        self.services.gate_status = "ERROR"
        code, output, summary = self.run_all()
        self.assertEqual(code, 0, output)
        gate = self.deployed("code-quality-gate")[0]
        self.assertTrue(gate["verified"])
        self.assertEqual(gate["statement"]["predicate"]["result"], "fail")
        self.assertIn("| ✅ | `code-quality-gate` v1 | 🔴 fail | 📏 quality gate ERROR: new\\_coverage |", summary)

    def test_enforce_blocks_on_a_failed_check_but_still_attaches_it(self):
        self.services.gate_status = "ERROR"
        code, output, _ = self.run_all("--enforce")
        self.assertEqual(code, 1)
        self.assertIn("enforce is on and these checks failed: code-quality-gate", output)
        self.assertEqual(len(self.services.deployed), 3)

    def test_a_commit_without_a_pull_request_is_negative_evidence(self):
        self.services.has_pull_request = False
        code, output, _ = self.run_all()
        self.assertEqual(code, 0, output)
        predicate = self.deployed("peer-approval")[0]["statement"]["predicate"]
        self.assertEqual((predicate["result"], predicate["pullRequest"], predicate["approvalCount"]), ("fail", None, 0))

    def test_changes_requested_is_not_an_approval(self):
        self.services.second_reviewer_approves = False
        self.run_all()
        predicate = self.deployed("peer-approval")[0]["statement"]["predicate"]
        self.assertEqual((predicate["result"], predicate["approvers"]), ("fail", []))

    # ---- errors ----------------------------------------------------------------

    def test_facts_that_cannot_be_established_attach_nothing_and_do_not_stop_other_types(self):
        self.services.has_analysis = False
        code, output, summary = self.run_all()
        self.assertEqual(code, 1)
        self.assertIn("SonarQube has no analysis of commit", output)
        self.assertEqual(self.deployed("code-quality-gate"), [])
        self.assertEqual(len(self.services.deployed), 2)
        self.assertIn("| ❌ | `code-quality-gate` v1 | | | the facts could not be established", summary)

    def test_bad_requests_are_rejected_before_any_token_is_requested(self):
        cases = [
            (["run", "--types", "peer-approval,nope", "--subject-repo-path", SUBJECT], "unknown evidence type(s): nope"),
            (["run", "--types", "peer-approval", "--subject-repo-path", SUBJECT, "--subject-sha256", "XYZ"], "64 lowercase hex"),
            (["run", "--types", "peer-approval", "--subject-repo-path", "no-slash"], "subject-repo-path must look like"),
            (["run", "--types", "peer-approval", "--subject-repo-path", SUBJECT, "--param", "sonar-project-key=x"], "not used by the requested types"),
        ]
        for args, message in cases:
            code, output, _ = self.run_cli(*args)
            self.assertEqual(code, 2, output)
            self.assertIn(message, output)
        self.assertEqual((self.services.vault_logins, self.services.jfrog_exchanges), ([], []))

    def test_a_missing_required_parameter_fails_only_that_type(self):
        code, output, _ = self.run_cli("run", "--types", "peer-approval,code-quality-gate", "--subject-repo-path", SUBJECT)
        self.assertEqual(code, 1)
        self.assertIn("code-quality-gate: missing parameter(s): sonar-project-key", output)
        self.assertEqual(len(self.deployed("peer-approval")), 1)

    def test_a_custom_predicate_that_is_not_an_object_is_refused(self):
        self.predicate_file.write_text("[1, 2, 3]")
        code, output, _ = self.run_all()
        self.assertEqual(code, 1)
        self.assertIn("must hold one JSON object", output)
        self.assertEqual(self.deployed("custom"), [])

    def test_nothing_is_signed_when_jfrog_returns_a_different_statement(self):
        self.services.tamper_statement = True
        code, output, _ = self.run_all()
        self.assertEqual(code, 1)
        self.assertIn("refusing to sign", output)
        self.assertEqual((self.services.sign_calls, self.services.deployed), ([], []))

    def test_an_untrusted_public_key_is_reported(self):
        self.services.trust_a_different_key()
        code, output, _ = self.run_all()
        self.assertEqual(code, 1)
        self.assertIn("did not verify it. Is public key 'evd-approval-prod-v3' in trusted keys?", output)

    def test_a_failed_api_call_shows_the_servers_message(self):
        code, output, _ = self.run_all(settings=self.services.settings(**{"vault.authPath": "wrong"}))
        self.assertEqual(code, 1)
        self.assertIn("returned 404", output)
        self.assertIn("no route POST /v1/auth/wrong/login", output)

    # ---- collectors run with a scrubbed environment ----------------------------

    def test_collectors_do_not_inherit_the_jobs_secrets(self):
        catalog = cli.load_catalog()
        os.environ.update({"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-token", "GH_TOKEN": "ghs_token",
                           "SOME_ORG_SECRET": "s3cret", "GITHUB_REPOSITORY": REPO, "GITHUB_SHA": SHA})
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in
                                 ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH_TOKEN", "SOME_ORG_SECRET", "GITHUB_REPOSITORY", "GITHUB_SHA")])
        settings = self.services.settings()

        gate_env = collection.collector_env(catalog["code-quality-gate"], {"sonar-project-key": "k", "predicate-file": "/x"},
                                            settings["collectorEnv"], {"SONAR_TOKEN": "squ_secret"}, self.tmp / "out.json")
        self.assertEqual(gate_env["SONAR_TOKEN"], "squ_secret")
        self.assertEqual(gate_env["EVD_PARAM_SONAR_PROJECT_KEY"], "k")
        for hidden in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH_TOKEN", "SOME_ORG_SECRET", "EVD_PARAM_PREDICATE_FILE"):
            self.assertNotIn(hidden, gate_env)

        approval_env = collection.collector_env(catalog["peer-approval"], {}, settings["collectorEnv"], {}, self.tmp / "out.json")
        self.assertEqual(approval_env["GH_TOKEN"], "ghs_token")   # declared in its catalog entry
        self.assertNotIn("SONAR_TOKEN", approval_env)

    def test_the_sonarqube_token_from_vault_reaches_sonarqube(self):
        self.run_all()
        self.assertEqual(self.services.sonar_auth, ["Basic c3F1X3NlY3JldDo="])   # base64 of "squ_secret:"


class ScannerTest(Kit):
    """Scanner evidence types, run against output recorded from the real scanners."""

    def test_secret_detection_records_where_secrets_are_never_the_secrets(self):
        calls = self.fake("trufflehog", TRUFFLEHOG_OUTPUT)
        code, output, summary = self.collect("secret-detection")
        self.assertEqual(code, 0, output)
        predicate = self.collected("secret-detection")
        self.assertEqual(predicate["result"], "fail")
        self.assertEqual(predicate["scanner"], {"name": "trufflehog", "version": SCANNER_VERSIONS["trufflehog"]})
        self.assertEqual(predicate["summary"], {"total": 2, "verified": 0, "unverified": 2, "unknown": 0})
        self.assertEqual([(f["detector"], f["file"], f["line"]) for f in predicate["findings"]],
                         [("SlackWebhook", "config/settings.py", 1), ("PrivateKey", "deploy-key.pem", 1)])
        # The recording holds this marker wherever TruffleHog printed the secret.
        self.assertIn(REMOVED_SECRET, TRUFFLEHOG_OUTPUT)
        self.assertNotIn(REMOVED_SECRET, json.dumps(predicate) + output + summary)
        self.assertIn("| ✅ | `secret-detection` v1 | 🔴 fail | 🔑 2 secrets found: 2 unverified |", summary)
        argv = self.calls(calls)[-1]["argv"]
        self.assertEqual(argv[:5] + argv[7:],
                         ["filesystem", ".", "--json", "--no-update", "--local-dev", "--no-verification"])
        self.assertEqual(argv[5], "--exclude-paths")   # .git, so its objects are not reported a second time

    def test_secret_verification_is_off_unless_asked(self):
        calls = self.fake("trufflehog", TRUFFLEHOG_OUTPUT)
        code, output, _ = self.collect("secret-detection", "secrets-verify=true")
        self.assertEqual(code, 0, output)
        self.assertTrue(self.collected("secret-detection")["verification"])
        self.assertNotIn("--no-verification", self.calls(calls)[-1]["argv"])

        code, output, _ = self.collect("secret-detection", "secrets-verify=yes")
        self.assertEqual(code, 1)
        self.assertIn("secrets-verify must be true or false", output)

    def test_no_secret_found_is_a_pass(self):
        self.fake("trufflehog", "")
        code, output, _ = self.collect("secret-detection")
        self.assertEqual(code, 0, output)
        predicate = self.collected("secret-detection")
        self.assertEqual((predicate["result"], predicate["summary"]["total"], predicate["findings"]), ("pass", 0, []))

    def test_sca_records_every_vulnerability_and_the_database_date(self):
        calls = self.fake("grype", GRYPE_OUTPUT)
        code, output, _ = self.collect("sca")
        self.assertEqual(code, 0, output)
        predicate = self.collected("sca")
        self.assertEqual((predicate["result"], predicate["failOn"], predicate["target"]), ("fail", "high", "dir:."))
        self.assertEqual(predicate["scanner"], {"name": "grype", "version": SCANNER_VERSIONS["grype"]})
        self.assertEqual(predicate["database"]["built"], json.loads(GRYPE_OUTPUT)["descriptor"]["db"]["status"]["built"])
        self.assertEqual(predicate["summary"], {"critical": 2, "high": 2, "medium": 9, "low": 0, "negligible": 0, "unknown": 0})
        pyyaml = next(f for f in predicate["findings"] if f["id"] == "GHSA-8q59-q68h-6hv4")
        self.assertEqual(pyyaml, {
            "id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343"], "severity": "critical",
            "package": {"name": "pyyaml", "version": "5.3", "type": "python", "purl": "pkg:pypi/pyyaml@5.3"},
            "fixedIn": ["5.4"], "fixState": "fixed", "locations": ["/requirements.txt"]})
        self.assertEqual(predicate["findings"][0]["severity"], "critical")   # most severe first

        call = self.calls(calls)[-1]
        self.assertEqual(call["argv"], [f"dir:{os.getcwd()}", "--output", "json"])
        # From an empty directory, so a .grype.yaml in the scanned repository cannot hide findings.
        self.assertNotEqual(call["cwd"], os.getcwd())
        self.assertEqual(call["cwdEntries"], [])
        self.assertEqual(call["env"]["GRYPE_CHECK_FOR_APP_UPDATE"], "false")

    def test_sca_keeps_the_grype_database_where_the_job_says(self):
        # The job moves it to the work volume: the runner pod may write only 4Gi elsewhere.
        calls = self.fake("grype", GRYPE_OUTPUT)
        cache = str(self.tmp / "grype-db")
        code, output, _ = self.collect("sca", extra_env={"GRYPE_DB_CACHE_DIR": cache})
        self.assertEqual(code, 0, output)
        self.assertEqual(self.calls(calls)[-1]["env"]["GRYPE_DB_CACHE_DIR"], cache)

    def test_sca_scans_the_artifact_itself(self):
        calls = self.fake("grype", GRYPE_OUTPUT)
        artifact = self.tmp / "hello-maven.jar"
        artifact.write_bytes(b"jar")
        code, output, _ = self.collect("sca", f"sca-target=file:{artifact}")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.collected("sca")["target"], f"file:{artifact}")
        self.assertEqual(self.calls(calls)[-1]["argv"], [f"file:{artifact}", "--output", "json"])

    def test_sca_fail_on_sets_the_threshold(self):
        report = json.loads(GRYPE_OUTPUT)
        report["matches"] = [m for m in report["matches"] if m["vulnerability"]["severity"] == "Medium"]
        self.fake("grype", json.dumps(report))
        self.collect("sca")
        self.assertEqual(self.collected("sca")["result"], "pass")
        self.collect("sca", "sca-fail-on=medium")
        self.assertEqual(self.collected("sca")["result"], "fail")

    def test_bad_scanner_parameters_are_refused(self):
        self.fake("grype", GRYPE_OUTPUT)
        cases = [("sca-target=registry:alpine:3.18", "sca-target must be dir:<path>, sbom:<file> or file:<file>"),
                 ("sca-fail-on=urgent", "sca-fail-on must be one of critical, high, medium, low, negligible")]
        for pair, message in cases:
            code, output, _ = self.collect("sca", pair)
            self.assertEqual(code, 1, output)
            self.assertIn(message, output)

    def test_a_scanner_that_is_not_installed_is_an_error_not_a_pass(self):
        code, output, _ = self.collect("secret-detection,sca", extra_env={"PATH": str(self.bin)})
        self.assertEqual(code, 1)
        self.assertIn("secret-detection: the facts could not be established: trufflehog is not installed", output)
        self.assertIn("sca: the facts could not be established: grype is not installed", output)
        self.assertFalse(self.out.joinpath("sca.json").exists())

    def test_a_scanner_that_fails_is_an_error_not_a_pass(self):
        self.fake("grype", exit_code=1,
                  stderr="the vulnerability database was built 2 weeks ago (max allowed age is 5 days)")
        code, output, _ = self.collect("sca")
        self.assertEqual(code, 1)
        self.assertIn("grype exited with 1: the vulnerability database was built 2 weeks ago", output)
        self.assertFalse(self.out.joinpath("sca.json").exists())

    def test_scanner_evidence_is_signed_with_the_scan_key_and_scanners_see_no_tokens(self):
        logs = [self.fake("trufflehog", TRUFFLEHOG_OUTPUT), self.fake("grype", GRYPE_OUTPUT)]
        code, output, _ = self.run_cli("run", "--types", "secret-detection,sca", "--subject-repo-path", SUBJECT,
                                       "--subject-sha256", SUBJECT_SHA)
        self.assertEqual(code, 0, output)
        self.assertEqual([(d["keyid"], d["verified"]) for d in self.services.deployed],
                         [("evd-scan-prod-v3", True)] * 2)
        for log in logs:
            for call in self.calls(log):
                self.assertFalse({"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "GH_TOKEN"}
                                 & set(call["env"]))


class DecouplingTest(Kit):
    """Evidence logic never depends on Vault or JFrog."""

    def test_collect_needs_neither_vault_nor_jfrog(self):
        settings = self.services.settings()
        for backend in ("identity", "vault", "jfrog"):
            del settings[backend]
        code, output, _ = self.collect(
            ALL_TYPES, "sonar-project-key=acme-bank_payments", f"predicate-file={self.predicate_file}",
            settings=settings,
            extra_env={"SONAR_TOKEN": "squ_from_env", "ACTIONS_ID_TOKEN_REQUEST_URL": "", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""})
        self.assertEqual(code, 0, output)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         ["code-quality-gate.json", "custom.json", "peer-approval.json"])
        self.assertEqual(self.collected("code-quality-gate")["analysisId"], "AX-1")
        self.assertEqual(self.services.sonar_auth, ["Basic c3F1X2Zyb21fZW52Og=="])   # base64 of "squ_from_env:"
        self.assertEqual((self.services.vault_logins, self.services.jfrog_exchanges, self.services.deployed), ([], [], []))

    def test_collect_reads_collector_secrets_from_the_environment(self):
        code, output, _ = self.collect(ALL_TYPES, "sonar-project-key=acme-bank_payments",
                                       f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 1)
        self.assertIn("code-quality-gate: secret SONAR_TOKEN is not set", output)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["custom.json", "peer-approval.json"])

    def test_evidence_logic_that_reaches_signing_is_caught(self):
        collector = EVIDENCE / "collectors" / "custom" / "v1" / "collect.py"
        sdk = EVIDENCE / "evidence_sdk.py"
        cases = [
            (collector, "import signing\n", ["collectors/custom/v1/collect.py"]),
            (collector, "from cli import main\n", ["collectors/custom/v1/collect.py"]),   # cli imports signing
            (sdk, "from signing import Vault\n", [str(p.relative_to(EVIDENCE)) for p in cli.evidence_logic()
                                                   if p.parent.parent.parent.name == "collectors"]),
            (EVIDENCE / "verification.py", "import signing\n", ["verification.py"]),
        ]
        for target, line, flagged in cases:
            original = target.read_text()
            self.addCleanup(target.write_text, original)
            target.write_text(original + line)
            problems = [p for p in cli.find_problems() if "reaches signing.py" in p]
            self.assertEqual(sorted(p.split(":")[0] for p in problems), sorted(flagged), line)
            target.write_text(original)


class CatalogTest(unittest.TestCase):
    def test_catalog_schemas_examples_and_lock_are_consistent(self):
        self.assertEqual(cli.find_problems(), [])

    def test_changing_a_published_schema_is_caught(self):
        target = EVIDENCE / "collectors" / "custom" / "v1" / "schema.json"
        original = target.read_text()
        self.addCleanup(target.write_text, original)
        changed = json.loads(original)
        changed["required"].remove("commit")
        target.write_text(json.dumps(changed))
        self.assertTrue(any("a published schema changed" in p for p in cli.find_problems()))

    def test_reformatting_a_schema_is_not_a_change(self):
        target = EVIDENCE / "collectors" / "custom" / "v1" / "schema.json"
        original = target.read_text()
        self.addCleanup(target.write_text, original)
        target.write_text(json.dumps(json.loads(original), indent=8))
        self.assertEqual(cli.find_problems(), [])


class SchemaTest(unittest.TestCase):
    SCHEMA = {
        "type": "object", "additionalProperties": False, "required": ["result", "count"],
        "properties": {
            "result": {"enum": ["pass", "fail"]},
            "count": {"type": "integer"},
            "sha": {"type": "string", "pattern": "^[0-9a-f]{4}$"},
            "who": {"type": ["string", "null"]},
            "items": {"type": "array", "minItems": 1, "items": {"type": "object", "required": ["id"]}},
        },
    }

    def test_a_matching_value_has_no_problems(self):
        value = {"result": "pass", "count": 2, "sha": "ab12", "who": None, "items": [{"id": 1}]}
        self.assertEqual(schema.validate(value, self.SCHEMA), [])

    def test_each_kind_of_problem_is_reported(self):
        cases = [
            ({"count": 1}, "missing required field 'result'"),
            ({"result": "maybe", "count": 1}, "must be one of"),
            ({"result": "pass", "count": "1"}, "$.count: expected integer, got string"),
            ({"result": "pass", "count": True}, "$.count: expected integer, got boolean"),
            ({"result": "pass", "count": 1, "extra": 0}, "unexpected field 'extra'"),
            ({"result": "pass", "count": 1, "sha": "XYZ"}, "does not match pattern"),
            ({"result": "pass", "count": 1, "items": []}, "fewer than 1 items"),
            ({"result": "pass", "count": 1, "items": [{}]}, "$.items[0]: missing required field 'id'"),
            ([], "$: expected object, got array"),
        ]
        for value, message in cases:
            problems = schema.validate(value, self.SCHEMA)
            self.assertTrue(any(message in p for p in problems), f"{value!r} -> {problems}")

    def test_keywords_the_validator_cannot_enforce_are_rejected(self):
        with self.assertRaises(schema.SchemaError) as caught:
            schema.check_schema({"type": "object", "properties": {"n": {"type": "integer", "minimum": 1}}})
        self.assertIn("$.n: unsupported keyword(s): minimum", str(caught.exception))


class FileStore(Kit):
    """Helpers to sign collected predicates into DSSE envelope files and verify them."""

    TYPES = "peer-approval,custom"

    def setUp(self):
        super().setUp()
        self.envelopes = self.tmp / "envelopes"

    def file_settings(self, **overrides):
        return self.services.settings(store="file", **overrides)

    def sign(self, types=None, *extra, settings=None, **kwargs):
        return self.run_cli("sign", "--types", types or self.TYPES, "--predicates", str(self.out), "--subject-repo-path", SUBJECT,
                            "--subject-sha256", SUBJECT_SHA, "--out", str(self.envelopes), *extra,
                            settings=settings or self.file_settings(), **kwargs)

    def envelope(self, type_id):
        return json.loads((self.envelopes / f"{type_id}.dsse.json").read_text())

    def verify(self, *extra, keys=None, **kwargs):
        keys = keys or self.trusted_keys("evd-approval-prod-v3", "evd-scan-prod-v3", "evd-self-prod-v3",
                                         "evd-build-prod-v3")
        return self.run_cli("verify", "--envelopes", str(self.envelopes), "--keys", str(keys), *extra,
                            settings=self.file_settings(), **kwargs)



class FileStoreTest(FileStore):
    """Collect in one job, sign with Vault Transit in another, and store DSSE envelopes as files: no JFrog."""

    def collect_and_sign(self, **kwargs):
        code, output, _ = self.collect(self.TYPES, f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        return self.sign(**kwargs)

    def test_collected_evidence_is_signed_by_vault_and_verifies_with_openssl(self):
        code, output, summary = self.collect_and_sign()
        self.assertEqual(code, 0, output)
        self.assertEqual(sorted(p.name for p in self.envelopes.iterdir()), ["custom.dsse.json", "peer-approval.dsse.json"])
        for type_id, key_id in (("peer-approval", "evd-approval-prod-v3"), ("custom", "evd-self-prod-v3")):
            envelope = self.envelope(type_id)
            self.assertEqual(envelope["payloadType"], "application/vnd.in-toto+json")
            self.assertEqual(envelope["signatures"][0]["keyid"], key_id)
            self.assertTrue(self.openssl_verifies(envelope), type_id)
            statement = json.loads(base64.b64decode(envelope["payload"]))
            self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(statement["subject"], [{"name": SUBJECT, "digest": {"sha256": SUBJECT_SHA}}])
            self.assertEqual(statement["predicateType"], f"https://evidence.acme-bank.example/{type_id}/v1")
            self.assertEqual(statement["predicate"], self.collected(type_id))
        self.assertIn("| ✅ | `peer-approval` v1 | 🟢 pass | 👥 1 approval on pull request #7 | `evd-approval-prod-v3` |", summary)
        self.assertEqual(sorted(self.services.sign_calls), ["evd-approval-prod", "evd-self-prod"])
        self.assertEqual((self.services.jfrog_exchanges, self.services.deployed), ([], []))

    def test_the_log_follows_each_step_of_vault_transit_signing(self):
        code, output, summary = self.collect_and_sign()
        self.assertEqual(code, 0, output)
        envelope = self.envelope("custom")
        signed = pae(envelope["payloadType"], base64.b64decode(envelope["payload"]))
        digest = hashlib.sha256(signed).hexdigest()
        workflow = f"{REPO}/.github/workflows/evidence.yml@refs/heads/main"
        for line in (
            f"🏦 Vault {self.services.url}, namespace platform: login at auth/github-actions, Transit at transit-evidence,"
            " RSA PKCS#1 v1.5 with SHA-256",
            f"📜 In-toto statement about {SUBJECT}, SHA-256 {SUBJECT_SHA}: https://evidence.acme-bank.example/custom/v1,"
            f" {len(base64.b64decode(envelope['payload'])):,} bytes",
            "🪪 Identity token from GitHub's OIDC endpoint, valid until 08:05:00 UTC."
            " Vault checks these claims against role evidence-self-prod:",
            "     aud                 https://vault.acme-bank.example",
            f"     job_workflow_ref    {workflow}",
            "     runner_environment  self-hosted",
            "🔐 Vault login with role evidence-self-prod: batch token, valid 10m, policies evidence-self-prod-transit-sign."
            " Request login-2,",
            f"✍️ Transit sign with evd-self-prod: RSA PKCS#1 v1.5 over the SHA-256 of {len(signed):,} bytes,"
            f" the statement's DSSE encoding. Their SHA-256: {digest}",
            "✅ Vault signed with evd-self-prod version 3, key id evd-self-prod-v3: a 256-byte signature. Request sign-2,",
        ):
            self.assertIn(line, output)
        # The sign job's summary says the same, after the table of evidence.
        self.assertLess(summary.index("### 🔏 Evidence signed"), summary.index("### 🔐 How Vault Transit signed"))
        self.assertRegex(summary, r"\| ✅ \| role `evidence-self-prod` \| `aud` `https://vault.acme-bank.example`<br>"
                                  rf"`job_workflow_ref` `{re.escape(workflow)}`<br>.*\| batch token, valid 10m, policies"
                                  r" `evidence-self-prod-transit-sign` \| `login-2` · \d+ ms \|")
        self.assertRegex(summary, rf"\| ✅ \| `custom` v1 \| `evd-self-prod` version 3, RSA PKCS#1 v1.5 \| {len(signed):,}"
                                  rf" bytes, SHA-256 `{digest[:16]}…` \| key id `evd-self-prod-v3` · request `sign-2` · \d+ ms \|")

    def test_a_refused_login_shows_the_claims_vault_refused(self):
        code, output, _ = self.collect(self.TYPES, f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        self.services.refuse_logins = True
        code, output, summary = self.sign()
        self.assertEqual(code, 1)
        refusal = "does not match any associated bound claim values"
        # The log shows the claims before the login, so the refusal can be read against them.
        self.assertLess(output.index(f"     job_workflow_ref    {REPO}/.github/workflows/evidence.yml@refs/heads/main"),
                        output.index(f"⛔ POST {self.services.url}/v1/auth/github-actions/login returned 400"))
        self.assertIn(refusal, output)
        self.assertRegex(summary, r"\| ❌ \| role `evidence-approval-prod` \| `aud` .*\| .*does not match any associated")
        self.assertEqual(self.services.sign_calls, [])

    def test_pss_envelopes_verify(self):
        code, output, _ = self.collect_and_sign(settings=self.file_settings(**{"vault.signatureAlgorithm": "pss"}))
        self.assertEqual(code, 0, output)
        self.assertEqual(self.envelope("custom")["signatures"][0]["keyid"], "evd-self-prod-v3;PS256")
        self.assertTrue(self.openssl_verifies(self.envelope("custom")))
        code, output, _ = self.verify()
        self.assertEqual(code, 0, output)

    def test_the_signing_job_runs_no_collector_and_no_scanner(self):
        self.fake("trufflehog", TRUFFLEHOG_OUTPUT)
        self.fake("grype", GRYPE_OUTPUT)
        code, output, _ = self.collect("secret-detection,sca")
        self.assertEqual(code, 0, output)
        # The signing job has no scanner on PATH and no GitHub token: it only reads what collect wrote.
        code, output, _ = self.sign("secret-detection,sca", extra_env={"PATH": os.environ["PATH"], "GH_TOKEN": ""})
        self.assertEqual(code, 0, output)
        self.assertEqual([self.envelope(t)["signatures"][0]["keyid"] for t in ("secret-detection", "sca")],
                         ["evd-scan-prod-v3"] * 2)
        self.assertEqual([role for role, _ in self.services.vault_logins], ["evidence-scan-prod"])

    def test_each_predicate_is_checked_again_before_it_is_signed(self):
        code, output, _ = self.collect(self.TYPES, f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        approval = self.collected("peer-approval")
        del approval["result"]
        (self.out / "peer-approval.json").write_text(json.dumps(approval))
        code, output, summary = self.sign()
        self.assertEqual(code, 1)
        self.assertIn("peer-approval: the predicate does not match its schema: $: missing required field 'result'", output)
        self.assertEqual(sorted(p.name for p in self.envelopes.iterdir()), ["custom.dsse.json"])
        self.assertEqual(self.services.sign_calls, ["evd-self-prod"])

    def test_a_predicate_about_another_commit_is_not_signed(self):
        code, output, _ = self.collect(self.TYPES, f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        code, output, _ = self.sign(extra_env={"GITHUB_SHA": "c" * 40})
        self.assertEqual(code, 1)
        self.assertIn(f"the predicate was collected for commit {SHA}, not {'c' * 40}", output)
        self.assertEqual(self.services.sign_calls, [])

    def test_a_type_that_was_not_collected_fails_only_that_type(self):
        code, output, _ = self.collect("custom", f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        code, output, _ = self.sign()
        self.assertEqual(code, 1)
        self.assertIn("peer-approval: no collected predicate peer-approval.json", output)
        self.assertTrue((self.envelopes / "custom.dsse.json").exists())

    def test_run_with_the_file_store_collects_and_signs_in_one_job(self):
        code, output, _ = self.run_cli("run", "--types", self.TYPES, "--subject-repo-path", SUBJECT,
                                       "--subject-sha256", SUBJECT_SHA, "--param", f"predicate-file={self.predicate_file}",
                                       "--out", str(self.envelopes), settings=self.file_settings())
        self.assertEqual(code, 0, output)
        self.assertTrue(all(self.openssl_verifies(self.envelope(t)) for t in ("peer-approval", "custom")))
        self.assertEqual(self.services.jfrog_exchanges, [])

    def test_the_file_store_needs_a_digest_and_a_folder_before_any_token_is_requested(self):
        cases = [
            (["--subject-repo-path", SUBJECT, "--out", str(self.envelopes)], "subject-sha256 is required"),
            (["--subject-repo-path", SUBJECT, "--subject-sha256", SUBJECT_SHA], "pass --out"),
        ]
        for args, message in cases:
            code, output, _ = self.run_cli("sign", "--types", "custom", "--predicates", str(self.out), *args,
                                           settings=self.file_settings())
            self.assertEqual(code, 2, output)
            self.assertIn(message, output)
        code, output, _ = self.run_cli("sign", "--types", "custom", "--predicates", str(self.out),
                                       "--subject-repo-path", SUBJECT, settings=self.services.settings(store="s3"))
        self.assertEqual(code, 2)
        self.assertIn("unknown store 's3'", output)
        self.assertEqual(self.services.vault_logins, [])

    # ---- verify: public keys only -------------------------------------------------

    def test_verify_accepts_what_vault_signed(self):
        self.collect_and_sign()
        code, output, summary = self.verify("--subject-sha256", SUBJECT_SHA, "--types", self.TYPES)
        self.assertEqual(code, 0, output)
        self.assertIn("| ✅ | `custom` v1 | ⚪ n/a | 📝 1 claim by acme-bank/payments: loadTest | `evd-self-prod-v3` |", summary)
        self.assertIn("| ✅ | `peer-approval` v1 | 🟢 pass | 👥 1 approval on pull request #7 | `evd-approval-prod-v3` |", summary)
        self.assertIn(f"🎯 `{SUBJECT}` · SHA-256 `{SUBJECT_SHA}`", summary)
        self.assertIn("**2 of 2 verified · 🟢 1 pass · ⚪ 1 n/a**", summary)
        # Each verified statement follows, folded: what a reviewer reads, after the signature held.
        self.assertIn("<details><summary>✅ <code>custom</code> v1 · ⚪ n/a · 📝 1 claim by acme-bank/payments: loadTest"
                      " · signed by <code>evd-self-prod-v3</code></summary>", summary)
        self.assertIn('"p95Ms": 180', summary)
        self.assertIn("::group::🧾 peer-approval v1: the verified statement", output)

    def test_verify_reads_a_folder_per_artifact(self):
        """Downloading a run's envelopes gives a folder per call of evidence.yml: evidence-envelopes-<type>/."""
        self.collect_and_sign()
        for path in list(self.envelopes.glob("*.dsse.json")):
            folder = self.envelopes / f"evidence-envelopes-{path.name[:-len('.dsse.json')]}"
            folder.mkdir()
            path.rename(folder / path.name)
        code, output, _ = self.verify("--subject-sha256", SUBJECT_SHA, "--types", self.TYPES)
        self.assertEqual(code, 0, output)
        self.assertIn("🧾 2 of 2 verified", output)

    def test_verify_needs_no_vault_and_no_jfrog(self):
        self.collect_and_sign()
        logins = list(self.services.vault_logins)
        settings = self.file_settings()
        for backend in ("identity", "vault", "jfrog"):
            del settings[backend]
        code, output, _ = self.run_cli("verify", "--envelopes", str(self.envelopes),
                                       "--keys", str(self.trusted_keys("evd-approval-prod-v3", "evd-self-prod-v3")),
                                       settings=settings, extra_env={"ACTIONS_ID_TOKEN_REQUEST_URL": ""})
        self.assertEqual(code, 0, output)
        self.assertEqual(self.services.vault_logins, logins)

    def test_verify_refuses_a_changed_payload(self):
        self.collect_and_sign()
        envelope = self.envelope("peer-approval")
        statement = json.loads(base64.b64decode(envelope["payload"]))
        statement["predicate"]["approvalCount"] = 2
        envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
        (self.envelopes / "peer-approval.dsse.json").write_text(json.dumps(envelope))
        code, output, _ = self.verify()
        self.assertEqual(code, 1)
        self.assertIn("peer-approval: no valid signature: the signature by 'evd-approval-prod-v3' does not verify", output)

    def test_verify_refuses_keys_it_does_not_trust(self):
        self.collect_and_sign()
        code, output, _ = self.verify(keys=self.trusted_keys("evd-self-prod-v3"))
        self.assertEqual(code, 1)
        self.assertIn("peer-approval: no valid signature: key 'evd-approval-prod-v3' is not trusted", output)

        other = self.services._new_key("other").with_suffix(".pub")
        code, output, _ = self.verify(keys=self.trusted_keys("evd-approval-prod-v3", "evd-self-prod-v3", public_key=other))
        self.assertEqual(code, 1)
        self.assertIn("custom: no valid signature: the signature by 'evd-self-prod-v3' does not verify", output)

    def test_verify_refuses_evidence_about_another_artifact(self):
        self.collect_and_sign()
        code, output, _ = self.verify("--subject-sha256", "f" * 64)
        self.assertEqual(code, 1)
        self.assertIn(f"the evidence is about another artifact: no subject has SHA-256 {'f' * 64}", output)

    def test_verify_reports_a_type_with_no_envelope(self):
        self.collect_and_sign()
        code, output, _ = self.verify("--types", "peer-approval,custom,sca")
        self.assertEqual(code, 1)
        self.assertIn("sca: no envelope for this type", output)

    def test_a_key_from_another_family_cannot_vouch_for_a_type(self):
        """The self key is the squads' own: it must not be able to sign scan or approval evidence."""
        code, output, _ = self.collect(self.TYPES, f"predicate-file={self.predicate_file}")
        self.assertEqual(code, 0, output)
        jwt = self.tmp / "vault.jwt"
        jwt.write_text("jwt")
        os.environ["EVD_VAULT_JWT_FILE"] = str(jwt)
        self.addCleanup(os.environ.pop, "EVD_VAULT_JWT_FILE")
        settings = self.file_settings(identity="file")
        kind = "https://evidence.acme-bank.example/peer-approval/v1"
        with contextlib.redirect_stdout(io.StringIO()):
            key_id, envelope = signing.envelope(self.collected("peer-approval"), kind, "self", SUBJECT, SUBJECT_SHA,
                                                signing.Vault(settings))
        self.assertEqual(key_id, "evd-self-prod-v3")
        keys = verification.load_trusted_keys(self.trusted_keys("evd-self-prod-v3"))
        with self.assertRaises(EvidenceError) as caught:
            verification.verify(envelope, keys, cli.load_catalog(), settings)
        self.assertIn("peer-approval evidence must be signed with an evd-approval-prod key, not 'evd-self-prod-v3'",
                      str(caught.exception))


class BuildEvidenceTest(FileStore):
    """test-results and provenance: what the squad's own build did, signed with the build key."""

    TYPES = "test-results,provenance"
    # What GitHub sets for a run of the squad's workflow.
    GITHUB = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/hello-maven.yml@refs/heads/main",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY_ID": "1460010558",
        "GITHUB_REPOSITORY_OWNER_ID": "71595780",
        "GITHUB_RUN_ID": "44001716002",
        "GITHUB_RUN_ATTEMPT": "2",
        "RUNNER_ENVIRONMENT": "self-hosted",
    }

    def collect_build(self, reports=REPORTS / "surefire-pass", **github):
        return self.collect(self.TYPES, f"test-reports={reports}", extra_env={**self.GITHUB, **github})

    def test_every_tool_reports_the_same_way(self):
        expected = {
            "surefire-pass": {"tests": 4, "passed": 4, "failed": 0, "errored": 0, "skipped": 0, "flaky": 0},
            "surefire-fail": {"tests": 8, "passed": 5, "failed": 1, "errored": 1, "skipped": 1, "flaky": 1},
            "pytest-pass": {"tests": 3, "passed": 3, "failed": 0, "errored": 0, "skipped": 0, "flaky": 0},
            "pytest-fail": {"tests": 6, "passed": 3, "failed": 1, "errored": 1, "skipped": 1, "flaky": 0},
            "node-pass": {"tests": 3, "passed": 3, "failed": 0, "errored": 0, "skipped": 0, "flaky": 0},
            "node-fail": {"tests": 6, "passed": 4, "failed": 1, "errored": 0, "skipped": 1, "flaky": 0},
        }
        for name, summary in expected.items():
            with self.subTest(name):
                code, output, _ = self.collect("test-results", f"test-reports={REPORTS / name}")
                self.assertEqual(code, 0, output)
                predicate = self.collected("test-results")
                self.assertEqual(predicate["summary"], summary)
                self.assertEqual(predicate["result"], "pass" if name.endswith("-pass") else "fail")
                self.assertEqual(predicate["commit"], SHA)
                self.assertEqual(len(predicate["failedTests"]), summary["failed"] + summary["errored"])
                # The failing tests assert with a message that holds "token=should-never-reach-the-evidence".
                self.assertNotIn("should-never-reach-the-evidence", json.dumps(predicate))
                for report in predicate["reports"]:
                    raw = (REPORTS / name / report["file"]).read_bytes()
                    self.assertEqual(report["sha256"], hashlib.sha256(raw).hexdigest())

    def test_failed_tests_are_named_with_their_report(self):
        self.collect("test-results", f"test-reports={REPORTS / 'surefire-fail'}")
        self.assertEqual(self.collected("test-results")["failedTests"], [
            {"suite": "lab.hello.BrokenTest", "test": "greetsInFrench", "outcome": "failed",
             "report": "TEST-lab.hello.BrokenTest.xml"},
            {"suite": "lab.hello.BrokenTest", "test": "throwsInsteadOfAsserting", "outcome": "errored",
             "report": "TEST-lab.hello.BrokenTest.xml"}])

    def test_no_test_at_all_is_a_fail(self):
        """What a build run with -DskipTests uploads: reports with no test case in them."""
        reports = self.tmp / "skipped"
        reports.mkdir()
        (reports / "TEST-lab.hello.AppTest.xml").write_text('<testsuite name="lab.hello.AppTest" tests="0"/>')
        self.collect("test-results", f"test-reports={reports}")
        predicate = self.collected("test-results")
        self.assertEqual((predicate["result"], predicate["summary"]["tests"]), ("fail", 0))

    def test_xml_that_is_not_a_test_report_is_skipped(self):
        reports = self.tmp / "failsafe"
        shutil.copytree(REPORTS / "surefire-pass", reports)
        (reports / "failsafe-summary.xml").write_text("<failsafe-summary result='0'><completed>4</completed></failsafe-summary>")
        self.collect("test-results", f"test-reports={reports}")
        predicate = self.collected("test-results")
        self.assertEqual([r["file"] for r in predicate["reports"]], ["TEST-lab.hello.AppTest.xml"])

    def test_reports_that_cannot_be_read_are_an_error_not_a_pass(self):
        empty, broken = self.tmp / "empty", self.tmp / "broken"
        empty.mkdir()
        broken.mkdir()
        (broken / "junit.xml").write_text("<testsuites><testsuite>")
        for folder, message in ((self.tmp / "missing", "is not a directory"),
                                (empty, "no JUnit XML report"),
                                (broken, "junit.xml is not well-formed XML")):
            with self.subTest(message):
                code, output, _ = self.collect("test-results", f"test-reports={folder}")
                self.assertEqual(code, 1, output)
                self.assertIn(message, output)
                self.assertFalse((self.out / "test-results.json").exists())

    def test_provenance_is_slsa_with_github_workflow_build_type(self):
        code, output, _ = self.collect("provenance", extra_env=self.GITHUB)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.collected("provenance"), {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"ref": "refs/heads/main", "repository": f"https://github.com/{REPO}",
                                                    "path": ".github/workflows/hello-maven.yml"}},
                "internalParameters": {"github": {"event_name": "push", "repository_id": "1460010558",
                                                  "repository_owner_id": "71595780",
                                                  "runner_environment": "self-hosted"}},
                "resolvedDependencies": [{"uri": f"git+https://github.com/{REPO}@refs/heads/main",
                                          "digest": {"gitCommit": SHA}}],
            },
            "runDetails": {
                "builder": {"id": f"https://github.com/{REPO}/.github/workflows/hello-maven.yml@refs/heads/main"},
                "metadata": {"invocationId": f"https://github.com/{REPO}/actions/runs/44001716002/attempts/2"},
            },
        })

    def test_provenance_refuses_a_workflow_of_another_repository(self):
        code, output, _ = self.collect(
            "provenance", extra_env={**self.GITHUB, "GITHUB_WORKFLOW_REF": "evil/repo/.github/workflows/x.yml@refs/heads/main"})
        self.assertEqual(code, 1, output)
        self.assertIn(f"does not name a workflow of {REPO}", output)

    def test_build_evidence_is_signed_with_the_build_key_and_provenance_as_slsa(self):
        code, output, _ = self.collect_build()
        self.assertEqual(code, 0, output)
        code, output, _ = self.sign(settings=self.file_settings())
        self.assertEqual(code, 0, output)
        self.assertEqual(sorted(self.services.sign_calls), ["evd-build-prod", "evd-build-prod"])
        provenance = json.loads(base64.b64decode(self.envelope("provenance")["payload"]))
        self.assertEqual(provenance["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(provenance["subject"], [{"name": SUBJECT, "digest": {"sha256": SUBJECT_SHA}}])
        tests = json.loads(base64.b64decode(self.envelope("test-results")["payload"]))
        self.assertEqual(tests["predicateType"], "https://evidence.acme-bank.example/test-results/v1")
        for type_id in ("provenance", "test-results"):
            self.assertTrue(self.openssl_verifies(self.envelope(type_id)), type_id)

        code, output, _ = self.verify("--subject-sha256", SUBJECT_SHA, "--types", self.TYPES)
        self.assertEqual(code, 0, output)
        self.assertIn("✅ provenance v1: verified · ⚪ n/a · 🏗️ hello-maven.yml on refs/heads/main, commit aaaaaaaaaaaa,"
                      " run 44001716002 attempt 2 · signed by evd-build-prod-v3", output)
        self.assertIn("✅ test-results v1: verified · 🟢 pass · 🧪 4 tests: 4 passed · signed by evd-build-prod-v3", output)

    def test_a_scan_key_cannot_vouch_for_build_evidence(self):
        self.collect_build()
        jwt = self.tmp / "vault.jwt"
        jwt.write_text("jwt")
        os.environ["EVD_VAULT_JWT_FILE"] = str(jwt)
        self.addCleanup(os.environ.pop, "EVD_VAULT_JWT_FILE")
        settings = self.file_settings(identity="file")
        with contextlib.redirect_stdout(io.StringIO()):
            _, envelope = signing.envelope(self.collected("provenance"), "https://slsa.dev/provenance/v1", "scan",
                                           SUBJECT, SUBJECT_SHA, signing.Vault(settings))
        keys = verification.load_trusted_keys(self.trusted_keys("evd-scan-prod-v3"))
        with self.assertRaises(EvidenceError) as caught:
            verification.verify(envelope, keys, cli.load_catalog(), settings)
        self.assertIn("provenance evidence must be signed with an evd-build-prod key", str(caught.exception))

    def test_a_standard_predicate_type_names_one_type_only(self):
        settings = self.services.settings()
        catalog = cli.load_catalog()
        self.assertEqual(core_evidence_type("https://slsa.dev/provenance/v1", catalog, settings), ("provenance", "v1"))
        # The kit's own name for that type and version is not accepted: only the standard one is.
        with self.assertRaises(EvidenceError):
            core_evidence_type("https://evidence.acme-bank.example/provenance/v1", catalog, settings)
        self.assertEqual(core_evidence_type("https://evidence.acme-bank.example/sca/v1", catalog, settings), ("sca", "v1"))


class ProvenanceAttestationTest(FileStore):
    """GitHub's attestation of the artifact, verified with gh, then signed with the build key."""

    TYPES = "provenance-attestation"
    # gh attestation verify, recorded by scanners/record.py on the attestation of gh's own release archive.
    RECORDED = json.loads((SCANNERS / "gh-attestation.json").read_text())
    SIGNER = f"{REPO}/.github/workflows/evidence.yml"

    def setUp(self):
        super().setUp()
        self.artifact = self.tmp / "hello-maven.jar"
        self.artifact.write_bytes(b"the squad's jar")
        self.sha256 = hashlib.sha256(b"the squad's jar").hexdigest()

    def gh(self, output=None, **kwargs):
        """A stand-in gh that answers as the recorded one did. Returns its calls' log."""
        if output is None:
            recorded = json.loads(json.dumps(self.RECORDED))
            # The recording is about gh's archive: the stand-in vouches for this test's artifact instead.
            for subject in recorded[0]["verificationResult"]["statement"]["subject"]:
                if subject["digest"]["sha256"] == SCANNER_VERSIONS["gh"]["sha256"]:
                    subject["digest"]["sha256"] = self.sha256
            output = json.dumps(recorded)
        return self.fake("gh", output, version=f"gh version {SCANNER_VERSIONS['gh']['version']} (2026-09-30)", **kwargs)

    def collect_attestation(self):
        return self.collect(self.TYPES, f"attested-file={self.artifact}", f"attestation-signer={self.SIGNER}")

    def test_a_verified_attestation_is_recorded_then_signed_with_the_build_key(self):
        calls = self.gh()
        code, output, _ = self.collect_attestation()
        self.assertEqual(code, 0, output)
        predicate = self.collected("provenance-attestation")
        self.assertEqual(predicate["result"], "pass")
        self.assertEqual(predicate["artifact"], {"file": "hello-maven.jar", "sha256": self.sha256})
        self.assertEqual(predicate["verifier"], {"name": "gh", "version": SCANNER_VERSIONS["gh"]["version"]})
        self.assertEqual(predicate["policy"], {"repository": REPO, "signerWorkflow": self.SIGNER, "sourceDigest": SHA,
                                               "predicateType": "https://slsa.dev/provenance/v1"})
        attestation = predicate["attestations"][0]
        self.assertEqual(attestation["signer"], "https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk")
        self.assertEqual(attestation["sourceDigest"], SCANNER_VERSIONS["gh"]["commit"])
        self.assertEqual(attestation["subjects"], [SCANNER_VERSIONS["gh"]["file"]])   # of the 21 the statement names
        self.assertEqual([t["authority"] for t in attestation["timestamps"]], ["https://rekor.sigstore.dev"])
        self.assertEqual(len(attestation["transparencyLogIndexes"]), 1)
        # gh enforced the policy, with the job's token: this repository, the platform's workflow, this commit.
        verify = [call for call in self.calls(calls) if call["argv"][:2] == ["attestation", "verify"]]
        self.assertEqual(verify[0]["argv"], [
            "attestation", "verify", str(self.artifact), "--repo", REPO, "--signer-workflow", self.SIGNER,
            "--source-digest", SHA, "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"])
        self.assertEqual(verify[0]["env"]["GH_TOKEN"], "ghs_token")
        # What the attestation says, never the bundle: no certificate or signature reaches the predicate.
        bundle = self.RECORDED[0]["attestation"]["bundle"]
        self.assertNotIn(bundle["dsseEnvelope"]["signatures"][0]["sig"], json.dumps(predicate))
        self.assertNotIn(bundle["verificationMaterial"]["certificate"]["rawBytes"][:40], json.dumps(predicate))

        code, output, _ = self.sign()
        self.assertEqual(code, 0, output)
        self.assertEqual(self.envelope("provenance-attestation")["signatures"][0]["keyid"], "evd-build-prod-v3")
        code, output, _ = self.verify("--subject-sha256", SUBJECT_SHA, "--types", self.TYPES)
        self.assertEqual(code, 0, output)
        self.assertIn("✅ provenance-attestation v1: verified · 🟢 pass · 🪪 1 GitHub attestation verified: signed by"
                      " deployment.yml on refs/heads/trunk, logged by rekor.sigstore.dev · signed by evd-build-prod-v3",
                      output)

    def test_no_attestation_is_a_fail_and_is_signed(self):
        """What the lab's private repository answers on GitHub's Free plan: no attestations, ever."""
        for message in ("Error: HTTP 404: Not Found (https://api.github.com/repos/x/y/attestations/sha256:0)",
                        "Error: no attestations found"):
            with self.subTest(message):
                self.gh("", exit_code=1, stderr=message)
                code, output, _ = self.collect_attestation()
                self.assertEqual(code, 0, output)
                predicate = self.collected("provenance-attestation")
                self.assertEqual((predicate["result"], predicate["summary"], predicate["attestations"]),
                                 ("fail", {"verified": 0}, []))
                self.assertEqual(predicate["reason"],
                                 f"GitHub holds no provenance attestation for these bytes: {message[len('Error: '):]}")
        code, output, _ = self.sign()
        self.assertEqual(code, 0, output)
        code, output, _ = self.verify("--types", self.TYPES)
        self.assertIn("🔴 fail · 🪪 GitHub holds no attestation for these bytes", output)

    def test_an_attestation_that_does_not_verify_is_an_error_not_a_fail(self):
        self.gh("", exit_code=1, stderr=f"Error: expected SourceRepositoryDigest to be {SHA}, got {'f' * 40}")
        code, output, _ = self.collect_attestation()
        self.assertEqual(code, 1)
        self.assertIn("gh could not verify GitHub's attestation for these bytes: expected SourceRepositoryDigest", output)
        self.assertFalse((self.out / "provenance-attestation.json").exists())

        self.gh("[]")
        code, output, _ = self.collect_attestation()
        self.assertEqual(code, 1)
        self.assertIn("gh verified the attestations but listed none", output)


class RepositoryControlsTest(FileStore):
    """The repository's controls, from the snapshot read-controls took, checked and signed with the scan key."""

    TYPES = "repository-controls"
    CONTROLS = Path(__file__).resolve().parent / "controls"

    def collect_controls(self, snapshot):
        return self.collect(self.TYPES, f"controls-snapshot={snapshot}")

    def test_a_protected_branch_passes_every_check(self):
        code, output, _ = self.collect_controls(self.CONTROLS / "protected.json")
        self.assertEqual(code, 0, output)
        predicate = self.collected("repository-controls")
        self.assertEqual((predicate["result"], predicate["summary"]), ("pass", {"passed": 9, "failed": 0, "unknown": 0}))
        self.assertEqual((predicate["repository"], predicate["branch"], predicate["commit"]), (REPO, "main", SHA))
        raw = (self.CONTROLS / "protected.json").read_bytes()
        # The snapshot itself is kept, pinned by its SHA-256: who had access and which rules held, at release time.
        self.assertEqual(predicate["snapshot"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(predicate["snapshot"]["controls"], json.loads(raw))
        self.assertEqual(predicate["access"], {"roles": {"admin": 1, "maintain": 1, "write": 1, "triage": 0, "read": 0},
                                               "outsideWriters": 1, "organizationOwners": 1, "writeDeployKeys": 1,
                                               "invitations": 1})

    def test_controls_github_will_not_show_are_unknown_and_count_as_missing(self):
        """What this lab's repository shows: private on the Free plan, with workflows allowed to approve."""
        code, output, _ = self.collect_controls(self.CONTROLS / "private-free.json")
        self.assertEqual(code, 0, output)
        predicate = self.collected("repository-controls")
        self.assertEqual((predicate["result"], predicate["summary"]), ("fail", {"passed": 1, "failed": 1, "unknown": 7}))
        results = {check["id"]: check["result"] for check in predicate["checks"]}
        self.assertEqual((results["pull-request-required"], results["no-bypass"]), ("unknown", "unknown"))
        self.assertEqual((results["workflows-cannot-approve"], results["workflow-token-read-only"]), ("fail", "pass"))
        self.assertEqual(predicate["unavailable"], ["branch_protection", "rules.branch", "rules.rulesets"])

    def test_classic_branch_protection_counts_too(self):
        snapshot = json.loads((self.CONTROLS / "private-free.json").read_text())
        snapshot["rules"] = {"branch": [], "rulesets": []}
        snapshot["actions"]["workflow"]["can_approve_pull_request_reviews"] = False
        snapshot["branch_protection"] = {
            "allow_deletions": {"enabled": False}, "allow_force_pushes": {"enabled": False},
            "enforce_admins": {"enabled": True},
            "required_pull_request_reviews": {"dismiss_stale_reviews": True, "require_last_push_approval": True,
                                              "required_approving_review_count": 2}}
        path = self.tmp / "classic.json"
        path.write_text(json.dumps(snapshot))
        code, output, _ = self.collect_controls(path)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.collected("repository-controls")["result"], "pass")

        # An administrator who may bypass, or a pull request rule anyone may skip, is a missing control.
        snapshot["branch_protection"]["enforce_admins"] = {"enabled": False}
        path.write_text(json.dumps(snapshot))
        self.collect_controls(path)
        results = {check["id"]: check["result"] for check in self.collected("repository-controls")["checks"]}
        self.assertEqual(results["no-bypass"], "fail")

    def test_a_snapshot_it_cannot_trust_is_an_error_not_a_fail(self):
        other = json.loads((self.CONTROLS / "protected.json").read_text())
        other["repository"] = "evil/other"
        (self.tmp / "other.json").write_text(json.dumps(other))
        (self.tmp / "not-a-snapshot.json").write_text('{"format": "something/v9"}')
        for path, message in ((self.tmp / "missing.json", "cannot be read"),
                              (self.tmp / "not-a-snapshot.json", "is not a repository-controls/v1 snapshot"),
                              (self.tmp / "other.json", f"the snapshot is of evil/other, not of {REPO}")):
            with self.subTest(message):
                code, output, _ = self.collect_controls(path)
                self.assertEqual(code, 1, output)
                self.assertIn(message, output)
                self.assertFalse((self.out / "repository-controls.json").exists())

    def test_the_controls_are_signed_with_the_scan_key(self):
        code, output, _ = self.collect_controls(self.CONTROLS / "private-free.json")
        self.assertEqual(code, 0, output)
        code, output, _ = self.sign()
        self.assertEqual(code, 0, output)
        self.assertEqual(self.envelope("repository-controls")["signatures"][0]["keyid"], "evd-scan-prod-v3")
        code, output, _ = self.verify("--subject-sha256", SUBJECT_SHA, "--types", self.TYPES)
        self.assertEqual(code, 0, output)
        self.assertIn("✅ repository-controls v1: verified · 🔴 fail · 🛡️ 1 of 9 controls in place: 1 failed, 7 unknown"
                      " · 1 admin, 1 outside writer · signed by evd-scan-prod-v3", output)


class VerificationTest(unittest.TestCase):
    """The kit's own RSA verifier agrees with openssl."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="evidence-rsa-"))
        cls.addClassCleanup(shutil.rmtree, cls.dir, ignore_errors=True)
        cls.key = cls.dir / "key.pem"
        openssl("genrsa", "-out", str(cls.key), "2048")
        cls.public = verification.load_public_key(openssl("rsa", "-in", str(cls.key), "-pubout").stdout.decode())

    def sign(self, data, *sigopts):
        args = ["dgst", "-sha256", "-sign", str(self.key)]
        for option in sigopts:
            args += ["-sigopt", option]
        return openssl(*args, data=data).stdout

    def test_pkcs1v15_and_pss_signatures_verify(self):
        data = b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
        cases = [((), False), (("rsa_padding_mode:pss", "rsa_pss_saltlen:32"), True),
                 (("rsa_padding_mode:pss", "rsa_pss_saltlen:0"), True)]
        for sigopts, pss in cases:
            signature = self.sign(data, *sigopts)
            self.assertTrue(verification.signature_matches(self.public, data, signature, pss), sigopts)
            self.assertFalse(verification.signature_matches(self.public, data + b" ", signature, pss), sigopts)
            self.assertFalse(verification.signature_matches(self.public, data, signature, not pss), sigopts)
            flipped = bytes([signature[-1] ^ 1]) + signature[:-1]
            self.assertFalse(verification.signature_matches(self.public, data, flipped, pss), sigopts)

    def test_only_rsa_public_keys_in_pem_are_read(self):
        with self.assertRaises(EvidenceError):
            verification.load_public_key(self.key.read_text())     # a private key
        ec = openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout").stdout
        ec_public = openssl("ec", "-pubout", data=ec).stdout.decode()
        with self.assertRaises(EvidenceError):
            verification.load_public_key(ec_public)


class DisplayTest(unittest.TestCase):
    """What a job's log and step summary say about evidence. Squads write some of it, so it is escaped."""

    def report(self, rows, **kwargs):
        summary = Path(tempfile.mkdtemp(prefix="evidence-summary-")) / "summary.md"
        self.addCleanup(shutil.rmtree, summary.parent, ignore_errors=True)
        printed = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summary)}), \
                contextlib.redirect_stdout(printed):
            display.report(rows, "heading", "verified", "signed by", "Signed by", **kwargs)
        return printed.getvalue(), summary.read_text()

    def test_each_type_says_what_it_found_in_one_line(self):
        expected = {
            "secret-detection/v1/examples/pass.json": "🔑 no secrets found",
            "secret-detection/v1/examples/fail.json": "🔑 2 secrets found: 2 unverified",
            "sca/v2/examples/pass.json": "🐞 no known vulnerabilities",
            "sca/v2/examples/fail.json": "🐞 13 vulnerabilities: 2 critical, 2 high, 9 medium (fails on high)",
            "test-results/v1/examples/pass.json": "🧪 4 tests: 4 passed",
            "test-results/v1/examples/fail.json": "🧪 8 tests: 5 passed, 1 failed, 1 errored, 1 skipped, 1 flaky",
            "provenance/v1/examples/hello-maven.json":
                "🏗️ hello-maven.yml on refs/heads/main, commit 3affa072b111, run 44001716002 attempt 1",
            "peer-approval/v1/examples/pass.json": "👥 1 approval on pull request #7",
            "peer-approval/v1/examples/fail-no-pull-request.json": "👥 no pull request for this commit",
            "code-quality-gate/v1/examples/fail.json": "📏 quality gate ERROR: new_coverage",
            "custom/v1/examples/load-test.json": "📝 1 claim by acme-bank/payments: loadTest",
            "provenance-attestation/v1/examples/gh-release.json":
                "🪪 1 GitHub attestation verified: signed by deployment.yml on refs/heads/trunk, logged by rekor.sigstore.dev",
            "provenance-attestation/v1/examples/private-repository.json": "🪪 GitHub holds no attestation for these bytes",
            "repository-controls/v1/examples/pass.json": "🛡️ 9 of 9 controls in place · 1 admin, 1 outside writer",
            "repository-controls/v1/examples/fail-private-free.json":
                "🛡️ 1 of 9 controls in place: 1 failed, 7 unknown · 1 admin, 1 outside writer",
        }
        for example, line in expected.items():
            with self.subTest(example):
                type_id = example.split("/", 1)[0]
                predicate = json.loads((EVIDENCE / "collectors" / example).read_text())
                self.assertEqual(display.facts(type_id, predicate), line)

    def test_a_shape_it_does_not_know_shows_the_summary_counts(self):
        self.assertEqual(display.facts("new-type", {"summary": {"checked": 3, "skipped": 1, "complete": True}}),
                         "3 checked, 1 skipped")
        self.assertEqual(display.facts("provenance", {"buildDefinition": {}}), "")

    def test_what_squads_wrote_cannot_break_the_table_or_add_markup(self):
        claims = {"a | b <img src=x onerror=alert(1)> [link](https://evil.example)": 1}
        rows = [{"type": "custom", "version": "v1", "status": "verified", "result": "n/a", "detail": "key`|`id",
                 "predicate": {"declaredBy": "squad", "claims": claims}},
                {"type": "sca", "version": "", "status": "error", "result": "n/a", "detail": "<b>|</b>\nsecond line"}]
        _, summary = self.report(rows)
        table = [line for line in summary.splitlines() if line.startswith(("| ✅", "| ❌"))]
        self.assertEqual(len(table), 2)
        for line in table:
            self.assertEqual(len(re.findall(r"(?<!\\)\|", line)), 6, line)   # five columns, no more
        # Escaped with a backslash, they show as text.
        self.assertNotRegex(summary, r"(?<!\\)<(img|b|/b)[ >]")
        self.assertNotRegex(summary, r"(?<!\\)\[link")
        self.assertIn(r"\<img src=x onerror=alert(1)\>", summary)

    def test_a_verified_statement_is_folded_and_cut_when_it_is_large(self):
        predicate = {"result": "fail", "note": "```", "findings": [{"id": f"CVE-2026-{n:05}"} for n in range(5000)]}
        statement = {"predicateType": "https://example/sca/v2", "predicate": predicate,
                     "subject": [{"name": "app.jar", "digest": {"sha256": "0" * 64}}]}
        rows = [{"type": "sca", "version": "v2", "status": "verified", "result": "fail", "detail": "evd-scan-lab-v1",
                 "predicate": predicate, "statement": statement}]
        printed, summary = self.report(rows, subject=("app.jar", "0" * 64), statements=True)
        self.assertIn("<details><summary>✅ <code>sca</code> v2 · 🔴 fail", summary)
        self.assertIn("\n````json\n", summary)      # longer than any backtick run in the predicate
        self.assertIn("Cut at 20,000 characters", summary)
        self.assertLess(len(summary), display.STATEMENT_LIMIT + 2000)
        self.assertIn("::group::🧾 sca v2: the verified statement", printed)

    def test_errors_are_annotations_encoded_as_github_reads_them(self):
        printed = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(printed):
            display.announce("error", "50% done:\n then, stopped", title="sca v2: scan, failed")
        self.assertEqual(printed.getvalue(), "::error title=sca v2%3A scan%2C failed::50%25 done: then, stopped\n")


class WorkflowTest(unittest.TestCase):
    """The reusable workflow keeps scanners away from the signing token, and pins what the evidence is about."""

    WORKFLOWS = REPO_ROOT / ".github" / "workflows"
    WORKFLOW = WORKFLOWS / "evidence.yml"

    def setUp(self):
        self.runner_temp = Path(tempfile.mkdtemp(prefix="evidence-runner-"))
        self.addCleanup(shutil.rmtree, self.runner_temp, ignore_errors=True)

    @classmethod
    def jobs(cls):
        """Each job's lines in evidence.yml, by job id. Enough YAML for these checks, without a parser."""
        text = cls.WORKFLOW.read_text().split("\njobs:\n", 1)[1]
        return {match[1]: match[2] for match in re.finditer(r"(?m)^  ([a-z-]+):\n((?:(?:    .*)?\n)*)", text)}

    @classmethod
    def step(cls, job, name):
        """A step's lines, from its '- name:' to the next step."""
        return cls.jobs()[job].split(f"      - name: {name}\n", 1)[1].split("\n      - ", 1)[0]

    def run_step(self, job, name, **env):
        """Run a step's script with bash as the runner would, python3 replaced by a recorder of its arguments.

        Returns (exit code, output, the step's outputs, python3's arguments or None).
        """
        script = []
        for line in self.step(job, name).split("        run: |\n", 1)[1].splitlines():
            if line.strip() and not line.startswith(" " * 10):
                break                       # a comment that heads the next step
            script.append(line[10:])
        script = "\n".join(script)
        recorder = self.runner_temp / "bin" / "python3"
        recorder.parent.mkdir(exist_ok=True)
        recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >"$RUNNER_TEMP/python3-args"\n')
        recorder.chmod(0o755)
        outputs = self.runner_temp / "github-output"
        outputs.write_text("")
        (self.runner_temp / "python3-args").unlink(missing_ok=True)
        done = subprocess.run(["bash", "-e", "-c", script], capture_output=True, text=True, cwd=self.runner_temp, env={
            "PATH": f"{recorder.parent}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_OUTPUT": str(outputs), "GITHUB_WORKSPACE": str(self.runner_temp),
            "GITHUB_STEP_SUMMARY": str(self.runner_temp / "step-summary"), **env})
        recorded = self.runner_temp / "python3-args"
        return (done.returncode, done.stdout + done.stderr,
                dict(line.split("=", 1) for line in outputs.read_text().splitlines()),
                recorded.read_text().splitlines() if recorded.exists() else None)

    def test_no_job_that_runs_a_collector_can_request_an_id_token(self):
        jobs = self.jobs()
        self.assertEqual(sorted(jobs), ["attest", "collect", "read-controls", "sign"])
        self.assertNotIn("id-token", jobs["collect"])
        self.assertIn("id-token: write", jobs["sign"])
        self.assertIn("needs: collect", jobs["sign"])
        self.assertIn("args=(collect ", jobs["collect"])
        self.assertIn("args=(sign ", jobs["sign"])
        self.assertNotIn("args=(sign ", jobs["collect"])
        self.assertNotIn("install-scanners", jobs["sign"])
        # attest holds a token too, for GitHub's Sigstore: it runs GitHub's attest action and nothing of the kit's.
        self.assertIn("id-token: write\n      attestations: write", jobs["attest"])
        self.assertIn("if: inputs.type == 'provenance-attestation'", jobs["attest"])
        self.assertIn("uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
                      jobs["attest"])
        for kit in ("cli.py", "install-scanners", ".evidence-kit", "actions/checkout"):
            self.assertNotIn(kit, jobs["attest"])
        # read-controls calls repository-snapshot.yml, the one workflow github-sts gives a token to read the
        # controls (tests/test_snapshot.py checks that), and passes it nothing of the caller's.
        self.assertIn("uses: ./.github/workflows/repository-snapshot.yml", jobs["read-controls"])
        self.assertIn("id-token: write", jobs["read-controls"])
        self.assertIn("if: inputs.type == 'repository-controls'", jobs["read-controls"])
        for other in ("params", "source-artifact", "subject-artifact", "check:"):
            self.assertNotIn(other, jobs["read-controls"])

    def test_collect_waits_for_the_attestation_and_sign_for_collect(self):
        jobs = self.jobs()
        self.assertIn("needs: [attest, read-controls]", jobs["collect"])
        for job in ("attest", "read-controls"):
            self.assertIn(f"(needs.{job}.result == 'success' || needs.{job}.result == 'skipped')", jobs["collect"])
        self.assertIn("attestations: read", jobs["collect"])
        # The snapshot, like the predicate, travels by the id its own upload returned, never by name.
        reusable = (self.WORKFLOWS / "repository-snapshot.yml").read_text()
        self.assertIn("value: ${{ jobs.snapshot.outputs.snapshot-id }}", reusable)
        self.assertIn("snapshot-id: ${{ steps.hand-off.outputs.artifact-id }}", reusable)
        download = self.step("collect", "📸 Download the controls snapshot")
        self.assertIn("artifact-ids: ${{ needs.read-controls.outputs.snapshot-id }}", download)
        self.assertNotIn("name:", download)

    def test_github_attests_the_file_the_platform_hashed(self):
        subject = self.runner_temp / "subject"
        subject.mkdir()
        (subject / "hello-maven.jar").write_bytes(b"jar")
        code, output, outputs, _ = self.run_step("attest", "🎯 Hash it", EVD_IN_SUBJECT_ARTIFACT="hello-maven-jar")
        self.assertEqual((code, outputs["sha256"]), (0, hashlib.sha256(b"jar").hexdigest()), output)
        self.assertIn("subject-digest: sha256:${{ steps.subject.outputs.sha256 }}",
                      self.step("attest", "🪪 Have GitHub attest its build provenance"))

        code, output, _, _ = self.run_step("attest", "🎯 Hash it", EVD_IN_SUBJECT_ARTIFACT="")
        self.assertEqual(code, 1, output)
        self.assertIn("provenance-attestation needs subject-artifact", output)
        (subject / "notes.txt").write_text("and something else")
        code, output, _, _ = self.run_step("attest", "🎯 Hash it", EVD_IN_SUBJECT_ARTIFACT="hello-maven-jar")
        self.assertEqual(code, 1, output)
        self.assertIn("must hold exactly one file, the artifact, not 2", output)

    def test_the_collect_job_writes_scanner_data_to_the_work_volume(self):
        jobs = self.jobs()
        self.assertIn("GRYPE_DB_CACHE_DIR: ${{ runner.temp }}/grype-db", jobs["collect"])
        self.assertIn("TMPDIR: ${{ runner.temp }}", jobs["collect"])

    def test_the_sign_job_takes_what_collect_uploaded_not_any_artifact_with_that_name(self):
        """A caller job of the same run could upload its own evidence-predicates before collect runs."""
        jobs = self.jobs()
        self.assertIn("predicates-id: ${{ steps.hand-off.outputs.artifact-id }}", jobs["collect"])
        self.assertIn("id: hand-off", self.step("collect", "📤 Hand the predicate to the sign job"))
        download = self.step("sign", "📥 Download the predicate")
        self.assertIn("artifact-ids: ${{ needs.collect.outputs.predicates-id }}", download)
        self.assertNotIn("name:", download)
        # An empty id would make download-artifact take every artifact of the run. The status is explicit:
        # the default success() would skip sign whenever attest was skipped.
        self.assertIn("if: ${{ !cancelled() && needs.collect.result == 'success'"
                      " && needs.collect.outputs.predicates-id != '' }}", jobs["sign"])
        self.assertIn("EVD_IN_SHA256: ${{ needs.collect.outputs.subject-sha256 }}", jobs["sign"])

    def test_the_platform_hashes_the_artifact_itself(self):
        subject = self.runner_temp / "subject"
        subject.mkdir()
        (subject / "hello-maven.jar").write_bytes(b"jar")
        sha256 = hashlib.sha256(b"jar").hexdigest()
        pin = dict(EVD_IN_TYPE="provenance", EVD_IN_SHA256="", EVD_IN_SUBJECT_ARTIFACT="hello-maven-jar",
                   EVD_IN_SUBJECT="lab/hello|<b>`x`</b>.jar")

        code, output, outputs, _ = self.run_step("collect", "🎯 Pin the subject", **pin)
        self.assertEqual(code, 0, output)
        self.assertEqual((outputs["sha256"], outputs["file"]), (sha256, str(subject / "hello-maven.jar")))
        self.assertIn(f"🔒 SHA-256 computed here, from the downloaded file: {sha256}", output)
        summary = (self.runner_temp / "step-summary").read_text()
        self.assertIn(f"| 🔒 SHA-256 | `{sha256}`, computed here, from the downloaded file |", summary)
        self.assertIn("| 📦 Artifact | `hello-maven.jar`, 3 bytes, from the artifact `hello-maven-jar` of this run |", summary)
        self.assertIn("| 🏷️ Name | `lab/hellobx/b.jar` |", summary)   # what the caller named loses its markup
        self.assertIn("| 📋 Type | `provenance` |", summary)

        code, output, _, _ = self.run_step("collect", "🎯 Pin the subject", **{**pin, "EVD_IN_SHA256": "1" * 64})
        self.assertEqual(code, 1, output)
        self.assertIn(f"holds a file with SHA-256 {sha256}", output)

        (subject / "notes.txt").write_text("and something else")
        code, output, _, _ = self.run_step("collect", "🎯 Pin the subject", **pin)
        self.assertEqual(code, 1, output)
        self.assertIn("must hold exactly one file, the artifact, not 2", output)

    def test_provenance_needs_an_artifact_the_platform_downloaded(self):
        pin = dict(EVD_IN_TYPE="provenance", EVD_IN_SHA256="1" * 64, EVD_IN_SUBJECT_ARTIFACT="", EVD_IN_SUBJECT="app")
        code, output, _, _ = self.run_step("collect", "🎯 Pin the subject", **pin)
        self.assertEqual(code, 1, output)
        self.assertIn("provenance needs subject-artifact", output)
        code, output, outputs, _ = self.run_step("collect", "🎯 Pin the subject", **{**pin, "EVD_IN_TYPE": "sca"})
        self.assertEqual((code, outputs.get("sha256")), (0, "1" * 64), output)
        code, output, _, _ = self.run_step("collect", "🎯 Pin the subject",
                                           **{**pin, "EVD_IN_TYPE": "provenance-attestation"})
        self.assertEqual(code, 1, output)
        self.assertIn("provenance-attestation needs subject-artifact", output)

    def test_each_call_collects_and_signs_one_type(self):
        pin = dict(EVD_IN_SHA256="1" * 64, EVD_IN_SUBJECT_ARTIFACT="", EVD_IN_SUBJECT="app")
        for given in ("sca,provenance", "sca provenance", "", "SCA"):
            code, output, _, _ = self.run_step("collect", "🎯 Pin the subject", EVD_IN_TYPE=given, **pin)
            self.assertEqual(code, 1, given)
            self.assertIn("pass one evidence type id, and call evidence.yml once per type", output)
        # Each call's artifacts carry its type, so the calls of one run never overwrite each other's.
        self.assertIn("name: evidence-predicates-${{ inputs.type }}",
                      self.step("collect", "📤 Hand the predicate to the sign job"))
        self.assertIn("name: evidence-envelopes-${{ inputs.type }}", self.step("sign", "📤 Upload the signed envelope"))

    def test_callers_call_evidence_once_per_type_and_verify_them_all(self):
        for name in ("hello-maven", "hello-python", "hello-node", "demo"):
            workflow = (self.WORKFLOWS / f"{name}.yml").read_text()
            call = workflow.split("\n  evidence:\n", 1)[1].split("\n  verify:\n", 1)[0]
            self.assertIn("fail-fast: false", call, name)
            self.assertIn("type: ${{ matrix.type }}", call, name)
            self.assertNotIn("types:", call, name)
            # GitHub checks a called workflow's permissions before any job runs: attest's included.
            self.assertIn("id-token: write\n      attestations: write", call, name)
            self.assertIn("pattern: evidence-envelopes-*\n          merge-multiple: true", workflow, name)

    def test_each_type_installs_only_the_scanner_it_calls(self):
        installer = self.runner_temp / ".evidence-kit" / "scripts" / "install-scanners.sh"
        installer.parent.mkdir(parents=True)
        # Records what it was asked for, and installs stand-ins that answer --version as the real ones do.
        installer.write_text('#!/bin/sh\necho "$@" >>"$RUNNER_TEMP/installed"\nmkdir -p "$1"\n'
                             'printf \'#!/bin/sh\\necho trufflehog 3.99.9\\n\' >"$1/trufflehog"\n'
                             'printf \'#!/bin/sh\\necho "Application: grype"\\necho "Version: 0.121.0"\\n\' >"$1/grype"\n'
                             'printf \'#!/bin/sh\\necho "gh version 2.102.0 (2026-09-30)"\\necho https://github.com\\n\' >"$1/gh"\n'
                             'chmod 755 "$1"/*\n')
        installer.chmod(0o755)
        installed = self.runner_temp / "installed"
        bin_dir = self.runner_temp / "scanners" / "bin"
        summary = self.runner_temp / "step-summary"
        for type_id, tool, role, shown in (("secret-detection", "trufflehog", "Scanner", "TruffleHog 3.99.9"),
                                           ("sca", "grype", "Scanner", "Grype 0.121.0"),
                                           ("provenance-attestation", "gh", "Verifier", "gh 2.102.0")):
            installed.unlink(missing_ok=True)
            summary.unlink(missing_ok=True)
            code, output, _, _ = self.run_step("collect", "🧰 Install the tool the collector calls", EVD_IN_TYPE=type_id)
            self.assertEqual(code, 0, output)
            self.assertEqual(installed.read_text(), f"{bin_dir} {tool}\n")
            self.assertIn(f"🧰 {shown}, its archive checked against its pinned SHA-256", output)
            self.assertIn(f"🧰 **{role}** {shown}, its archive", summary.read_text())
        for type_id in ("test-results", "provenance", "peer-approval", "custom"):
            installed.unlink(missing_ok=True)
            code, output, _, _ = self.run_step("collect", "🧰 Install the tool the collector calls", EVD_IN_TYPE=type_id)
            self.assertEqual(code, 0, output)
            self.assertFalse(installed.exists(), type_id)
            self.assertIn(f"🧰 {type_id} calls no tool", output)

    def test_the_collect_step_says_where_the_artifact_and_the_reports_are(self):
        step = dict(EVD_IN_TYPE="sca", EVD_IN_PARAMS="", EVD_IN_SUBJECT_FILE="/work/subject/app.jar",
                    EVD_IN_REPORTS="hello-maven-test-reports")
        code, output, _, args = self.run_step("collect", "🔎 Collect", **step)
        self.assertEqual(code, 0, output)
        self.assertEqual(args[1:4], ["collect", "--types", "sca"])
        self.assertIn("sca-target=file:/work/subject/app.jar", args)
        self.assertFalse(any(arg.startswith("test-reports=") for arg in args))

        # The caller may point sca at something else: the predicate records what was scanned.
        code, output, _, args = self.run_step("collect", "🔎 Collect", **{**step, "EVD_IN_PARAMS": "sca-target=dir:."})
        self.assertEqual(code, 0, output)
        self.assertIn("sca-target=dir:.", args)
        self.assertNotIn("sca-target=file:/work/subject/app.jar", args)

        step["EVD_IN_TYPE"] = "test-results"
        code, output, _, args = self.run_step("collect", "🔎 Collect", **step)
        self.assertEqual(code, 0, output)
        self.assertIn(f"test-reports={self.runner_temp}/reports", args)
        self.assertFalse(any(arg.startswith("sca-target=") for arg in args))
        self.assertIn("if: inputs.reports-artifact != '' && inputs.type == 'test-results'",
                      self.step("collect", "🧪 Download the build's test reports"))

        # But never test-results at files of its choosing, such as a report committed to the repository.
        code, output, _, args = self.run_step("collect", "🔎 Collect", **{**step, "EVD_IN_PARAMS": "test-reports=fake"})
        self.assertEqual((code, args), (1, None), output)
        self.assertIn("test-reports is set by evidence.yml, not by the caller", output)

        code, output, _, args = self.run_step("collect", "🔎 Collect", **{**step, "EVD_IN_REPORTS": ""})
        self.assertEqual((code, args), (1, None), output)
        self.assertIn("test-results needs reports-artifact", output)

        # GitHub's attestation must be of the file the platform downloaded, signed by the platform's workflow.
        step["EVD_IN_TYPE"] = "provenance-attestation"
        code, output, _, args = self.run_step("collect", "🔎 Collect", **step)
        self.assertEqual(code, 0, output)
        self.assertIn("attested-file=/work/subject/app.jar", args)
        self.assertIn("attestation-signer=Depthmark-Lab/test-evidences/.github/workflows/evidence.yml", args)
        for param in ("attested-file=/tmp/other.jar", "attestation-signer=squad/repo/.github/workflows/own.yml",
                      "controls-snapshot=/tmp/made-up.json"):
            code, output, _, args = self.run_step("collect", "🔎 Collect", **{**step, "EVD_IN_PARAMS": param})
            self.assertEqual((code, args), (1, None), output)
            self.assertIn(f"{param.split('=')[0]} is set by evidence.yml, not by the caller", output)

        # repository-controls reads the snapshot read-controls took, where collect downloaded it.
        code, output, _, args = self.run_step("collect", "🔎 Collect", **{**step, "EVD_IN_TYPE": "repository-controls"})
        self.assertEqual(code, 0, output)
        self.assertIn(f"controls-snapshot={self.runner_temp}/controls/repository-controls.json", args)

    def test_the_installed_scanners_are_the_recorded_ones(self):
        script = (REPO_ROOT / "scripts" / "install-scanners.sh").read_text()
        pinned = dict(re.findall(r'(?m)^(TRUFFLEHOG|GRYPE|GH)_VERSION="([^"]+)"', script))
        self.assertEqual({"trufflehog": pinned["TRUFFLEHOG"], "grype": pinned["GRYPE"], "gh": pinned["GH"]},
                         {"trufflehog": SCANNER_VERSIONS["trufflehog"], "grype": SCANNER_VERSIONS["grype"],
                          "gh": SCANNER_VERSIONS["gh"]["version"]})
        self.assertEqual(len(re.findall(r'(?m)^(?:TRUFFLEHOG|GRYPE|GH)_SHA256="[0-9a-f]{64}"$', script)), 3)
        # The recording verified the very archive install-scanners.sh pins.
        self.assertIn(f'GH_SHA256="{SCANNER_VERSIONS["gh"]["sha256"]}"', script)


if __name__ == "__main__":
    unittest.main()
