"""Tests for the evidence kit. Standard library plus the openssl command.

Run from the repository root:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = REPO_ROOT / "evidence"
sys.path.insert(0, str(EVIDENCE))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cli  # noqa: E402
import collection  # noqa: E402
import schema  # noqa: E402
import signing  # noqa: E402
import verification  # noqa: E402
from core import EvidenceError, pae  # noqa: E402
from mock_services import REPO, SCANNERS, SHA, Services, fake_scanner, openssl  # noqa: E402

SUBJECT = "apps-generic-local/payments/1.0/payments.jar"
SUBJECT_SHA = "0" * 64
ALL_TYPES = "peer-approval,code-quality-gate,custom"

# Recorded from the real scanners by scanners/record.py.
TRUFFLEHOG_OUTPUT = (SCANNERS / "trufflehog.jsonl").read_text()
GRYPE_OUTPUT = (SCANNERS / "grype.json").read_text()
SCANNER_VERSIONS = json.loads((SCANNERS / "versions.json").read_text())
REMOVED_SECRET = "SECRET-REMOVED-BY-RECORD-PY"


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
        self.assertIn("| peer-approval | v1 | attached | pass |", summary)

    def test_one_login_per_key_family_and_one_jfrog_exchange(self):
        self.run_all()
        self.assertEqual(sorted(role for role, _ in self.services.vault_logins),
                         ["evidence-approval-prod", "evidence-scan-prod", "evidence-self-prod"])
        self.assertEqual({jwt for _, jwt in self.services.vault_logins}, {"jwt-for-https://vault.acme-bank.example"})
        self.assertEqual(self.services.jfrog_exchanges, ["jwt-for-jfrog-evidence"])

    def test_secrets_are_masked_and_never_printed(self):
        _, output, _ = self.run_all()
        self.assertIn("::add-mask::squ_secret", output)
        self.assertIn("::add-mask::jf.token", output)
        leaks = [line for line in output.splitlines()
                 if ("squ_secret" in line or "hvs." in line or "jf.token" in line) and not line.startswith("::add-mask::")]
        self.assertEqual(leaks, [])

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
        self.assertIn("| code-quality-gate | v1 | attached | fail |", summary)

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
        self.assertIn("| code-quality-gate | v1 | error |", summary)

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
        code, output, _ = self.collect("secret-detection")
        self.assertEqual(code, 0, output)
        predicate = self.collected("secret-detection")
        self.assertEqual(predicate["result"], "fail")
        self.assertEqual(predicate["scanner"], {"name": "trufflehog", "version": SCANNER_VERSIONS["trufflehog"]})
        self.assertEqual(predicate["summary"], {"total": 2, "verified": 0, "unverified": 2, "unknown": 0})
        self.assertEqual([(f["detector"], f["file"], f["line"]) for f in predicate["findings"]],
                         [("SlackWebhook", "config/settings.py", 1), ("PrivateKey", "deploy-key.pem", 1)])
        # The recording holds this marker wherever TruffleHog printed the secret.
        self.assertIn(REMOVED_SECRET, TRUFFLEHOG_OUTPUT)
        self.assertNotIn(REMOVED_SECRET, json.dumps(predicate) + output)
        argv = self.calls(calls)[-1]["argv"]
        self.assertEqual(argv[:4] + argv[6:], ["filesystem", ".", "--json", "--no-update", "--no-verification"])
        self.assertEqual(argv[4], "--exclude-paths")   # .git, so its objects are not reported a second time

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
        cases = [("sca-target=registry:alpine:3.18", "sca-target must be dir:<path> or sbom:<file>"),
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


class FileStoreTest(Kit):
    """Collect in one job, sign with Vault Transit in another, and store DSSE envelopes as files: no JFrog."""

    TYPES = "peer-approval,custom"

    def setUp(self):
        super().setUp()
        self.envelopes = self.tmp / "envelopes"

    def file_settings(self, **overrides):
        return self.services.settings(store="file", **overrides)

    def sign(self, types=TYPES, *extra, settings=None, **kwargs):
        return self.run_cli("sign", "--types", types, "--predicates", str(self.out), "--subject-repo-path", SUBJECT,
                            "--subject-sha256", SUBJECT_SHA, "--out", str(self.envelopes), *extra,
                            settings=settings or self.file_settings(), **kwargs)

    def envelope(self, type_id):
        return json.loads((self.envelopes / f"{type_id}.dsse.json").read_text())

    def verify(self, *extra, keys=None, **kwargs):
        keys = keys or self.trusted_keys("evd-approval-prod-v3", "evd-scan-prod-v3", "evd-self-prod-v3")
        return self.run_cli("verify", "--envelopes", str(self.envelopes), "--keys", str(keys), *extra,
                            settings=self.file_settings(), **kwargs)

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
        self.assertIn("| peer-approval | v1 | signed | pass | evd-approval-prod-v3 |", summary)
        self.assertEqual(sorted(self.services.sign_calls), ["evd-approval-prod", "evd-self-prod"])
        self.assertEqual((self.services.jfrog_exchanges, self.services.deployed), ([], []))

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
        self.assertIn("| custom | v1 | verified | n/a | evd-self-prod-v3 |", summary)
        self.assertIn("| peer-approval | v1 | verified | pass | evd-approval-prod-v3 |", summary)

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
        key_id, envelope = signing.envelope(self.collected("peer-approval"), kind, "self", SUBJECT, SUBJECT_SHA,
                                            signing.Vault(settings))
        self.assertEqual(key_id, "evd-self-prod-v3")
        keys = verification.load_trusted_keys(self.trusted_keys("evd-self-prod-v3"))
        with self.assertRaises(EvidenceError) as caught:
            verification.verify(envelope, keys, cli.load_catalog(), settings)
        self.assertIn("peer-approval evidence must be signed with an evd-approval-prod key, not 'evd-self-prod-v3'",
                      str(caught.exception))


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


class WorkflowTest(unittest.TestCase):
    """The reusable workflow keeps scanners away from the signing token."""

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "evidence.yml"

    @classmethod
    def jobs(cls):
        """Each job's lines in evidence.yml, by job id. Enough YAML for these checks, without a parser."""
        text = cls.WORKFLOW.read_text().split("\njobs:\n", 1)[1]
        return {match[1]: match[2] for match in re.finditer(r"(?m)^  ([a-z-]+):\n((?:(?:    .*)?\n)*)", text)}

    def test_only_the_sign_job_can_request_an_id_token(self):
        jobs = self.jobs()
        self.assertEqual(sorted(jobs), ["collect", "sign"])
        self.assertNotIn("id-token", jobs["collect"])
        self.assertIn("id-token: write", jobs["sign"])
        self.assertIn("needs: collect", jobs["sign"])
        self.assertIn("args=(collect ", jobs["collect"])
        self.assertIn("args=(sign ", jobs["sign"])
        self.assertNotIn("args=(sign ", jobs["collect"])
        self.assertNotIn("install-scanners", jobs["sign"])

    def test_the_collect_job_writes_scanner_data_to_the_work_volume(self):
        jobs = self.jobs()
        self.assertIn("GRYPE_DB_CACHE_DIR: ${{ runner.temp }}/grype-db", jobs["collect"])
        self.assertIn("TMPDIR: ${{ runner.temp }}", jobs["collect"])

    def test_the_installed_scanners_are_the_recorded_ones(self):
        script = (REPO_ROOT / "scripts" / "install-scanners.sh").read_text()
        pinned = dict(re.findall(r'(?m)^(TRUFFLEHOG|GRYPE)_VERSION="([^"]+)"', script))
        self.assertEqual({"trufflehog": pinned["TRUFFLEHOG"], "grype": pinned["GRYPE"]},
                         {name: SCANNER_VERSIONS[name] for name in ("trufflehog", "grype")})
        self.assertEqual(len(re.findall(r'(?m)^(?:TRUFFLEHOG|GRYPE)_SHA256="[0-9a-f]{64}"$', script)), 2)


if __name__ == "__main__":
    unittest.main()
