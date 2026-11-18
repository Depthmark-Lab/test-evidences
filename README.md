# test-evidences

Generates release evidence on the self-hosted runners of the Talos cluster and signs it with Vault Transit, which holds the private keys. Each piece of evidence becomes a DSSE envelope around an in-toto statement about one artifact, which anyone can check with the public keys in `trusted-keys/`.

It runs the evidence signing kit designed in `~/code/evidence-kit-v2`, adapted to the lab: the homelab Vault instead of Vault Enterprise with Azure managed keys, and envelopes stored as workflow artifacts instead of attached in JFrog.

Three Hello World web services in `samples/` (Maven, Python, Node) show how evidence about a squad's own build, its test results and its provenance, gets signed without the platform ever running the squad's code.

## How it flows

```
demo.yml  build ──► evidence.yml ─────────────────────────────────────────────► demo.yml  verify
          sample      collect                     sign                                    trusted-keys/
          app,        no id-token permission      id-token: write                         only, no Vault
          sha256      scanners + collectors ──►   check schema and commit again
                      predicates (artifact)       Vault JWT login (one per key family)
                                                  Transit signs the DSSE bytes
                                                  envelopes (artifact) ─────────────►
```

- The collect job cannot request an OIDC token, so nothing a scanner runs can log in to Vault.
- Vault trusts only `evidence.yml` on the allowed branches, on a self-hosted runner. Each key family has its own role and may sign with its own key only.
- `verify` refuses a key from the wrong family, so a squad's self-declared `custom` evidence can never pass for a scan.

## Evidence about a squad's build

Scanners can run on the platform: they read files, and no squad code runs. Tests cannot. They need the squad's build, with its toolchain and its flags, and running that build would mean running the squad's code next to the scanners. So the squad's job builds and tests as it always has, and hands `evidence.yml` two artifacts: the deployable, and its JUnit XML reports.

```
hello-<lang>.yml  build ────────────► evidence.yml ─────────────────────────────────────► hello-<lang>.yml  verify
(the squad's)     its toolchain        collect: downloads the artifact, computes its         hashes the artifact
                  and flags            SHA-256 itself, scans it (sca file:), reads the       itself, checks every
                  JUnit XML reports    reports (test-results), reads GitHub's variables      envelope with
                  the deployable       for the run (provenance)                              trusted-keys/ only
                                       sign: scan key, build key
```

| Type | Who established the facts | Key | What the signature means |
|---|---|---|---|
| `secret-detection` | the platform: TruffleHog on the commit's files | `evd-scan-lab` | the platform ran its scanner |
| `sca` v2 | the platform: Grype on the artifact itself, a jar or a bundle with its dependencies | `evd-scan-lab` | the platform scanned these exact bytes |
| `test-results` | the squad's build, read from its JUnit XML | `evd-build-lab` | this run's build reported these results |
| `provenance` | GitHub, through the variables it sets for the run | `evd-build-lab` | this run of this workflow, at this commit, produced these bytes |

- **Attestation.** Each envelope is one: an in-toto statement about the artifact's SHA-256, signed in DSSE by a key only `evidence.yml` can use. The squad's own workflow cannot get a token for any key.
- **Provenance** is SLSA build provenance v1 (`https://slsa.dev/provenance/v1`) with GitHub's own build type, so SLSA tools can read it. `builder.id` is the squad's workflow; the build key's signature says the platform vouches for it.
- **GitHub's artifact attestations** (`actions/attest-build-provenance`) would make the same SLSA statement through Sigstore, but a private repository needs GitHub Enterprise Cloud for them, and Depthmark-Lab is on the Free plan.
- **What the platform cannot see** is whether the reports came from running those tests: a build step could write its own `junit.xml`. Provenance names the workflow file and the commit, so anyone can read what the build did. Policy still catches the usual tricks: `-DskipTests` reports no test and makes `test-results` fail, `testFailureIgnore` hides nothing since the reports list the failures, and a test that passed only on a rerun counts as flaky.
- **Never the squad's paths.** `evidence.yml` refuses a `test-reports` parameter from the caller, so `test-results` reads what the build uploaded, not a report committed to the repository. `provenance` is refused without `subject-artifact`: the platform vouches only for bytes it downloaded and hashed itself.

## Layout

```
.github/workflows/evidence.yml   reusable workflow, the trust boundary: collect, then sign
.github/workflows/demo.yml       builds a sample app, runs evidence.yml on it, verifies the result
.github/workflows/hello-*.yml    a squad's own CI for each sample service: build, evidence.yml, verify
.github/workflows/ci.yml         check and tests on every push
evidence/
  settings.json                  lab: homelab Vault, tier lab, store file
  catalog.json                   the evidence types
  cli.py                         run, collect, sign, verify, list, check, lock: the only place both sides meet
  collection.py                  evidence side: runs a collector, validates its predicate
  signing.py                     signing side: identity, Vault, JFrog, DSSE envelopes
  verification.py                consumer side: checks envelopes with public keys only
  display.py                     what collect, sign and verify print and add to the run's summary page
  core.py, schema.py             shared helpers, JSON Schema subset validator
  evidence_sdk.py                helpers for collectors
  collectors/<type>/<version>/   collect.py, schema.json, examples/
scripts/install-scanners.sh      TruffleHog and Grype, pinned by version and SHA-256
scripts/show-envelopes.py        prints what envelopes say: key id, subject, predicate
samples/hello-{maven,python,node} Hello World web services with unit tests, as squads would write them
trusted-keys/                    public keys from Transit, one per key version
demo/predicate.json              what the demo declares through the custom type
tests/                           77 tests against stand-in services, recorded scanner output and recorded JUnit XML
action.yml, Dockerfile           the one-job and container forms of the kit
```

## One-time setup

Run in this order. The Vault steps need an admin token; the homelab repository holds the Vault side so that changing a workflow here cannot change who Vault trusts.

1. **Vault must be healthy.** On 2026-11-16, `vault-0` and `vault-2` had been sealed for three days and only `vault-1` was serving. Unseal them first.
2. **Transit mount, keys and public keys.** Run it from the root of this repository: the folder is relative to where you run it.
   ```
   ~/code/alexandreodelisle/homelab/vault/transit-evidence/bootstrap.sh trusted-keys
   ```
   Commit the `trusted-keys/*.pub.pem` files it writes, one per key family: scan, approval, self and build. Rerun it when a family is added; it leaves existing keys alone.
3. **JWT roles and policies:**
   ```
   ~/code/alexandreodelisle/homelab/vault/apply.sh evidence-scan-lab evidence-approval-lab evidence-self-lab evidence-build-lab
   ```
4. **Runner group.** `rg-talos-lab` must allow this repository.
5. **Runner memory, recommended.** At 512Mi the `sca` type passed on the runner, with little to spare: locally it was OOM-killed at 384Mi. Raise the runner container limit of `gha-runner-scale-set-lab` to about 1Gi for headroom. Measured in the runner image: Grype about 374 MiB while it downloads its database, which it does on every run since the runners are ephemeral, and TruffleHog about 250 MiB, next to the runner's own processes. That is with `--local-dev`, which the collector passes: without it TruffleHog runs as two processes of that size, even with `--no-update`, and at 512Mi the kernel killed the whole runner.

Disk needs nothing: only `/home/runner/_work` is a volume, and the pod may write just 4Gi anywhere else, so `evidence.yml` keeps Grype's 3.3 GB database and temporary files under `runner.temp`.

## Running it

Run the `demo` workflow from the Actions tab, or `gh workflow run demo.yml --ref <branch>`. GitHub offers a workflow that has only `workflow_dispatch` once its file is on `main`; until then `gh` answers that no workflow is named `demo.yml`. With `--ref`, the run uses the branch's version of the file. With the default types it produces four envelopes:

| Type | Signed with | Expected result on the sample |
|---|---|---|
| `secret-detection` | `evd-scan-lab` | `fail`: a Slack webhook and a private key, both random |
| `sca` | `evd-scan-lab` | `fail`: 2 critical, 2 high, 9 medium in old requests, PyYAML and Jinja2 |
| `peer-approval` | `evd-approval-lab` | `fail` unless the commit came from an approved pull request |
| `custom` | `evd-self-lab` | no result: the squad declared it, nobody verified it |

`fail` is recorded and signed; it fails the run only with `enforce`. The envelopes are in the run's `evidence-envelopes` artifact.

The sample squads run on their own: `hello-maven`, `hello-python` and `hello-node` start on a push that changes their sample or their workflow, and from the Actions tab once they are on `main`. Each produces four envelopes about its deployable:

| Type | Signed with | Expected result |
|---|---|---|
| `secret-detection` | `evd-scan-lab` | `pass` |
| `sca` | `evd-scan-lab` | `pass`, target `file:` the jar or bundle: current Jackson, Flask and Express have no known vulnerability |
| `test-results` | `evd-build-lab` | `pass`: 4 Surefire tests, 3 pytest tests, 3 Node tests |
| `provenance` | `evd-build-lab` | no result: SLSA provenance naming the workflow, commit and run |

To check envelopes yourself:

```
gh run download <run id> -n evidence-envelopes -D /tmp/envelopes
python3 evidence/cli.py verify --envelopes /tmp/envelopes --keys trusted-keys
python3 scripts/show-envelopes.py /tmp/envelopes/*.dsse.json
```

## What was tested

- The 77 tests: the kit against stand-in GitHub, Vault, JFrog and SonarQube, scanners replaying recorded output, JUnit XML that Surefire, pytest and Node wrote for the samples (passing, failing, erroring, skipped and flaky), both stores, the collect and sign split, verification against openssl, the step summaries (one line of facts per type, and Markdown escaped where squads wrote the text), and `evidence.yml`: its shape, and its subject and parameter steps run with bash.
- In the runner image `ghcr.io/actions/actions-runner:2.338.2`, capped at 512Mi and 1 CPU: `install-scanners.sh`, and `collect` with the real TruffleHog and Grype on the sample app. With the work directory on a volume, as on the runners, the cold `sca` run wrote 3.3 GB there and 196 KB to the container itself. At 384Mi it was OOM-killed.
- Against a local `vault server -dev`: `bootstrap.sh` and `apply.sh` with the new roles, JWT login with GitHub-shaped tokens, signing with PKCS#1 v1.5 and PSS, `verify`, openssl, and every refusal: another workflow or branch, a GitHub-hosted runner, the wrong audience, a scan token using the self key, exporting a key.
- The samples end to end, on 2026-11-17: each built and tested with its real toolchain, then `collect` in the runner image with the real TruffleHog and Grype on the jar and the bundles, then `sign` through a local Vault set up by `bootstrap.sh` and `apply.sh` with the build family, then `verify` and openssl: 12 envelopes, each with its family's key. The squad's own workflow was refused a token, and a jar changed by one byte matched none of its evidence. The Maven jar is reproducible: the same SHA-256 from two different builds, and from the runner.

On the Talos runners: `ci` passed on `gha-runner-scale-set-lab` in `rg-talos-lab` on 2026-11-16, so the runner group admits this repository, and `demo` collected all four types at 512Mi on 2026-11-17 before Vault refused its branch. The `hello-*` workflows first ran on 2026-11-17 (PR #3): `setup-java` and `setup-python` worked and the Maven and Python builds passed, `setup-node` failed for Node 26 (the image lacks `libatomic.so.1`, so the sample now uses Node 24), and TruffleHog's two processes got both collect runners OOM-killed (the collector now passes `--local-dev`). The second push the same day (commit e087073, runs 44203875582, 44203875573 and 44203875527) built, collected and signed all three samples on the runners: 12 envelopes, signed by Vault Transit with the scan and build keys. Their `verify` jobs failed only because `trusted-keys/evd-build-lab-v1.pub.pem` was not committed yet: `bootstrap.sh` had written it outside the worktree. With that file, all 12 verify, and openssl agrees.

## Differences from the bank kit

- Store `file` instead of JFrog, and `verify` instead of JFrog's check. The JFrog store is unchanged and still tested.
- Transit generates the keys itself instead of using Azure Key Vault managed keys, which need Vault Enterprise.
- Vault trusts branch refs, not `v*` tags: there is no release workflow here yet, so release-please, `RELEASING.md` and the version tests were left out.
- The kit is checked out from this repository at the caller's commit instead of being pinned as an action, so only workflows in this repository can call `evidence.yml`.
