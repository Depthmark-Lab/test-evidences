# Evidence lab: context for Claude

This repository, `Depthmark-Lab/test-evidences`, runs the evidence signing kit on real infrastructure: the self-hosted runners on the Talos cluster and the homelab Vault, whose Transit engine holds the private keys. The kit itself was designed for a bank in `~/code/evidence-kit-v2` (fake names, `acme-bank`); this is a working copy of `evidence-kit/` from there, adapted to the lab. Port fixes in both directions.

## The rule that always holds: evidence logic never touches JFrog or Vault

Collectors and evidence processing hold the business logic: which facts to gather, how to shape them into a predicate, whether the result is `pass` or `fail`, and whether the predicate matches its schema. They know nothing about where evidence is signed or stored. They hand over a predicate and stop.

- `signing.py` is the only module that talks to Vault or JFrog. `cli.py` is the only place where it meets the evidence logic.
- Collectors, `evidence_sdk.py`, `collection.py`, `schema.py` and `core.py` never import `signing.py`, directly or through another module. Neither does `verification.py`: a verifier needs public keys only. `cli.py check` fails if one does, and CI runs it on every push.
- A collector's secrets reach it as values, through a resolver that `cli.py` supplies: Vault in `run`, the environment in `collect`. The collector cannot tell which.
- `signing.py` never interprets a predicate. With JFrog it only checks that JFrog's statement carries the predicate unchanged; with the file store it builds the same statement itself.
- The catalog is where the two sides meet in data. Only `cli.py` and `signing.py` read `family` and the secret `path`; `verification.py` reads `family` to check which key may sign a type.
- `collect` runs every evidence type with a settings file that has no Vault or JFrog section, and so does `verify`. Tests do exactly that, so the split cannot quietly erode.

Why: evidence types change often and have many owners, while the signing path is the trust boundary and changes rarely. Replacing Vault or JFrog, or running evidence with no backend at all, must not touch a collector.

When you add or change code, keep it on its side. If evidence logic seems to need something from Vault or JFrog, pass the value in from `cli.py` instead.

## How the lab signs

- **Two jobs in `.github/workflows/evidence.yml`.** `collect` runs the collectors and scanners without `id-token` permission. `sign` checks each predicate against its schema and its commit again, then signs. A scanner can therefore never request a signing token. `tests/test_kit.py` (`WorkflowTest`) fails if the collect job gains `id-token` or the sign job installs scanners.
- **Store `file`, no JFrog.** `signing.envelope` builds the in-toto v1 statement JFrog would prepare (subject named by `subject-repo-path`, pinned by SHA-256), signs its DSSE encoding with Transit, and `cli.py` writes `<type>.dsse.json`. The workflow uploads them as the artifact `evidence-envelopes`. The JFrog store is still there and still tested.
- **`verify` plays JFrog's part.** It checks each envelope with the PEM files in `trusted-keys/` only, never asking Vault, and refuses a key whose family or tier does not match the evidence type in the catalog, so the squads' self key cannot vouch for a scan. RSA verification is pure Python and tested against openssl.
- **Predicates go from collect to sign by artifact id**, the one collect's upload returned, never by name: a caller job of the same run could upload its own `evidence-predicates`. `WorkflowTest` checks it.
- **Evidence about the squad's build** (`test-results`, `provenance`) is signed with the `build` family. The squad's job builds and tests with its own flags and uploads the deployable and its JUnit XML; `evidence.yml` takes them as `subject-artifact` and `reports-artifact`. It never runs squad code. With `subject-artifact` it hashes the file itself and binds every statement to that SHA-256, `sca` scans the file (`sca` v2, `file:`), and `provenance` is allowed; without it, `provenance` is refused. A caller's `test-reports` parameter is refused, so `test-results` reads what the build uploaded. `WorkflowTest` runs those step scripts with bash.
- **Standard predicate types.** A catalog entry may map a version to another standard's predicateType (`"predicateTypes": {"v1": "https://slsa.dev/provenance/v1"}`); every other version is `<predicateBase>/<type>/<version>`. `core.predicate_type` and `core.evidence_type` are the two directions, shared by `cli.py` and `verification.py`.
- **Keys:** Transit mount `transit-evidence`, one non-exportable RSA 2048 key per family and tier: `evd-scan-lab`, `evd-approval-lab`, `evd-self-lab`, `evd-build-lab`. The key id is `<key>-v<version>`, plus `;PS256` for PSS.
- **Trust:** Vault JWT roles `evidence-<family>-lab` on the `github-actions` mount bind `job_workflow_ref` to `evidence.yml` on `main`, and `runner_environment` to `self-hosted`. Until the process is hardened, they also accept `feature/vault-transit-signing`, `fix/collect-runner-limits` and `feature/build-evidence`, for end-to-end tests. Each role's policy allows `update` on its own key's sign path and nothing else. Tokens are batch tokens, 10 minutes.

## Where things live

| What | Where |
|---|---|
| Kit, workflows, tests | this repository |
| Vault roles and policies | homelab repository, `vault/jwt/evidence-{scan,approval,self,build}-lab/`, applied by the user with `vault/apply.sh` |
| Transit mount and keys | homelab repository, `vault/transit-evidence/bootstrap.sh`, run once by the user; it also exports the public keys |
| Trusted public keys | `trusted-keys/` here, written by that script and committed |
| Runners | homelab repository, `talos/apps/action-runner-controller-dev/gha-runner-scale-set-lab/`: labels `self-hosted, talos, linux, lab`, runner group `rg-talos-lab`. `lab-k8s` shares the first three labels, so always include `lab` |
| Scanners | `scripts/install-scanners.sh`, pinned by version and SHA-256, no root needed |
| Sample squads | `samples/hello-{maven,python,node}`, built by `.github/workflows/hello-*.yml` with their own toolchains: Temurin 25 and the Maven wrapper, Python 3.14, Node 26. JUnit XML they wrote is recorded in `tests/reports/` |

Writing to Vault is always the user's step. Never print secret values: no `vault kv get` without `-field` piped into a consumer, no `env`.

## Facts measured on the runner image

`ghcr.io/actions/actions-runner:2.338.2` (Ubuntu 24.04) has Python 3.12, openssl, curl, tar, sha256sum and git, and runs as uid 1001 without privilege escalation. In that image, TruffleHog 3.99.9 peaks at about 263 MiB RSS whatever its `--concurrency`, and Grype 0.121.0 at about 375 MiB, because the database is always downloaded fresh on ephemeral runners. The lab runner container is limited to 512Mi, shared with the runner's own processes (35Mi when idle). On the runner at 512Mi, all four default types were collected on 2026-11-17 (run 44001716002), `sca` included. Locally the cold `sca` collector was OOM-killed at 384Mi, so the margin is thin: raising the limit to about 1Gi is worth it, but not required.

Builds on the runner: the image has no Java, Maven, Node, pip or venv, so squad workflows use `setup-java`, `setup-python` and `setup-node`. It has `unzip`, so the Maven wrapper downloads the `.zip` distribution, which is what `distributionSha256Sum` pins. A Maven build with default JVM settings was OOM-killed at 512Mi during the tests (Maven's JVM plus Surefire's fork); with `JAVA_TOOL_OPTIONS=-XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:MaxRAMPercentage=25 -Xss512k` it passed at 512Mi and at 384Mi.

Local memory numbers are pessimistic: the Mac runs the amd64 image under emulation. Through the collector there, TruffleHog was OOM-killed at 512Mi three times in three, after it finished scanning, while the same collector passed at 512Mi on the real runner (run 44001716002). Trust runner numbers over local ones.

Disk: only `/home/runner/_work` is a volume (openebs hostpath, no quota). Everything else the pod writes counts against an ephemeral-storage limit of 4Gi, the buildkit sidecar's limit, which Kubernetes applies to the whole pod. Grype's database takes 3.3 GB, so the collect job sets `GRYPE_DB_CACHE_DIR` and `TMPDIR` under `runner.temp`; the `sca` catalog entry passes `GRYPE_DB_CACHE_DIR` through. Without that, the pod was evicted mid-scan on 2026-11-16 (run 43978188427), and the runner only reports "received a shutdown signal".

## Working on the kit

```
python3 evidence/cli.py check                 # catalog, schemas, examples, lock, store and layering agree
python3 -m unittest discover -s tests -v      # 72 tests against stand-in services, needs openssl and bash
python3 evidence/cli.py list                  # evidence types and their parameters
python3 evidence/cli.py collect --types sca --out /tmp/predicates     # no Vault, no JFrog
python3 evidence/cli.py verify --envelopes /tmp/envelopes --keys trusted-keys
python3 scripts/show-envelopes.py /tmp/envelopes/*.dsse.json      # what they say, after verify
python3 tests/scanners/record.py              # refresh recorded scanner output, needs trufflehog, grype, openssl
```

Python standard library only. Keep it that way in the signing path. Scanners are external programs that collectors call. They are not Python dependencies.

## Not yet verified

Verified on 2026-11-16 against a local `vault server -dev` (2.1.2): `bootstrap.sh` and `apply.sh` with the new roles (both idempotent), login, signing with PKCS#1 v1.5 and PSS, verification by the kit and by openssl, and the refusals (another workflow or branch, a GitHub-hosted runner, the wrong audience, a scan token using the self key, exporting the key). The homelab Vault runs 1.20.4 and was not touched.

On the Talos runners, `ci` passed in runner group `rg-talos-lab` on 2026-11-16. `demo` ran once the same day and the collect job was evicted for disk (see above), so `sign` never reached Vault. On 2026-11-17, `demo` on `fix/collect-runner-limits` (run 44001716002) collected all four types, and the homelab Vault refused GitHub's real OIDC token for each family: "claim job_workflow_ref does not match any associated bound claim values", as it should for that branch. Never run: a successful signature from the runners, and the `hello-*` workflows. The samples were proven end to end on 2026-11-17 with a local Vault 2.1.2 set up by `bootstrap.sh` and `apply.sh` (four families): 12 envelopes verified by the kit and by openssl, the squad workflow's token refused, a changed jar matching none of its evidence. `demo.yml` has only `workflow_dispatch`, so GitHub offers it only once the file is on `main`. Vault trusts `evidence.yml` from `main` and the two test branches above only: on any other branch, `sign` is refused at login.
