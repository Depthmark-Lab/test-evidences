# test-evidences

Generates release evidence on the self-hosted runners of the Talos cluster and signs it with Vault Transit, which holds the private keys. Each piece of evidence becomes a DSSE envelope around an in-toto statement about one artifact, which anyone can check with the public keys in `trusted-keys/`.

It runs the evidence signing kit designed in `~/code/evidence-kit-v2`, adapted to the lab: the homelab Vault instead of Vault Enterprise with Azure managed keys, and envelopes stored as workflow artifacts instead of attached in JFrog.

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

## Layout

```
.github/workflows/evidence.yml   reusable workflow, the trust boundary: collect, then sign
.github/workflows/demo.yml       builds a sample app, runs evidence.yml on it, verifies the result
.github/workflows/ci.yml         check and tests on every push
evidence/
  settings.json                  lab: homelab Vault, tier lab, store file
  catalog.json                   the evidence types
  cli.py                         run, collect, sign, verify, list, check, lock: the only place both sides meet
  collection.py                  evidence side: runs a collector, validates its predicate
  signing.py                     signing side: identity, Vault, JFrog, DSSE envelopes
  verification.py                consumer side: checks envelopes with public keys only
  core.py, schema.py             shared helpers, JSON Schema subset validator
  evidence_sdk.py                helpers for collectors
  collectors/<type>/<version>/   collect.py, schema.json, examples/
scripts/install-scanners.sh      TruffleHog and Grype, pinned by version and SHA-256
trusted-keys/                    public keys from Transit, one per key version
demo/predicate.json              what the demo declares through the custom type
tests/                           55 tests against stand-in services and recorded scanner output
action.yml, Dockerfile           the one-job and container forms of the kit
```

## One-time setup

Run in this order. The Vault steps need an admin token; the homelab repository holds the Vault side so that changing a workflow here cannot change who Vault trusts.

1. **Vault must be healthy.** On 2026-11-16, `vault-0` and `vault-2` had been sealed for three days and only `vault-1` was serving. Unseal them first.
2. **Transit mount, keys and public keys:**
   ```
   ~/code/alexandreodelisle/homelab/vault/transit-evidence/bootstrap.sh trusted-keys
   ```
   Commit the three `trusted-keys/*.pub.pem` files it writes.
3. **JWT roles and policies:**
   ```
   ~/code/alexandreodelisle/homelab/vault/apply.sh evidence-scan-lab evidence-approval-lab evidence-self-lab
   ```
4. **Runner group.** `rg-talos-lab` must allow this repository.
5. **Runner memory.** Raise the runner container limit of `gha-runner-scale-set-lab` from 512Mi to about 1Gi, or the `sca` type will likely be OOM-killed. Measured in the runner image: Grype about 300 MiB, TruffleHog about 263 MiB, next to the runner's own processes.

## Running it

Run the `demo` workflow from the Actions tab, or `gh workflow run demo.yml --ref feature/vault-transit-signing`. With the default types it produces four envelopes:

| Type | Signed with | Expected result on the sample |
|---|---|---|
| `secret-detection` | `evd-scan-lab` | `fail`: a Slack webhook and a private key, both random |
| `sca` | `evd-scan-lab` | `fail`: 2 critical, 2 high, 9 medium in old requests, PyYAML and Jinja2 |
| `peer-approval` | `evd-approval-lab` | `fail` unless the commit came from an approved pull request |
| `custom` | `evd-self-lab` | no result: the squad declared it, nobody verified it |

`fail` is recorded and signed; it fails the run only with `enforce`. The envelopes are in the run's `evidence-envelopes` artifact. To check them yourself:

```
gh run download <run id> -n evidence-envelopes -D /tmp/envelopes
python3 evidence/cli.py verify --envelopes /tmp/envelopes --keys trusted-keys
```

## What was tested

- The 55 tests: the kit against stand-in GitHub, Vault, JFrog and SonarQube, scanners replaying recorded output, both stores, the collect and sign split, verification against openssl, and the shape of `evidence.yml`.
- In the runner image `ghcr.io/actions/actions-runner:2.338.2`, capped at 512Mi: `install-scanners.sh`, and `collect` with the real TruffleHog and Grype on the sample app.
- Against a local `vault server -dev`: `bootstrap.sh` and `apply.sh` with the new roles, JWT login with GitHub-shaped tokens, signing with PKCS#1 v1.5 and PSS, `verify`, openssl, and every refusal: another workflow or branch, a GitHub-hosted runner, the wrong audience, a scan token using the self key, exporting a key.

Not run yet: the workflows on the Talos runners, real GitHub OIDC tokens against the homelab Vault (1.20.4), and the runner group's access.

## Differences from the bank kit

- Store `file` instead of JFrog, and `verify` instead of JFrog's check. The JFrog store is unchanged and still tested.
- Transit generates the keys itself instead of using Azure Key Vault managed keys, which need Vault Enterprise.
- Vault trusts branch refs, not `v*` tags: there is no release workflow here yet, so release-please, `RELEASING.md` and the version tests were left out.
- The kit is checked out from this repository at the caller's commit instead of being pinned as an action, so only workflows in this repository can call `evidence.yml`.
