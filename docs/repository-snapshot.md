# Repository snapshot

A snapshot of what decides who can change a repository's code, and how, taken by one reusable workflow with a read-only github-sts token. It stands on its own: the evidence kit can use it, but it needs nothing from the kit.

## The pieces

| File | Role |
|---|---|
| `scripts/snapshot-repository.py` | Reads the controls and writes them as JSON. Standard library only, imports nothing from `evidence/` |
| `.github/workflows/repository-snapshot.yml` | Reusable workflow, the only one github-sts gives the token to |
| `.github/sts/test-controls-read-app/repository-snapshot.sts.yaml` | The trust policy that grants it |
| `.github/workflows/repository-controls.yml` | Calls it every day and compares the controls with the committed ones |
| `tests/test_snapshot.py` | Its tests, with their own stand-ins for GitHub and github-sts |

## What it reads

- The repository's merge settings.
- The rules on the default branch, and the rulesets they come from, with who may bypass them.
- Classic branch protection.
- What workflows may do: allowed actions, the default token, whether they may approve pull requests.
- Everyone with access, their role and how they got it: directly, as an outside collaborator, or through a team or the organization. Also teams, organization owners and pending invitations.
- Deploy keys, by fingerprint, never the key.
- Each environment and who may approve deployments to it.

## The output

JSON with no URL and no value that changes on its own, every list sorted, so two snapshots of the same controls are the same bytes and a diff is a change of a control. Format `repository-controls/v1`. What GitHub refuses to show, because of the plan or the token's permissions, is written as `{"unavailable": "HTTP <status>: <message>"}`, never left out: on a private repository on the Free plan, the branch rules, rulesets and branch protection are.

With `--check`, the script compares the live controls with a committed snapshot and exits 1 on any difference, printing it. On GitHub Actions, the step summary says what was taken, what GitHub did not show, and the difference.

## Why one workflow

The token reads a repository's administration settings and its organization's members, so it is given to one place only. The trust policy matches the OIDC claim `job_workflow_ref`, which names the workflow file that defines the job: `repository-snapshot.yml`, whichever workflow calls it, on `main`, on a self-hosted runner. Its job runs the script and nothing else, the script revokes the token as soon as the snapshot is taken, and only the snapshot leaves the job, as an artifact. `tests/test_snapshot.py` fails if another workflow names the github-sts pool or runs the script, or if the pool gets a second identity.

The token is `administration`, `environments`, `members` and `metadata`, read only, for the calling repository only.

## Calling it

```yaml
jobs:
  controls:
    uses: ./.github/workflows/repository-snapshot.yml
    permissions:
      contents: read
      id-token: write
    with:
      check: controls/repository-controls.json    # optional: fail when the live controls differ
```

| Input | Default | Use |
|---|---|---|
| `check` | none | Path of a committed snapshot in the caller's repository. Missing, the job only takes the snapshot and says so |
| `artifact-name` | `repository-controls` | Name of the uploaded snapshot |
| `runs-on` | `["self-hosted", "talos", "lab"]` | Runner labels, as a JSON list |

The output `snapshot-id` is the snapshot's artifact id: download it with `actions/download-artifact` and `artifact-ids`, never by name, which another job of the run could reuse. The snapshot is uploaded even when the controls differ, since it is what to commit when the change was intended.

Callers: `repository-controls.yml`, and `evidence.yml` for the `repository-controls` evidence type, which checks the snapshot against the platform's minimums and signs it.

## Behind the token

- **GitHub App** `test-evidences-lab-controls-read-1` (id 5826225), minted from `app-manifests/specs/` in Depthmark-Lab/test-github-sts. It holds `contents: read` too: github-sts reads each trust policy with a token from the pool's own App.
- **Pool** `test-controls-read-app` on the dev broker, `github-sts-dev.adelisle.com`, in `talos/apps/github-sts-dev/github-sts/values.yaml` of the homelab repository.
- **Key** in Azure Key Vault `kv-homelab-ni7gw`, sign only, granted to the broker by `azure/variables.tf` in github-sts-ksm.
- **Trust policy** read by the broker from this repository's default branch: it takes effect once on `main`.

## Limits

- Lab only: the workflow checks out the script from this repository at the caller's commit, as `evidence.yml` does with the kit, so callers live in this repository. Elsewhere, pin the workflow and the script by version.
- The trust policy also accepts `feature/build-evidence` while that branch is tested. Drop it once the branch is merged.
- The App is installed on every repository of Depthmark-Lab. Narrow it to the repositories that hold a trust policy for it.

## Locally

```bash
GH_TOKEN=$(gh auth token) python3 scripts/snapshot-repository.py --repo Depthmark-Lab/test-evidences --out controls.json
python3 -m unittest tests.test_snapshot -v
```
