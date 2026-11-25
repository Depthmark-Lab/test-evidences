"""Provenance: where the artifact was built, as SLSA build provenance v1.

Says which workflow, at which commit, in which run and on which kind of runner
produced the artifact, in the shape of GitHub's own build type
(https://actions.github.io/buildtypes/workflow/v1), so SLSA tools can read it.
Every fact comes from variables GitHub sets for the run, which the squad's
build steps cannot change. The artifact is the statement's subject:
evidence.yml offers this type only when it downloaded the artifact from the
run and computed its SHA-256 itself.

builder.id is the squad's workflow, which ran the build. Who vouches for the
statement is the signature: only evidence.yml can sign with the build key.
GitHub's own artifact attestations would say the same through Sigstore, but in
a private repository they need GitHub Enterprise Cloud.
"""
from evidence_sdk import commit, emit, env, repository, unable

BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"

server = env("GITHUB_SERVER_URL")
repo = repository()
workflow_ref = env("GITHUB_WORKFLOW_REF")         # <owner>/<repo>/.github/workflows/<file>@<ref>
workflow, _, ref = workflow_ref.partition("@")
if not workflow.startswith(f"{repo}/.github/workflows/") or not ref:
    unable(f"GITHUB_WORKFLOW_REF '{workflow_ref}' does not name a workflow of {repo}")

emit({
    "buildDefinition": {
        "buildType": BUILD_TYPE,
        "externalParameters": {
            "workflow": {"ref": ref, "repository": f"{server}/{repo}", "path": workflow[len(repo) + 1:]},
        },
        "internalParameters": {
            "github": {
                "event_name": env("GITHUB_EVENT_NAME"),
                "repository_id": env("GITHUB_REPOSITORY_ID"),
                "repository_owner_id": env("GITHUB_REPOSITORY_OWNER_ID"),
                "runner_environment": env("RUNNER_ENVIRONMENT"),
            },
        },
        "resolvedDependencies": [
            {"uri": f"git+{server}/{repo}@{env('GITHUB_REF')}", "digest": {"gitCommit": commit()}},
        ],
    },
    "runDetails": {
        "builder": {"id": f"{server}/{workflow_ref}"},
        "metadata": {
            "invocationId": f"{server}/{repo}/actions/runs/{env('GITHUB_RUN_ID')}/attempts/{env('GITHUB_RUN_ATTEMPT')}",
        },
    },
})
