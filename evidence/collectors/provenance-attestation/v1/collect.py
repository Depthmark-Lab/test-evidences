"""Provenance attestation: GitHub's own attestation of where the artifact was built, verified.

evidence.yml's attest job has GitHub attest the artifact: actions/attest-build-provenance
signs SLSA build provenance for its SHA-256 with Sigstore, under that job's OIDC
identity, and GitHub keeps the attestation with the repository. This collector has gh
verify it: the signature, its certificate against Sigstore's trusted roots, the
transparency log or timestamp, and the policy that attestation-signer signed it, the
platform's evidence.yml, from this repository at this commit. It records what the
verified attestations say, never the bundles themselves.

GitHub names the workflow that asked for the attestation as the signer, evidence.yml,
and the squad's workflow as the build configuration: the squad's job built the
artifact, evidence.yml downloaded and hashed it, and GitHub vouches for both.

When GitHub holds no attestation for these bytes, the result is fail. On a private
repository without GitHub Enterprise Cloud, GitHub keeps none at all: its API answers
404. An attestation that exists but does not verify is an error, not a fail: the
attest job of the same call made it, so nothing is signed until someone has looked.
"""
import hashlib
import json
import os
import subprocess

from evidence_sdk import commit, emit, param, repository, run_tool, unable

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
# What gh says when GitHub holds no attestation for a digest: an empty list, or 404 where attestations are off.
NONE_FOUND = ("no attestations found", "HTTP 404")


def file_sha256(name):
    digest = hashlib.sha256()
    with open(name, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def record(verified, sha256):
    """What one verified attestation says: who signed it, for which source and run, and where it was logged."""
    result = verified.get("verificationResult") or {}
    certificate = (result.get("signature") or {}).get("certificate") or {}
    statement = result.get("statement") or {}
    builder = ((statement.get("predicate") or {}).get("runDetails") or {}).get("builder") or {}
    material = ((verified.get("attestation") or {}).get("bundle") or {}).get("verificationMaterial") or {}
    return {
        "signer": certificate.get("buildSignerURI", ""),
        "buildConfig": certificate.get("buildConfigURI", ""),
        "sourceRepository": certificate.get("sourceRepositoryURI", ""),
        "sourceRef": certificate.get("sourceRepositoryRef", ""),
        "sourceDigest": certificate.get("sourceRepositoryDigest", ""),
        "trigger": certificate.get("buildTrigger", ""),
        "runnerEnvironment": certificate.get("runnerEnvironment", ""),
        "runInvocation": certificate.get("runInvocationURI", ""),
        "issuer": certificate.get("issuer", ""),
        "certificateIssuer": certificate.get("certificateIssuer", ""),
        "builderId": builder.get("id", ""),
        # A statement may name many files; these are the names it gives these bytes.
        "subjects": sorted(s.get("name", "") for s in statement.get("subject") or []
                           if (s.get("digest") or {}).get("sha256") == sha256),
        "timestamps": [{"type": t.get("type", ""), "authority": t.get("uri", ""), "time": t.get("timestamp", "")}
                       for t in result.get("verifiedTimestamps") or []],
        "transparencyLogIndexes": [int(e["logIndex"]) for e in material.get("tlogEntries") or []
                                   if str(e.get("logIndex", "")).isdigit()],
    }


path = param("attested-file")
signer = param("attestation-signer")
if not os.path.isfile(path):
    unable(f"attested-file {path} is not a file")
sha256 = file_sha256(path)
version = run_tool(["gh", "--version"]).split()[2]          # gh version 2.102.0 (2026-09-30)
policy = {"repository": repository(), "signerWorkflow": signer, "sourceDigest": commit(),
          "predicateType": PREDICATE_TYPE}
facts = {"commit": commit(), "artifact": {"file": os.path.basename(path), "sha256": sha256},
         "verifier": {"name": "gh", "version": version}, "policy": policy}

try:
    done = subprocess.run(["gh", "attestation", "verify", path, "--repo", policy["repository"],
                           "--signer-workflow", signer, "--source-digest", policy["sourceDigest"],
                           "--predicate-type", PREDICATE_TYPE, "--format", "json"], capture_output=True, text=True)
except FileNotFoundError:
    unable("gh is not installed on this runner")

if done.returncode != 0:
    reason = (done.stderr.strip().splitlines() or ["no message"])[-1].removeprefix("Error: ")
    if not any(marker in reason for marker in NONE_FOUND):
        unable(f"gh could not verify GitHub's attestation for these bytes: {reason}")
    emit({"result": "fail", **facts, "summary": {"verified": 0}, "attestations": [],
          "reason": f"GitHub holds no provenance attestation for these bytes: {reason}"})
else:
    try:
        attestations = [record(verified, sha256) for verified in json.loads(done.stdout)]
    except (ValueError, TypeError, AttributeError):
        unable("gh printed a verification result that is not the JSON it documents")
    if not attestations:
        unable("gh verified the attestations but listed none")
    emit({"result": "pass", **facts, "summary": {"verified": len(attestations)}, "attestations": attestations})
