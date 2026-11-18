#!/usr/bin/env python3
"""evidence: collect, validate, sign and store release evidence.

  run      collect the requested evidence types, sign them and store them
  collect  collect and validate only, and write the predicates to files: no Vault, no JFrog
  sign     sign and store predicates that collect wrote, in a job that may request tokens
  verify   check signed envelopes with trusted public keys only: no Vault, no JFrog
  list     show the evidence types a pipeline can ask for
  check    verify the catalog, schemas, examples and layering (CI runs this on every change)
  lock     record the hash of new schemas so a published schema cannot change

Where signed evidence goes depends on settings "store": "jfrog" attaches it to
the artifact, "file" writes one DSSE envelope per type to --out.

This file is the only place where the evidence logic (collection.py) meets
Vault and JFrog (signing.py).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import collection  # noqa: E402
import schema as schemas  # noqa: E402
import signing  # noqa: E402
import verification  # noqa: E402
from core import EvidenceError, load_json, predicate_type  # noqa: E402
from display import announce, report  # noqa: E402
from version import __version__  # noqa: E402

COLLECTORS = collection.COLLECTORS
LOCK = ROOT / "schemas.lock.json"
STORES = ("jfrog", "file")


def load_settings():
    return load_json(os.environ.get("EVD_SETTINGS") or ROOT / "settings.json")


def load_catalog():
    return load_json(ROOT / "catalog.json")


# ---- run, collect and sign ----------------------------------------------------


def parse_params(pairs):
    params = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not name.strip():
            raise EvidenceError(f"parameter '{pair}' is not in name=value form")
        params[name.strip()] = value.strip()
    return params


def parse_types(text, catalog):
    types = list(dict.fromkeys(t.strip() for t in text.split(",") if t.strip()))
    if not types:
        raise EvidenceError("no evidence type requested")
    unknown = [t for t in types if t not in catalog]
    if unknown:
        raise EvidenceError(f"unknown evidence type(s): {', '.join(unknown)}. Known types: {', '.join(sorted(catalog))}")
    return types


def parse_request(args, catalog):
    """Return (types, params), or raise for a bad request before anything runs."""
    types = parse_types(args.types, catalog)
    params = parse_params(args.param)
    declared = {name for t in types for name in catalog[t].get("params", {})}
    stray = sorted(set(params) - declared)
    if stray:
        raise EvidenceError(f"parameter(s) not used by the requested types: {', '.join(stray)}")
    return types, params


def check_subject(args, settings):
    """Reject a bad subject or store request before any token is requested."""
    store = settings.get("store", "jfrog")
    if store not in STORES:
        raise EvidenceError(f"unknown store '{store}' in settings. Known stores: {', '.join(STORES)}")
    if "/" not in args.subject_repo_path.strip("/"):
        raise EvidenceError("subject-repo-path must look like <repository>/<path to artifact>")
    if args.subject_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.subject_sha256):
        raise EvidenceError("subject-sha256 must be 64 lowercase hex characters")
    if store == "file" and not args.subject_sha256:
        raise EvidenceError("store is 'file': subject-sha256 is required, as there is no JFrog to resolve it")
    if store == "file" and not args.out:
        raise EvidenceError("store is 'file': pass --out, the directory to write the signed envelopes to")


def make_store(settings, args, vault):
    """Return (store, status, done as) for the store the settings name.

    store(type_id, entry, predicate) signs one predicate and returns the key id.
    """
    def kind(type_id, entry):
        return predicate_type(settings, type_id, entry, entry["current"])

    if settings.get("store", "jfrog") == "file":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)

        def write(type_id, entry, predicate):
            key_id, envelope = signing.envelope(predicate, kind(type_id, entry), entry["family"],
                                                args.subject_repo_path, args.subject_sha256, vault)
            write_json(out / f"{type_id}.dsse.json", envelope)
            return key_id
        return write, "signed", "signed by"

    jfrog = signing.JFrog(settings)

    def attach(type_id, entry, predicate):
        return signing.publish(predicate, kind(type_id, entry), entry["family"], args.subject_repo_path,
                               args.subject_sha256, vault, jfrog)
    return attach, "attached", "signed by"


def process(types, catalog, produce, status, finish):
    """Produce each type's predicate and pass it to finish(type_id, entry, predicate). Returns report rows.

    produce(type_id, entry) returns a predicate checked against its schema.
    finish returns the detail to report: a key id, a file name.
    """
    rows = []
    for type_id in types:
        entry = catalog[type_id]
        row = {"type": type_id, "version": entry["current"]}
        try:
            predicate = produce(type_id, entry)
            row.update(status=status, result=predicate.get("result", "n/a"), detail=finish(type_id, entry, predicate),
                       predicate=predicate)
        except EvidenceError as exc:
            # One type failing must not stop the others.
            row.update(status="error", result="n/a", detail=str(exc))
        rows.append(row)
    return rows


def collector(settings, params, resolver, workdir):
    """Return produce(type_id, entry) that runs the collector. resolver(entry) resolves that type's secrets."""
    shared = settings.get("collectorEnv", {})
    return lambda type_id, entry: collection.collect(type_id, entry, params, shared, resolver(entry), Path(workdir))


def outcome(rows, enforce):
    if any(row["status"] == "error" for row in rows):
        return 1
    failed = [row["type"] for row in rows if row["result"] == "fail"]
    if failed and enforce:
        announce("error", f"enforce is on and these checks failed: {', '.join(failed)}")
        return 1
    return 0


def cmd_run(args):
    settings, catalog = load_settings(), load_catalog()
    # Reject bad requests before any token is requested.
    types, params = parse_request(args, catalog)
    check_subject(args, settings)

    vault = signing.Vault(settings)
    store, status, done_as = make_store(settings, args, vault)

    def from_vault(entry):
        return lambda _name, spec: vault.read_secret(entry["family"], spec["path"], spec["field"])

    with tempfile.TemporaryDirectory(prefix="evidence-") as workdir:
        rows = process(types, catalog, collector(settings, params, from_vault, workdir), status, store)
    report(rows, signed_heading(status), status, done_as, "Signed by",
           subject=(args.subject_repo_path, args.subject_sha256))
    return outcome(rows, args.enforce)


def signed_heading(status):
    return "🔏 Evidence signed with Vault Transit" + (", attached in JFrog" if status == "attached" else "")


def cmd_collect(args):
    settings, catalog = load_settings(), load_catalog()
    types, params = parse_request(args, catalog)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def from_environment(_entry):
        def resolve(name, _spec):
            if not os.environ.get(name):
                raise EvidenceError(f"secret {name} is not set: collect reads collector secrets from the environment")
            return os.environ[name]
        return resolve

    def write(type_id, _entry, predicate):
        path = out / f"{type_id}.json"
        write_json(path, predicate)
        return path.name

    with tempfile.TemporaryDirectory(prefix="evidence-") as workdir:
        rows = process(types, catalog, collector(settings, params, from_environment, workdir), "collected", write)
    print(f"📁 Predicates go to {out}", flush=True)
    report(rows, "🔎 Evidence collected, not signed yet", "collected", "written to", "Written to")
    return 1 if any(row["status"] == "error" for row in rows) else 0


def cmd_sign(args):
    """The second half of collect: sign predicates another job wrote, in a job that may request tokens.

    The job that ran the collectors and scanners never held id-token, so they
    could not request a signing token. Each predicate is checked against its
    schema again here, and must be about the commit this job runs for.
    """
    settings, catalog = load_settings(), load_catalog()
    types = parse_types(args.types, catalog)
    check_subject(args, settings)
    folder = Path(args.predicates)
    commit = os.environ.get("EVD_COMMIT") or os.environ.get("GITHUB_SHA", "")

    def from_file(type_id, entry):
        try:
            predicate = load_json(folder / f"{type_id}.json")
        except OSError:
            raise EvidenceError(f"no collected predicate {type_id}.json in {folder}") from None
        except ValueError:
            raise EvidenceError(f"{type_id}.json is not JSON") from None
        collection.check(type_id, entry["current"], predicate)
        if commit and predicate.get("commit", commit) != commit:
            raise EvidenceError(f"the predicate was collected for commit {predicate.get('commit')}, not {commit}")
        return predicate

    vault = signing.Vault(settings)
    store, status, done_as = make_store(settings, args, vault)
    rows = process(types, catalog, from_file, status, store)
    report(rows, signed_heading(status), status, done_as, "Signed by",
           subject=(args.subject_repo_path, args.subject_sha256))
    return outcome(rows, args.enforce)


def cmd_verify(args):
    settings, catalog = load_settings(), load_catalog()
    if args.subject_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.subject_sha256):
        raise EvidenceError("subject-sha256 must be 64 lowercase hex characters")
    keys = verification.load_trusted_keys(args.keys)
    files = sorted(Path(args.envelopes).glob("*.dsse.json"))
    if not files:
        raise EvidenceError(f"no envelopes (*.dsse.json) in {args.envelopes}")
    expected = parse_types(args.types, catalog) if args.types else []

    rows = []
    for path in files:
        row = {"type": path.name[:-len(".dsse.json")], "version": "", "result": "n/a"}
        try:
            type_id, version, key_id, statement = verification.verify(
                load_json(path), keys, catalog, settings, args.subject_sha256)
            if type_id != row["type"]:
                raise EvidenceError(f"the file is named for {row['type']} but holds {type_id} evidence")
            row.update(version=version, status="verified", result=statement["predicate"].get("result", "n/a"),
                       detail=key_id, predicate=statement["predicate"], statement=statement)
        except (EvidenceError, ValueError) as exc:
            row.update(status="error", detail=str(exc))
        rows.append(row)
    for type_id in expected:
        if not any(row["type"] == type_id for row in rows):
            rows.append({"type": type_id, "version": "", "status": "error", "result": "n/a",
                         "detail": "no envelope for this type"})
    subjects = [row["statement"]["subject"][0] for row in rows if row.get("statement")]
    subject = (subjects[0]["name"], subjects[0]["digest"]["sha256"]) if subjects else None
    report(rows, "🛡️ Evidence verified with trusted public keys", "verified", "signed by", "Signed by",
           subject=subject, statements=True)
    return outcome(rows, args.enforce)


def write_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


# ---- list, check, lock -------------------------------------------------------


def cmd_list(_args):
    settings, catalog = load_settings(), load_catalog()
    for type_id in sorted(catalog):
        entry = catalog[type_id]
        print(f"{type_id}  ({entry['family']} key, {entry['current']})  {entry.get('description', '')}")
        print(f"    predicate type: {predicate_type(settings, type_id, entry, entry['current'])}")
        for name, spec in entry.get("params", {}).items():
            need = "required" if spec.get("required") else "optional"
            print(f"    param {name} ({need}): {spec.get('description', '')}")
    return 0


def schema_hash(path):
    canonical = json.dumps(load_json(path), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def evidence_logic():
    """The files that hold evidence logic. None of them may reach signing.py."""
    return [ROOT / "collection.py", *sorted(COLLECTORS.glob("*/*/*.py"))]


def kit_imports(path):
    """The kit modules (evidence/*.py) a Python file imports, directly or through other kit modules."""
    found, pending = set(), [path]
    while pending:
        tree = ast.parse(pending.pop().read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top not in found and (ROOT / f"{top}.py").is_file():
                    found.add(top)
                    pending.append(ROOT / f"{top}.py")
    return found


def find_problems():
    """Everything that must hold before a change to the catalog or a collector is merged."""
    problems = []
    settings, catalog = load_settings(), load_catalog()
    lock = load_json(LOCK) if LOCK.exists() else {}
    standard_types = {}

    for type_id, entry in sorted(catalog.items()):
        where = f"catalog '{type_id}'"
        if not re.fullmatch(r"[a-z][a-z0-9-]*", type_id):
            problems.append(f"{where}: id must be lowercase letters, digits and dashes")
        if entry.get("family") not in settings["families"]:
            problems.append(f"{where}: family '{entry.get('family')}' has no key. Known families: {settings['families']}")
        if not (COLLECTORS / type_id / str(entry.get("current"))).is_dir():
            problems.append(f"{where}: current version '{entry.get('current')}' has no collector folder")
        for name, spec in entry.get("secrets", {}).items():
            if not {"path", "field"} <= set(spec):
                problems.append(f"{where}: secret '{name}' needs 'path' and 'field'")
        timeout = entry.get("timeout", collection.DEFAULT_TIMEOUT)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
            problems.append(f"{where}: timeout must be a whole number of seconds")
        for version, kind in entry.get("predicateTypes", {}).items():
            if not (COLLECTORS / type_id / version).is_dir():
                problems.append(f"{where}: predicateTypes names version '{version}', which has no collector folder")
            if not re.fullmatch(r"https://\S+", str(kind)) or str(kind).startswith(settings["predicateBase"]):
                problems.append(f"{where}: predicateTypes '{version}' must be another standard's https URL, "
                                f"not '{kind}'")
            if kind in standard_types:
                problems.append(f"{where}: predicateTypes '{kind}' is already used by {standard_types[kind]}")
            standard_types[kind] = f"{type_id}/{version}"

    for folder in sorted(COLLECTORS.glob("*/*")):
        if not folder.is_dir():
            continue
        type_id, version = folder.parent.name, folder.name
        where = f"{type_id}/{version}"
        if type_id not in catalog:
            problems.append(f"{where}: collector folder has no catalog entry")
        if not (folder / "collect.py").is_file():
            problems.append(f"{where}: missing collect.py")
        try:
            schema = load_json(folder / "schema.json")
            schemas.check_schema(schema)
        except (OSError, ValueError, schemas.SchemaError) as exc:
            problems.append(f"{where}: schema.json is not usable: {exc}")
            continue

        examples = sorted((folder / "examples").glob("*.json"))
        if not any(not e.name.startswith("invalid-") for e in examples):
            problems.append(f"{where}: needs at least one valid example in examples/")
        for example in examples:
            errors = schemas.validate(load_json(example), schema)
            if example.name.startswith("invalid-") and not errors:
                problems.append(f"{where}: {example.name} should be rejected by the schema but is accepted")
            if not example.name.startswith("invalid-") and errors:
                problems.append(f"{where}: {example.name} does not match the schema: {errors[0]}")

        locked = lock.get(where)
        if locked is None:
            problems.append(f"{where}: schema is not locked yet. Run: python3 evidence/cli.py lock")
        elif locked != schema_hash(folder / "schema.json"):
            problems.append(f"{where}: a published schema changed. Restore it and add a new version folder instead")

    if settings.get("store", "jfrog") not in STORES:
        problems.append(f"settings: unknown store '{settings.get('store')}'. Known stores: {', '.join(STORES)}")

    independent = [(path, "Evidence logic must not depend on Vault or JFrog; hand a predicate to cli.py instead")
                   for path in evidence_logic()]
    independent.append((ROOT / "verification.py", "A verifier needs public keys only, never Vault or JFrog"))
    independent.append((ROOT / "display.py", "Showing evidence needs the predicate only, never Vault or JFrog"))
    for path, why in independent:
        where = path.relative_to(ROOT)
        try:
            reached = kit_imports(path)
        except (OSError, SyntaxError, ValueError) as exc:
            problems.append(f"{where}: cannot be read as Python: {exc}")
            continue
        if "signing" in reached:
            problems.append(f"{where}: reaches signing.py. {why}")
    return problems


def cmd_check(_args):
    problems = find_problems()
    for problem in problems:
        announce("error", problem)
    if not problems:
        print("catalog, schemas, examples, lock and layering are consistent")
    return 1 if problems else 0


def cmd_lock(_args):
    lock = load_json(LOCK) if LOCK.exists() else {}
    added = []
    for path in sorted(COLLECTORS.glob("*/*/schema.json")):
        key = f"{path.parent.parent.name}/{path.parent.name}"
        if key not in lock:           # existing entries are never rewritten
            lock[key] = schema_hash(path)
            added.append(key)
    with open(LOCK, "w", encoding="utf-8") as handle:
        json.dump(lock, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("locked: " + (", ".join(added) if added else "nothing new"))
    return 0


def add_request_arguments(parser):
    parser.add_argument("--types", required=True, help="comma-separated evidence type ids")
    parser.add_argument("--param", action="append", default=[], metavar="NAME=VALUE", help="collector parameter, repeatable")


def add_store_arguments(parser):
    parser.add_argument("--subject-repo-path", required=True, help="Artifactory path of the artifact, or its name in the statement")
    parser.add_argument("--subject-sha256", default="", help="SHA-256 of the artifact (recommended, required by store 'file')")
    parser.add_argument("--out", default="", help="store 'file' only: directory to write one <type>.dsse.json to")
    parser.add_argument("--enforce", action="store_true", help="exit non-zero when a check's result is 'fail' (evidence is still stored)")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="evidence", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="collect, sign and store evidence")
    add_request_arguments(run)
    add_store_arguments(run)
    run.set_defaults(handler=cmd_run)

    collect = commands.add_parser("collect", help="collect and validate evidence without signing it: no Vault, no JFrog")
    add_request_arguments(collect)
    collect.add_argument("--out", required=True, help="directory to write the predicates to, one <type>.json each")
    collect.set_defaults(handler=cmd_collect)

    sign = commands.add_parser("sign", help="sign and store predicates that collect wrote")
    sign.add_argument("--types", required=True, help="comma-separated evidence type ids to sign")
    sign.add_argument("--predicates", required=True, help="directory collect wrote the predicates to")
    add_store_arguments(sign)
    sign.set_defaults(handler=cmd_sign)

    verify = commands.add_parser("verify", help="check signed envelopes with trusted public keys only")
    verify.add_argument("--envelopes", required=True, help="directory holding <type>.dsse.json files")
    verify.add_argument("--keys", required=True, help="directory holding trusted <key id>.pub.pem files")
    verify.add_argument("--subject-sha256", default="", help="SHA-256 every envelope's subject must carry")
    verify.add_argument("--types", default="", help="comma-separated evidence type ids that must all be present")
    verify.add_argument("--enforce", action="store_true", help="exit non-zero when a check's result is 'fail'")
    verify.set_defaults(handler=cmd_verify)

    commands.add_parser("list", help="show available evidence types").set_defaults(handler=cmd_list)
    commands.add_parser("check", help="verify catalog, schemas, examples and layering").set_defaults(handler=cmd_check)
    commands.add_parser("lock", help="lock new schemas").set_defaults(handler=cmd_lock)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except EvidenceError as exc:
        announce("error", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
