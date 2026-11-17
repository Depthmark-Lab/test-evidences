#!/usr/bin/env python3
"""Print what DSSE envelopes say: the key id, the subject and the predicate of each statement.

Shows, does not verify: run `evidence/cli.py verify` first. Standard library only.
Usage: scripts/show-envelopes.py <type>.dsse.json...
"""
import base64
import json
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        envelope = json.load(handle)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    print(f"== {path.rsplit('/', 1)[-1]}")
    print(f"   signed by      {', '.join(s['keyid'] for s in envelope['signatures'])}")
    print(f"   predicateType  {statement['predicateType']}")
    for subject in statement["subject"]:
        print(f"   subject        {subject['name']}  sha256:{subject['digest']['sha256']}")
    print("   " + json.dumps(statement["predicate"], indent=2).replace("\n", "\n   "))
