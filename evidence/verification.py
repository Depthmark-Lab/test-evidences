"""Verification: check signed evidence the way a consumer would, with public keys only.

Reads DSSE envelopes and the PEM public keys a verifier trusts, one file per
key id (trusted-keys/evd-scan-lab-v1.pub.pem). Knows nothing of Vault or JFrog
and never asks either one: a verifier that needs the signer to answer is not
independent of it. Like the evidence logic, it must never import signing.py.

An envelope is accepted only if all of these hold:
  - a signature verifies against a trusted key (RSA, PKCS#1 v1.5 or PSS, SHA-256)
  - that key belongs to the family and tier the catalog gives the evidence type,
    so a squad's self key cannot vouch for a scan
  - the statement is an in-toto v1 statement whose predicate matches the schema
    of its type and version
  - the subject carries the expected SHA-256, when one is given

Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

import schema as schemas
from core import PAYLOAD_TYPE, STATEMENT_TYPE, EvidenceError, evidence_type, pae

KEY_ID = re.compile(r"evd-(?P<family>[a-z0-9]+)-(?P<tier>[a-z0-9]+)-v(?P<version>[0-9]+)")

RSA_ENCRYPTION = bytes.fromhex("06092a864886f70d010101")
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
SHA256_LENGTH = 32


# ---- RSA public keys and signatures -------------------------------------------


def _der(data, pos, tag):
    """Read one DER element with the given tag at pos. Returns (start, end) of its value."""
    if pos + 2 > len(data) or data[pos] != tag:
        raise ValueError("unexpected DER structure")
    length, pos = data[pos + 1], pos + 2
    if length & 0x80:
        count = length & 0x7F
        length, pos = int.from_bytes(data[pos:pos + count], "big"), pos + count
    if pos + length > len(data):
        raise ValueError("truncated DER")
    return pos, pos + length


def load_public_key(pem):
    """Return (n, e) from an RSA public key in PEM SubjectPublicKeyInfo form, as Vault Transit exports it."""
    lines = [line.strip() for line in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise EvidenceError("not a PEM public key (BEGIN PUBLIC KEY)")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
        start, _ = _der(der, 0, 0x30)                    # SubjectPublicKeyInfo
        algorithm, after = _der(der, start, 0x30)        # AlgorithmIdentifier
        if not der[algorithm:after].startswith(RSA_ENCRYPTION):
            raise ValueError("not an RSA key")
        bits, bits_end = _der(der, after, 0x03)          # BIT STRING holding RSAPublicKey
        if der[bits] != 0:
            raise ValueError("unexpected unused bits")
        key = der[bits + 1:bits_end]
        start, _ = _der(key, 0, 0x30)
        n_start, n_end = _der(key, start, 0x02)
        e_start, e_end = _der(key, n_end, 0x02)
    except ValueError as exc:
        raise EvidenceError(f"cannot read the public key: {exc}") from None
    return int.from_bytes(key[n_start:n_end], "big"), int.from_bytes(key[e_start:e_end], "big")


def _mgf1(seed, length):
    output, counter = b"", 0
    while len(output) < length:
        output += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


def _pss_matches(encoded, digest, modulus_bits):
    """EMSA-PSS verification (RFC 8017 9.1.2) with SHA-256 and MGF1-SHA-256, any salt length."""
    em_bits = modulus_bits - 1
    em_length = (em_bits + 7) // 8
    if encoded >> (8 * em_length):
        return False
    em = encoded.to_bytes(em_length, "big")
    if em_length < SHA256_LENGTH + 2 or em[-1] != 0xBC:
        return False
    masked, hashed = em[:-SHA256_LENGTH - 1], em[-SHA256_LENGTH - 1:-1]
    spare_bits = 8 * em_length - em_bits
    if spare_bits and masked[0] >> (8 - spare_bits):
        return False
    db = bytearray(a ^ b for a, b in zip(masked, _mgf1(hashed, len(masked))))
    db[0] &= 0xFF >> spare_bits
    separator = next((i for i, byte in enumerate(db) if byte), None)
    if separator is None or db[separator] != 1:
        return False
    salt = bytes(db[separator + 1:])
    return hmac.compare_digest(hashlib.sha256(b"\x00" * 8 + digest + salt).digest(), hashed)


def signature_matches(public_key, data, signature, pss=False):
    """Whether signature is an RSA SHA-256 signature of data by public_key."""
    n, e = public_key
    length = (n.bit_length() + 7) // 8
    if len(signature) != length:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    encoded = pow(value, e, n)
    digest = hashlib.sha256(data).digest()
    if pss:
        return _pss_matches(encoded, digest, n.bit_length())
    info = SHA256_DIGEST_INFO + digest
    expected = b"\x00\x01" + b"\xff" * (length - len(info) - 3) + b"\x00" + info
    return hmac.compare_digest(encoded.to_bytes(length, "big"), expected)


# ---- envelopes -------------------------------------------------------------------


def load_trusted_keys(folder):
    """Every <key id>.pub.pem in folder, as {key id: (n, e)}."""
    keys = {}
    for path in sorted(Path(folder).glob("*.pub.pem")):
        keys[path.name[:-len(".pub.pem")]] = load_public_key(path.read_text(encoding="utf-8"))
    if not keys:
        raise EvidenceError(f"no trusted public keys (*.pub.pem) in {folder}")
    return keys


def _signed_by(envelope, payload, keys):
    """Return the key id of the first signature that verifies against a trusted key, or raise."""
    reasons = []
    for signature in envelope.get("signatures") or []:
        key_id = str(signature.get("keyid", ""))
        alias, _, scheme = key_id.partition(";")
        if alias not in keys:
            reasons.append(f"key '{alias}' is not trusted")
            continue
        if scheme not in ("", "PS256"):
            reasons.append(f"key id '{key_id}' names an unknown signature scheme")
            continue
        try:
            raw = base64.b64decode(str(signature.get("sig", "")), validate=True)
        except ValueError:
            reasons.append(f"the signature by '{alias}' is not base64")
            continue
        if signature_matches(keys[alias], pae(envelope["payloadType"], payload), raw, pss=scheme == "PS256"):
            return alias
        reasons.append(f"the signature by '{alias}' does not verify")
    raise EvidenceError("no valid signature: " + ("; ".join(reasons) or "the envelope has no signatures"))


def verify(envelope, keys, catalog, settings, sha256=""):
    """Check one DSSE envelope. Returns (type id, version, key id, statement), or raises EvidenceError."""
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        raise EvidenceError(f"not a DSSE envelope with payload type {PAYLOAD_TYPE}")
    try:
        payload = base64.b64decode(str(envelope.get("payload", "")), validate=True)
    except ValueError:
        raise EvidenceError("the payload is not base64") from None
    key_id = _signed_by(envelope, payload, keys)

    try:
        statement = json.loads(payload)
    except ValueError:
        raise EvidenceError("the signed payload is not JSON") from None
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        raise EvidenceError(f"the signed payload is not an in-toto statement ({STATEMENT_TYPE})")

    type_id, version = evidence_type(str(statement.get("predicateType", "")), catalog, settings)

    signer = KEY_ID.fullmatch(key_id)
    family = catalog[type_id]["family"]
    if not signer or signer["family"] != family or signer["tier"] != settings["tier"]:
        raise EvidenceError(f"{type_id} evidence must be signed with an evd-{family}-{settings['tier']} key, "
                            f"not '{key_id}'")

    problems = schemas.validate(statement.get("predicate"), _schema(type_id, version))
    if problems:
        raise EvidenceError("the predicate does not match its schema: " + "; ".join(problems[:5]))

    if sha256:
        digests = [(subject.get("digest") or {}).get("sha256") for subject in statement.get("subject") or []
                   if isinstance(subject, dict)]
        if sha256 not in digests:
            raise EvidenceError(f"the evidence is about another artifact: no subject has SHA-256 {sha256}")
    return type_id, version, key_id, statement


def _schema(type_id, version):
    path = Path(__file__).resolve().parent / "collectors" / type_id / version / "schema.json"
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError:
        raise EvidenceError(f"this kit has no schema for {type_id} {version}") from None
