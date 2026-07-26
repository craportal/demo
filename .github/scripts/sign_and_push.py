#!/usr/bin/env python3
"""Keyless-sign een SBOM tegen de LOKALE (private) Fulcio en push 'm ondertekend
naar de eidp-dossier-ingest via de BFF.

Repliceert exact de eidp-FulcioSigner-flow zodat de eidp-acceptance-gate
(verify_build_attestation) de handtekening + cert accepteert:
  1. ephemeral ECDSA P-256-keypair;
  2. in-toto-statement met subject-digest = sha256(SBOM);
  3. proof-of-possession over de OIDC-`sub` -> Fulcio /api/v2/signingCert -> cert
     (SAN = de job_workflow_ref-URI, bevat owner/repo);
  4. DSSE-signature over PAE(payloadType, statement) met de ephemeral key;
  5. PUT {sbom, attestation(DSSE-envelope, base64), certificate(PEM)} -> /ci-ingest/sbom.

Fulcio + Rekor blijven PRIVAAT: dit draait op een self-hosted runner op het lokale net.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def _mint_oidc_token(audience: str) -> str:
    """Vraag een GitHub-Actions-OIDC-token met de gevraagde audience."""
    req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    req_tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    url = f"{req_url}&audience={audience}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {req_tok}"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)["value"]


def _sub_claim(token: str) -> str:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims.get("email") or claims["sub"]


def _fulcio_cert(fulcio_url: str, oidc_token: str, key: ec.EllipticCurvePrivateKey) -> str:
    pub_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    subject = _sub_claim(oidc_token)
    pop = key.sign(subject.encode(), ec.ECDSA(hashes.SHA256()))
    body = json.dumps(
        {
            "credentials": {"oidcIdentityToken": oidc_token},
            "publicKeyRequest": {
                "publicKey": {"algorithm": "ECDSA", "content": pub_pem},
                "proofOfPossession": base64.b64encode(pop).decode(),
            },
        }
    ).encode()
    req = urllib.request.Request(
        f"{fulcio_url.rstrip('/')}/api/v2/signingCert",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    cert = data.get("signedCertificateEmbeddedSct") or data.get(
        "signedCertificateDetachedSct"
    )
    if not cert:
        raise SystemExit(f"fulcio response mist certificate chain: {list(data)}")
    return cert["chain"]["certificates"][0]


def main() -> None:
    sbom_path = os.environ["SBOM_PATH"]
    fulcio_url = os.environ["FULCIO_URL"]
    ingest_url = os.environ["INGEST_URL"].rstrip("/")
    audience = os.environ["INGEST_AUDIENCE"]

    sbom = open(sbom_path, "rb").read()

    # Eén GH-OIDC-token dekt zowel Fulcio (signing) als de BFF (push): zelfde audience.
    token = _mint_oidc_token(audience)

    statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "sbom", "digest": {"sha256": hashlib.sha256(sbom).hexdigest()}}
            ],
            "predicateType": "https://cyclonedx.org/bom",
            "predicate": {},
        }
    ).encode()

    key = ec.generate_private_key(ec.SECP256R1())
    cert_pem = _fulcio_cert(fulcio_url, token, key)
    signature = key.sign(_pae(INTOTO_PAYLOAD_TYPE, statement), ec.ECDSA(hashes.SHA256()))

    envelope = {
        "payloadType": INTOTO_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement).decode(),
        "signatures": [{"sig": base64.b64encode(signature).decode()}],
    }
    print(f"signed keyless; cert SAN-bevat de workflow-identiteit; pushing -> {ingest_url}/sbom")

    payload = json.dumps(
        {
            "sbom": base64.b64encode(sbom).decode(),
            "attestation": base64.b64encode(json.dumps(envelope).encode()).decode(),
            "certificate": cert_pem,
        }
    ).encode()
    req = urllib.request.Request(
        f"{ingest_url}/sbom",
        data=payload,
        method="PUT",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print("ingest OK:", resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"ingest FAILED {exc.code}: {exc.read().decode()}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
