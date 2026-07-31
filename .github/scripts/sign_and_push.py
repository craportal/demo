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
import urllib.parse
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


def _sign(
    sbom: bytes, fulcio_url: str, token: str, extra_subjects: list[dict]
) -> tuple[dict, str]:
    """Teken een SBOM keyless tegen de lokale Fulcio; levert envelope + cert."""
    subjects = [
        {"name": "sbom", "digest": {"sha256": hashlib.sha256(sbom).hexdigest()}}
    ] + extra_subjects
    statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": subjects,
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
    return envelope, cert_pem


def _push_evidence(
    evidence_url: str, token: str, kind: str, build_id: str, ref: str,
    sbom: bytes, envelope: dict, cert_pem: str,
) -> None:
    """Push naar de evidence-tak onder een expliciete `kind`.

    De kind is wat source en artefact tot een paar maakt: de verify-worker zoekt in
    een build-map naar beide en vergelijkt ze pas als ze er allebei zijn. Eerder ging
    de source-scan hier als `artifact` naar binnen — dan vormt het paar zich nooit en
    draait de vergelijking dus nooit, terwijl het er in het dossier compleet uitziet.
    """
    bundle = json.dumps({"dsseEnvelope": envelope, "certificate": cert_pem}).encode()
    body, content_type = _multipart(
        {"sbom": (f"{kind}.cdx.json", sbom), "bundle": ("bundle.json", bundle)}
    )
    query = urllib.parse.urlencode({"kind": kind, "build_id": build_id, "ref": ref})
    req = urllib.request.Request(
        f"{evidence_url}?{query}",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print(f"evidence ingest OK ({kind}):", resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"evidence ingest {kind} faalde (non-fataal) {exc.code}: {exc.read().decode()}")


def main() -> None:
    fulcio_url = os.environ["FULCIO_URL"]
    ingest_url = os.environ["INGEST_URL"].rstrip("/")
    audience = os.environ["INGEST_AUDIENCE"]
    evidence_url = os.environ.get("EVIDENCE_URL", "").rstrip("/")
    build_id = os.environ.get("BUILD_ID", "")
    ref = os.environ.get("REF", "")

    source_sbom = open(os.environ["SOURCE_SBOM"], "rb").read()
    artifact_path = os.environ.get("ARTIFACT_SBOM", "")
    artifact_sbom = open(artifact_path, "rb").read() if artifact_path else b""
    image_digest = os.environ.get("IMAGE_DIGEST", "")

    # Eén GH-OIDC-token dekt zowel Fulcio (signing) als de BFF (push): zelfde audience.
    token = _mint_oidc_token(audience)

    # De artefact-attestatie draagt TWEE subjects: de SBOM-digest, waar de
    # acceptance-gate op controleert, én de image-digest, die het bewijs bindt aan wat
    # er daadwerkelijk is uitgeleverd. Zonder die tweede hangt de attestatie aan een
    # bestand in plaats van aan een release.
    extra: list[dict] = []
    if image_digest:
        algo, _, hexdigest = image_digest.partition(":")
        extra.append({"name": "image", "digest": {algo or "sha256": hexdigest or image_digest}})

    # Het dossier krijgt het artefact als dat er is: dat is de runtime-waarheid.
    # Zonder image-build valt het terug op de source, zodat de flow blijft werken.
    dossier_sbom = artifact_sbom or source_sbom
    dossier_env, dossier_cert = _sign(dossier_sbom, fulcio_url, token, extra if artifact_sbom else [])

    print(f"signed keyless; cert-SAN bevat de workflow-identiteit; pushing -> {ingest_url}/sbom")
    payload = json.dumps(
        {
            "sbom": base64.b64encode(dossier_sbom).decode(),
            "attestation": base64.b64encode(json.dumps(dossier_env).encode()).decode(),
            "certificate": dossier_cert,
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
            print("dossier ingest OK:", resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"dossier ingest FAILED {exc.code}: {exc.read().decode()}", file=sys.stderr)
        raise SystemExit(1)

    # Evidence-tak: beide SBOM's onder één build_id, elk met een eigen handtekening.
    # Pas als het paar compleet is vergelijkt de verify-worker source tegen artefact —
    # dat is de controle op build-injectie.
    if evidence_url:
        src_env, src_cert = _sign(source_sbom, fulcio_url, token, [])
        _push_evidence(evidence_url, token, "source", build_id, ref, source_sbom, src_env, src_cert)
        if artifact_sbom:
            _push_evidence(
                evidence_url, token, "artifact", build_id, ref,
                artifact_sbom, dossier_env, dossier_cert,
            )
        else:
            print("geen artefact-SBOM: alleen source gepusht, dus geen vergelijking")


def _multipart(fields: dict[str, tuple[str, bytes]]) -> tuple[bytes, str]:
    """Bouw een multipart/form-data body (stdlib) uit {veld: (bestandsnaam, bytes)}."""
    boundary = "----trustengineboundary7f3a9c"
    out = bytearray()
    for name, (filename, content) in fields.items():
        out += f"--{boundary}\r\n".encode()
        out += (
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        out += content + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


if __name__ == "__main__":
    main()
