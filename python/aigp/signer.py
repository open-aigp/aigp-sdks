"""
Transport-agnostic event signing interfaces for AIGP.

This module keeps key management vendor-neutral by exposing a signer
protocol and a reference ES256 implementation. Callers can plug in KMS/HSM
or any external signer that implements EventSigner.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from aigp.events import _base64url_encode, _canonical_json


@runtime_checkable
class EventSigner(Protocol):
    """
    Generic JWS signer interface.

    Implementations must return a JOSE-formatted signature for the algorithm
    in use. For ES256, this is the 64-byte r||s form (not ASN.1 DER).
    """

    @property
    def alg(self) -> str:
        ...

    @property
    def key_id(self) -> str:
        ...

    def sign(self, signing_input: bytes) -> bytes:
        ...


class ES256PrivateKeySigner:
    """
    Reference ES256 signer backed by a PEM-encoded P-256 private key.

    This is a local key signer for development and portable deployments.
    Production setups can implement EventSigner using cloud KMS/HSM.
    """

    def __init__(self, private_key_pem: bytes, *, key_id: str = ""):
        self._private_key_pem = private_key_pem
        self._key_id = key_id

    @property
    def alg(self) -> str:
        return "ES256"

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, signing_input: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for ES256 signing. "
                "Install it with: pip install cryptography"
            ) from exc

        private_key = serialization.load_pem_private_key(self._private_key_pem, password=None)
        der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def sign_event_with_signer(
    event: dict[str, Any],
    signer: EventSigner,
) -> dict[str, Any]:
    """
    Sign an AIGP event with a pluggable EventSigner.

    Args:
        event: AIGP event dict.
        signer: EventSigner implementation (local key, KMS, HSM, etc.).

    Returns:
        Copy of event populated with event_signature and signature_key_id.
    """
    header = {"alg": signer.alg, "typ": "JWT"}
    if signer.key_id:
        header["kid"] = signer.key_id

    header_b64 = _base64url_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _base64url_encode(_canonical_json(event))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    sig_bytes = signer.sign(signing_input)
    if not sig_bytes:
        raise ValueError("Signer returned an empty signature.")

    signed = dict(event)
    signed["event_signature"] = f"{header_b64}.{payload_b64}.{_base64url_encode(sig_bytes)}"
    signed["signature_key_id"] = signer.key_id
    return signed


__all__ = [
    "EventSigner",
    "ES256PrivateKeySigner",
    "sign_event_with_signer",
]
