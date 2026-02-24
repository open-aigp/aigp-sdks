"""Tests for transport-agnostic signer interfaces."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from aigp import (
    ES256PrivateKeySigner,
    sign_event_with_signer,
    verify_event_signature,
)
from aigp.events import create_aigp_event, compute_governance_hash


def _sample_event() -> dict:
    return create_aigp_event(
        event_type="INJECT_SUCCESS",
        event_category="inject",
        agent_id="agent.test",
        trace_id="1" * 32,
        governance_hash=compute_governance_hash("policy content"),
    )


def test_sign_event_with_es256_signer_verifies():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signer = ES256PrivateKeySigner(private_key_pem, key_id="key.agent-test.2026-02")
    signed = sign_event_with_signer(_sample_event(), signer)
    assert signed["signature_key_id"] == "key.agent-test.2026-02"
    assert signed["event_signature"]
    assert verify_event_signature(signed, public_key_pem)


def test_sign_event_with_signer_preserves_fields():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    signer = ES256PrivateKeySigner(private_key_pem, key_id="key.test")
    event = _sample_event()
    signed = sign_event_with_signer(event, signer)

    for key in event:
        if key not in ("event_signature", "signature_key_id"):
            assert signed[key] == event[key]
