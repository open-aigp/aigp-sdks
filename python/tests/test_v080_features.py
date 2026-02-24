"""
Tests for AIGP v0.8.0 Features
===============================

Tests the four major v0.8.0 capabilities:
1. Event Signing (JWS ES256 via sign_event / verify_event_signature)
2. Causal Ordering (sequence_number auto-increment, causality_ref)
3. Unverified boundary events
4. Pointer Pattern (hash_mode="pointer" in compute_leaf_hash / compute_merkle_governance_hash)
"""

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace

from aigp.instrumentor import AIGPInstrumentor
from aigp.events import (
    create_aigp_event,
    compute_governance_hash,
    compute_leaf_hash,
    compute_merkle_governance_hash,
    sign_event,
    verify_event_signature,
)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture(autouse=True)
def setup_tracer():
    """Set up a real OTel TracerProvider for tests."""
    resource = Resource.create({"service.name": "aigp-test"})
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)
    yield
    provider.shutdown()


@pytest.fixture
def instrumentor():
    """Create an AIGPInstrumentor for testing."""
    return AIGPInstrumentor(
        agent_id="agent.test-bot",
        agent_name="Test Bot",
        org_id="org.test",
    )


@pytest.fixture
def ec_key_pair():
    """Generate an EC P-256 key pair for signing tests."""
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
    return private_key_pem, public_key_pem


@pytest.fixture
def sample_event():
    """Create a sample AIGP event for signing tests."""
    return create_aigp_event(
        event_type="INJECT_SUCCESS",
        event_category="governance",
        agent_id="agent.test-bot",
        trace_id="0" * 32,
        governance_hash=compute_governance_hash("test content"),
        policy_name="policy.test",
        policy_version=1,
    )


# ===================================================================
# 1. Event Signing
# ===================================================================

class TestEventSigning:
    """Tests for JWS ES256 event signing and verification."""

    def test_sign_event_produces_jws_compact(self, sample_event, ec_key_pair):
        """Signed event has event_signature in JWS Compact Serialization (3 dot-separated parts)."""
        private_key_pem, _ = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test-signer")
        parts = signed["event_signature"].split(".")
        assert len(parts) == 3, f"Expected 3 JWS parts, got {len(parts)}"

    def test_sign_event_sets_signature_key_id(self, sample_event, ec_key_pair):
        """Signed event has signature_key_id populated with the provided key_id."""
        private_key_pem, _ = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test-signer")
        assert signed["signature_key_id"] == "key.test-signer"

    def test_verify_event_signature_valid(self, sample_event, ec_key_pair):
        """Sign then verify with the correct public key returns True."""
        private_key_pem, public_key_pem = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test")
        assert verify_event_signature(signed, public_key_pem) is True

    def test_verify_event_signature_invalid_key(self, sample_event, ec_key_pair):
        """Sign with one key, verify with a different key returns False."""
        private_key_pem, _ = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test")

        # Generate a different key pair
        other_private_key = ec.generate_private_key(ec.SECP256R1())
        other_public_key_pem = other_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert verify_event_signature(signed, other_public_key_pem) is False

    def test_verify_event_signature_tampered(self, sample_event, ec_key_pair):
        """Sign event, modify a field, verify returns False."""
        private_key_pem, public_key_pem = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test")

        # Tamper with the event after signing
        signed["governance_hash"] = "tampered_hash_value"
        assert verify_event_signature(signed, public_key_pem) is False

    def test_verify_event_signature_empty(self, sample_event, ec_key_pair):
        """Event with no signature returns False."""
        _, public_key_pem = ec_key_pair
        assert verify_event_signature(sample_event, public_key_pem) is False

    def test_sign_event_preserves_fields(self, sample_event, ec_key_pair):
        """Signed event has all original fields plus signature fields."""
        private_key_pem, _ = ec_key_pair
        signed = sign_event(sample_event, private_key_pem, key_id="key.test")

        for key in sample_event:
            assert key in signed, f"Original field {key!r} missing from signed event"
            if key not in ("event_signature", "signature_key_id"):
                assert signed[key] == sample_event[key], (
                    f"Field {key!r} changed: {sample_event[key]!r} -> {signed[key]!r}"
                )
        assert "event_signature" in signed
        assert "signature_key_id" in signed
        assert signed["event_signature"] != ""


# ===================================================================
# 2. Causal Ordering via emit()
# ===================================================================

class TestCausalOrderingViaEmit:
    """Tests for sequence_number auto-increment and causality_ref via emit()."""

    def test_sequence_numbers_auto_increment(self, instrumentor):
        """Multiple events in the same trace get incrementing sequence_number 1, 2, 3..."""
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            e1 = instrumentor.emit("event.a", content="a", span=span)
            e2 = instrumentor.emit("event.b", content="b", span=span)
            e3 = instrumentor.emit("event.c", content="c", span=span)
        assert e1["sequence_number"] == 1
        assert e2["sequence_number"] == 2
        assert e3["sequence_number"] == 3

    def test_sequence_numbers_per_trace(self, instrumentor):
        """Events in different traces get independent sequence counters."""
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("trace-a") as span_a:
            ea1 = instrumentor.emit("event.a", content="a", span=span_a)
            ea2 = instrumentor.emit("event.b", content="b", span=span_a)
        with tracer.start_as_current_span("trace-b") as span_b:
            eb1 = instrumentor.emit("event.c", content="c", span=span_b)
        assert ea1["sequence_number"] == 1
        assert ea2["sequence_number"] == 2
        assert eb1["sequence_number"] == 1

    def test_causality_ref_passed_through(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "event.a", content="a", causality_ref="some-event-id", span=span,
            )
        assert event["causality_ref"] == "some-event-id"

    def test_causality_ref_default_empty(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("event.a", content="a", span=span)
        assert event["causality_ref"] == ""


# ===================================================================
# 3. Unverified Boundary via emit()
# ===================================================================

class TestUnverifiedBoundary:
    """Tests for unverified boundary events via generic emit()."""

    def test_boundary_event(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "UNVERIFIED_BOUNDARY",
                event_category="boundary",
                content="request payload",
                annotations={"target_agent_id": "agent.external-llm"},
                span=span,
            )
        assert event["event_type"] == "UNVERIFIED_BOUNDARY"
        assert event["event_category"] == "boundary"
        assert event["annotations"]["target_agent_id"] == "agent.external-llm"

    def test_boundary_with_content_hash(self, instrumentor):
        content = "request to ungoverned system"
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "UNVERIFIED_BOUNDARY",
                event_category="boundary",
                content=content,
                annotations={"target_agent_id": "agent.dark-node"},
                span=span,
            )
        assert event["governance_hash"] == compute_governance_hash(content)

    def test_boundary_no_content_no_hash(self, instrumentor):
        tracer = trace.get_tracer("test")
        with pytest.raises(ValueError, match="governance_hash is required"):
            with tracer.start_as_current_span("test-span") as span:
                instrumentor.emit(
                    "UNVERIFIED_BOUNDARY",
                    event_category="boundary",
                    annotations={"target_agent_id": "agent.external"},
                    span=span,
                )

    def test_boundary_causality_ref(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "UNVERIFIED_BOUNDARY",
                event_category="boundary",
                content="causal-boundary",
                causality_ref="preceding-event-id",
                annotations={"target_agent_id": "agent.external"},
                span=span,
            )
        assert event["causality_ref"] == "preceding-event-id"


# ===================================================================
# 4. Pointer Pattern
# ===================================================================

class TestPointerPattern:
    """Tests for hash_mode='pointer' in compute_leaf_hash and compute_merkle_governance_hash."""

    def test_pointer_mode_hashes_uri_not_content(self):
        """pointer mode produces a different hash than content mode for the same content."""
        content = "the actual policy content"
        uri = "s3://aigp-governance/sha256:abc123"

        content_hash = compute_leaf_hash("policy", "policy.test", content)
        pointer_hash = compute_leaf_hash(
            "policy", "policy.test", content,
            hash_mode="pointer", content_ref=uri,
        )
        assert content_hash != pointer_hash

    def test_pointer_mode_requires_content_ref(self):
        """hash_mode='pointer' without content_ref raises ValueError."""
        with pytest.raises(ValueError, match="content_ref is required"):
            compute_leaf_hash(
                "policy", "policy.test", "content",
                hash_mode="pointer", content_ref="",
            )

    def test_pointer_mode_deterministic(self):
        """Same URI produces the same hash every time."""
        uri = "s3://aigp-governance/sha256:abc123"
        hash1 = compute_leaf_hash(
            "policy", "policy.test", "",
            hash_mode="pointer", content_ref=uri,
        )
        hash2 = compute_leaf_hash(
            "policy", "policy.test", "",
            hash_mode="pointer", content_ref=uri,
        )
        assert hash1 == hash2

    def test_merkle_with_mixed_modes(self):
        """compute_merkle_governance_hash works with a mix of content and pointer mode resources."""
        resources = [
            ("policy", "policy.inline", "inline policy content"),
            {
                "resource_type": "prompt",
                "resource_name": "prompt.large",
                "content": "",
                "hash_mode": "pointer",
                "content_ref": "s3://bucket/prompt-v3.txt",
            },
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)

        assert len(root_hash) == 64  # SHA-256 hex
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 2
        assert merkle_tree["algorithm"] == "sha256"

    def test_merkle_pointer_leaf_has_hash_mode(self):
        """Merkle tree leaves include hash_mode when the resource uses pointer mode."""
        resources = [
            ("policy", "policy.inline", "content A"),
            {
                "resource_type": "prompt",
                "resource_name": "prompt.external",
                "content": "",
                "hash_mode": "pointer",
                "content_ref": "s3://bucket/key",
            },
        ]
        _, merkle_tree = compute_merkle_governance_hash(resources)

        pointer_leaves = [
            leaf for leaf in merkle_tree["leaves"]
            if leaf["resource_name"] == "prompt.external"
        ]
        assert len(pointer_leaves) == 1
        assert pointer_leaves[0]["hash_mode"] == "pointer"

    def test_merkle_pointer_leaf_has_content_ref(self):
        """Merkle tree leaves include content_ref when the resource uses pointer mode."""
        uri = "s3://bucket/prompt-sha256:deadbeef"
        resources = [
            ("policy", "policy.inline", "content A"),
            {
                "resource_type": "prompt",
                "resource_name": "prompt.external",
                "content": "",
                "hash_mode": "pointer",
                "content_ref": uri,
            },
        ]
        _, merkle_tree = compute_merkle_governance_hash(resources)

        pointer_leaves = [
            leaf for leaf in merkle_tree["leaves"]
            if leaf["resource_name"] == "prompt.external"
        ]
        assert len(pointer_leaves) == 1
        assert pointer_leaves[0]["content_ref"] == uri

    def test_dict_resource_format(self):
        """Dict-based resource input works for compute_merkle_governance_hash."""
        resources = [
            {
                "resource_type": "policy",
                "resource_name": "policy.test",
                "content": "",
                "hash_mode": "pointer",
                "content_ref": "s3://bucket/key",
            },
            {
                "resource_type": "prompt",
                "resource_name": "prompt.test",
                "content": "inline prompt content",
            },
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)

        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 2
        assert len(merkle_tree["leaves"]) == 2
