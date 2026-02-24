"""
Tests for AIGP generic emit() API
==================================

Tests the single ``instrumentor.emit()`` method with various event types,
verifying governance hash computation, annotations, denial fields,
OTel trace correlation, and callback invocation.
"""

import re

import pytest

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace

from aigp.instrumentor import AIGPInstrumentor
from aigp.events import compute_governance_hash


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


# ===================================================================
# Basic emit() behavior
# ===================================================================

class TestEmitBasic:
    """Core tests for instrumentor.emit()."""

    def test_emit_returns_event_dict(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "policy.delivered",
                event_category="governance",
                content="Max position: $10M",
                span=span,
            )
        assert isinstance(event, dict)
        assert event["event_type"] == "POLICY_DELIVERED"
        assert event["event_category"] == "governance"

    def test_emit_computes_governance_hash(self, instrumentor):
        content = "Max position: $10M"
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("policy.delivered", content=content, span=span)
        assert event["governance_hash"] == compute_governance_hash(content)

    def test_emit_no_content_no_hash(self, instrumentor):
        tracer = trace.get_tracer("test")
        with pytest.raises(ValueError, match="governance_hash is required"):
            with tracer.start_as_current_span("test-span") as span:
                instrumentor.emit("audit.login", span=span)

    def test_emit_sets_agent_id(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["agent_id"] == "agent.test-bot"

    def test_emit_sets_org_id(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["org_id"] == "org.test"

    def test_emit_has_valid_event_id(self, instrumentor):
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert uuid_pattern.match(event["event_id"])

    def test_emit_has_event_time(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["event_time"].endswith("Z")

    def test_emit_has_spec_version(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["spec_version"] == "0.10.0"

    def test_emit_default_category(self, instrumentor):
        """Default event_category is 'governance'."""
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("policy.delivered", content="policy.delivered", span=span)
        assert event["event_category"] == "governance"

    def test_emit_normalizes_event_type(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("myplatform.custom.action", content="myplatform.custom.action", span=span)
        assert event["event_type"] == "MYPLATFORM_CUSTOM_ACTION"

    def test_emit_generates_trace_id_without_active_span(self, instrumentor):
        event = instrumentor.emit("INJECT_SUCCESS", content="policy")
        assert len(event["trace_id"]) == 32
        assert re.match(r"^[a-f0-9]{32}$", event["trace_id"])


# ===================================================================
# Free-form event types
# ===================================================================

class TestFreeFormEventTypes:
    """AIGP does not prescribe event types — any string works."""

    def test_custom_event_type(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "myplatform.custom.action",
                event_category="custom",
                content="myplatform.custom.action",
                span=span,
            )
        assert event["event_type"] == "MYPLATFORM_CUSTOM_ACTION"
        assert event["event_category"] == "custom"

    def test_governance_event(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "INJECT_SUCCESS",
                event_category="governance",
                policy_name="policy.trading-limits",
                policy_version=4,
                content="Max position: $10M",
                span=span,
            )
        assert event["event_type"] == "INJECT_SUCCESS"
        assert event["policy_name"] == "policy.trading-limits"
        assert event["policy_version"] == 4

    def test_denial_event(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "INJECT_DENIED",
                governance_hash=compute_governance_hash("Access control violation"),
                denial_reason="Access control violation",
                severity="high",
                violation_type="ACCESS_CONTROL",
                span=span,
            )
        assert event["denial_reason"] == "Access control violation"
        assert event["severity"] == "high"
        assert event["violation_type"] == "ACCESS_CONTROL"

    def test_prompt_event(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "PROMPT_USED",
                prompt_name="prompt.trading-system",
                prompt_version=2,
                content="You are a trading assistant...",
                span=span,
            )
        assert event["prompt_name"] == "prompt.trading-system"
        assert event["prompt_version"] == 2
        assert event["governance_hash"] == compute_governance_hash("You are a trading assistant...")


# ===================================================================
# Annotations
# ===================================================================

class TestAnnotations:
    """Annotations carry informational context (not hashed)."""

    def test_annotations_passed_through(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "TOOL_INVOKED",
                content="{}",
                annotations={"tool_name": "tool.stripe-api", "scope": "charge"},
                span=span,
            )
        assert event["annotations"]["tool_name"] == "tool.stripe-api"
        assert event["annotations"]["scope"] == "charge"

    def test_annotations_empty_by_default(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["annotations"] == {}

    def test_annotations_not_hashed(self, instrumentor):
        """Same content with different annotations must produce the same governance hash."""
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event1 = instrumentor.emit("test.event", content="hello", annotations={"a": 1}, span=span)
            event2 = instrumentor.emit("test.event", content="hello", annotations={"b": 2}, span=span)
        assert event1["governance_hash"] == event2["governance_hash"]


# ===================================================================
# Data classification
# ===================================================================

class TestDataClassification:
    """Data classification is an optional field on any event."""

    def test_data_classification_set(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "INJECT_SUCCESS",
                content="policy content",
                data_classification="confidential",
                span=span,
            )
        assert event["data_classification"] == "confidential"

    def test_data_classification_empty_by_default(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["data_classification"] == ""


# ===================================================================
# Merkle tree (multi-resource)
# ===================================================================

class TestMerkleTree:
    """Multi-resource proofs via the resources= parameter."""

    def test_single_resource_no_merkle_tree(self, instrumentor):
        content = "Max $10M"
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "GOVERNANCE_PROOF",
                resources=[("policy", "policy.limits", content)],
                span=span,
            )
        # Single resource: flat hash, no merkle tree
        assert event["governance_hash"] == compute_governance_hash(content)
        assert "governance_merkle_tree" not in event or event.get("governance_merkle_tree") is None

    def test_multiple_resources_merkle_tree(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "GOVERNANCE_PROOF",
                resources=[
                    ("policy", "policy.limits", "Max $10M"),
                    ("prompt", "prompt.system", "You are a trading assistant"),
                    ("tool", "tool.stripe", '{"scope": "charge"}'),
                ],
                span=span,
            )
        assert event["governance_hash"] != ""
        assert event["hash_type"] == "merkle-sha256"
        tree = event["governance_merkle_tree"]
        assert tree["leaf_count"] == 3
        assert tree["algorithm"] == "sha256"
        assert len(tree["leaves"]) == 3

    def test_merkle_tree_deterministic(self, instrumentor):
        """Same resources produce the same root hash regardless of call."""
        resources = [
            ("policy", "policy.limits", "Max $10M"),
            ("prompt", "prompt.system", "You are a trading assistant"),
        ]
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event1 = instrumentor.emit("proof", resources=resources, span=span)
            event2 = instrumentor.emit("proof", resources=resources, span=span)
        assert event1["governance_hash"] == event2["governance_hash"]

    def test_merkle_tree_with_inclusion_proofs(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit(
                "GOVERNANCE_PROOF",
                resources=[
                    ("policy", "policy.limits", "Max $10M"),
                    ("prompt", "prompt.system", "You are a trading assistant"),
                    ("tool", "tool.search", '{"scope":"read"}'),
                ],
                include_inclusion_proofs=True,
                span=span,
            )
        tree = event["governance_merkle_tree"]
        assert "inclusion_proofs" in tree
        assert len(tree["inclusion_proofs"]) == tree["leaf_count"]


# ===================================================================
# Causal ordering
# ===================================================================

class TestCausalOrdering:
    """Sequence numbers auto-increment per trace; causality_ref links events."""

    def test_sequence_numbers_auto_increment(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            e1 = instrumentor.emit("event.a", content="a", span=span)
            e2 = instrumentor.emit("event.b", content="b", span=span)
            e3 = instrumentor.emit("event.c", content="c", span=span)
        assert e1["sequence_number"] == 1
        assert e2["sequence_number"] == 2
        assert e3["sequence_number"] == 3

    def test_sequence_numbers_per_trace(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("trace-a") as span_a:
            ea1 = instrumentor.emit("event.a", content="a", span=span_a)
            ea2 = instrumentor.emit("event.b", content="b", span=span_a)
        with tracer.start_as_current_span("trace-b") as span_b:
            eb1 = instrumentor.emit("event.c", content="c", span=span_b)
        assert ea1["sequence_number"] == 1
        assert ea2["sequence_number"] == 2
        assert eb1["sequence_number"] == 1  # Independent counter

    def test_causality_ref_passed_through(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("event.a", content="a", causality_ref="prev-id", span=span)
        assert event["causality_ref"] == "prev-id"

    def test_causality_ref_default_empty(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("event.a", content="a", span=span)
        assert event["causality_ref"] == ""


# ===================================================================
# Event callback
# ===================================================================

class TestEventCallback:
    """Event callback receives every emitted event."""

    def test_callback_called(self):
        captured = []
        instr = AIGPInstrumentor(
            agent_id="agent.test",
            event_callback=captured.append,
        )
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            instr.emit("INJECT_SUCCESS", content="content A", span=span)
            instr.emit("PROMPT_USED", content="content B", span=span)
        assert len(captured) == 2
        assert captured[0]["event_type"] == "INJECT_SUCCESS"
        assert captured[1]["event_type"] == "PROMPT_USED"

    def test_callback_exception_does_not_propagate(self):
        def bad_callback(event):
            raise RuntimeError("callback failure")

        instr = AIGPInstrumentor(
            agent_id="agent.test",
            event_callback=bad_callback,
        )
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            # Should not raise
            event = instr.emit("test.event", content="c", span=span)
        assert event is not None


# ===================================================================
# OTel trace correlation
# ===================================================================

class TestOTelCorrelation:
    """AIGP events carry OTel trace_id, span_id, trace_flags."""

    def test_trace_id_from_span(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert len(event["trace_id"]) == 32  # 128-bit hex
        assert event["trace_id"] != ""

    def test_span_id_from_span(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert len(event["span_id"]) == 16  # 64-bit hex
        assert event["span_id"] != ""

    def test_trace_flags_from_span(self, instrumentor):
        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            event = instrumentor.emit("test.event", content="test.event", span=span)
        assert event["trace_flags"] in ("00", "01")  # unsampled or sampled


# ===================================================================
# Resource attributes
# ===================================================================

class TestResourceAttributes:
    """get_resource_attributes() returns OTel Resource attrs."""

    def test_resource_attributes(self, instrumentor):
        attrs = instrumentor.get_resource_attributes()
        assert attrs["aigp.agent.id"] == "agent.test-bot"
        assert attrs["aigp.agent.name"] == "Test Bot"
        assert attrs["aigp.org.id"] == "org.test"
