"""Tests for AIGP event creation and governance hash computation."""

import re
import json
from aigp.events import create_aigp_event, compute_governance_hash


class TestGovernanceHash:
    """Tests for governance hash computation (AIGP Spec Section 8)."""

    def test_sha256_produces_64_char_hex(self):
        """Section 8.3: SHA-256 output is exactly 64 lowercase hex characters."""
        result = compute_governance_hash("Max position: $10M")
        assert len(result) == 64
        assert re.match(r"^[a-f0-9]{64}$", result)

    def test_sha256_reproducibility(self):
        """Section 8.7: Same content produces same hash."""
        content = "You are a trading assistant. Max position: $10M."
        hash1 = compute_governance_hash(content)
        hash2 = compute_governance_hash(content)
        assert hash1 == hash2

    def test_different_content_different_hash(self):
        """Different content must produce different hash."""
        hash1 = compute_governance_hash("Policy version 1")
        hash2 = compute_governance_hash("Policy version 2")
        assert hash1 != hash2

    def test_sha384_support(self):
        """Section 8.1: Implementations MAY support sha384."""
        result = compute_governance_hash("test", algorithm="sha384")
        assert len(result) == 96  # SHA-384 = 96 hex chars

    def test_sha512_support(self):
        """Section 8.1: Implementations MAY support sha512."""
        result = compute_governance_hash("test", algorithm="sha512")
        assert len(result) == 128  # SHA-512 = 128 hex chars

    def test_utf8_encoding(self):
        """Section 8.2: Input MUST be UTF-8 encoded."""
        # Unicode content should work correctly
        result = compute_governance_hash("Max Betrag: 10M Euro")
        assert len(result) == 64

    def test_no_normalization(self):
        """Section 8.2: No whitespace normalization applied."""
        hash_with_spaces = compute_governance_hash("hello  world")
        hash_without_spaces = compute_governance_hash("hello world")
        assert hash_with_spaces != hash_without_spaces


class TestCreateAIGPEvent:
    """Tests for AIGP event creation (AIGP Spec Section 5)."""

    def test_required_fields_present(self):
        """Section 5.1: All required fields must be present."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            governance_hash="a" * 64,
        )

        assert "event_id" in event
        assert event["event_type"] == "INJECT_SUCCESS"
        assert event["event_category"] == "inject"
        assert "event_time" in event
        assert event["agent_id"] == "agent.test-bot"
        assert event["governance_hash"] == "a" * 64
        assert event["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_event_id_is_uuid(self):
        """Section 5.1: event_id MUST be UUID v4."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        assert re.match(uuid_pattern, event["event_id"])

    def test_event_time_format(self):
        """Section 5.1: event_time MUST be RFC 3339 with ms precision and Z."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        # Pattern: YYYY-MM-DDTHH:MM:SS.mmmZ
        assert event["event_time"].endswith("Z")
        assert "T" in event["event_time"]
        assert "." in event["event_time"]

    def test_otel_correlation_fields(self):
        """Section 11.4: OTel span_id, parent_span_id, trace_flags."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            governance_hash="a" * 64,
            span_id="00f067aa0ba902b7",
            parent_span_id="a1b2c3d4e5f6a7b8",
            trace_flags="01",
        )

        assert event["span_id"] == "00f067aa0ba902b7"
        assert event["parent_span_id"] == "a1b2c3d4e5f6a7b8"
        assert event["trace_flags"] == "01"

    def test_otel_fields_default_empty(self):
        """OTel fields default to empty string when not provided."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        assert event["span_id"] == ""
        assert event["parent_span_id"] == ""
        assert event["trace_flags"] == ""

    def test_optional_fields_default_values(self):
        """Section 5: Optional fields have correct defaults."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        assert event["agent_name"] == ""
        assert event["org_id"] == ""
        assert event["policy_version"] == 0
        assert event["data_classification"] == ""
        assert event["denial_reason"] == ""
        assert event["severity"] == ""
        assert event["annotations"] == {}
        assert event["spec_version"] == "0.10.0"

    def test_query_hash_field(self):
        """v0.7.0: query_hash is included when provided."""
        event = create_aigp_event(
            event_type="MEMORY_READ",
            event_category="memory",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
            query_hash="b" * 64,
        )
        assert event["query_hash"] == "b" * 64

    def test_query_hash_default_empty(self):
        """v0.7.0: query_hash defaults to empty string."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        assert event["query_hash"] == ""

    def test_previous_hash_field(self):
        """v0.7.0: previous_hash is included when provided."""
        event = create_aigp_event(
            event_type="MEMORY_WRITTEN",
            event_category="memory",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
            previous_hash="c" * 64,
        )
        assert event["previous_hash"] == "c" * 64

    def test_previous_hash_default_empty(self):
        """v0.7.0: previous_hash defaults to empty string."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
        )
        assert event["previous_hash"] == ""

    def test_json_serializable(self):
        """AIGP events MUST be representable as JSON (Section 2.2)."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test-bot",
            trace_id="test-trace",
            governance_hash="a" * 64,
            annotations={"regulatory_hooks": ["FINRA", "SEC"]},
        )
        # Should not raise
        json_str = json.dumps(event)
        parsed = json.loads(json_str)
        assert parsed["event_type"] == "INJECT_SUCCESS"
