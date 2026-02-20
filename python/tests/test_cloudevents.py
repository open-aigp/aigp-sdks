"""
Tests for AIGP CloudEvents Binding
===================================

Tests the CloudEvents wrapping/unwrapping functions defined in
aigp.cloudevents, per AIGP Specification Section 13.
"""

import pytest

from aigp.events import create_aigp_event, compute_governance_hash
from aigp.cloudevents import (
    wrap_as_cloudevent,
    unwrap_from_cloudevent,
    build_ce_headers,
    ce_type_from_event_type,
    event_type_from_ce_type,
    CE_SPECVERSION,
    AIGP_TYPE_PREFIX,
    AIGP_SOURCE_SCHEME,
    AIGP_DATA_SCHEMA,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides):
    """Create a minimal AIGP event for testing."""
    defaults = {
        "event_type": "INJECT_SUCCESS",
        "event_category": "governance",
        "agent_id": "agent.trading-bot-v2",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "governance_hash": compute_governance_hash("test content"),
    }
    defaults.update(overrides)
    return create_aigp_event(**defaults)


# ---------------------------------------------------------------------------
# wrap_as_cloudevent
# ---------------------------------------------------------------------------

class TestWrapAsCloudevent:
    """Tests for wrap_as_cloudevent()."""

    def test_required_ce_attributes(self):
        """CloudEvents REQUIRED attributes are present."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)

        assert ce["specversion"] == CE_SPECVERSION
        assert ce["id"] == event["event_id"]
        assert ce["type"] == "org.aigp.v1.inject_success"
        assert ce["source"].startswith(AIGP_SOURCE_SCHEME)

    def test_type_is_lowercase(self):
        """CloudEvents type uses lowercase event_type."""
        event = _make_event(event_type="GOVERNANCE_PROOF",
                            event_category="governance")
        ce = wrap_as_cloudevent(event)
        assert ce["type"] == "org.aigp.v1.governance_proof"

    def test_source_includes_org_and_agent(self):
        """Source URI is aigp://<org_id>/<agent_id>."""
        event = _make_event(org_id="org.finco")
        ce = wrap_as_cloudevent(event)
        assert ce["source"] == "aigp://org.finco/agent.trading-bot-v2"

    def test_source_defaults_org_to_default(self):
        """When org_id is empty, source uses 'default'."""
        event = _make_event()
        # org_id defaults to "" in create_aigp_event
        ce = wrap_as_cloudevent(event)
        assert ce["source"] == "aigp://default/agent.trading-bot-v2"

    def test_time_from_event_time(self):
        """CE time is mapped from AIGP event_time."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["time"] == event["event_time"]

    def test_datacontenttype(self):
        """datacontenttype is application/json."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["datacontenttype"] == "application/json"

    def test_dataschema_included_by_default(self):
        """dataschema points to AIGP JSON Schema."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["dataschema"] == AIGP_DATA_SCHEMA

    def test_dataschema_excluded_when_disabled(self):
        """dataschema can be omitted."""
        event = _make_event()
        ce = wrap_as_cloudevent(event, include_dataschema=False)
        assert "dataschema" not in ce

    def test_subject_is_policy_name(self):
        """Subject is set to policy_name when present."""
        event = _make_event(policy_name="policy.trading-limits")
        ce = wrap_as_cloudevent(event)
        assert ce["subject"] == "policy.trading-limits"

    def test_subject_falls_back_to_prompt_name(self):
        """Subject falls back to prompt_name when policy_name is empty."""
        event = _make_event(
            event_type="PROMPT_USED",
            event_category="governance",
            prompt_name="prompt.customer-support-v3",
        )
        ce = wrap_as_cloudevent(event)
        assert ce["subject"] == "prompt.customer-support-v3"

    def test_subject_absent_when_no_resource(self):
        """Subject is absent when neither policy nor prompt name is set."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert "subject" not in ce

    def test_data_is_full_aigp_event(self):
        """The data field contains the full AIGP event."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["data"] == event
        assert ce["data"]["event_type"] == "INJECT_SUCCESS"

    def test_raises_on_missing_event_id(self):
        """Raises ValueError when event_id is missing."""
        event = _make_event()
        event["event_id"] = ""
        with pytest.raises(ValueError, match="event_id"):
            wrap_as_cloudevent(event)

    def test_raises_on_missing_event_type(self):
        """Raises ValueError when event_type is missing."""
        event = _make_event()
        event["event_type"] = ""
        with pytest.raises(ValueError, match="event_type"):
            wrap_as_cloudevent(event)

    def test_raises_on_missing_agent_id(self):
        """Raises ValueError when agent_id is missing."""
        event = _make_event()
        event["agent_id"] = ""
        with pytest.raises(ValueError, match="agent_id"):
            wrap_as_cloudevent(event)


# ---------------------------------------------------------------------------
# AIGP Extension Attributes
# ---------------------------------------------------------------------------

class TestAIGPExtensionAttributes:
    """Tests for AIGP CloudEvents extension attributes."""

    def test_aigpagentid(self):
        """aigpagentid is always present."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["aigpagentid"] == "agent.trading-bot-v2"

    def test_aigporgid_present_when_set(self):
        """aigporgid is present when org_id is non-empty."""
        event = _make_event(org_id="org.finco")
        ce = wrap_as_cloudevent(event)
        assert ce["aigporgid"] == "org.finco"

    def test_aigporgid_absent_when_default(self):
        """aigporgid is absent when org_id is empty/default."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert "aigporgid" not in ce

    def test_aigpcategory(self):
        """aigpcategory maps from event_category."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["aigpcategory"] == "governance"

    def test_aigpclassification(self):
        """aigpclassification maps from data_classification."""
        event = _make_event(data_classification="confidential")
        ce = wrap_as_cloudevent(event)
        assert ce["aigpclassification"] == "confidential"

    def test_aigpclassification_absent_when_empty(self):
        """aigpclassification is absent when data_classification is empty."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert "aigpclassification" not in ce

    def test_aigpseverity(self):
        """aigpseverity maps from severity."""
        event = _make_event(severity="critical")
        ce = wrap_as_cloudevent(event)
        assert ce["aigpseverity"] == "critical"

    def test_aigpseverity_absent_when_empty(self):
        """aigpseverity is absent when severity is empty."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert "aigpseverity" not in ce

    def test_aigphashtype(self):
        """aigphashtype maps from hash_type."""
        event = _make_event()
        ce = wrap_as_cloudevent(event)
        assert ce["aigphashtype"] == "sha256"

    def test_extension_names_are_lowercase_alnum(self):
        """All AIGP extension attribute names are lowercase a-z0-9."""
        event = _make_event(
            org_id="org.finco",
            data_classification="confidential",
            severity="high",
        )
        ce = wrap_as_cloudevent(event)
        aigp_keys = [k for k in ce if k.startswith("aigp")]
        for key in aigp_keys:
            assert key == key.lower(), f"Extension key {key!r} is not lowercase"
            assert key.isalnum(), f"Extension key {key!r} contains non-alnum chars"
            assert len(key) <= 20, f"Extension key {key!r} exceeds 20 chars"


# ---------------------------------------------------------------------------
# unwrap_from_cloudevent
# ---------------------------------------------------------------------------

class TestUnwrapFromCloudevent:
    """Tests for unwrap_from_cloudevent()."""

    def test_roundtrip(self):
        """wrap -> unwrap returns the original AIGP event."""
        event = _make_event(org_id="org.finco")
        ce = wrap_as_cloudevent(event)
        unwrapped = unwrap_from_cloudevent(ce)
        assert unwrapped == event

    def test_rejects_wrong_specversion(self):
        """Raises on unsupported specversion."""
        ce = {"specversion": "2.0", "type": "org.aigp.v1.test", "data": {}}
        with pytest.raises(ValueError, match="specversion"):
            unwrap_from_cloudevent(ce)

    def test_rejects_non_aigp_type(self):
        """Raises when type doesn't start with org.aigp.v1."""
        ce = {"specversion": "1.0", "type": "com.example.other", "data": {}}
        with pytest.raises(ValueError, match="not an AIGP event"):
            unwrap_from_cloudevent(ce)

    def test_rejects_missing_data(self):
        """Raises when data field is missing."""
        ce = {"specversion": "1.0", "type": "org.aigp.v1.inject_success"}
        with pytest.raises(ValueError, match="no 'data' field"):
            unwrap_from_cloudevent(ce)

    def test_rejects_non_dict_data(self):
        """Raises when data is not a dict."""
        ce = {
            "specversion": "1.0",
            "type": "org.aigp.v1.inject_success",
            "data": "not a dict",
        }
        with pytest.raises(ValueError, match="must be a dict"):
            unwrap_from_cloudevent(ce)


# ---------------------------------------------------------------------------
# Type conversion helpers
# ---------------------------------------------------------------------------

class TestTypeConversion:
    """Tests for ce_type_from_event_type and event_type_from_ce_type."""

    def test_to_ce_type(self):
        """Event types are lowercased and prefixed."""
        assert ce_type_from_event_type("INJECT_SUCCESS") == "org.aigp.v1.inject_success"
        assert ce_type_from_event_type("PROMPT_DENIED") == "org.aigp.v1.prompt_denied"
        assert ce_type_from_event_type("TOOL_INVOKED") == "org.aigp.v1.tool_invoked"
        assert ce_type_from_event_type("UNVERIFIED_BOUNDARY") == "org.aigp.v1.unverified_boundary"

    def test_from_ce_type(self):
        """CE type prefix is stripped, returning the original event type."""
        assert event_type_from_ce_type("org.aigp.v1.inject_success") == "inject_success"
        assert event_type_from_ce_type("org.aigp.v1.governance_proof") == "governance_proof"

    def test_roundtrip_type(self):
        """event_type -> ce_type -> event_type roundtrip."""
        for et in [
            "INJECT_SUCCESS",
            "PROMPT_DENIED",
            "A2A_CALL",
            "myplatform.custom.event",
        ]:
            assert event_type_from_ce_type(ce_type_from_event_type(et)) == et.lower()

    def test_from_ce_type_rejects_non_aigp(self):
        with pytest.raises(ValueError):
            event_type_from_ce_type("com.example.other")


# ---------------------------------------------------------------------------
# Binary mode headers
# ---------------------------------------------------------------------------

class TestBuildCeHeaders:
    """Tests for build_ce_headers()."""

    def test_http_headers(self):
        """HTTP headers use ce- prefix."""
        event = _make_event(org_id="org.finco", data_classification="confidential")
        headers = build_ce_headers(event, prefix="ce-")

        assert headers["ce-specversion"] == "1.0"
        assert headers["ce-id"] == event["event_id"]
        assert headers["ce-type"] == "org.aigp.v1.inject_success"
        assert headers["ce-source"] == "aigp://org.finco/agent.trading-bot-v2"
        assert headers["ce-aigpagentid"] == "agent.trading-bot-v2"
        assert headers["ce-aigporgid"] == "org.finco"
        assert headers["ce-aigpcategory"] == "governance"
        assert headers["ce-aigpclassification"] == "confidential"

    def test_kafka_headers(self):
        """Kafka headers use ce_ prefix."""
        event = _make_event(org_id="org.finco")
        headers = build_ce_headers(event, prefix="ce_")

        assert headers["ce_specversion"] == "1.0"
        assert headers["ce_type"] == "org.aigp.v1.inject_success"
        assert headers["ce_aigpagentid"] == "agent.trading-bot-v2"

    def test_default_prefix_is_http(self):
        """Default prefix is ce- (HTTP)."""
        event = _make_event()
        headers = build_ce_headers(event)
        assert "ce-specversion" in headers

    def test_optional_headers_absent_when_empty(self):
        """Optional extension headers are absent when AIGP fields are empty."""
        event = _make_event()
        headers = build_ce_headers(event)
        assert "ce-aigpseverity" not in headers
        assert "ce-aigpclassification" not in headers
