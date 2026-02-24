"""
Tests for AIGP OpenLineage facet builders.

Validates that AIGP governance events can be correctly transformed into
OpenLineage-compatible facet dicts with zero OpenLineage library dependency.
"""

import json
import re

import pytest

from aigp.openlineage import (
    build_governance_run_facet,
    build_resource_input_facets,
    build_openlineage_run_event,
    PRODUCER,
    RUN_FACET_SCHEMA_URL,
    RESOURCE_FACET_SCHEMA_URL,
    OPENLINEAGE_SCHEMA_URL,
)
from aigp.events import (
    create_aigp_event,
    compute_governance_hash,
    compute_merkle_governance_hash,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_policy_delivered(**overrides):
    """Create a minimal governance.policy.delivered AIGP event."""
    defaults = dict(
        event_type="INJECT_SUCCESS",
        event_category="governance",
        agent_id="agent.test-bot",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        governance_hash="a" * 64,
    )
    defaults.update(overrides)
    return create_aigp_event(**defaults)


def _make_merkle_event():
    """Create a governance.proof.delivered event with Merkle tree including context and lineage resources."""
    resources = [
        ("policy", "policy.trading-limits", "Max position: $10M"),
        ("prompt", "prompt.scoring-v3", "You are a helpful assistant"),
        ("context", "context.env-config", '{"env": "production"}'),
        ("lineage", "lineage.upstream-orders", '{"datasets": ["orders", "customers"]}'),
    ]
    root, tree = compute_merkle_governance_hash(resources)
    return create_aigp_event(
        event_type="GOVERNANCE_PROOF",
        event_category="governance",
        agent_id="agent.credit-scorer",
        trace_id="abc123def456",
        governance_hash=root,
        hash_type="merkle-sha256",
        governance_merkle_tree=tree,
        data_classification="confidential",
    )


# ===================================================================
# TestGovernanceRunFacet
# ===================================================================

class TestGovernanceRunFacet:
    """Tests for AIGPGovernanceRunFacet builder."""

    def test_basic_facet_structure(self):
        event = _make_policy_delivered()
        facet = build_governance_run_facet(event)

        assert facet["_producer"] == PRODUCER
        assert facet["_schemaURL"] == RUN_FACET_SCHEMA_URL
        assert facet["governanceHash"] == "a" * 64
        assert facet["hashType"] == "sha256"
        assert facet["agentId"] == "agent.test-bot"
        assert facet["traceId"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert facet["specVersion"] == "0.10.0"

    def test_leaf_count_single_resource(self):
        event = _make_policy_delivered()
        facet = build_governance_run_facet(event)
        assert facet["leafCount"] == 1

    def test_leaf_count_merkle_tree(self):
        event = _make_merkle_event()
        facet = build_governance_run_facet(event)
        assert facet["leafCount"] == 4
        assert facet["hashType"] == "merkle-sha256"

    def test_enforcement_allowed(self):
        event = _make_policy_delivered()
        facet = build_governance_run_facet(event)
        assert facet["enforcementResult"] == "allowed"

    def test_enforcement_denied_inject(self):
        event = create_aigp_event(
            event_type="INJECT_DENIED",
            event_category="governance",
            agent_id="agent.test",
            trace_id="trace-denied",
            governance_hash="a" * 64,
        )
        facet = build_governance_run_facet(event)
        assert facet["enforcementResult"] == "denied"

    def test_enforcement_denied_violation(self):
        event = create_aigp_event(
            event_type="POLICY_VIOLATION",
            event_category="governance",
            agent_id="agent.test",
            trace_id="trace-violation",
            governance_hash="b" * 64,
        )
        facet = build_governance_run_facet(event)
        assert facet["enforcementResult"] == "denied"

    def test_enforcement_denied_blocked(self):
        event = create_aigp_event(
            event_type="INFERENCE_BLOCKED",
            event_category="governance",
            agent_id="agent.test",
            trace_id="trace-blocked",
            governance_hash="c" * 64,
        )
        facet = build_governance_run_facet(event)
        assert facet["enforcementResult"] == "denied"

    def test_data_classification_included(self):
        event = _make_policy_delivered(data_classification="confidential")
        facet = build_governance_run_facet(event)
        assert facet["dataClassification"] == "confidential"

    def test_data_classification_absent_when_empty(self):
        event = _make_policy_delivered()
        facet = build_governance_run_facet(event)
        assert "dataClassification" not in facet

    def test_json_serializable(self):
        event = _make_policy_delivered(data_classification="restricted")
        facet = build_governance_run_facet(event)
        json_str = json.dumps(facet)
        parsed = json.loads(json_str)
        assert parsed["governanceHash"] == "a" * 64
        assert parsed["specVersion"] == "0.10.0"


# ===================================================================
# TestResourceInputFacets
# ===================================================================

class TestResourceInputFacets:
    """Tests for AIGPResourceInputFacet builder."""

    def test_single_policy_resource(self):
        event = _make_policy_delivered(
            policy_name="policy.trading-limits",
            policy_version=4,
        )
        facets = build_resource_input_facets(event)

        assert len(facets) == 1
        f = facets[0]
        assert f["_producer"] == PRODUCER
        assert f["_schemaURL"] == RESOURCE_FACET_SCHEMA_URL
        assert f["resourceType"] == "policy"
        assert f["resourceName"] == "policy.trading-limits"
        assert f["resourceVersion"] == 4
        assert f["leafHash"] == "a" * 64

    def test_single_prompt_resource(self):
        event = create_aigp_event(
            event_type="PROMPT_USED",
            event_category="governance",
            agent_id="agent.test",
            trace_id="trace-prompt",
            prompt_name="prompt.scoring-v3",
            prompt_version=2,
            governance_hash="b" * 64,
        )
        facets = build_resource_input_facets(event)
        assert len(facets) == 1
        assert facets[0]["resourceType"] == "prompt"
        assert facets[0]["resourceName"] == "prompt.scoring-v3"
        assert facets[0]["resourceVersion"] == 2

    def test_merkle_tree_produces_multiple_facets(self):
        event = _make_merkle_event()
        facets = build_resource_input_facets(event)

        assert len(facets) == 4
        types = {f["resourceType"] for f in facets}
        assert types == {"policy", "prompt", "context", "lineage"}

        # All have leaf hashes (64-char hex)
        for f in facets:
            assert re.match(r"^[a-f0-9]{64}$", f["leafHash"])
            assert f["_producer"] == PRODUCER

    def test_single_tool_resource_from_annotations(self):
        event = create_aigp_event(
            event_type="TOOL_INVOKED",
            event_category="tool",
            agent_id="agent.test",
            trace_id="trace-tool",
            governance_hash="c" * 64,
            annotations={"tool_name": "tool.order-lookup"},
        )
        facets = build_resource_input_facets(event)
        assert len(facets) == 1
        assert facets[0]["resourceType"] == "tool"
        assert facets[0]["resourceName"] == "tool.order-lookup"

    def test_single_model_resource_from_annotations(self):
        event = create_aigp_event(
            event_type="MODEL_LOADED",
            event_category="model",
            agent_id="agent.test",
            trace_id="trace-model",
            governance_hash="d" * 64,
            annotations={"model_name": "model.gpt4-trading-v2"},
        )
        facets = build_resource_input_facets(event)
        assert len(facets) == 1
        assert facets[0]["resourceType"] == "model"
        assert facets[0]["resourceName"] == "model.gpt4-trading-v2"

    def test_empty_event_returns_no_facets(self):
        event = create_aigp_event(
            event_type="governance.agent.registered",
            event_category="governance",
            agent_id="agent.test",
            trace_id="trace-lifecycle",
            governance_hash="d" * 64,
        )
        facets = build_resource_input_facets(event)
        assert facets == []

    def test_merkle_facets_json_serializable(self):
        event = _make_merkle_event()
        facets = build_resource_input_facets(event)
        json_str = json.dumps(facets)
        parsed = json.loads(json_str)
        assert len(parsed) == 4


# ===================================================================
# TestOpenLineageRunEvent
# ===================================================================

class TestOpenLineageRunEvent:
    """Tests for the convenience RunEvent builder."""

    def test_complete_structure(self):
        event = _make_policy_delivered(
            policy_name="policy.trading-limits",
            policy_version=4,
        )
        ol = build_openlineage_run_event(
            event,
            job_namespace="finco.trading",
            job_name="trading-bot-v2.invoke",
        )

        # Top-level fields
        assert ol["eventType"] == "COMPLETE"
        assert "eventTime" in ol
        assert ol["producer"] == PRODUCER
        assert ol["schemaURL"] == OPENLINEAGE_SCHEMA_URL

        # Run
        assert "runId" in ol["run"]
        assert "aigp_governance" in ol["run"]["facets"]
        governance = ol["run"]["facets"]["aigp_governance"]
        assert governance["governanceHash"] == "a" * 64

        # Job
        assert ol["job"]["namespace"] == "finco.trading"
        assert ol["job"]["name"] == "trading-bot-v2.invoke"

        # Inputs
        assert len(ol["inputs"]) == 1
        inp = ol["inputs"][0]
        assert inp["namespace"] == "finco.trading"
        assert inp["name"] == "policy.trading-limits"
        assert "aigp_resource" in inp["inputFacets"]

        # Outputs (empty for governance)
        assert ol["outputs"] == []

    def test_run_id_defaults_to_trace_id(self):
        event = _make_policy_delivered(
            policy_name="policy.test",
        )
        ol = build_openlineage_run_event(event, "ns", "job")
        assert ol["run"]["runId"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_custom_run_id(self):
        event = _make_policy_delivered(policy_name="policy.test")
        ol = build_openlineage_run_event(
            event, "ns", "job", run_id="custom-run-123"
        )
        assert ol["run"]["runId"] == "custom-run-123"

    def test_custom_event_type(self):
        event = _make_policy_delivered(policy_name="policy.test")
        ol = build_openlineage_run_event(
            event, "ns", "job", event_type="START"
        )
        assert ol["eventType"] == "START"

    def test_merkle_tree_inputs(self):
        event = _make_merkle_event()
        ol = build_openlineage_run_event(
            event,
            job_namespace="finco.scoring",
            job_name="credit-scorer.invoke",
        )

        assert len(ol["inputs"]) == 4
        input_names = {inp["name"] for inp in ol["inputs"]}
        assert "policy.trading-limits" in input_names
        assert "prompt.scoring-v3" in input_names
        assert "context.env-config" in input_names
        assert "lineage.upstream-orders" in input_names

        # Governance facet shows Merkle
        governance = ol["run"]["facets"]["aigp_governance"]
        assert governance["hashType"] == "merkle-sha256"
        assert governance["leafCount"] == 4

    def test_json_serializable(self):
        event = _make_policy_delivered(
            policy_name="policy.test",
            data_classification="internal",
        )
        ol = build_openlineage_run_event(event, "test.ns", "test.job")
        json_str = json.dumps(ol)
        parsed = json.loads(json_str)
        assert parsed["eventType"] == "COMPLETE"
        assert parsed["job"]["namespace"] == "test.ns"

    def test_event_time_format(self):
        event = _make_policy_delivered(policy_name="policy.test")
        ol = build_openlineage_run_event(event, "ns", "job")
        # Should be ISO 8601 with milliseconds
        assert re.match(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
            ol["eventTime"],
        )
